// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Canonical balanced bulk-load and the tree-walk
//! validation contract. Pure — object I/O
//! goes through the caller-supplied fetch closure.

use crate::encoding::{self, DecodeError, ObjectType};
use crate::hash::GrainId;
use crate::manifest::node::{
    self, DirEntry, EntryKind, FileGrains, GrainListIndexChild, GrainRef, InteriorChild,
};
use crate::manifest::{
    DEPTH_MAX, DIR_INTERIOR_MAX_CHILDREN, DIR_LEAF_MAX_ENTRIES, EncodeNodeError,
    FILE_INLINE_MAX_REFS, GRAINLIST_INDEX_MAX_CHILDREN, GRAINLIST_LEAF_MAX_REFS,
    MANIFEST_NODE_MAX_BYTES,
};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::task::{Context, Poll, Waker};

/// A built tree: every encoded node of ONE directory's B-tree (or one
/// grain-list tree), root LAST; `root` is its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltTree {
    pub root: GrainId,
    pub nodes: Vec<(GrainId, Vec<u8>)>,
}

/// Balanced-split sizes: L = ceil(n/cap) slices; the first
/// (n mod L) get ceil(n/L), the rest floor(n/L). Pure function of n.
fn split_counts(n: usize, cap: usize) -> Vec<usize> {
    debug_assert!(n > cap && cap > 0);
    let l = n.div_ceil(cap);
    let q = n / l;
    let r = n % l;
    let mut out = Vec::with_capacity(l);
    for i in 0..l {
        out.push(if i < r { q + 1 } else { q });
    }
    out
}

/// Build the canonical node set for one directory from its strictly
/// memcmp-sorted entries. The empty slice yields the canonical empty
/// leaf.
///
/// # Errors
/// [`EncodeNodeError::NotStrictlySorted`] if `entries` is not strictly
/// memcmp-sorted as a WHOLE — checked here, up front, because the node
/// codecs see only one slice each and cannot see across a leaf
/// boundary; otherwise the [`EncodeNodeError`] variant from the node
/// codecs (caps, file payload consistency).
pub fn build_dir(entries: &[DirEntry]) -> Result<BuiltTree, EncodeNodeError> {
    // Strict memcmp order is a PRECONDITION of the bulk load, and
    // `encode_dir_leaf` enforces it only WITHIN each slice it is handed.
    // Input unsorted across a leaf boundary — a name duplicated at the
    // [129, 128] split of C+1 entries, say — therefore built a
    // hashable, internally-consistent tree that no leaf rejected, and
    // only the tree walk caught it much later, as `CrossNodeOrder`, on
    // bytes that already existed. One O(n) pass here closes that:
    // checked at the public entry point rather than in
    // `build_dir_level`, so it runs exactly once instead of per level,
    // and it REJECTS rather than sorting or deduping on the caller's
    // behalf — quietly reordering a caller's entries would change which
    // directory the resulting id names.
    if !node::check_strictly_sorted(entries, |e| &e.name) {
        return Err(EncodeNodeError::NotStrictlySorted);
    }
    let mut nodes = Vec::new();
    let root = build_dir_level(entries, &mut nodes)?;
    Ok(BuiltTree { root, nodes })
}

fn build_dir_level(
    entries: &[DirEntry],
    nodes: &mut Vec<(GrainId, Vec<u8>)>,
) -> Result<GrainId, EncodeNodeError> {
    if entries.len() <= DIR_LEAF_MAX_ENTRIES as usize {
        let bytes = node::encode_dir_leaf(entries)?;
        let id = GrainId::of(&bytes);
        nodes.push((id, bytes));
        return Ok(id);
    }
    // Leaves for every slice, then interiors over them, recursively.
    let mut level: Vec<InteriorChild> = Vec::new();
    let mut rest = entries;
    for take in split_counts(entries.len(), DIR_LEAF_MAX_ENTRIES as usize) {
        let (slice, tail) = rest.split_at(take);
        rest = tail;
        let bytes = node::encode_dir_leaf(slice)?;
        let id = GrainId::of(&bytes);
        nodes.push((id, bytes));
        // split_counts never yields an empty slice (n > cap); the
        // if-let is the lint-clean spelling of that invariant.
        if let Some(first) = slice.first() {
            level.push(InteriorChild {
                first_key: first.name.clone(),
                child: id,
                subtree_entry_count: slice.len() as u64,
            });
        }
    }
    loop {
        if level.len() <= DIR_INTERIOR_MAX_CHILDREN as usize {
            let bytes = node::encode_dir_interior(&level)?;
            let id = GrainId::of(&bytes);
            nodes.push((id, bytes));
            return Ok(id);
        }
        let mut next: Vec<InteriorChild> = Vec::new();
        let mut rest = level.as_slice();
        for take in split_counts(level.len(), DIR_INTERIOR_MAX_CHILDREN as usize) {
            let (slice, tail) = rest.split_at(take);
            rest = tail;
            let bytes = node::encode_dir_interior(slice)?;
            let id = GrainId::of(&bytes);
            nodes.push((id, bytes));
            if let Some(first) = slice.first() {
                next.push(InteriorChild {
                    first_key: first.first_key.clone(),
                    child: id,
                    subtree_entry_count: slice.iter().map(|c| c.subtree_entry_count).sum(),
                });
            }
        }
        level = next;
    }
}

/// Build the canonical spill tree for a file's grain refs
/// (len > K — callers inline otherwise). Returns the built tree.
///
/// # Errors
/// [`EncodeNodeError::SpillUnderK`] if `refs.len() <= K` (callers
/// inline instead); otherwise the [`EncodeNodeError`] variant from the
/// grain-list codecs (caps, grain length bounds, cumulative
/// consistency).
pub fn build_grain_list(refs: &[GrainRef]) -> Result<BuiltTree, EncodeNodeError> {
    // <= K must inline (canonical-form rule). This was a debug_assert
    // until execution — a no-op in release, where it silently produced
    // a non-canonical one-leaf spill that only failed later, at walk.
    if let Ok(count) = u32::try_from(refs.len())
        && count <= FILE_INLINE_MAX_REFS
    {
        return Err(EncodeNodeError::SpillUnderK { count });
    }
    let mut nodes = Vec::new();
    if refs.len() <= GRAINLIST_LEAF_MAX_REFS as usize {
        let bytes = node::encode_grain_list_leaf(refs)?;
        let id = GrainId::of(&bytes);
        nodes.push((id, bytes));
        return Ok(BuiltTree { root: id, nodes });
    }
    let mut level: Vec<GrainListIndexChild> = Vec::new();
    let mut cum_len: u64 = 0;
    let mut cum_count: u64 = 0;
    let mut rest = refs;
    for take in split_counts(refs.len(), GRAINLIST_LEAF_MAX_REFS as usize) {
        let (slice, tail) = rest.split_at(take);
        rest = tail;
        let bytes = node::encode_grain_list_leaf(slice)?;
        let id = GrainId::of(&bytes);
        nodes.push((id, bytes));
        cum_len += slice.iter().map(|r| u64::from(r.unpacked_len)).sum::<u64>();
        cum_count += slice.len() as u64;
        level.push(GrainListIndexChild {
            child: id,
            cum_unpacked_len: cum_len,
            cum_ref_count: cum_count,
        });
    }
    // One index level covers N^2 = 2^34 refs (4 PiB at the shipped
    // 256 KiB average) — deeper recursion is unreachable for v1 inputs;
    // encode one index. [Unit corrected at the format event: the older
    // note said "16 EiB of 1 MiB grains" and was wrong by 1024x in the
    // UNIT as well as stale in the grain size — 2^34 * 2^20 is 16 PiB.]
    let bytes = node::encode_grain_list_index(&level)?;
    let id = GrainId::of(&bytes);
    nodes.push((id, bytes));
    Ok(BuiltTree { root: id, nodes })
}

/// Tree-walk validation errors (format doc, normative contract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidateError {
    /// The source interrupted the walk before a verdict.
    SourceInterrupted,
    Decode(DecodeError),
    MissingObject {
        id: GrainId,
    },
    /// Fetched bytes do not hash to the id they were fetched under —
    /// a lying or corrupted store. This is also what makes object
    /// CYCLES infeasible: a cycle would require a hash preimage.
    CorruptObject {
        id: GrainId,
    },
    WrongObjectType {
        id: GrainId,
    },
    DepthExceeded,
    /// Interior `first_key` != child's actual first entry (rule 1).
    SeparatorMismatch,
    /// Cross-node ordering violated (rule 2).
    CrossNodeOrder,
    /// Node fill does not match the balanced-split arithmetic (rule 3).
    FillNotCanonical,
    /// Claimed `subtree_entry_count` wrong (rule 5).
    CountMismatch,
    /// Inline-iff-<=K violated across file payload vs spill (rule 5).
    SpillNotCanonical,
    /// Grain-list cumulative fields inconsistent (rule 5).
    CumulativeMismatch,
}

impl From<DecodeError> for ValidateError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "decode: {e}"),
            Self::SourceInterrupted => write!(f, "tree walk interrupted by source"),
            Self::MissingObject { id } => write!(f, "missing object {id}"),
            Self::CorruptObject { id } => write!(f, "object {id} does not hash to its id"),
            Self::WrongObjectType { id } => write!(f, "wrong object type for {id}"),
            Self::DepthExceeded => write!(f, "tree depth exceeds cap"),
            Self::SeparatorMismatch => write!(f, "interior first_key != child first entry"),
            Self::CrossNodeOrder => write!(f, "cross-node entry order violated"),
            Self::FillNotCanonical => write!(f, "node fill not canonical (balanced split)"),
            Self::CountMismatch => write!(f, "subtree_entry_count mismatch"),
            Self::SpillNotCanonical => write!(f, "inline-iff-<=K violated"),
            Self::CumulativeMismatch => write!(f, "grain-list cumulative mismatch"),
        }
    }
}

impl std::error::Error for ValidateError {}

/// Aggregate facts a validated walk proves.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TreeStats {
    pub dirs: u64,
    pub files: u64,
    pub symlinks: u64,
    pub entries: u64,
    pub grains: u64,
    pub bytes: u64,
}

impl TreeStats {
    /// Field-wise SATURATING sum — how a memoized subtree delta is
    /// replayed onto its parent. See the `entries` comment in
    /// `walk_dir`: replay is what makes the counting fields reachable
    /// at `u64::MAX` from a handful of objects, and these totals are
    /// diagnostics, so they saturate rather than abort a walk whose
    /// verdict is otherwise sound.
    fn saturating_sum(self, other: Self) -> Self {
        Self {
            dirs: self.dirs.saturating_add(other.dirs),
            files: self.files.saturating_add(other.files),
            symlinks: self.symlinks.saturating_add(other.symlinks),
            entries: self.entries.saturating_add(other.entries),
            grains: self.grains.saturating_add(other.grains),
            bytes: self.bytes.saturating_add(other.bytes),
        }
    }
}

/// Structure collector for ONE directory's own B-tree (rule 3): leaf
/// entry-counts in traversal order plus each interior's
/// `(depth, child_count)`. Every directory gets a fresh collector —
/// each subdirectory is its own tree with its own canonical shape.
#[derive(Debug, Default)]
struct Shape {
    /// (depth, entry count) of each leaf, in traversal (sort) order.
    /// The DEPTH is load-bearing: canonical bulk-loaded trees are
    /// uniform-height, and without pinning depth a lopsided topology
    /// reproduces the expected width sequence exactly and validates
    /// while hashing differently, so the shape includes depth.
    leaves: Vec<(u32, u64)>,
    /// (depth, `child_count`) of each interior, in traversal order.
    interior_widths: Vec<(u32, u64)>,
}

impl Shape {
    fn work(&self) -> u64 {
        self.leaves.len().saturating_add(self.interior_widths.len()) as u64
    }
}

/// A grain-list leaf's byte-derived facts: pure functions of its
/// hash-verified bytes (`len`, the sum of its refs' `unpacked_len`; and
/// `ref_count`, the number of refs). `ref_count` doubles as the leaf's
/// shape WIDTH — the number a memo hit pushes into `Shape` alongside
/// its depth is this same field, not a second copy of it.
#[derive(Debug, Clone, Copy)]
struct LeafFacts {
    unpacked_len: u64,
    ref_count: u64,
}

/// One directory on the NESTING worklist: the id, the subtree totals
/// accumulated for it so far, and the subdirectories still to descend
/// into (in canonical name order, popped from the back).
#[derive(Debug)]
struct DirFrame {
    id: GrainId,
    acc: TreeStats,
    todo: Vec<GrainId>,
}

/// The mutable state one directory's own B-tree walk threads through:
/// that directory's OWN stats delta, the subdirectory ids it names
/// (the nesting worklist's next layer, never a recursive descent), the
/// walk-wide memo of file spill trees already verified against the
/// exact claim a dir entry made about them, and the walk-wide memo of
/// grain-list LEAF facts (see `walk_grain_list`'s doc for why leaves,
/// unlike either walk's own result, are safe to cache by id).
struct DirWalk<'a> {
    stats: TreeStats,
    todo: Vec<GrainId>,
    spill_seen: &'a mut BTreeSet<(GrainId, u64, u32)>,
    leaf_facts: &'a mut BTreeMap<GrainId, LeafFacts>,
    /// The decoded entries, in canonical order, when the caller asked for them.
    entries: Option<Vec<DirEntry>>,
}

/// Validate the whole directory tree rooted at `root` and return its totals.
///
/// The engine is [`TreeCursor`]: this is that cursor driven to its
/// first stop, so every caller, golden vector, reject fixture and
/// fuzz corpus runs through the resumable walk. `fetch` must be
/// MONOTONE for the length of the call — [`TreeCursor`] carries that
/// contract, and why a violation of it is a wrong accept rather than
/// a refusal.
///
/// # Errors
/// Returns [`ValidateError::MissingObject`] for the first id `fetch` does not
/// answer for, in canonical walk order, and otherwise exactly the
/// [`ValidateError`] the walk raises — the same verdict, and the same first
/// error, as the pre-cursor validator returned for the same resident set.
pub fn validate_dir_tree(
    root: &GrainId,
    fetch: &dyn Fn(&GrainId) -> Option<Vec<u8>>,
) -> Result<TreeStats, ValidateError> {
    // The one-shot is the cursor driven to its first stop: a `Need` is
    // exactly the `MissingObject` this function always reported, and a
    // `Done` its `TreeStats`. No hint pass runs here — a caller that
    // fetches on demand asks for hints itself, at the point it fetches.
    let mut cursor = TreeCursor::new(*root);
    match cursor.resume(fetch)? {
        Step::Done(stats) => Ok(stats),
        Step::Need(id) => Err(ValidateError::MissingObject { id }),
    }
}

/// What one [`TreeCursor::resume`] call ended on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The whole tree verified — the totals [`validate_dir_tree`] returns.
    Done(TreeStats),
    /// The walk cannot continue without this object. It is EXACTLY the id
    /// the one-shot [`validate_dir_tree`] reports as
    /// [`ValidateError::MissingObject`] over the same resident set: the
    /// first miss in canonical walk order. The cursor's VERDICT state is
    /// unchanged by this stop — resuming without making the object
    /// resident returns the same `Need` again. (Its diagnostics are not:
    /// an abandoned directory walk is counted, and the frame it was
    /// entering stays queued.) What the abandoned walk DID commit to the
    /// cursor survives the stop: `spill_seen` and `leaf_facts` entries it
    /// inserted are still there on the re-run, so the re-run sees memo
    /// HITS where the one-shot saw misses. That is sound only because
    /// both are success-only memos of facts that are a pure function of
    /// hash-verified bytes — which is exactly why `fetch` must be
    /// MONOTONE, and why the caller enforces it structurally.
    Need(GrainId),
}

/// Object and work callbacks for driving the canonical cursor with asynchronous reads.
pub trait TreeSource {
    /// Resolve a structure node. The cursor also checks its hash.
    fn node(&mut self, id: GrainId) -> impl Future<Output = Result<Vec<u8>, ValidateError>> + Send;

    /// Charge before visiting nodes or edges, including memo hits.
    fn charge(&mut self, steps: u64) -> impl Future<Output = Result<(), ValidateError>> + Send;

    /// Check a file edge against the source's frame evidence.
    fn file_ref(
        &mut self,
        reference: GrainRef,
    ) -> impl Future<Output = Result<(), ValidateError>> + Send;
}

struct Resident<'a>(&'a dyn Fn(&GrainId) -> Option<Vec<u8>>);

impl TreeSource for Resident<'_> {
    fn node(&mut self, id: GrainId) -> impl Future<Output = Result<Vec<u8>, ValidateError>> + Send {
        std::future::ready(self.0(&id).ok_or(ValidateError::MissingObject { id }))
    }

    fn charge(&mut self, _steps: u64) -> impl Future<Output = Result<(), ValidateError>> + Send {
        std::future::ready(Ok(()))
    }

    fn file_ref(
        &mut self,
        _reference: GrainRef,
    ) -> impl Future<Output = Result<(), ValidateError>> + Send {
        std::future::ready(Ok(()))
    }
}

fn with_resident<T>(
    work: impl Future<Output = Result<T, ValidateError>>,
) -> Result<T, ValidateError> {
    // Resident implements every callback with Ready.
    match std::pin::pin!(work).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => Err(ValidateError::SourceInterrupted),
    }
}

/// Where a [`TreeCursor`] stands between resumes.
#[derive(Debug)]
enum Position {
    /// `validate_one_dir(dir)` has not completed: either never started,
    /// or abandoned on a `MissingObject` (its fresh `Shape` and its own
    /// stats delta are discarded either way — the re-run recomputes
    /// both; its `spill_seen` and `leaf_facts` insertions are NOT
    /// discarded, and are re-read as hits by the re-run). `stack` holds its ancestors, parent on top.
    Entering(GrainId),
    /// This directory's own B-tree is verified; its `todo` is being
    /// drained onto the nesting worklist.
    Draining(DirFrame),
    /// The walk ended; every later `resume` returns this same outcome.
    Finished(Result<TreeStats, ValidateError>),
}

/// [`validate_dir_tree`] as a RESUMABLE walk: the same verdict, the same
/// first error, the same `TreeStats`, but the cross-directory state —
/// the directory memo, `spill_seen`, `leaf_facts` and the nesting
/// worklist — survives a stop, so a caller that fetches structure nodes
/// on demand re-walks at most the directory it stopped in, never the
/// prefix of the tree it already verified.
///
/// # Granularity
/// The unit of resumption is ONE DIRECTORY's own B-tree walk
/// (`validate_one_dir`): a stop inside it abandons that walk and the
/// re-run repeats it over what is now resident. The walkers themselves
/// (`walk_dir`, `walk_grain_list`, `validate_file_grains`) are the
/// one-shot's, unchanged — which is what makes the verdict the
/// one-shot's by construction WITHIN a directory, and the
/// post-order checks make it so ACROSS directories: every
/// child-content-dependent parent check runs after the child's walk
/// returns, so a child-internal error propagates through `?` before any
/// parent check can, whether the child was walked in this resume or an
/// earlier one.
///
/// # Cost
/// Each directory's resident B-tree is re-walked once per stop inside
/// it; with [`TreeCursor::prefetch_hints`] driving the caller's fetches
/// that is bounded by the directory's B-tree height plus its spill
/// trees' heights (≤ 2 × `DEPTH_MAX` + 1, typically 3), not by its node
/// count — but ONLY while the DISPATCHES that directory's hint pass makes
/// before reaching its first absent node stay below [`HINT_WORK_MAX`].
/// Past that the bound is gone; the precondition is stated below and
/// pinned by two rows. A one-child directory chain is linear in the number of levels:
/// each level is walked twice, once on the miss that stops the cursor
/// there and once on the resume that passes through it — the
/// `(visits, dir_walks) == (2n, 2n)` this module's own chain row pins,
/// against the pump's n(n+1)/2 + n.
///
/// THREE things degrade a directory to one re-walk per missing node —
/// O(L²) in THAT directory's node count, no worse than the pump was
/// everywhere. Two are the caller's: a store that fails hints, and a
/// pool that cannot admit them. The third is this walk's own and needs
/// neither.
///
/// Every pass restarts at the entering directory's root, and a unit is
/// charged per DISPATCH — every frame, every `todo` slot, every node
/// examination — BEFORE any memo/seen/residency check, so a REPEATED
/// child costs a unit each time. Once the dispatches made before the
/// first absent node reach [`HINT_WORK_MAX`], the pass exhausts without
/// reaching it and returns empty. A COOPERATING store reaches this on a
/// LEGAL manifest.
///
/// **The quantity is DISPATCHES, not resident nodes**, and the two come
/// apart by three orders of magnitude. `decode_grain_list_index` bounds
/// an index's child count and requires strictly increasing cumulatives
/// but never requires the children to be DISTINCT, so:
///
/// - `wide_spill`, where every dispatched child is a distinct resident
///   leaf and the two models coincide: 4,094 leaves validate in 2
///   rounds, 4,095 in 3, and each further leaf costs one more round and
///   one more full re-walk (5,000 leaves: 908 rounds). 4,096 resident
///   objects, 409,476 bytes.
/// - an index naming ONE maximum-width resident leaf 4,094 times, plus
///   one further leaf the store withholds: blind with **THREE resident
///   objects**, 5,050,409 resident bytes. The walk ACCEPTS this
///   manifest (536,739,840 grains from four objects and 9,900,087
///   published bytes), so it is not a shape the format refuses.
///
/// The contrast runs in ONE direction only: resident nodes collapse from
/// 4,096 to 3, while the byte cost goes the OTHER way. Every figure here
/// is measured. At 4,093 repeats the budget is likewise fully spent and
/// the pass still SEES, so the predicate is what gets EMITTED, not what
/// gets spent.
///
/// The cliff figures are pinned by three rows (the 5,000-leaf round count is
/// prose only): `hints_go_blind_when_the_resident_prefix_reaches_the_work_budget`
/// for the `wide_spill` cliff, its 4,096 resident objects and 409,476 bytes;
/// `hints_go_blind_with_three_resident_nodes_via_a_repeated_leaf` for the charge
/// model; `a_legal_repeated_leaf_manifest_blinds_the_hint_pass` for the repeated-leaf
/// figures and the walk accepting it. The first is the distinct-node row, where
/// dispatches and resident nodes coincide, so it cannot see the repeated-leaf quantity.
///
/// It lasts as long as the exhausting prefix does. That prefix does NOT
/// shrink for a directory's own B-tree, nor for a single spill entry
/// that never validates — both attack shapes above — so for those it is
/// permanent. A prefix spread over SEVERAL spill entries can shrink and
/// sight can recover, because a validated entry enters `spill_seen` and
/// every later pass skips it.
///
/// The remedy for all three degradations is the same one — the
/// exact-frontier machine, carried as a register row, not built here.
///
/// # `fetch` must be MONOTONE
/// Once `fetch(id)` has answered `Some(b)` it must answer `Some(b)` for
/// the rest of this cursor's life; a `None` may later become `Some`; an
/// answer must never change from `Some(b)` to `None` or to `Some(b')`.
/// The memo, `spill_seen` and `leaf_facts` all assume it. **A violating
/// `fetch` is NOT refused — it produces a WRONG ACCEPT** (a memo hit
/// skips the fetch that would have reported the object missing), so the
/// caller enforces monotonicity structurally rather than relying on this
/// walk to notice.
#[derive(Debug)]
pub struct TreeCursor {
    /// Subtree totals by directory id. Memoizing a directory's
    /// RESULT is sound only because the worklist makes every
    /// directory start its own walk at depth 1 with a fresh `Shape`
    /// — `walk_dir` and `walk_grain_list` are NOT memoizable by
    /// their own result for that reason. Stated here, on the memo
    /// that reason licenses.
    memo: BTreeMap<GrainId, TreeStats>,
    spill_seen: BTreeSet<(GrainId, u64, u32)>,
    leaf_facts: BTreeMap<GrainId, LeafFacts>,
    stack: Vec<DirFrame>,
    position: Position,
    /// The id this cursor was built on. Not needed by the walk itself
    /// (`position` carries where it stands): kept for diagnostics and
    /// for a restart control that re-enters the walk
    /// from this root frame.
    root: GrainId,
    /// Diagnostics: how many `validate_one_dir` runs (including re-runs
    /// after a stop) this cursor has made.
    dir_walks: u64,
}

impl TreeCursor {
    /// A cursor positioned before `root`'s own walk; nothing fetched yet.
    #[must_use]
    pub fn new(root: GrainId) -> Self {
        Self {
            memo: BTreeMap::new(),
            spill_seen: BTreeSet::new(),
            leaf_facts: BTreeMap::new(),
            stack: Vec::new(),
            position: Position::Entering(root),
            root,
            dir_walks: 0,
        }
    }

    /// Walk until the tree is verified, an object is missing, or a rule
    /// is violated.
    ///
    /// # Errors
    /// Exactly [`validate_dir_tree`]'s, except that a missing object is a
    /// [`Step::Need`] rather than [`ValidateError::MissingObject`]. After
    /// an error the cursor is finished: every later call returns the same
    /// error.
    pub fn resume(
        &mut self,
        fetch: &dyn Fn(&GrainId) -> Option<Vec<u8>>,
    ) -> Result<Step, ValidateError> {
        with_resident(self.resume_with(&mut Resident(fetch)))
    }

    /// Walk using a source that can wait for nodes, check file edges, and
    /// meter work. Keep this future alive to resume inside a directory.
    /// Memo hits assume immutable node bytes and stable file-edge evidence
    /// for this cursor's lifetime.
    ///
    /// # Errors
    /// A canonical walk violation or an interruption from the source.
    ///
    /// # Cancellation safety
    /// Discard the cursor if this future is dropped before completion.
    pub async fn resume_with(
        &mut self,
        source: &mut impl TreeSource,
    ) -> Result<Step, ValidateError> {
        loop {
            source.charge(1).await?;
            let mut descend: Option<GrainId> = None;
            match &mut self.position {
                Position::Finished(outcome) => return outcome.clone().map(Step::Done),
                Position::Entering(id) => {
                    let id = *id;
                    self.dir_walks = self.dir_walks.saturating_add(1);
                    match validate_one_dir_with(
                        &id,
                        source,
                        &mut self.spill_seen,
                        &mut self.leaf_facts,
                        false,
                    )
                    .await
                    {
                        Ok((mut frame, _)) => {
                            // A one-child directory's `todo` is allocated at
                            // `Vec`'s minimum capacity (four ids, 132 bytes);
                            // on a deep chain that slack is a third of the
                            // retained state. Trim it once, here.
                            frame.todo.shrink_to_fit();
                            self.position = Position::Draining(frame);
                        }
                        Err(ValidateError::MissingObject { id: missing }) => {
                            return Ok(Step::Need(missing));
                        }
                        Err(e) => {
                            self.position = Position::Finished(Err(e.clone()));
                            return Err(e);
                        }
                    }
                }
                Position::Draining(frame) => {
                    if let Some(child) = frame.todo.pop() {
                        if let Some(sub) = self.memo.get(&child).copied() {
                            frame.acc = frame.acc.saturating_sum(sub);
                        } else {
                            descend = Some(child);
                        }
                    } else {
                        // `todo` drained: this directory's whole subtree
                        // is verified.
                        let subtree = frame.acc;
                        self.memo.insert(frame.id, subtree);
                        // `stack` holds only the live frame's ancestors,
                        // so the frame that drains with an empty stack is
                        // the root's — the one place `root` is read.
                        debug_assert!(
                            !self.stack.is_empty() || frame.id == self.root,
                            "the last frame to drain must be the root's"
                        );
                        if let Some(mut parent) = self.stack.pop() {
                            parent.acc = parent.acc.saturating_sum(subtree);
                            self.position = Position::Draining(parent);
                        } else {
                            let mut total = subtree;
                            total.dirs = total.dirs.saturating_add(1); // the root itself
                            self.position = Position::Finished(Ok(total));
                            return Ok(Step::Done(total));
                        }
                    }
                }
            }
            if let Some(child) = descend {
                let parent = std::mem::replace(&mut self.position, Position::Entering(child));
                if let Position::Draining(frame) = parent {
                    self.stack.push(frame);
                }
            }
        }
    }

    /// How many `validate_one_dir` runs this cursor has made, re-runs
    /// after a stop included. Diagnostics for the node-visit oracle.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn dir_walks(&self) -> u64 {
        self.dir_walks
    }
}

/// Emitted ids per [`TreeCursor::prefetch_hints`] pass. A bound on the
/// VEC, independent of the work bound below.
pub const PREFETCH_HINT_MAX: usize = 4096;

/// Work units per [`TreeCursor::prefetch_hints`] pass: every worklist
/// FRAME considered, every `todo` SLOT considered and every resident
/// NODE examined (a `fetch` call) costs one, charged BEFORE any
/// memo/seen/residency check — so no shape can make the pass iterate
/// something the counter does not see (an empty stacked frame on a deep
/// chain, a memoized child repeated across a wide leaf, a resident
/// prefix re-examined every round). Exhausted, the pass ends silently:
/// hints are advisory, and the exact walk is what carries the verdict.
///
/// Silently is the whole cost, and it is not always transient. What this
/// bounds is DISPATCHES, not distinct nodes — a repeated child costs a
/// unit each time, by the design stated above — so one legal index
/// naming a single resident leaf 4,094 times exhausts the pass with
/// three resident nodes. A directory whose exhausting prefix cannot
/// shrink (its own B-tree, or a spill entry that never validates and so
/// never enters `spill_seen`) is exhausted on every later pass too. See
/// [`TreeCursor`]'s `# Cost` for the precondition and both measured
/// cliffs.
pub const HINT_WORK_MAX: usize = 4096;

/// The per-pass work counter. `charge` answers whether the caller may
/// continue.
struct HintWork {
    left: usize,
}

impl HintWork {
    fn charge(&mut self) -> bool {
        if self.left == 0 {
            return false;
        }
        self.left -= 1;
        true
    }

    /// Peeks whether the budget is already spent, without spending
    /// another unit. A recursive child loop uses this to stop
    /// DISPATCHING once exhausted, rather than making one
    /// immediately-returning call per remaining child — the callee's own
    /// `charge()` already refuses those calls, but only after the
    /// call/frame overhead of making them. Without this, a deeply nested
    /// maximum-fanout structure keeps making free (O(1), non-recursing)
    /// calls for every sibling at every already-visited level long after
    /// the pass has nothing left to spend.
    fn exhausted(&self) -> bool {
        self.left == 0
    }

    /// How many children of the node being examined can still be
    /// REACHED — read by the projections to size what they retain.
    ///
    /// It is EXACT, not conservative: every dispatch charges one unit at
    /// the callee's first line, and nothing charges between a node's own
    /// `charge()` and its child loop, so a frame can never DISPATCH more
    /// than this many times. That is a bound on dispatches, not on
    /// children — which is why a projection may be truncated here only
    /// once it holds nothing but items that WILL be dispatched (see
    /// [`project_dir_node`], whose `DirLeaf` arm drops the free skips
    /// first).
    ///
    /// The projections take a `&HintWork` rather than a number so
    /// that the two call sites cannot disagree about WHICH
    /// quantity bounds a dispatch. Two plausible wrong answers
    /// sit right there — `*budget` and `max - out.len()` — and
    /// both are in fact caught by shipped rows: passing `*budget`
    /// reds
    /// `hints_go_blind_with_three_resident_nodes_via_a_repeated_leaf`
    /// (4 against 4,096) and passing `max - out.len()` reds
    /// `a_binding_hint_cap_keeps_the_verdict` (529 rounds against
    /// 15), because the emission cap bounds EMISSIONS and a
    /// resident child dispatches without emitting. So this shape
    /// is legibility, not the only thing standing between the
    /// pass and a silent regression.
    fn dispatches_left(&self) -> usize {
        self.left
    }
}

impl TreeCursor {
    /// Objects the walk will need soon, for a caller that fetches in
    /// batches: every not-yet-resident node reachable through RESIDENT
    /// nodes of the directory currently being entered (its own B-tree
    /// and the spill trees its leaves name), then the child directories
    /// still queued on the nesting worklist, innermost frame first. At
    /// most `max` ids, in canonical walk order, deduplicated; at most
    /// [`HINT_WORK_MAX`] units of work.
    ///
    /// Advisory: the cursor never depends on a hint having been fetched,
    /// and a hint is never a verdict — a hostile node's children are
    /// listed exactly as an honest node's are, and the walk that follows
    /// still refuses the hostile node first. Worklist entries are NOT
    /// residency-checked here (that would clone every resident node's
    /// bytes through `fetch`); the caller filters against what it holds.
    /// MAY contain the id the last [`Step::Need`] reported if it is still
    /// absent.
    ///
    /// Reads through `fetch` but changes no state: a hint pass over an
    /// undecodable or mis-hashed node stops at that node, as does one
    /// over a node wider than [`MANIFEST_NODE_MAX_BYTES`] — the widest
    /// any legal manifest structure node encodes to, so a wider one is
    /// refused before it is even hashed. The closure a
    /// caller hands THIS method may see objects the caller later drops;
    /// only the closure handed to [`TreeCursor::resume`] is bound by the
    /// monotone contract.
    ///
    /// **WHERE `fetch` IS CALLED IS A CONTRACT, not an implementation
    /// detail.** It is called ONLY on ids reachable through the directory
    /// being ENTERED — that is, from the two `missing_in_*` walkers. The
    /// worklist loop over queued child directories deliberately calls it
    /// nowhere (it reads `memo`, `seen` and `todo` only), which is why
    /// "worklist entries are NOT residency-checked" above is a statement
    /// about cost AND about this contract.
    ///
    /// A caller may therefore treat "my `fetch` closure was asked for id
    /// X" as "X is reachable through the directory being entered", and
    /// granary-client does: `resolve::hints_for_round` records exactly
    /// the POOLED ids this pass asked for — it does NOT itself demote —
    /// and the round loop folds that set into `demoted`, which
    /// `is_eviction_victim` reads, because a node the entering walk
    /// depends on must not be evicted one resume before it is needed. **Adding a
    /// `fetch` call to the worklist loop would silently make the pooled
    /// queued roots that loop EXAMINES look like entering
    /// dependencies**, so the client's pool would lose those as eviction
    /// victims and, WHEN THEY HOLD ENOUGH CAPACITY THAT NO OTHER
    /// ELIGIBLE VICTIM SUFFICES, stop speculating until a promotion
    /// prunes them or the resolve ends. Under lighter pressure admission
    /// simply continues; the capacity antecedent is row 252's and it
    /// belongs here too. Not "every" root and not "for the rest of the
    /// resolve": the loop is work-bounded by `HINT_WORK_MAX` and
    /// promotion recovers capacity — the same two qualifications the
    /// client's own register row 252 carries, and they were missed here
    /// by the sweep that added them there. Nothing in THIS crate
    /// fails if that changes; the row that catches it lives in
    /// granary-client
    /// (`hints_for_round_demotes_only_the_pooled_ids_the_pass_reached`),
    /// which fails if a `fetch(child)` call is added to this loop.
    /// The frames loop reads only `memo`, `seen` and `todo`,
    /// so examining a queued root must not call `fetch` or mark it
    /// as an entering dependency.
    #[must_use]
    pub fn prefetch_hints(&self, fetch: &dyn Fn(&GrainId) -> Option<Vec<u8>>, max: usize) -> Hints {
        self.prefetch_hints_counted(fetch, max).0
    }

    /// [`TreeCursor::prefetch_hints`] plus the work units it spent — the
    /// quantity the work oracles pin.
    fn prefetch_hints_counted(
        &self,
        fetch: &dyn Fn(&GrainId) -> Option<Vec<u8>>,
        max: usize,
    ) -> (Hints, usize) {
        // The advertised emission ceiling, enforced rather than assumed. A
        // caller may ask for more; today it would still get at most
        // `HINT_WORK_MAX` because every emission costs a work unit, but that
        // is a coincidence of the two constants being equal, not a bound.
        let max = max.min(PREFETCH_HINT_MAX);
        let mut entering: Vec<GrainId> = Vec::new();
        let mut queued_roots: Vec<GrainId> = Vec::new();
        let mut seen: BTreeSet<GrainId> = BTreeSet::new();
        let mut work = HintWork {
            left: HINT_WORK_MAX,
        };
        let live = match &self.position {
            Position::Entering(id) => {
                missing_in_dir_tree(
                    id,
                    fetch,
                    1,
                    &self.spill_seen,
                    &self.leaf_facts,
                    &mut seen,
                    &mut entering,
                    max,
                    &mut work,
                );
                None
            }
            // Defensive, not reachable today: `resume`'s loop only
            // RETURNS while `self.position` is `Finished` (the early
            // return above, or the `Step::Done` arm) or still `Entering`
            // (the `MissingObject` arm returns `Step::Need` without ever
            // reassigning `self.position`, so it stays on the same id).
            // Every `Draining` value the loop assigns is consumed by a
            // further loop iteration before `resume` returns — so
            // between resumes, which is the only time this method runs,
            // the cursor is never caught here. Kept (not deleted) so the
            // match stays exhaustive against a future caller that DOES
            // leave the cursor mid-drain.
            Position::Draining(frame) => Some(frame),
            Position::Finished(_) => {
                return (
                    Hints {
                        entering,
                        queued_roots,
                    },
                    HINT_WORK_MAX - work.left,
                );
            }
        };
        'frames: for frame in live.into_iter().chain(self.stack.iter().rev()) {
            // One unit per FRAME considered — an empty frame on a deep
            // chain is work too.
            if !work.charge() {
                break 'frames;
            }
            // Popped from the back, so the back is the walk's next child.
            for child in frame.todo.iter().rev() {
                // One unit per SLOT considered, before the memo/seen check.
                if !work.charge() {
                    break 'frames;
                }
                if entering.len().saturating_add(queued_roots.len()) >= max {
                    break 'frames;
                }
                if self.memo.contains_key(child) || !seen.insert(*child) {
                    continue;
                }
                queued_roots.push(*child);
            }
        }
        (
            Hints {
                entering,
                queued_roots,
            },
            HINT_WORK_MAX - work.left,
        )
    }
}

/// What one hint pass named, by PROVENANCE — the caller's eviction rule
/// depends on it: `entering` is reachable through resident
/// nodes of the directory being entered (fetching it removes that
/// directory's re-walk), `queued_roots` are child directories still on
/// the nesting worklist (the walk will ENTER them later). Both in
/// canonical walk order. The two are DISJOINT, but the dedup is
/// ONE-DIRECTIONAL: `entering` is filled first, and a `queued_roots`
/// candidate already reachable through the entering directory is dropped
/// by the shared `seen` set. If that id is ABSENT it appears under
/// `entering` instead; if it is RESIDENT it appears in NEITHER vector,
/// because the entering walk seeds `seen` with resident nodes and pushes
/// only absent ones. Two content-identical sibling directories, or one
/// named twice, reach that case.
/// `queued_roots` is therefore a SUBSET of the worklist's queued roots,
/// not "every queued root" — a caller MUST NOT read "present in
/// `entering`" as "not a queued root". The eviction rule depends on it:
/// only a pooled entry the walk has never reached may ever be a victim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hints {
    pub entering: Vec<GrainId>,
    pub queued_roots: Vec<GrainId>,
}

/// The refusals both hint walkers share, in one place — including the
/// one this pass would otherwise not have.
///
/// [`MANIFEST_NODE_MAX_BYTES`] is the widest byte length ANY legal
/// manifest structure node encodes to, so wider bytes are corrupt or
/// hostile and never a manifest node. Refusing them HERE is what makes
/// what the pass HASHES, DECODES and RETAINS a property of this file
/// rather than of whatever closure a caller passes:
/// [`TreeCursor::prefetch_hints`] takes an arbitrary `Fn(&GrainId) ->
/// Option<Vec<u8>>`, and without this the widest object the pass would
/// hash, decode and hold across a descent was that closure's choice.
/// Today's one production caller serves only objects it has already
/// capped, but a guard that lives in the caller is a guard this pass
/// does not have.
///
/// It does NOT make the pass's heap ceiling unconditional, and reading
/// it that way is the mistake this paragraph exists to prevent: the
/// closure's `Vec` is allocated before the pass sees a byte of it, so
/// nothing here can cap its SIZE — only what is done with it. See
/// [`HINT_PASS_WALK_RETENTION_MAX_BYTES`], which states the residue.
///
/// Ordered BEFORE the hash deliberately: hashing an unbounded blob is
/// the cost being avoided, and the size test does not consult the hash
/// at all, so a caller cannot evade it by returning bytes that DO name
/// themselves. NO ROW PINS THAT ORDERING — moving this test after the
/// hash leaves every row in `tree/tests.rs` green,
/// because both orders refuse
/// the same nodes and emit the same hints, and differ only in what is
/// spent. Recorded as a surviving equivalent mutant rather than
/// pretended to be tested.
///
/// It refuses no node the pass would otherwise have USED, and the
/// reason takes two mechanisms rather than one. Each decoder checks
/// its COUNT CAP before allocating and its per-field caps as it
/// reads, which bounds the payload a valid decode can consume — a
/// maximal dir leaf reaches 1,281,294 bytes, a maximal interior about
/// 76 KB, and only the maximal grain-list index reaches the ceiling
/// exactly. Each then ends in `Cursor::finish`, which rejects
/// anything left over, so padding cannot make a decodable node wider
/// either. Between them, no byte string longer than the ceiling
/// decodes; the guard changes what the pass SPENDS, never what it
/// emits. (`finish` alone would not suffice: it bounds the PADDING,
/// and the caps bound the payload.)
///
/// It is scoped to structure nodes because that is all the pass descends
/// through. An over-wide object of some other type — a `Bin`, a `Root` —
/// was hashed and then dropped into the do-nothing arm before this
/// guard, and is refused before the hash after it. Neither emits
/// anything.
///
/// Returns the object's type and a cursor over its payload, or `None`
/// when the bytes are over-wide, mis-hashed or not a well-formed
/// envelope. A caller that gets `None` does what it did before: it
/// stops at this node, emitting nothing for it.
fn open_structure_node<'b>(
    id: &GrainId,
    bytes: &'b [u8],
) -> Option<(ObjectType, encoding::Cursor<'b>)> {
    if bytes.len() > MANIFEST_NODE_MAX_BYTES as usize {
        return None;
    }
    if GrainId::of(bytes) != *id {
        return None;
    }
    encoding::open_envelope(bytes).ok()
}

/// What one directory-tree node contributes to the hint pass, PROJECTED
/// out of the encoded node so that neither the node's bytes nor its
/// decoded entries outlive the projection.
enum DirProjection {
    /// A `DirLeaf`'s spill `(root, size, grain_count)` triples — the
    /// exact key type of `spill_seen` — in canonical entry order, with
    /// the `spill_seen` hits already dropped.
    Spills(Vec<(GrainId, u64, u32)>),
    /// A `DirInterior`'s child ids, in canonical order.
    Children(Vec<GrainId>),
    /// Refused, undecodable, or an object type the directory walk never
    /// descends through.
    Nothing,
}

/// Decode one directory-tree node and project what the walk still needs
/// from it, CONSUMING the encoded bytes.
///
/// By value, and that is the point: the encoded node and its decoded
/// entry vector both die when this returns, so a caller cannot hold
/// either across its descent. The `DirLeaf` arm is the one that had no
/// `drop(bytes)` at all before this — it retained the encoded node AND
/// the decoded entries across every spill descent, unlike its own
/// `DirInterior` sibling.
///
/// The `spill_seen` filter runs BEFORE anything is truncated,
/// and the order is what makes the truncation legitimate at all.
/// The budget bounds DISPATCHES, and in this arm a loop
/// iteration is not a dispatch: a `spill_seen` hit, and every
/// entry that is not a spilled file, is skipped without charging
/// a work unit. Truncating the raw entries would therefore spend
/// slots on iterations that cost nothing and drop entries the
/// pass can still afford — with entries `[hit, A, B]` and two
/// dispatches left it would keep `[hit, A]` and lose B.
/// Filtering first leaves a list on which every remaining item
/// COSTS AT LEAST ONE WORK UNIT IF IT IS REACHED — which is the
/// actual precondition [`HintWork::dispatches_left`] needs, and
/// is weaker than "every item will be dispatched". Items at the
/// tail may not be reached at all, because the dispatches ahead
/// of them spend the budget; that is what the loop's
/// [`HintWork::exhausted`] peek is for, and the paragraph below
/// says so. A reader who took the stronger form would conclude
/// the peek is redundant; it is not.
///
/// The truncation is [`HintWork::dispatches_left`], read here rather
/// than passed in: the ids past that prefix are unreachable this pass,
/// and retaining them is what put a full decoded vector on every live
/// frame. The caller's [`HintWork::exhausted`] peek is still needed and
/// is not a duplicate — the dispatches themselves spend the budget as
/// they run, so a projection sized when the frame was entered can
/// outlive what the frame can afford.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the by-value `bytes` IS the retention contract: taking `&[u8]` \
              would let the caller hold the encoded node across its descent, \
              which is the defect this projection exists to close"
)]
fn project_dir_node(
    id: &GrainId,
    bytes: Vec<u8>,
    spill_seen: &BTreeSet<(GrainId, u64, u32)>,
    work: &HintWork,
) -> DirProjection {
    let Some((ty, cursor)) = open_structure_node(id, &bytes) else {
        return DirProjection::Nothing;
    };
    match ty {
        ObjectType::DirLeaf => {
            let Ok(entries) = node::decode_dir_leaf(cursor) else {
                return DirProjection::Nothing;
            };
            DirProjection::Spills(
                entries
                    .iter()
                    .filter_map(|e| match &e.kind {
                        EntryKind::File {
                            size,
                            grains: FileGrains::Spill { grain_count, root },
                            ..
                        } => Some((*root, *size, *grain_count)),
                        _ => None,
                    })
                    .filter(|key| !spill_seen.contains(key))
                    .take(work.dispatches_left())
                    .collect(),
            )
        }
        ObjectType::DirInterior => {
            let Ok(children) = node::decode_dir_interior(cursor) else {
                return DirProjection::Nothing;
            };
            DirProjection::Children(
                children
                    .iter()
                    .take(work.dispatches_left())
                    .map(|ch| ch.child)
                    .collect(),
            )
        }
        ObjectType::GrainListLeaf
        | ObjectType::GrainListIndex
        | ObjectType::Bin
        | ObjectType::BinmapIndex
        | ObjectType::BinTable
        | ObjectType::BinmapShard
        | ObjectType::Root
        | ObjectType::Sheaf => DirProjection::Nothing,
    }
}

/// Decode one grain-list node and project the child ids the walk still
/// needs from it, CONSUMING the encoded bytes — the grain-list half of
/// [`project_dir_node`], and by value for the same reason.
///
/// Empty for every node that is not a `GrainListIndex`, which is what
/// the caller did before: a leaf, a mis-hashed node, a bad envelope and
/// an undecodable index all descend into nothing.
///
/// The truncation carries [`project_dir_node`]'s contract unchanged.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the by-value `bytes` IS the retention contract: taking `&[u8]` \
              would let the caller hold the encoded node across its descent, \
              which is the defect this projection exists to close"
)]
fn project_grain_list_children(id: &GrainId, bytes: Vec<u8>, work: &HintWork) -> Vec<GrainId> {
    let Some((ty, cursor)) = open_structure_node(id, &bytes) else {
        return Vec::new();
    };
    if ty != ObjectType::GrainListIndex {
        return Vec::new();
    }
    let Ok(children) = node::decode_grain_list_index(cursor) else {
        return Vec::new();
    };
    children
        .iter()
        .take(work.dispatches_left())
        .map(|ch| ch.child)
        .collect()
}

/// `usize::min` is not a `const fn` on this toolchain; the ceiling
/// below is a compile-time expression, so it needs one.
const fn min_usize(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}

/// What one hint pass can hold at once in its live walk, DERIVED from
/// the format caps rather than asserted — the quantity the two
/// projections above exist to bound.
///
/// The peak is reached DURING a decode, not after one. At that instant
/// the live walk holds: the node being projected — its encoded bytes,
/// at most [`MANIFEST_NODE_MAX_BYTES`] for any node that DECODES, plus
/// its decoded vector — and one projected vector per frame. The
/// decoded term is largest for a maximal grain-list index
/// (`GRAINLIST_INDEX_MAX_CHILDREN` children at 56 bytes = 7,340,032,
/// against 1,396,480 for the widest dir leaf's entries), and the encoded
/// term is capped at the ceiling for every shape, so the sum takes the
/// index's.
///
/// The frame count is [`DEPTH_MAX`] and not one fewer, and two review
/// lanes read it opposite ways, so it is worth stating which is right:
/// the frame doing the decoding is COLLECTING its own projection at that
/// same instant, so the fifteen ancestors and the one under construction
/// are all alive together. That FRAME COUNT is exact; the per-frame
/// WIDTH is not, and saying "exact on the grain-list side" without that
/// distinction over-states it — each frame projects `dispatches_left`
/// ids, which the descent has already spent one unit per level of, so
/// the term is loose by a few thousand bytes even on the worst tower. A
/// measurement was reported for the worst tower this bound admits:
/// fifteen maximal directory interiors, a maximal dir leaf, and a
/// 16-deep maximal-width index chain, 32 live frames: 16,053,310 bytes,
/// 68,560 under the sum. That reported figure is not
/// reproduced by anything in this tree: no test here builds the
/// full tower, so the byte count above has no executable check
/// beside it. Treat
/// it as corroboration of the direction, not as a pinned number; what is
/// pinned is the sum below. On the directory side it is loose on purpose:
/// it prices all
/// `DEPTH_MAX` directory frames as `DirLeaf` spill-triple frames when at
/// most ONE can be a leaf (only `DirInterior` recurses in the dir tree)
/// and the other fifteen hold 33-byte ids. The 48-byte triple slot also
/// absorbs the `Spills` `collect`'s geometric growth, which cannot
/// exceed a capacity of [`DIR_LEAF_MAX_ENTRIES`].
///
/// The sum is 16,121,870 bytes, 15.4 MiB, pinned below.
///
/// Before the projection, each live grain-list frame held its own full
/// decoded vector, so the same 16-deep maximal-index chain peaked at
/// `16 * 7,340,032 + 6,422,542` = 123,863,054 bytes, 118.1 MiB.
/// Separately — and not counted in that figure — the `DirLeaf` arm held
/// its encoded node AND its decoded entries across every spill descent,
/// the one recursive descent in this file that released nothing at all.
/// Both are closed by the same change.
///
/// What this ceiling does NOT bound, stated because
/// [`open_structure_node`] can look as though it does: the ALLOCATION
/// behind the `Vec` a caller's closure chooses to return. Two ways it
/// escapes — the closure may return a `Vec` far longer than the ceiling
/// (refused, but already allocated), and it may return a SHORT, valid
/// node in a `Vec` with an enormous CAPACITY, which the guard's
/// `bytes.len()` test does not see at all and which stays live for the
/// whole projection. Both happen inside the closure, before the pass
/// sees a byte, so no guard here can cap either — the guard can only
/// refuse to HASH, DECODE or RETAIN what it is handed. What it does buy
/// is that an over-wide blob is transient:
/// it is refused before the hash and dropped before any descent, so it
/// never stacks with a second one, and the sum above holds for every
/// node the pass actually decodes. The one production caller serves only
/// `nodes` and `pool`, both filled from fetches declared at
/// `MANIFEST_NODE_MAX_BYTES` — so a bound on the closure exists, it is
/// simply the caller's rather than this file's, which is the honest
/// residue of register row 219 and not something the row's own test can
/// close.
///
/// Pass-wide state is deliberately OUTSIDE this sum, and small: the
/// emitted vector (`entering`, which is the `out` every frame pushes to)
/// and `queued_roots` hold at most [`PREFETCH_HINT_MAX`] ids between
/// them — about 135 KB — and `seen` takes at most [`HINT_WORK_MAX`]
/// insertions, a few hundred KB with its B-tree overhead. Under a
/// megabyte together, and none of it is per-frame, which is why the
/// constant is named for the WALK's retention rather than the pass's.
///
/// NOT A MEMORY GATE, and the distinction is the honest part of this
/// comment: hoisting a decoded vector back out of a projection helper
/// turns nothing here red. What makes the retention structural is those
/// helpers' by-value `bytes: Vec<u8>` parameter — the encoded node
/// cannot outlive the projection without a signature change. This
/// constant is the arithmetic, checked at compile time so that a
/// format-cap change cannot move the ceiling silently.
const HINT_PASS_WALK_RETENTION_MAX_BYTES: usize = MANIFEST_NODE_MAX_BYTES as usize
    + GRAINLIST_INDEX_MAX_CHILDREN as usize * size_of::<GrainListIndexChild>()
    + DEPTH_MAX as usize
        * min_usize(HINT_WORK_MAX, GRAINLIST_INDEX_MAX_CHILDREN as usize)
        * size_of::<GrainId>()
    + DEPTH_MAX as usize
        * min_usize(HINT_WORK_MAX, DIR_LEAF_MAX_ENTRIES as usize)
        * size_of::<(GrainId, u64, u32)>();

/// The requirement (under 20 MiB), and then the literal, so the
/// figures in the comment above cannot go stale behind a cap change.
const _: () = assert!(HINT_PASS_WALK_RETENTION_MAX_BYTES < 20 * 1024 * 1024);
const _: () = assert!(HINT_PASS_WALK_RETENTION_MAX_BYTES == 16_121_870);

/// [`TreeCursor::prefetch_hints`]'s walk over one directory's B-tree:
/// list the missing nodes reachable through resident ones, visiting each
/// distinct id once (a hint pass is enumeration, not validation, so the
/// per-visit `Shape` push that forbids memoizing `walk_dir` does not
/// apply). Stops where the real walk would refuse: past `DEPTH_MAX`, at
/// a mis-hashed node, at an undecodable one — and when the work budget
/// is spent. It also stops at a node wider than any legal structure node
/// (see [`open_structure_node`]), which the real walk does not do
/// because no such node can decode.
#[expect(
    clippy::too_many_arguments,
    reason = "the hint pass threads the cursor's read-only state"
)]
fn missing_in_dir_tree(
    id: &GrainId,
    fetch: &dyn Fn(&GrainId) -> Option<Vec<u8>>,
    depth: u32,
    spill_seen: &BTreeSet<(GrainId, u64, u32)>,
    leaf_facts: &BTreeMap<GrainId, LeafFacts>,
    seen: &mut BTreeSet<GrainId>,
    out: &mut Vec<GrainId>,
    max: usize,
    work: &mut HintWork,
) {
    // Charged before every check: a repeated child costs a unit each time.
    if !work.charge() || out.len() >= max || depth > DEPTH_MAX || !seen.insert(*id) {
        return;
    }
    let Some(bytes) = fetch(id) else {
        out.push(*id);
        return;
    };
    match project_dir_node(id, bytes, spill_seen, work) {
        DirProjection::Spills(spills) => {
            for &(root, _size, grain_count) in &spills {
                // Peeked, not charged. The projection sized this vector
                // by what the frame could afford when it was ENTERED;
                // the dispatches below spend that budget as they run, so
                // a later entry can still find nothing left. `_size` is
                // carried only because it is part of the `spill_seen`
                // key the projection filtered on.
                if work.exhausted() {
                    break;
                }
                // The same leaf budget `validate_file_grains`
                // computes for the real walk: mirrors
                // `leaf_budget_refusal`'s threshold. Spent here as an
                // EMISSION budget (see `missing_in_grain_list`'s doc
                // comment) — one fresh counter per spill ENTRY, and
                // that ENTRY scope is the exact guarantee: a
                // traversal cannot emit more absent ids than the
                // entry that started it declared room for. It is NOT
                // a per-ROOT guarantee. A hostile index may name
                // another entry's spill root as a child, and the
                // first entry to reach it claims it (`seen` is
                // pass-wide), so that subtree's frontier is
                // enumerated under the TRAVERSING entry's budget
                // rather than its own. That costs nothing real: hints
                // are advisory and change no verdict, every emission
                // is work-charged so the pass-wide `HINT_WORK_MAX`
                // still caps total emissions, the shape is one the
                // real walk refuses, and a single entry declaring
                // `u32::MAX` grains over its own wide index already
                // reaches the same emission volume inside its own
                // budget.
                let leaf_cap = u64::from(GRAINLIST_LEAF_MAX_REFS);
                let declared = u64::from(grain_count);
                let leaf_budget = if declared <= leaf_cap {
                    1
                } else {
                    declared.div_ceil(leaf_cap)
                };
                let mut budget = leaf_budget;
                missing_in_grain_list(
                    &root,
                    fetch,
                    1,
                    leaf_facts,
                    seen,
                    out,
                    max,
                    work,
                    &mut budget,
                );
            }
        }
        DirProjection::Children(children) => {
            for child in &children {
                // Peeked, not charged — see the `Spills` arm above.
                if work.exhausted() {
                    break;
                }
                missing_in_dir_tree(
                    child,
                    fetch,
                    depth + 1,
                    spill_seen,
                    leaf_facts,
                    seen,
                    out,
                    max,
                    work,
                );
            }
        }
        DirProjection::Nothing => {}
    }
}

/// The spill-tree half of the hint pass. A leaf already in `leaf_facts`
/// is never asked for: the real walk answers it from the memo.
///
/// `budget` is an EMISSION budget, not a per-node fan-out cap: it starts
/// at the entry's `leaf_budget` (see the `DirLeaf` call site) and is
/// shared by `&mut` across the WHOLE spill-root traversal — one unit is
/// spent only immediately before an absent id is actually pushed to
/// `out`. Descending into a resident index costs nothing against it
/// (only `work`, the pass-wide step counter, is charged for that).
///
/// This is deliberately NOT capped per node. `grain_count` is `u32`, so
/// the largest possible `leaf_budget` is `ceil((2^32 - 1) /
/// GRAINLIST_LEAF_MAX_REFS) = 32_768` — below
/// `GRAINLIST_INDEX_MAX_CHILDREN` (`131_072`) — so no canonical spill tree
/// the real walk accepts is ever more than one leaf, or one index over
/// leaves. A per-node cap checked the wrong quantity: it let a
/// branching tree of resident index nodes reset its allowance at every
/// level, multiplying the total absent ids a hint pass could be made to
/// declare far past what any accepted manifest could ever hold — every
/// node's OWN fan-out can sit under the cap while the reachable
/// frontier grows exponentially with depth. Capping total EMISSIONS
/// instead closes that regardless of shape, and can never truncate a
/// legitimate spill's hints, because the legitimate frontier is never
/// larger than the budget to begin with.
#[expect(
    clippy::too_many_arguments,
    reason = "the hint pass threads the cursor's read-only state"
)]
fn missing_in_grain_list(
    id: &GrainId,
    fetch: &dyn Fn(&GrainId) -> Option<Vec<u8>>,
    depth: u32,
    leaf_facts: &BTreeMap<GrainId, LeafFacts>,
    seen: &mut BTreeSet<GrainId>,
    out: &mut Vec<GrainId>,
    max: usize,
    work: &mut HintWork,
    budget: &mut u64,
) {
    // `*budget == 0` is tested BEFORE `seen.insert`, and the order is
    // load-bearing even though the clause itself is currently unreachable.
    //
    // Dead: the root call always passes a budget of at least 1 (the
    // `leaf_budget` formula floors at 1) and every recursive call is
    // preceded in the child loop by `if work.exhausted() || *budget == 0
    // { break; }`. The zero-budget check costs one branch and protects any
    // recursion path added without that pre-check. It serves the same
    // defensive role as the unreachable `Position::Draining` arm elsewhere
    // in this file, while keeping the ordering constraint local to the
    // side-effecting `seen.insert` call below.
    //
    // Load-bearing: `seen.insert` has a SIDE EFFECT. With the two
    // clauses the other way round, a zero-budget entry would CLAIM the
    // id and then return without emitting it, and a later spill entry
    // that still has budget could never emit it — an id lost to the
    // hint pass for the rest of the pass. Nothing today can reach that
    // state, so no shipped row discriminates this ordering. It is correct
    // by construction rather than asserted by a test; the side effect above
    // is the reason for keeping the zero-budget check first even though the
    // current call paths cannot reach it.
    if !work.charge()
        || out.len() >= max
        || depth > DEPTH_MAX
        || leaf_facts.contains_key(id)
        || *budget == 0
        || !seen.insert(*id)
    {
        return;
    }
    let Some(bytes) = fetch(id) else {
        // The only spend site: an id actually declared missing, and
        // nowhere else — descending past a resident index above never
        // reaches here. Guarded by the zero test in the early-return
        // above, so this can never underflow.
        *budget -= 1;
        out.push(*id);
        return;
    };
    // The encoded node and its decoded child vector both die inside the
    // projection: holding either would retain one node ceiling per live
    // frame — up to `DEPTH_MAX` of them at once on a hostile chain of
    // maximum-width indexes. A work unit bounds the NUMBER of nodes
    // examined, not their SIZE, so the retained bytes are the part the
    // counter cannot see.
    let children = project_grain_list_children(id, bytes, work);
    for child in &children {
        // Peeked, not charged — see `missing_in_dir_tree`'s `Spills`
        // arm. Stops DISPATCHING remaining siblings once the shared
        // emission budget (or the pass-wide work budget) is spent,
        // rather than making one immediately-returning call per
        // remaining child.
        if work.exhausted() || *budget == 0 {
            break;
        }
        missing_in_grain_list(
            child,
            fetch,
            depth + 1,
            leaf_facts,
            seen,
            out,
            max,
            work,
            budget,
        );
    }
}

/// One directory's own B-tree: fresh depth budget, fresh `Shape`,
/// fill-canonicity checked once over the whole tree (rule 3). Returns
/// the frame the nesting worklist drains — this directory's OWN stats
/// plus the child directories it names.
#[cfg(test)]
fn validate_one_dir(
    id: &GrainId,
    fetch: &dyn Fn(&GrainId) -> Option<Vec<u8>>,
    spill_seen: &mut BTreeSet<(GrainId, u64, u32)>,
    leaf_facts: &mut BTreeMap<GrainId, LeafFacts>,
) -> Result<DirFrame, ValidateError> {
    with_resident(validate_one_dir_with(
        id,
        &mut Resident(fetch),
        spill_seen,
        leaf_facts,
        false,
    ))
    .map(|(frame, _)| frame)
}

/// [`validate_one_dir`], optionally also returning the decoded entries.
async fn validate_one_dir_with(
    id: &GrainId,
    source: &mut impl TreeSource,
    spill_seen: &mut BTreeSet<(GrainId, u64, u32)>,
    leaf_facts: &mut BTreeMap<GrainId, LeafFacts>,
    collect: bool,
) -> Result<(DirFrame, Vec<DirEntry>), ValidateError> {
    let mut shape = Shape::default();
    let mut walk = DirWalk {
        stats: TreeStats::default(),
        todo: Vec::new(),
        spill_seen,
        leaf_facts,
        entries: collect.then(Vec::new),
    };
    let (_span, total) = walk_dir(id, source, 1, &mut walk, &mut shape).await?;
    source.charge(shape.work()).await?;
    check_fill_canonical(
        &shape,
        total,
        u64::from(DIR_LEAF_MAX_ENTRIES),
        u64::from(DIR_INTERIOR_MAX_CHILDREN),
    )?;
    // Popped from the back, so reversing here keeps siblings in
    // canonical name order — the order the recursive walker descended
    // in, and so the order a multi-fault tree reports its first fault.
    walk.todo.reverse();
    Ok((
        DirFrame {
            id: *id,
            acc: walk.stats,
            todo: walk.todo,
        },
        walk.entries.unwrap_or_default(),
    ))
}

/// Validate ONE directory's own B-tree and return what it holds: its entries
/// in canonical order and the ids of the child directories it names, without
/// descending into them.
///
/// This is the per-directory step of [`validate_dir_tree`] (tree-walk rules 1-3
/// and 5 over this directory's tree, a fresh depth budget, and the checks on
/// every file's grain list), exposed so a caller that already trusts the child
/// ids it will look up can validate only the directories it touches. `fetch`
/// carries the same monotone-answer contract as for [`validate_dir_tree`].
///
/// # Errors
/// The [`ValidateError`] the walk raises for this directory's tree.
pub fn validate_dir_btree(
    id: &GrainId,
    fetch: &dyn Fn(&GrainId) -> Option<Vec<u8>>,
) -> Result<(Vec<DirEntry>, Vec<GrainId>), ValidateError> {
    validate_dir_btree_seeded(id, fetch, &BTreeSet::new())
}

/// [`validate_dir_btree`] that skips the spill-tree walk of every file whose
/// claim `(spill root, size, grain count)` is in `verified_spills`. The caller
/// vouches for those claims: each was proved by an earlier complete walk of a
/// tree that named it, so a directory that merely repeats an entry verbatim
/// need not fetch that file's grain list again.
///
/// # Errors
/// As [`validate_dir_btree`].
pub fn validate_dir_btree_seeded(
    id: &GrainId,
    fetch: &dyn Fn(&GrainId) -> Option<Vec<u8>>,
    verified_spills: &BTreeSet<(GrainId, u64, u32)>,
) -> Result<(Vec<DirEntry>, Vec<GrainId>), ValidateError> {
    let mut spill_seen = verified_spills.clone();
    let mut leaf_facts = BTreeMap::new();
    let (mut frame, entries) = with_resident(validate_one_dir_with(
        id,
        &mut Resident(fetch),
        &mut spill_seen,
        &mut leaf_facts,
        true,
    ))?;
    // `validate_one_dir_with` leaves the worklist reversed for popping.
    frame.todo.reverse();
    Ok((entries, frame.todo))
}

/// Returns (`first_name`, `last_name`) span and entry count of the subtree
/// for the parent's rule-1/2/5 checks.
/// **NEVER memoize this by node id.** Its result is not a function of
/// `id` alone: it pushes `(depth, width)` into the shared `Shape` that
/// `check_fill_canonical` compares against a recomputed uniform height,
/// and the same node legitimately occurs at different depths under
/// different parents. No row in this file's tests is known to go red
/// under such a memo; the rule rests on that argument alone.
async fn walk_dir(
    id: &GrainId,
    source: &mut impl TreeSource,
    depth: u32,
    walk: &mut DirWalk<'_>,
    shape: &mut Shape,
) -> Result<(Option<(Vec<u8>, Vec<u8>)>, u64), ValidateError> {
    source.charge(1).await?;
    if depth > DEPTH_MAX {
        return Err(ValidateError::DepthExceeded);
    }
    let bytes = source.node(*id).await?;
    if GrainId::of(&bytes) != *id {
        return Err(ValidateError::CorruptObject { id: *id });
    }
    let (ty, cursor) = encoding::open_envelope(&bytes)?;
    match ty {
        ObjectType::DirLeaf => {
            let entries = node::decode_dir_leaf(cursor)?;
            source.charge(entries.len() as u64).await?;
            shape.leaves.push((depth, entries.len() as u64));
            for e in &entries {
                // EVERY total saturates, not just the two that carry a
                // declared u64. Without the memo, overflowing a counting field
                // such as `entries` would mean walking u64::MAX of them; memo
                // replay removes that cost: 256 entries all naming one child,
                // nested eight deep, is nine objects and
                // `256 * (256^8 - 1) / 255` entries. Release runs with
                // overflow-checks on, so a plain `+=` would abort the walker
                // on a number it only reports.
                walk.stats.entries = walk.stats.entries.saturating_add(1);
                match &e.kind {
                    EntryKind::Dir { child } => {
                        walk.stats.dirs = walk.stats.dirs.saturating_add(1);
                        // Child dir: its own tree, with a fresh depth
                        // budget and a fresh Shape (rule 4) — so it
                        // goes on the caller's WORKLIST. Descending
                        // here put the format's deliberately uncapped
                        // nesting axis on the native stack.
                        walk.todo.push(*child);
                    }
                    EntryKind::File { size, grains, .. } => {
                        walk.stats.files = walk.stats.files.saturating_add(1);
                        // Declared size/count are refuted by
                        // validate_file_grains one line down — saturate
                        // the diagnostic totals so a lying u64 cannot
                        // abort the walker first (overflow-checks are
                        // on in release).
                        walk.stats.grains = walk
                            .stats
                            .grains
                            .saturating_add(u64::from(grains.grain_count()));
                        walk.stats.bytes = walk.stats.bytes.saturating_add(*size);
                        validate_file_grains(
                            *size,
                            grains,
                            source,
                            walk.spill_seen,
                            walk.leaf_facts,
                        )
                        .await?;
                    }
                    EntryKind::Symlink { .. } => {
                        walk.stats.symlinks = walk.stats.symlinks.saturating_add(1);
                    }
                    EntryKind::Fifo | EntryKind::Socket => {}
                }
            }
            let span = entries
                .first()
                .zip(entries.last())
                .map(|(f, l)| (f.name.as_bytes().to_vec(), l.name.as_bytes().to_vec()));
            let count = entries.len() as u64;
            if let Some(out) = walk.entries.as_mut() {
                out.extend(entries);
            }
            Ok((span, count))
        }
        ObjectType::DirInterior => {
            let children = node::decode_dir_interior(cursor)?;
            shape.interior_widths.push((depth, children.len() as u64));
            let mut total: u64 = 0;
            let mut prev_last: Option<Vec<u8>> = None;
            let mut first_of_node: Option<Vec<u8>> = None;
            for ch in &children {
                let (span, count) =
                    Box::pin(walk_dir(&ch.child, source, depth + 1, walk, shape)).await?;
                // An empty child is never canonical under a parent.
                let (first, last) = span.ok_or(ValidateError::FillNotCanonical)?;
                // ORDER IS LOAD-BEARING ACROSS RESUMES: every
                // child-derived check below runs AFTER the child's walk returned, so a
                // child-internal error propagates through `?` before any parent check
                // can — which is what lets `TreeCursor` keep the one-shot's first error
                // when a child directory is walked in a later resume than its parent. A
                // pre-descent check that peeks at a child reopens the inversion the
                // differential rows guard against.
                if first.as_slice() != ch.first_key.as_bytes() {
                    return Err(ValidateError::SeparatorMismatch);
                }
                if let Some(pl) = &prev_last
                    && pl.as_slice() >= first.as_slice()
                {
                    return Err(ValidateError::CrossNodeOrder);
                }
                if count != ch.subtree_entry_count {
                    return Err(ValidateError::CountMismatch);
                }
                if first_of_node.is_none() {
                    first_of_node = Some(first);
                }
                prev_last = Some(last);
                // `count` was just checked against the declared subtree
                // count and every entry behind it was actually walked,
                // so overflow is unreachable in practice — checked
                // anyway: the walker is total on ANY input.
                total = total
                    .checked_add(count)
                    .ok_or(ValidateError::CountMismatch)?;
            }
            let span = first_of_node.zip(prev_last);
            Ok((span, total))
        }
        ObjectType::GrainListLeaf
        | ObjectType::GrainListIndex
        | ObjectType::Bin
        | ObjectType::BinmapIndex
        | ObjectType::BinTable
        | ObjectType::BinmapShard
        | ObjectType::Root
        | ObjectType::Sheaf => Err(ValidateError::WrongObjectType { id: *id }),
    }
}

/// Rule 3 (fill canonicity): recompute the canonical shape for `total`
/// entries and compare against what the walk recorded. Applies to BOTH
/// tree kinds: directories pass (C, F); spill trees pass (N, N).
///
/// A canonical bulk-loaded tree is UNIFORM HEIGHT — that is what makes
/// its shape a pure function of `total`. Every leaf sits at depth
/// `height`, and the interiors of bottom-up level j sit at depth
/// `height - 1 - j` with their widths matching the split arithmetic IN
/// TRAVERSAL ORDER. Comparing widths WITHOUT their depths is not
/// sufficient: a depth-lopsided tree can reproduce the same width
/// sequence, validate, and still hash differently from what the
/// builder emits (a reverse-depth-sorted comparison, when run,
/// accepted exactly such a tree for 257x256 entries).
fn check_fill_canonical(
    shape: &Shape,
    total: u64,
    leaf_cap: u64,
    fanout: u64,
) -> Result<(), ValidateError> {
    // Bound the recompute by the WALKED shape before materializing it:
    // the expected leaf COUNT is a cheap closed form, and if it
    // disagrees with what the walk recorded the tree is non-canonical —
    // reject by counting instead of allocating `total / leaf_cap`
    // expected sizes for an astronomical claimed total.
    let expected_leaf_count = if total <= leaf_cap {
        1
    } else {
        total.div_ceil(leaf_cap)
    };
    if expected_leaf_count != shape.leaves.len() as u64 {
        return Err(ValidateError::FillNotCanonical);
    }
    // Expected leaf sizes, then expected interior widths per level
    // bottom-up: group the node count of the level below by `fanout`
    // until one root remains.
    let expected_leaves: Vec<u64> = if total <= leaf_cap {
        vec![total]
    } else {
        split_counts_u64(total, leaf_cap)
    };
    let mut expected_interiors: Vec<Vec<u64>> = Vec::new();
    let mut height: u32 = 1;
    let mut width = expected_leaves.len() as u64;
    while width > 1 {
        let level: Vec<u64> = if width <= fanout {
            vec![width]
        } else {
            split_counts_u64(width, fanout)
        };
        width = level.len() as u64;
        expected_interiors.push(level);
        height += 1;
    }
    // Every leaf: exact size, traversal order, all at depth `height`.
    if shape.leaves.len() != expected_leaves.len() {
        return Err(ValidateError::FillNotCanonical);
    }
    for (&(depth, size), expected) in shape.leaves.iter().zip(&expected_leaves) {
        if depth != height || size != *expected {
            return Err(ValidateError::FillNotCanonical);
        }
    }
    // Each interior level at its own exact depth, widths in traversal
    // order. The root is depth 1, so bottom-up level j is at
    // `height - 1 - j`.
    let mut want_depth = height.saturating_sub(1);
    for level in &expected_interiors {
        let got: Vec<u64> = shape
            .interior_widths
            .iter()
            .filter(|&&(depth, _)| depth == want_depth)
            .map(|&(_, w)| w)
            .collect();
        if got != *level {
            return Err(ValidateError::FillNotCanonical);
        }
        want_depth = want_depth.saturating_sub(1);
    }
    // Defense in depth: no interior may sit outside 1..=height-1. The
    // leaf-depth check above already implies this (any out-of-range
    // interior pushes its leaves off `height`), so this line is not
    // separately reachable — it is kept, like `SpillNotCanonical`, so
    // the invariant is stated where it is relied upon.
    if shape
        .interior_widths
        .iter()
        .any(|&(depth, _)| depth >= height)
    {
        return Err(ValidateError::FillNotCanonical);
    }
    Ok(())
}

/// `split_counts` for u64 totals (same arithmetic; validation side).
fn split_counts_u64(n: u64, cap: u64) -> Vec<u64> {
    let l = n.div_ceil(cap);
    let q = n / l;
    let r = n % l;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "l <= n/cap bounded by DEPTH_MAX shapes"
    )]
    let mut out = Vec::with_capacity(l as usize);
    for i in 0..l {
        out.push(if i < r { q + 1 } else { q });
    }
    out
}

async fn validate_file_grains(
    size: u64,
    grains: &FileGrains,
    source: &mut impl TreeSource,
    seen: &mut BTreeSet<(GrainId, u64, u32)>,
    leaf_facts: &mut BTreeMap<GrainId, LeafFacts>,
) -> Result<(), ValidateError> {
    match grains {
        FileGrains::Inline(refs) => {
            for &reference in refs {
                source.file_ref(reference).await?;
            }
            Ok(()) // node decode already checked size/sum/K
        }
        FileGrains::Spill { grain_count, root } => {
            // The memo key is the whole ENTRY's claim, never `root`
            // alone: `size` and `grain_count` come from the dir entry,
            // not from the tree, and refuting them is what this
            // function DOES. Two entries may name one grain-list root
            // with different declared sizes; under a root-only key the
            // second would inherit the first's `Ok` and be ACCEPTED —
            // a tree that is refused today. Only success is cached:
            // the first failure ends the whole walk, so a failure memo
            // would never be read.
            let key = (*root, size, *grain_count);
            if seen.contains(&key) {
                return Ok(());
            }
            // The declared count buys a FIXED number of leaves, and
            // this is the same closed form `check_fill_canonical`
            // demands EQUALITY against below — so anything the budget
            // stops was certain to be refused, with this same variant.
            // It is not a new rule; it is the existing one, applied
            // before the walk rather than after it. Without it
            // `walk_grain_list` is `DEPTH_MAX`-bounded but unbounded in
            // LEAF VISITS: an index's children are ordered by their
            // declared cumulative fields, which a REPEATED child
            // satisfies (each repeat's contribution is added again), so
            // fifteen index levels of fanout 4 over sixteen objects ask
            // for 4^15 visits and grow `shape.leaves` by one entry per
            // VISIT — about 17 GB — before any verdict lands.
            let leaf_cap = u64::from(GRAINLIST_LEAF_MAX_REFS);
            let declared = u64::from(*grain_count);
            let leaf_budget = if declared <= leaf_cap {
                1
            } else {
                declared.div_ceil(leaf_cap)
            };
            let mut shape = Shape::default();
            let (got_len, got_count) =
                walk_grain_list(root, source, 1, &mut shape, leaf_budget, leaf_facts).await?;
            // ORDER IS LOAD-BEARING ACROSS RESUMES: every
            // child-derived check below runs AFTER the child's walk returned, so a
            // child-internal error propagates through `?` before any parent check
            // can — which is what lets `TreeCursor` keep the one-shot's first error
            // when a child directory is walked in a later resume than its parent. A
            // pre-descent check that peeks at a child reopens the inversion the
            // differential rows guard against.
            if got_len != size || got_count != u64::from(*grain_count) {
                return Err(ValidateError::CountMismatch);
            }
            if u64::from(*grain_count) <= u64::from(FILE_INLINE_MAX_REFS) {
                return Err(ValidateError::SpillNotCanonical);
            }
            // Shape canonicity for spill trees — SAME generalized check
            // as directories (format doc: balanced split applies to
            // BOTH tree kinds), parameterized by (leaf cap N, fanout N):
            // <= N refs must be ONE leaf (no index at all); above N,
            // leaf sizes match the split arithmetic AND index widths
            // match the bottom-up grouping — a gratuitous extra index
            // level over canonically sized leaves is rejected.
            source.charge(shape.work()).await?;
            check_fill_canonical(
                &shape,
                got_count,
                u64::from(GRAINLIST_LEAF_MAX_REFS),
                u64::from(GRAINLIST_INDEX_MAX_CHILDREN),
            )?;
            seen.insert(key);
            Ok(())
        }
    }
}

/// The leaf-budget refusal both of `walk_grain_list`'s leaf paths
/// share — the memo hit and the decode arm. One body, so the predicate
/// and the error variant cannot drift apart between them: the accept
/// set must never depend on whether a leaf id happens to be repeated.
/// Only the CHECK is shared, not the `(depth, width)` push that
/// follows it — on the decode path a leaf's width is not known until
/// after `decode_grain_list_leaf`, and hoisting the decode above the
/// check would change which refusal an over-budget UNDECODABLE leaf
/// gets (`FillNotCanonical` today, normatively before `Decode`).
fn leaf_budget_refusal(shape: &Shape, leaf_budget: u64) -> Result<(), ValidateError> {
    if shape.leaves.len() as u64 >= leaf_budget {
        return Err(ValidateError::FillNotCanonical);
    }
    Ok(())
}

/// `leaf_budget`: how many leaves the entry's declared `grain_count`
/// pays for — see the derivation at the call site. Total leaf VISITS,
/// not distinct leaves: a repeated child is a repeated visit, which is
/// the whole point.
///
/// **This function's own RESULT is never memoized by node id.**
/// Never memoize `walk_dir` or `walk_grain_list` by node id: a
/// walk-level result is not a function of `id` alone. Both walkers
/// push `(depth, width)` into the shared `Shape` that
/// `check_fill_canonical` compares against a recomputed uniform
/// height, and the same node legitimately occurs at different depths
/// under different parents.
///
/// A LEAF's byte-derived facts are a narrower thing than that result, and ARE a
/// pure function of `id` alone: `id` is hash-verified against the fetched bytes
/// before use (the `GrainId::of` check below), so `(len, ref_count)` are facts
/// about `id`'s unique preimage. Those facts ARE cached (`leaf_facts`, below) —
/// but a cache hit still performs the same budget check and the same
/// `(depth, cached_width)` push as an unmemoized visit, so the `Shape` this
/// call contributes is byte-identical either way. The doc of
/// `leaf_facts_at_two_depths` (this file's tests) states that a mutant skipping
/// the memo-hit push leaves a file with zero leaves where two are declared, so
/// the walk answers `FillNotCanonical` where it should answer `Ok`. Index nodes
/// carry no such id-pure facts (their content is declared cumulative fields
/// about children, not their own leaf bytes) and are never memoized.
async fn walk_grain_list(
    id: &GrainId,
    source: &mut impl TreeSource,
    depth: u32,
    shape: &mut Shape,
    leaf_budget: u64,
    leaf_facts: &mut BTreeMap<GrainId, LeafFacts>,
) -> Result<(u64, u64), ValidateError> {
    source.charge(1).await?;
    if depth > DEPTH_MAX {
        return Err(ValidateError::DepthExceeded);
    }
    // A memo hit skips fetch/hash/decode entirely, but not the budget
    // check or the shape push — both run exactly as they would on an
    // unmemoized visit, so a hit and a miss leave the same trace in
    // `shape`.
    if let Some(&facts) = leaf_facts.get(id) {
        leaf_budget_refusal(shape, leaf_budget)?;
        shape.leaves.push((depth, facts.ref_count));
        return Ok((facts.unpacked_len, facts.ref_count));
    }
    let bytes = source.node(*id).await?;
    if GrainId::of(&bytes) != *id {
        return Err(ValidateError::CorruptObject { id: *id });
    }
    let (ty, cursor) = encoding::open_envelope(&bytes)?;
    match ty {
        ObjectType::GrainListLeaf => {
            // Checked BEFORE the push, so `shape.leaves` never grows
            // past the budget either. `check_fill_canonical` requires
            // `shape.leaves.len()` to EQUAL this number, so the
            // budget-th leaf is the last one that can still be part of
            // an accepted tree and the next one is already refused.
            leaf_budget_refusal(shape, leaf_budget)?;
            let refs = node::decode_grain_list_leaf(cursor)?;
            let mut len = 0;
            for &reference in &refs {
                source.file_ref(reference).await?;
                len += u64::from(reference.unpacked_len);
            }
            let ref_count = refs.len() as u64;
            shape.leaves.push((depth, ref_count));
            // Inserted only now that this leaf's own validation has
            // fully succeeded (budget check passed, decode succeeded):
            // a leaf that fails anything fails the whole walk, so a
            // failure is never the thing a later visit would read back.
            leaf_facts.insert(
                *id,
                LeafFacts {
                    unpacked_len: len,
                    ref_count,
                },
            );
            Ok((len, ref_count))
        }
        ObjectType::GrainListIndex => {
            let children = node::decode_grain_list_index(cursor)?;
            shape.interior_widths.push((depth, children.len() as u64));
            let mut cum_len: u64 = 0;
            let mut cum_count: u64 = 0;
            for ch in &children {
                let (l, c) = Box::pin(walk_grain_list(
                    &ch.child,
                    source,
                    depth + 1,
                    shape,
                    leaf_budget,
                    leaf_facts,
                ))
                .await?;
                // ORDER IS LOAD-BEARING ACROSS RESUMES: every
                // child-derived check below runs AFTER the child's walk returned, so a
                // child-internal error propagates through `?` before any parent check
                // can — which is what lets `TreeCursor` keep the one-shot's first error
                // when a child directory is walked in a later resume than its parent. A
                // pre-descent check that peeks at a child reopens the inversion the
                // differential rows guard against.
                // Shared substructure (one child id repeated under an
                // index) lets the TRUE running sums exceed u64 while
                // every declared cumulative still matches along the
                // way — overflow is a mismatch verdict, never an abort.
                cum_len = cum_len
                    .checked_add(l)
                    .ok_or(ValidateError::CumulativeMismatch)?;
                cum_count = cum_count
                    .checked_add(c)
                    .ok_or(ValidateError::CumulativeMismatch)?;
                if cum_len != ch.cum_unpacked_len || cum_count != ch.cum_ref_count {
                    return Err(ValidateError::CumulativeMismatch);
                }
            }
            Ok((cum_len, cum_count))
        }
        ObjectType::DirLeaf
        | ObjectType::DirInterior
        | ObjectType::Bin
        | ObjectType::BinmapIndex
        | ObjectType::BinTable
        | ObjectType::BinmapShard
        | ObjectType::Root
        | ObjectType::Sheaf => Err(ValidateError::WrongObjectType { id: *id }),
    }
}

#[cfg(test)]
mod tests;
