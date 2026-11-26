// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Synchronous reads over an already-validated manifest structure map.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use granary_core::encoding::{self, DecodeError, ObjectType};
use granary_core::hash::GrainId;
use granary_core::manifest::{self, DirEntry, EntryKind, InteriorChild, Name, TreeStats};
use granary_core::sheaf::Timestamp;

/// A pinned, already-validated manifest structure map.
///
/// The caller has run granary-client's eager preamble, which walks and
/// validates the WHOLE tree — bounded by the WORK it does, not by a depth
/// cap — and re-hashes every node against the id it was fetched under. This
/// type therefore does NOT re-validate; it INDEXES. What it does check is
/// the narrow set of things it is about to DEPEND ON, each of them one
/// comparison against data the walk already holds: that every node it
/// visits decodes, that a node it reaches as a directory is a directory,
/// that the nesting worklist terminates, that no node occurs twice inside
/// one directory's B-tree, and that every interior child's declared
/// `subtree_entry_count` and `first_key` match what lies beneath it. Those
/// last three are the declarations the seek and lookup paths NAVIGATE by,
/// so a lie in one is a wrong answer rather than a refusal.
///
/// It does NOT check the grain-list trees. A `FileGrains::Spill` root is
/// never walked here, so the read path's own extent comparisons are all
/// that stand behind a lying grain-list index — see `read.rs`, which is
/// explicit about the one shape they cannot see.
///
/// Immutable for the life of the mount. Everything on it takes `&self`.
#[derive(Debug)]
pub struct Snapshot {
    nodes: BTreeMap<GrainId, Vec<u8>>,
    manifest_root: GrainId,
    /// The root's signed publish timestamp — every synthesised
    /// timestamp in the mount is this value. `Timestamp::is_valid` holds
    /// by construction: [`Snapshot::new`] refuses to build one otherwise
    /// ([`SnapshotError::InvalidTimestamp`]). Kept in the format's own
    /// unconverted unit — the checked conversion to the kernel's timestamp
    /// type, and the refusal of a root the kernel's type cannot represent,
    /// are the ADAPTER's, performed once at its own construction: this
    /// engine names no kernel type to convert into.
    timestamp: Timestamp,
    /// Per DIRECTORY B-tree root: the number of entries it holds, and the
    /// number of those that are subdirectories. Computed ONCE here rather
    /// than per `getattr`, because `nlink` needs the subdirectory count on
    /// every directory attribute reply and a per-call scan would be
    /// O(entries) per stat. Keyed by `GrainId`, so a directory reachable
    /// by K paths is counted once — content addressing merges
    /// byte-identical directories by design.
    dirs: BTreeMap<GrainId, DirFacts>,
    /// What the preamble's walk counted. `statfs` answers from this
    /// rather than inventing zeros — a `df` reporting a zero namelen is a
    /// worse lie than one reporting zero blocks.
    stats: TreeStats,
    /// The presentation policy — uid and gid — resolved ONCE at mount
    /// time and immutable for the mount's life. It lives HERE because
    /// `attr_for` is a method on `Snapshot` and takes no mount options
    /// among its arguments (it takes `&self`, an `Entry`, and the ino and
    /// generation the allocator supplies), so without this field the
    /// reader has no route to the mount options at all. This engine crate
    /// never reads process credentials itself; a caller resolves them and
    /// passes them in here.
    policy: AttrPolicy,
    /// The construction-time admission bound this snapshot was built
    /// under. Stored so a caller building a serve adapter
    /// (`GranaryFs::new`) can verify its OWN bound is no looser than the
    /// one this snapshot was already checked against — see
    /// [`ServeLimits`].
    limits: ServeLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirFacts {
    entries: u64,
    subdirs: u32,
}

/// The presentation policy a mount is configured with: the uid and gid
/// every synthesised attribute reports. Resolved ONCE, at mount time, and
/// immutable for the life of the mount — re-reading the process's ids per
/// callback would let two `getattr`s on one inode disagree.
///
/// Defined HERE rather than beside the rest of the attribute policy,
/// because `Snapshot` holds one and was built first: nothing may name a
/// type that only later work defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttrPolicy {
    pub uid: u32,
    pub gid: u32,
}

/// The construction-time admission bound a serve layer hands to
/// [`Snapshot::new`]: the longest symlink target its own `readlink` reply
/// can carry. `Snapshot::new` refuses a manifest holding a longer target
/// rather than admitting it and surfacing an opaque per-call error later.
///
/// **Why a sibling struct and not a field on [`AttrPolicy`]:** `AttrPolicy`
/// holds the mount's POSIX uid/gid presentation and is stored and read
/// per attribute — the wrong shape and subject for a
/// construction-time admission bound. A separate struct is also what a
/// `WinFsp` adapter needs, where the limit differs (or is absent) from any
/// value another adapter would choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeLimits {
    pub readlink_target_max_bytes: usize,
}

impl ServeLimits {
    /// This snapshot is not being built for a serve layer that has a
    /// `readlink` reply bound — every symlink target the format allows is
    /// admitted. Used by a caller with no such bound to answer at all (one
    /// reading the tree structurally rather than serving it), and by this
    /// crate's own construction-time tests, which must not name any
    /// adapter's bound.
    pub const UNBOUNDED: Self = Self {
        readlink_target_max_bytes: usize::MAX,
    };
}

/// One manifest entry found by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: Name,
    pub kind: EntryKind,
    pub leaf: GrainId,
}

/// One logical directory entry and the cursor after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaddirEntry {
    pub name: Vec<u8>,
    pub kind: EntryKind,
    pub next: u64,
}

/// Failure while constructing a snapshot index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    Decode {
        id: GrainId,
        source: DecodeError,
    },
    MissingNode {
        id: GrainId,
    },
    WrongType {
        id: GrainId,
    },
    DepthExceeded,
    Overflow,
    /// One node appeared twice inside a single directory's B-tree.
    RepeatedNode {
        id: GrainId,
    },
    /// An interior child's declared `subtree_entry_count` disagreed with
    /// the number of entries actually walked beneath it.
    CountMismatch {
        id: GrainId,
        declared: u64,
        walked: u64,
    },
    /// An interior child's declared `first_key` disagreed with the first
    /// name actually found beneath it.
    SeparatorMismatch {
        id: GrainId,
        declared: Name,
    },
    /// The root's publish timestamp is invalid — `nanos` is not strictly
    /// under one second ([`Timestamp::is_valid`]). Decode-time already
    /// refuses this (`granary_core`'s `take_timestamp` enforces
    /// `is_valid()` at parse), so this is DEFENCE IN DEPTH against a
    /// `Timestamp` constructed directly rather than decoded — `Snapshot`
    /// is public and `Timestamp`'s fields are public, so nothing else
    /// stops a caller from doing exactly that. Representability — whether
    /// such a valid value fits the KERNEL's timestamp type — is a
    /// different, platform-specific question and is the adapter's, not
    /// this engine's.
    InvalidTimestamp {
        timestamp: Timestamp,
    },
    /// A directory entry's symlink target is longer than the injected
    /// [`ServeLimits::readlink_target_max_bytes`] this snapshot was built
    /// against. Format-valid — v1 accepts `1..=4096` and that does not
    /// change — but not representable through THIS caller's bound, so it
    /// is refused here with a name rather than surfacing later as an
    /// opaque per-call error. The rule for every such refusal: fail at
    /// construction, with a name, never as a per-callback decision.
    UnrepresentableSymlinkTarget {
        /// The directory leaf the entry was found in.
        id: GrainId,
        /// The entry's own name, so a refused mount can be diagnosed. Its
        /// sibling `ReservedEntry` carries one for the same reason: a grain
        /// id and a byte count alone give an operator nothing to look for.
        name: Name,
        /// The target's length in bytes.
        len: usize,
    },
    /// A directory entry declared `EntryKind::Fifo` or `EntryKind::Socket`.
    /// A reserved entry is a decode-time refusal rather than a
    /// mount-time surprise: a manifest built by something other than
    /// granary's own harvester could carry one, and the mount does not
    /// attempt to materialise a type it has no working handler for. Refusing
    /// here — rather than at `attr_for` or `list_dir_plus`, both of which
    /// also refuse it — means a snapshot carrying one never mounts at all,
    /// so `readdir` can never advertise an entry `stat` then answers `EIO`
    /// for.
    ReservedEntry {
        /// The directory B-tree root the entry was found in.
        dir: GrainId,
        /// The entry's own name.
        name: Name,
        /// Which reserved tag it carried.
        kind: ReservedEntryKind,
    },
}

/// Which reserved manifest tag [`SnapshotError::ReservedEntry`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedEntryKind {
    Fifo,
    Socket,
}

impl core::fmt::Display for ReservedEntryKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fifo => write!(f, "fifo"),
            Self::Socket => write!(f, "socket"),
        }
    }
}

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode { id, source } => write!(f, "cannot decode directory node {id}: {source}"),
            Self::MissingNode { id } => write!(f, "directory node {id} is missing"),
            Self::WrongType { id } => write!(f, "node {id} is not a directory node"),
            Self::DepthExceeded => write!(f, "directory B-tree depth exceeds the format cap"),
            Self::Overflow => write!(f, "directory facts overflow their representation"),
            Self::RepeatedNode { id } => write!(
                f,
                "directory node {id} occurs more than once in one directory's B-tree"
            ),
            Self::CountMismatch {
                id,
                declared,
                walked,
            } => write!(
                f,
                "directory node {id} declares {declared} entries beneath it, walk found {walked}"
            ),
            Self::SeparatorMismatch { id, declared } => write!(
                f,
                "directory node {id} does not begin with its declared separator {declared:?}"
            ),
            Self::InvalidTimestamp { timestamp } => write!(
                f,
                // The pair, never a decimal: `nanos` is a non-negative
                // offset FORWARD from `secs`, so `-1` and
                // `500_000_000` is half a second before the epoch, and
                // "-1.500000000" reads as one and a half.
                "root publish timestamp (secs {}, nanos {}) is invalid: nanos must be strictly \
                 under one second",
                timestamp.secs, timestamp.nanos
            ),
            Self::UnrepresentableSymlinkTarget { id, name, len } => write!(
                f,
                "directory node {id} contains entry {name:?} with a symlink target of {len} bytes, longer than this mount's readlink reply can carry"
            ),
            Self::ReservedEntry { dir, name, kind } => write!(
                f,
                "directory node {dir} contains reserved {kind} entry {name:?}"
            ),
        }
    }
}

impl core::error::Error for SnapshotError {}

/// Failure while reading an indexed snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderError {
    NotFound,
    Inconsistent,
    ReadTooFragmented,
    /// The caller asked for more bytes than [`crate::READ_MAX_BYTES`].
    ///
    /// Distinct from [`Self::ReadTooFragmented`], which is about how many
    /// GRAINS a read spans: this one is about the byte length of the output
    /// buffer, which `read_at` must size before it fetches anything.
    ReadTooLarge,
    GrainUnavailable,
    UnsupportedEntry,
    LookupCountOverflow,
    HandleCountOverflow,
    InodeNumberExhausted,
}

impl core::fmt::Display for ReaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no entry named"),
            Self::Inconsistent => write!(f, "reader disagrees with the validated manifest"),
            Self::ReadTooFragmented => write!(f, "read spans too many grains"),
            Self::ReadTooLarge => write!(f, "read is larger than the reader's byte bound"),
            Self::GrainUnavailable => write!(f, "content grain is unavailable"),
            Self::UnsupportedEntry => write!(f, "entry type is unsupported by the mount"),
            Self::LookupCountOverflow => write!(f, "inode lookup count overflow"),
            Self::HandleCountOverflow => write!(f, "inode handle count overflow"),
            Self::InodeNumberExhausted => write!(f, "inode number space is exhausted"),
        }
    }
}

impl core::error::Error for ReaderError {}

#[cfg(test)]
thread_local! {
    static DECODES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static DIRSCANS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static DIRNODES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn bump_dirscan() {
    #[cfg(test)]
    DIRSCANS.with(|cell| cell.set(cell.get().saturating_add(1)));
}

/// Counts nodes VISITED by `scan_dir_node`, so the visited set's negative can
/// be a fast assertion instead of a hang. Without it the only observable
/// consequence of losing the set is that indexing takes `fanout^depth` — tens
/// of minutes in a debug test binary — which wedges a suite rather than
/// failing one.
fn bump_dirnode() {
    #[cfg(test)]
    DIRNODES.with(|cell| cell.set(cell.get().saturating_add(1)));
}

fn bump_decode() {
    #[cfg(test)]
    DECODES.with(|cell| cell.set(cell.get().saturating_add(1)));
}

#[cfg(test)]
pub(crate) fn reset_decodes() {
    DECODES.with(|cell| cell.set(0));
}

#[cfg(test)]
pub(crate) fn decodes() -> u64 {
    DECODES.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn bump_decode_for_read() {
    bump_decode();
}

#[derive(Debug)]
struct InteriorFrame {
    children: Vec<InteriorChild>,
    next_child: usize,
}

struct ManifestCursor<'a> {
    snapshot: &'a Snapshot,
    stack: Vec<InteriorFrame>,
    leaf: Vec<DirEntry>,
    position: usize,
}

impl<'a> ManifestCursor<'a> {
    fn seek(snapshot: &'a Snapshot, dir: &GrainId, index: u64) -> Result<Self, ReaderError> {
        let mut current = *dir;
        let mut remaining = index;
        let mut depth = 1_u32;
        let mut stack = Vec::new();
        loop {
            if depth > manifest::DEPTH_MAX {
                return Err(ReaderError::Inconsistent);
            }
            let bytes = snapshot
                .nodes
                .get(&current)
                .ok_or(ReaderError::Inconsistent)?;
            let (object_type, cursor) =
                encoding::open_envelope(bytes).map_err(|_| ReaderError::Inconsistent)?;
            bump_decode();
            match object_type {
                ObjectType::DirLeaf => {
                    let leaf =
                        manifest::decode_dir_leaf(cursor).map_err(|_| ReaderError::Inconsistent)?;
                    let position =
                        usize::try_from(remaining).map_err(|_| ReaderError::Inconsistent)?;
                    if position >= leaf.len() {
                        return Err(ReaderError::Inconsistent);
                    }
                    return Ok(Self {
                        snapshot,
                        stack,
                        leaf,
                        position,
                    });
                }
                ObjectType::DirInterior => {
                    let children = manifest::decode_dir_interior(cursor)
                        .map_err(|_| ReaderError::Inconsistent)?;
                    let mut selected = None;
                    for (position, child) in children.iter().enumerate() {
                        // Counts are PER CHILD, not cumulative prefixes. Carry the
                        // child-relative index downward by subtracting every whole
                        // preceding subtree; omitting this is wrong below depth one.
                        if remaining < child.subtree_entry_count {
                            let next_child =
                                position.checked_add(1).ok_or(ReaderError::Inconsistent)?;
                            selected = Some((child.child, next_child));
                            break;
                        }
                        remaining = remaining
                            .checked_sub(child.subtree_entry_count)
                            .ok_or(ReaderError::Inconsistent)?;
                    }
                    let (child, next_child) = selected.ok_or(ReaderError::Inconsistent)?;
                    stack.push(InteriorFrame {
                        children,
                        next_child,
                    });
                    current = child;
                    depth = depth.checked_add(1).ok_or(ReaderError::Inconsistent)?;
                }
                _ => return Err(ReaderError::Inconsistent),
            }
        }
    }

    fn next_entry(&mut self) -> Result<Option<DirEntry>, ReaderError> {
        loop {
            if let Some(entry) = self.leaf.get(self.position) {
                self.position = self
                    .position
                    .checked_add(1)
                    .ok_or(ReaderError::Inconsistent)?;
                return Ok(Some(entry.clone()));
            }
            if !self.advance_leaf()? {
                return Ok(None);
            }
        }
    }

    fn advance_leaf(&mut self) -> Result<bool, ReaderError> {
        loop {
            let child = if let Some(frame) = self.stack.last_mut() {
                let child = frame
                    .children
                    .get(frame.next_child)
                    .map(|child| child.child);
                if child.is_some() {
                    frame.next_child = frame
                        .next_child
                        .checked_add(1)
                        .ok_or(ReaderError::Inconsistent)?;
                }
                child
            } else {
                return Ok(false);
            };
            if let Some(child) = child {
                let depth = u32::try_from(self.stack.len())
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ReaderError::Inconsistent)?;
                self.descend_first(child, depth)?;
                return Ok(true);
            }
            let _finished = self.stack.pop();
        }
    }

    fn descend_first(&mut self, mut current: GrainId, mut depth: u32) -> Result<(), ReaderError> {
        loop {
            if depth > manifest::DEPTH_MAX {
                return Err(ReaderError::Inconsistent);
            }
            let bytes = self
                .snapshot
                .nodes
                .get(&current)
                .ok_or(ReaderError::Inconsistent)?;
            let (object_type, cursor) =
                encoding::open_envelope(bytes).map_err(|_| ReaderError::Inconsistent)?;
            bump_decode();
            match object_type {
                ObjectType::DirLeaf => {
                    let leaf =
                        manifest::decode_dir_leaf(cursor).map_err(|_| ReaderError::Inconsistent)?;
                    if leaf.is_empty() {
                        return Err(ReaderError::Inconsistent);
                    }
                    self.leaf = leaf;
                    self.position = 0;
                    return Ok(());
                }
                ObjectType::DirInterior => {
                    let children = manifest::decode_dir_interior(cursor)
                        .map_err(|_| ReaderError::Inconsistent)?;
                    let child = children
                        .first()
                        .map(|child| child.child)
                        .ok_or(ReaderError::Inconsistent)?;
                    self.stack.push(InteriorFrame {
                        children,
                        next_child: 1,
                    });
                    current = child;
                    depth = depth.checked_add(1).ok_or(ReaderError::Inconsistent)?;
                }
                _ => return Err(ReaderError::Inconsistent),
            }
        }
    }
}

/// Walks ONE directory's B-tree and returns the number of entries it holds.
///
/// Two things are checked here that the seek paths would otherwise have to
/// take on trust, and both are checked against data this walk already has
/// in hand.
///
/// **`seen` rejects a node reached twice within THIS directory's tree.**
/// Without it a map whose interiors share children is walked once per
/// root-to-node PATH rather than once per node — measured at four times the
/// work per level, so a 69 KB map of 376 nodes at fan-out 4 and depth 15
/// costs `4^15` visits and the mount never finishes starting. It is not a
/// narrowing: two occurrences of one id carry the same non-empty name span,
/// so `validate_dir_tree` already refuses such a map at their lowest common
/// ancestor with `CrossNodeOrder` (measured: it does so in under 10 us, flat
/// in depth). The set is per CALL and never walk-wide, because one node may
/// legitimately be one directory's root AND a leaf inside another
/// directory's tree. `dirs` dedups directory ROOTS, which bounds how many
/// times a directory is scanned but NOT the work of scanning subtrees that
/// many distinct roots share; that dimension is untouched here and
/// `validate_dir_tree` carries the identical exposure.
///
/// **Every interior child's declared `subtree_entry_count` is compared to
/// the count actually walked beneath it.** `ManifestCursor::seek` navigates
/// by those declarations while `readdir`'s bound comes from the scanned
/// total, and two oracles for one quantity is how a resume silently lands in
/// the wrong leaf: a directory of 600 entries declaring 1 for a subtree
/// holding 256 answered a resume at logical index 300 with `Ok` and 45
/// entries, dropping 255 files from the listing. Checking it once here, at
/// index time, is what makes the declaration safe to navigate by later.
/// `validate_dir_tree` makes the same comparison (`CountMismatch`), so this
/// too refuses only maps that were already refusable.
fn scan_dir_node(
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    id: &GrainId,
    depth: u32,
    facts: &mut DirFacts,
    nested: &mut Vec<GrainId>,
    seen: &mut BTreeSet<GrainId>,
    readlink_target_max_bytes: usize,
) -> Result<(Option<Name>, u64), SnapshotError> {
    if depth > manifest::DEPTH_MAX {
        return Err(SnapshotError::DepthExceeded);
    }
    if !seen.insert(*id) {
        return Err(SnapshotError::RepeatedNode { id: *id });
    }
    bump_dirnode();
    let bytes = nodes
        .get(id)
        .ok_or(SnapshotError::MissingNode { id: *id })?;
    let (object_type, cursor) = encoding::open_envelope(bytes)
        .map_err(|source| SnapshotError::Decode { id: *id, source })?;
    match object_type {
        ObjectType::DirLeaf => {
            let entries = manifest::decode_dir_leaf(cursor)
                .map_err(|source| SnapshotError::Decode { id: *id, source })?;
            let mut walked = 0_u64;
            for entry in &entries {
                // A FIFO or socket entry is a decode-time refusal,
                // not a mount-time surprise. This loop already visits every
                // entry to count it, so the check costs no extra traversal.
                // Checked BEFORE the counters below: a refused snapshot is
                // never returned, so what the counters would have held is
                // moot, and checking first keeps the refusal's reasoning
                // (kind, not count) separate from theirs.
                let reserved = match &entry.kind {
                    EntryKind::Fifo => Some(ReservedEntryKind::Fifo),
                    EntryKind::Socket => Some(ReservedEntryKind::Socket),
                    _ => None,
                };
                if let Some(kind) = reserved {
                    return Err(SnapshotError::ReservedEntry {
                        dir: *id,
                        name: entry.name.clone(),
                        kind,
                    });
                }
                // The same refusal discipline, for a format-valid value this
                // caller's injected bound cannot carry: refused here, by
                // name, rather than surfacing later as an opaque per-call
                // error. Checked in the same place and for the same reason
                // as the reserved-kind refusal above.
                if let EntryKind::Symlink { target } = &entry.kind {
                    let len = target.as_bytes().len();
                    if len > readlink_target_max_bytes {
                        return Err(SnapshotError::UnrepresentableSymlinkTarget {
                            id: *id,
                            name: entry.name.clone(),
                            len,
                        });
                    }
                }
                facts.entries = facts
                    .entries
                    .checked_add(1)
                    .ok_or(SnapshotError::Overflow)?;
                walked = walked.checked_add(1).ok_or(SnapshotError::Overflow)?;
                if let EntryKind::Dir { child } = &entry.kind {
                    facts.subdirs = facts
                        .subdirs
                        .checked_add(1)
                        .ok_or(SnapshotError::Overflow)?;
                    nested.push(*child);
                }
            }
            Ok((entries.first().map(|entry| entry.name.clone()), walked))
        }
        ObjectType::DirInterior => {
            let children = manifest::decode_dir_interior(cursor)
                .map_err(|source| SnapshotError::Decode { id: *id, source })?;
            let next_depth = depth.checked_add(1).ok_or(SnapshotError::Overflow)?;
            let mut walked = 0_u64;
            let mut first = None;
            for child in &children {
                let (child_first, beneath) = scan_dir_node(
                    nodes,
                    &child.child,
                    next_depth,
                    facts,
                    nested,
                    seen,
                    readlink_target_max_bytes,
                )?;
                if beneath != child.subtree_entry_count {
                    return Err(SnapshotError::CountMismatch {
                        id: child.child,
                        declared: child.subtree_entry_count,
                        walked: beneath,
                    });
                }
                // `first_key` is the third navigational declaration, and
                // `lookup` descends by it. A lie makes `lookup` answer
                // NotFound for a name `readdir` lists — `ls` shows the file
                // and `open` says ENOENT. The walk holds the child's real
                // first name right here, so the comparison is free. An empty
                // child under an interior has no first name to separate on,
                // which core refuses as `FillNotCanonical`.
                let child_first = child_first.ok_or_else(|| SnapshotError::SeparatorMismatch {
                    id: child.child,
                    declared: child.first_key.clone(),
                })?;
                if child_first != child.first_key {
                    return Err(SnapshotError::SeparatorMismatch {
                        id: child.child,
                        declared: child.first_key.clone(),
                    });
                }
                if first.is_none() {
                    first = Some(child_first);
                }
                walked = walked.checked_add(beneath).ok_or(SnapshotError::Overflow)?;
            }
            Ok((first, walked))
        }
        _ => Err(SnapshotError::WrongType { id: *id }),
    }
}

impl Snapshot {
    pub(crate) fn structure_node(&self, id: &GrainId) -> Result<&[u8], ReaderError> {
        self.nodes
            .get(id)
            .map(Vec::as_slice)
            .ok_or(ReaderError::Inconsistent)
    }

    /// Indexes an already-validated, resident manifest structure map.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] when a reachable node is absent, cannot be
    /// decoded as a directory node, exceeds the per-tree depth bound, makes
    /// an indexed counter overflow, occurs twice inside one directory's
    /// B-tree, declares a `subtree_entry_count` or a `first_key` that
    /// disagrees with what lies beneath it, when the root's publish
    /// timestamp is invalid (`nanos` not strictly under one second), when
    /// a directory entry declares a reserved kind (FIFO or socket), or when
    /// a symlink entry's target is longer than the `limits` bound the
    /// caller hands in can carry.
    pub fn new(
        nodes: BTreeMap<GrainId, Vec<u8>>,
        manifest_root: GrainId,
        timestamp: Timestamp,
        stats: TreeStats,
        policy: AttrPolicy,
        limits: ServeLimits,
    ) -> Result<Self, SnapshotError> {
        // `Timestamp::is_valid`, checked directly rather than via the decoder:
        // `take_timestamp` already refuses this on every real decode path,
        // but `Timestamp`'s fields are public, so this is the engine's own
        // defence in depth against a value constructed by hand.
        if !timestamp.is_valid() {
            return Err(SnapshotError::InvalidTimestamp { timestamp });
        }
        let mut dirs = BTreeMap::new();
        let mut worklist = vec![manifest_root];
        while let Some(dir_root) = worklist.pop() {
            let alloc::collections::btree_map::Entry::Vacant(slot) = dirs.entry(dir_root) else {
                continue;
            };
            let mut facts = DirFacts {
                entries: 0,
                subdirs: 0,
            };
            let mut nested = Vec::new();
            let mut seen = BTreeSet::new();
            bump_dirscan();
            let _ = scan_dir_node(
                &nodes,
                &dir_root,
                1,
                &mut facts,
                &mut nested,
                &mut seen,
                limits.readlink_target_max_bytes,
            )?;
            slot.insert(facts);
            worklist.extend(nested);
        }
        Ok(Self {
            nodes,
            manifest_root,
            timestamp,
            dirs,
            stats,
            policy,
            limits,
        })
    }

    /// Finds one exact byte name by B-tree descent.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::NotFound`] when no exact name exists, or
    /// [`ReaderError::Inconsistent`] when this walk disagrees with the caller's
    /// completed validation.
    pub fn lookup(&self, dir: &GrainId, name: &[u8]) -> Result<Entry, ReaderError> {
        let mut current = *dir;
        let mut depth = 1_u32;
        loop {
            if depth > manifest::DEPTH_MAX {
                return Err(ReaderError::Inconsistent);
            }
            let bytes = self.nodes.get(&current).ok_or(ReaderError::Inconsistent)?;
            let (object_type, cursor) =
                encoding::open_envelope(bytes).map_err(|_| ReaderError::Inconsistent)?;
            bump_decode();
            match object_type {
                ObjectType::DirLeaf => {
                    let entries =
                        manifest::decode_dir_leaf(cursor).map_err(|_| ReaderError::Inconsistent)?;
                    // Decode into an owned leaf for this lookup and BORROW while searching it:
                    // consuming the vector mid-search is needless. Across lookups we deliberately
                    // keep no decoded-node cache: the memory/latency trade is UNMEASURED.
                    return entries
                        .iter()
                        .find(|entry| entry.name.as_bytes() == name)
                        .map(|entry| Entry {
                            name: entry.name.clone(),
                            kind: entry.kind.clone(),
                            leaf: current,
                        })
                        .ok_or(ReaderError::NotFound);
                }
                ObjectType::DirInterior => {
                    let children = manifest::decode_dir_interior(cursor)
                        .map_err(|_| ReaderError::Inconsistent)?;
                    let Some(child) = children
                        .iter()
                        .rev()
                        .find(|child| child.first_key.as_bytes() <= name)
                    else {
                        return Err(ReaderError::NotFound);
                    };
                    current = child.child;
                    depth = depth.checked_add(1).ok_or(ReaderError::Inconsistent)?;
                }
                _ => return Err(ReaderError::Inconsistent),
            }
        }
    }

    /// Streams logical directory entries starting at `from`.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Inconsistent`] when cursor descent disagrees with
    /// the caller's completed validation.
    pub fn readdir(
        &self,
        dir: &GrainId,
        parent: &GrainId,
        from: u64,
        mut emit: impl FnMut(ReaddirEntry) -> bool,
    ) -> Result<(), ReaderError> {
        // Validate the directory BEFORE emitting anything. `.` and `..` are
        // synthesised and can be emitted without consulting `dirs`. That makes
        // the ordering load-bearing: emission would be non-transactional for
        // a `dir` present in `nodes` but absent from `dirs` (a DirLeaf that is
        // a child rather than a directory root). The caller could take two
        // entries and only THEN receive `Err(Inconsistent)`. A caller that has
        // already written those entries into a reply buffer cannot un-write
        // them.
        let facts = self.dirs.get(dir).ok_or(ReaderError::Inconsistent)?;
        let mut start = from;
        if start == 0 {
            if emit(ReaddirEntry {
                name: b".".to_vec(),
                kind: EntryKind::Dir { child: *dir },
                next: 1,
            }) {
                return Ok(());
            }
            start = 1;
        }
        if start == 1 {
            if emit(ReaddirEntry {
                name: b"..".to_vec(),
                kind: EntryKind::Dir { child: *parent },
                next: 2,
            }) {
                return Ok(());
            }
            start = 2;
        }
        let manifest_index = start.checked_sub(2).ok_or(ReaderError::Inconsistent)?;
        if manifest_index >= facts.entries {
            return Ok(());
        }
        let mut cursor = ManifestCursor::seek(self, dir, manifest_index)?;
        let mut logical_index = start;
        while let Some(entry) = cursor.next_entry()? {
            let next = logical_index
                .checked_add(1)
                .ok_or(ReaderError::Inconsistent)?;
            if emit(ReaddirEntry {
                name: entry.name.as_bytes().to_vec(),
                kind: entry.kind,
                next,
            }) {
                return Ok(());
            }
            logical_index = next;
        }
        Ok(())
    }

    #[must_use]
    pub const fn manifest_root(&self) -> GrainId {
        self.manifest_root
    }

    /// The root's publish timestamp, in the format's own unit. Valid under
    /// `Timestamp::is_valid` by construction — this is the only time accessor
    /// `Snapshot` has; the conversion to the kernel's timestamp type is the
    /// adapter's, once, at its own construction.
    #[must_use]
    pub const fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    #[must_use]
    pub const fn stats(&self) -> TreeStats {
        self.stats
    }

    #[must_use]
    pub const fn policy(&self) -> AttrPolicy {
        self.policy
    }

    /// The admission bound this snapshot was constructed under — a serve
    /// adapter reads this back to verify its own bound is no looser (see
    /// [`ServeLimits`]).
    #[must_use]
    pub const fn limits(&self) -> ServeLimits {
        self.limits
    }

    /// Returns the indexed entry count for one directory root.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Inconsistent`] if `dir` was not indexed.
    pub fn dir_entries(&self, dir: &GrainId) -> Result<u64, ReaderError> {
        self.dirs
            .get(dir)
            .map(|facts| facts.entries)
            .ok_or(ReaderError::Inconsistent)
    }

    /// Returns the indexed subdirectory count for one directory root.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Inconsistent`] if `dir` was not indexed.
    pub fn dir_subdirs(&self, dir: &GrainId) -> Result<u32, ReaderError> {
        self.dirs
            .get(dir)
            .map(|facts| facts.subdirs)
            .ok_or(ReaderError::Inconsistent)
    }
}

#[cfg(test)]
mod tests;
