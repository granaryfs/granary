// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
// @file-disposition-lines: 2418
// @file-disposition: SPLIT — DISCHARGED. All three children have landed in the
// planned order: emission, structure, budget. The file is well under the
// 3,000-line trigger, so this directive is not OWED — it is kept
// only to tell the next reader the split is finished rather than pending.
// It has gone stale three times in one session, once per child, and nothing
// checks that a directive's SENTENCE is still true; if a fourth subject is ever
// found here, a one-directional seam between two subjects is the test, not this line.

//! The resolve oracle: read a published volume back the way a mount
//! would, through the pure seams and nothing else.
//!
//! `max_seq` → root → binmap index → bin table → every shard → every
//! object, each one fetched by RANGE READ out of its bin, decompressed,
//! and re-hashed against the id that named it. The commit record is
//! fetched and content-address-checked alongside. What comes back is the
//! whole volume as a reader sees it.
//!
//! **Why it is generic over `R: RootStore + BinStore`.** There are two
//! consumers — the hermetic in-memory suite reading a real
//! `object_store` bucket, and the simulator reading fakes — and they must
//! run ONE body. A helper typed to the concrete backend forces the
//! simulator to write a second copy, and two copies of an oracle
//! disagree exactly where it matters: the copy that reads the fakes
//! learns the fakes' habits.
//!
//! **This is [`BinStore::get_bin_range`]'s production consumer.** The
//! method was nearly not extracted at all for want of a caller; this is
//! the caller. Without it the oracle stops at the metadata layer, and an
//! oracle that stops there cannot see the defect class it exists for: an
//! object uploaded in the WRONG ORDER leaves a head that still decodes
//! and a binmap that still names the right ids, so "the head decodes" and
//! "the object count is right" are both green while a crash between the
//! two writes leaves a volume that cannot be read. Only fetching the
//! bytes back distinguishes them.
//!
//! **[`ResolveError::NoHead`] is an OUTCOME, not a failure.** A volume
//! with no head is the COMMON state under a crash sweep — most crash
//! points in a publish are before the root CAS, and they all leave the
//! head exactly where it was — so "resolves completely **or** has no
//! head" is the property a sweep asserts, and half of it is unstatable by
//! a helper that panics on a missing root.
//!
//! **The signature: checked on one path, deliberately not on the other,
//! and the ENTRY POINT is the choice**. [`resolve_at_verified`]
//! and [`resolve_head_verified`] take a [`RootVerifier`] and always
//! consult it — an unknown signer and a failed check are named refusals,
//! [`ResolveError::UnknownSigner`] and [`ResolveError::BadSignature`],
//! taken before a single binmap object is fetched. [`resolve_at`] and
//! [`resolve_head`] are those same functions under
//! [`RootVerifier::unverified`]: the signature slot is carried through
//! unread, exactly as Part I's oracle did.
//!
//! **The unverified path is a real state and not a hole.** Verifying
//! needs the publishing key, which a reader resolving a volume does not
//! necessarily hold; the ORACLE's structural properties hold either way;
//! and the publisher's own head resolution (`remote_state`) already
//! refuses an unsigned or badly-signed head before extending it. A
//! caller holding the key but wanting the unverified path checks it
//! itself on [`ResolveOutcome::root_bytes`], which are the bytes as
//! stored.
//!
//! **What is NOT offered is a per-call anchor.** A
//! `resolve_at(.., Option<&Key>)` would put the accept set in the
//! caller's hands, and the gate would then be a property of the busiest
//! call site rather than of the reader — so the unverified path is
//! spelled by NAMING it, at a constructor, and the four functions above
//! are the whole of the choice.
//!
//! ```
//! # use granary_client::RootVerifier;
//! // Which entry point the caller uses IS the setting.
//! assert!(!RootVerifier::unverified().is_verifying());
//! assert!(RootVerifier::trusting([1_u8; 32]).unwrap().is_verifying());
//! ```
//!
//! **Content is fetched on demand, through [`ResolveTarget`], and
//! EMITTED during the resolve.** [`ResolveOutcome`] carries no object
//! map: the caller names a target (one file, by path, or the whole
//! tree) and passes a SINK, invoked with each byte range the target
//! actually needs, in manifest-walk order. A want's charge against
//! [`crate::fetcher::FETCH_INFLIGHT_BYTES`] is held from admission
//! until the sink returns for it — not merely until the wire call
//! answers — so bytes completed out of order and buffered for in-order
//! emission stay counted; a resolve that instead retained every grain
//! in a returned map would never release that charge and could deadlock
//! its own budget. **A DUPLICATE reference holds its charge for as long
//! as it holds the bytes**: a grain named at more than one position
//! stays resident, and charged, until its LAST position drains, never
//! released at an earlier one while a later duplicate still needs it.
//!
//! **The complete residency argument, every term named — RAM for one
//! resolve is bounded, not proportional to the volume's history, and
//! does not TRUST the manifest to be honest about it.** Four
//! independent bounds compose into the whole:
//!
//! 1. **A static duplicate-span pre-bound, ≤ `FETCH_INFLIGHT_BYTES`.**
//!    `emit_file`'s own `duplicate_span_peak` sweeps edge-derived span facts
//!    BEFORE any wire call or cache read and refuses up front
//!    (`ResolveError::DuplicateSpanExceedsBudget`) when the peak
//!    concurrent duplicate-holdback its OWN positions force would ever
//!    exceed the budget — a shape no admission ORDER could stream
//!    within it regardless, since the retention is forced by which
//!    positions the file names, not by which want happens to complete
//!    first. This bound is what keeps bound 4 below true: without it, a
//!    RUN of cache hits — none of which ever occupies an admission slot,
//!    so `in_flight` stays empty across the whole run — can each
//!    individually trip the escape hatch and admit unconditionally,
//!    accumulating resident bytes without limit as a manifest grows.
//! 2. **Byte-gated admission, charged at DECLARED size and ENFORCED AT
//!    COMPLETION.** `in_flight_bytes + charge <= FETCH_INFLIGHT_BYTES`
//!    (`fetcher.rs`'s own admission rule) is the baseline: nothing new
//!    admits once the running charge would cross the ceiling — and a
//!    `BinRange` want's charge is the caller-declared `unpacked_len`
//!    (`emit_file`'s own streaming want mapper; the MAX across
//!    positions for a duplicate, `grain_span_facts` — the same figure
//!    `duplicate_span_peak` sweeps for bound 1), never the compressed
//!    figure on the wire. The charge is a bound on RESIDENCY, not
//!    merely a number admission compares itself against, because
//!    `fetcher.rs` REFUSES (`FetchError::OverDeclared`) any completion
//!    whose actual length exceeds it, before those bytes are handed to
//!    a caller — on BOTH delivery paths: `finish()` on the wire (which
//!    also refuses ahead of its own `cache.insert`, so such bytes are
//!    never cached), and `deliver_cache_hit` on a CACHE HIT (where the
//!    object is already cached and stays so — the id is honest, only
//!    the declaration lies, and nothing is evicted). The bound depends
//!    on BOTH, so a reader reaching for the enforcement point must not
//!    stop at `finish()` — a manifest cannot buy cheap admission by
//!    declaring a grain smaller than its bin's own content
//!    decompresses to; the id it fetched under proves the content, and
//!    therefore the true size, was always fixed. Compressed bytes are
//!    a SEPARATE pool: the H2 connection window (`H2_CONN_WINDOW`)
//!    paces those independently, uncharged
//!    against this budget — the true worst-case peak the two pools
//!    together can hold is their SUM, never either alone.
//! 3. **One in-flight decompress, ≤
//!    [`granary_core::manifest::GRAIN_UNPACKED_MAX`].** Bound 2's
//!    refusal runs AFTER `GrainCodec::decompress_frame` has already
//!    produced the full decoded buffer — the codec's own law against
//!    writing past a frame's declared length caps that buffer at
//!    `GRAIN_UNPACKED_MAX` regardless of what any `Want` claimed, but
//!    for the one slot being decoded, that memory exists a moment
//!    before bound 2 can act on it. Real, honest, and unavoidable for
//!    any decompression at all — never stacked, since only the ONE slot
//!    a synchronous `finish()` call is processing is ever mid-decode at
//!    once.
//! 4. **One-want escape-hatch overshoot, ≤
//!    [`granary_core::manifest::GRAIN_UNPACKED_MAX`] /
//!    [`granary_store::bounds::META_MAX_BYTES`].** With bound 1 holding,
//!    the retained-for-duplicates pool can never itself exceed the
//!    budget, so the hatch
//!    (`crate::fetcher::Fetcher::fetch_streaming`'s own doc) fires only
//!    for a genuine front-want admission with nothing else in flight —
//!    never chained across a run of cache hits, since bound 1 already
//!    keeps their combined charge within the ceiling — and its own
//!    overshoot is bounded to that ONE want's admission charge: a cold
//!    `BinRange`'s declared `unpacked_len` — a content grain's
//!    `GrainRef` declaration, or a structure node's
//!    `MANIFEST_NODE_MAX_BYTES` ceiling; BOTH ≤ `GRAIN_UNPACKED_MAX`
//!    (the format's `GrainRef` ceiling for the former, `granary-core`'s
//!    own `const` witness for the latter) and ENFORCED the same way
//!    bound 2 is — a cold `Meta`'s `META_MAX_BYTES`, or a cache hit's
//!    own already-verified `bytes.len()`.
//!
//! This is what makes RAM for a resolve bounded by
//! [`METADATA_BUDGET_BYTES`] + `FETCH_INFLIGHT_BYTES` +
//! `POOL_CAP_BYTES` (the speculative hint pool — this term counts the
//! pool's ACTUAL node bytes only, never charged to the metadata
//! budget and not in flight either, so it is its own term; the map
//! and deque overhead PER ENTRY sits on top of it and is bounded only
//! by the entry count, which nothing caps directly, and the `demoted`
//! sidecar the hint-provenance demotion keeps is one more id per
//! entry on the same footing — a subset of the pool's keys, so it
//! scales with that same uncapped count; `hints_for_round`'s
//! transient `reached` set is one more, live from the
//! `prefetch_hints` call to `into_inner` and bounded by
//! `HINT_WORK_MAX` ids rather than by the pool; `hint_tried` is a
//! further uncharged term, bounded by the distinct child ids named by
//! charged nodes rather than by the nodes themselves) + `2 *
//! GRAIN_UNPACKED_MAX` + O(unique grains + stored-edge spine) +
//! **O(expanded paths × that file's inline refs), for the `WholeTree`
//! walk only** — whatever the volume's history — not by the volume's
//! total size, and not by whether the manifest told the truth about
//! either. Admission charging a `BinRange` at its declared size,
//! enforced at completion, means a completing want's charge only ever
//! RECONCILES toward `bytes.len()`, which is a no-op or a release —
//! never a term this bound needs to carry, and never again a figure
//! this resolve merely trusts a manifest to have honoured.
//!
//! **The `WholeTree` term is real, and the four bounds above do not
//! cover it.** `walk_all_files` builds one emission descriptor per
//! expanded PATH before the first sink call, and each one OWNS a copy
//! of that file's inline grain refs — re-decoded from the directory
//! entry once per path, so a DAG that shares subtrees copies them once
//! per path too. None of the bounds above sees those bytes: they are
//! not a fetch, not a decompress and not a held grain. The path-COUNT
//! axis is bounded (`WHOLE_TREE_PATH_BUDGET` expanded actions, whose
//! own doc carries the arithmetic); the BYTE axis is not, and at the
//! action ceiling this term measures ~5.08 GiB — reachable inside
//! every budget named above, on a manifest of a few kilobytes. A
//! `WholeTree` consumer sizes it separately; `Path` never pays it.
//!
//! **The no-wedge argument for the holdback charge, RESTATED with the
//! escape hatch — a SEPARATE property from residency above (never
//! hangs, as opposed to never over-retains).** Grain wants are built in
//! the SAME order the sink needs them (manifest-walk order, file order
//! within a file) and admitted FIFO — a front want that does not fit
//! the remaining budget waits rather than being bypassed by a smaller
//! one behind it (`fetcher.rs`'s own admission rule). Ordering alone is
//! NOT sufficient to prove the gap grain is always in flight: a
//! duplicate reference can keep bytes charged (and therefore the budget
//! closed) at positions strictly AFTER a want that has not been
//! admitted at all yet, and once every other in-flight want has
//! completed, nothing is left to ever poll — the budget would delay the
//! sink FOREVER, not merely delay it. The escape hatch is what restores
//! the guarantee: whenever nothing is in flight, the front of the
//! admission queue — which FIFO ordering makes exactly the gap grain
//! the sink is waiting on, at the moment it is the reason `held` is
//! full of completed-but-unemitted bytes — admits UNCONDITIONALLY,
//! bypassing the budget outright. So the budget can delay the sink; it
//! cannot deadlock it — but the argument for that now rests on the
//! hatch, not on admission ordering alone. **The completion-time charge
//! reconciliation does not reopen this.** It only ever pauses NEW
//! admissions — it never rescinds one already granted — and a single
//! want's own declared size can never alone exceed the whole budget
//! (`GRAIN_UNPACKED_MAX <= FETCH_INFLIGHT_BYTES`, `fetcher.rs`'s own
//! `const _` witness), so the gap grain the sink is waiting on always
//! still fits once its turn comes, however many earlier reconciliations
//! ran ahead of it.
//!
//! **Why emission happens inside the resolve.**
//! A caller that could hand this module an arbitrary object map would
//! make the accept set a property of the busiest call site rather than
//! of the resolve — the same problem as letting each call choose
//! whether to verify signatures. Moving emission INSIDE the resolve strengthens that: the
//! tree walked is always the VERIFIED root's, fetched through the same
//! seam and budget as everything else the resolve checks, and the
//! caller supplies only a target name and a sink for bytes — never an
//! object set of its own choosing.
//!
//! **Metadata (binmap index/table/shards, manifest structure nodes) is
//! BUDGETED, not windowed the way content is.** These objects are
//! RETAINED for the life of the resolve — the tree walk's own
//! monotonicity contract requires it (`TreeCursor`'s doc): once returned,
//! a node's bytes must remain available unchanged — so
//! nothing here can bound them by releasing a charge on emission the
//! way content grains are bounded; [`METADATA_BUDGET_BYTES`] is a flat
//! ceiling on their cumulative cost instead, charged pessimistically
//! (worst-case per fetch) BEFORE each wire call. Charging worst-case
//! costs only THIS resolve's own window — the client is the only
//! consumer of a refusal it triggers — which is the INVERSE of
//! the server-side case, where a control sized for one
//! caller's worst case starved every other caller sharing the budget.
//!
//! **Transport-down degraded reads
//! (named with the "transport-down" qualifier throughout
//! to distinguish this fallback from the cache's unrelated
//! `Mode::ReadOnlyDegraded`).** When the
//! transport itself is unusable — [`is_transport_down`]'s exhaustive
//! classification of [`RootStoreError`] — [`resolve_head_verified`]
//! falls back to serving [`resolve_head_degraded`]'s cache-only answer
//! at the cache dir's freshness anchor, rather than failing outright.
//! Five rules hold on that path, always: (a) CONTENT is still
//! hash-verified (the cache re-hashes on read; a corrupt cache object
//! is a MISS, never served) — a cached ROOT is not: it is path-keyed,
//! not content-addressed, and carries no self-verification of its own,
//! so its authenticity comes from the root signature (the head) and
//! the preimage chain (every ancestor), never from the cache; (b) it
//! never serves below the anchor floor — the degraded candidate IS the
//! floor, by construction ([`resolve_head_degraded`]'s own doc), a
//! deliberate exception to discovery's rule that the floor is never a head candidate, scoped to
//! this one path, with a stated residual (an actor sharing the cache
//! dir's write access can select which authentically-signed seq is
//! served, never inject content); (c) it is always announced, once,
//! naming the volume, the served seq and the anchor's age
//! ([`announce_degraded`]); (d) it is never silently partial — a file
//! whose grains are not FULLY cached fails naming the transport
//! failure ([`ResolveError::Degraded`]), never a truncated stream
//! (`emission::residency_preflight`, run once per file and, on
//! [`ResolveTarget::WholeTree`], once more over every file's want set
//! combined before the first structure node is sunk); (e) it REQUIRES
//! a verifying [`RootVerifier`], checked before any cache-dir file is
//! read — rule (a)'s gap is exactly why: a keyless reader has nothing
//! to check a served root against, so [`resolve_head`]'s keyless
//! wrapper never takes this path at all. [`resolve_at`]/
//! [`resolve_at_verified`] (an explicit seq) never take this path
//! either — an explicit seq is an instruction, never a
//! recovery. The one shared read path, [`read_root_bytes`], is what
//! keeps the head root and every `check_chain` ancestor root answering
//! the SAME way rather than two implementations that could drift.
//!
//! **Metadata is not specially handled here, and that has a stated
//! cost.** Structure nodes, binmap index/table/shards and sheaves
//! already read cache-first at fetch admission
//! (`fetcher::fetch_streaming`'s own `cache.get(&id)` before any wire
//! step) regardless of whether this resolve is degraded, so a cold
//! metadata miss simply falls through to the wire and surfaces the
//! genuine transport error on its own — no separate degraded-metadata
//! mechanism exists or is needed for a peer that REFUSES outright.
//! Against a BLACKHOLED peer instead (one that accepts the connection
//! and never answers, rather than refusing), that fallthrough is not
//! free: each missing metadata object burns its own
//! [`crate::http_store::SEAM_DEADLINE_BASE`] before the miss surfaces,
//! one deadline per object rather than one immediate refusal. Accepted
//! and DEFERRED, not fixed here: missing metadata still pays that per-call deadline.

use std::collections::{BTreeMap, BTreeSet};

use granary_core::binmap::{self, ShardEntry};
use granary_core::binstore::BinStore;
use granary_core::encoding::{self, DecodeError, ObjectType};
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::manifest::{
    self, EntryKind, FileGrains, GrainRef, Name, TreeStats, ValidateError,
};
use granary_core::root::{self, LinkError, RootDoc, RootIdentityError, VolumeName};
use granary_core::rootstore::{RefusalKind, RootStore, RootStoreError};
use granary_core::sheaf::{self, SheafDoc};
use granary_store::bounds::META_MAX_BYTES;
use granary_store::codec::CodecError;
use granary_store::crypto::{self, HeadError, TrustedKeys, TrustedKeysError};

use crate::cache::{Cache, HeadAnchor, HintUpdate, PersistedHint};
use crate::fetcher::{FetchError, FetchState, Fetcher, Want};
use crate::head::{self, HeadContext};

/// A volume as a reader sees it, resolved completely.
#[derive(Debug)]
pub struct ResolveOutcome {
    /// The seq that was resolved.
    pub seq: u64,
    /// The root bytes exactly as stored — the input to a signature
    /// check, and the preimage of the next publish's `parent`.
    pub root_bytes: Vec<u8>,
    /// The decoded root.
    pub doc: RootDoc,
    /// The binmap's routing width.
    pub prefix_bits: u8,
    /// The bin table's id, as the binmap index names it.
    pub bin_table: GrainId,
    /// The bin table: bin digests, positionally — an ordinal indexes
    /// this.
    pub bins: Vec<[u8; DIGEST_LEN]>,
    /// Every entry the binmap resolves, keyed by object id.
    pub entries: BTreeMap<GrainId, ShardEntry>,
    /// The shard ids, positionally, as the binmap index names them.
    pub shard_ids: Vec<GrainId>,
    /// This publish's commit record.
    pub sheaf: SheafDoc,
    /// What the head's manifest tree turned out to hold, counted during
    /// the walk that proved it resolves.
    pub tree: TreeStats,
}

/// Everything [`preamble`] proves: the root is decoded, every
/// binmap object resolves, the head sheaf cross-checks the root,
/// the whole manifest tree resolves, and every reachable grain ref
/// maps to a binmap entry. **Not `check_chain` and not emission**
/// — those are `resolve_at_verified_impl`'s own steps, run AFTER a
/// `Preamble` comes back, so that the mount can call [`preamble`]
/// and stop there: the chain is not IN the preamble, `cat` adds
/// it, the mount does not (there is no boolean and no mode
/// parameter — the scope decision is expressed in the call graph).
///
/// **`nodes` is carried out, not dropped.**
/// `resolve_at_verified_impl` itself still only threads it into
/// `emit_target`, exactly as before — this adds no new consumer
/// — but a caller that returns straight from `preamble()` (the
/// mount) is the first one that needs the structure map to survive
/// past this function's own return: from `open()` until
/// `snapshot()` consumes it (`mount.rs`'s `std::mem::take`) — not
/// for the life of the session.
/// **Owned, not borrowing.** Every field is owned data with no
/// lifetime tied to `remote` or to `cache` — deliberately: a `Preamble`
/// that borrowed either could not be stored past the call that produced
/// it, which is exactly what a long-lived mount needs to do.
///
/// `pub(crate)`: `granary-client`'s `lib.rs` surface is curated
/// and this is an internal seam between `resolve_at_verified_impl`
/// and its callers within the crate, not part of it.
#[derive(Debug)]
pub(crate) struct Preamble {
    /// The root bytes exactly as stored — carried through unchanged
    /// from [`resolve_root`].
    pub(crate) root_bytes: Vec<u8>,
    /// The decoded root, carried through unchanged from [`resolve_root`].
    pub(crate) doc: RootDoc,
    /// The binmap's routing width.
    pub(crate) prefix_bits: u8,
    /// The bin table's id, as the binmap index names it.
    pub(crate) bin_table: GrainId,
    /// The bin table: bin digests, positionally — an ordinal indexes
    /// this.
    pub(crate) bins: Vec<[u8; DIGEST_LEN]>,
    /// Every entry the binmap resolves, keyed by object id.
    pub(crate) entries: BTreeMap<GrainId, ShardEntry>,
    /// The shard ids, positionally, as the binmap index names them.
    pub(crate) shard_ids: Vec<GrainId>,
    /// This publish's commit record.
    pub(crate) sheaf: SheafDoc,
    /// Every manifest STRUCTURE node the walk visited, keyed by id —
    /// never the grain CONTENT. See [`fetch_tree_structure`].
    pub(crate) nodes: BTreeMap<GrainId, Vec<u8>>,
    /// What the head's manifest tree turned out to hold, counted during
    /// the walk that proved it resolves.
    pub(crate) tree: TreeStats,
}

/// Why a volume did not resolve.
///
/// A variant means the volume is BROKEN — something a root names cannot
/// be produced, does not decode, or does not hash to the id that named
/// it, or a claim one seq makes about the seq below it that the stored
/// chain does not bear out — UNLESS its own doc says otherwise, and
/// SEVERAL do: a refusal can equally mean the caller named something the
/// tree does not contain, that the tree is wider than one resolve may
/// expand, that the caller's own sink failed, or that the read was
/// served degraded. This paragraph is deliberately NOT a list, because a
/// list goes stale whenever a variant is added. Read the
/// VARIANT before classifying an error as corruption: a caller that
/// treats every failure but one as damage reports healthy volumes as
/// broken.
#[derive(Debug)]
pub enum ResolveError {
    /// No root at the seq asked for — for [`resolve_head`], no roots at
    /// all. A legitimate state rather than a defect, and not the only
    /// one — see this enum's own doc.
    NoHead,
    /// The store itself failed.
    Remote(RootStoreError),
    /// An object a root names is not there.
    Missing {
        /// What role the absent object plays.
        what: &'static str,
        /// The id that named it.
        id: GrainId,
    },
    /// Stored bytes do not decode.
    Decode {
        /// What was being read.
        what: &'static str,
        /// The decoder's complaint.
        source: DecodeError,
    },
    /// A content-addressed object's bytes do not hash to the id that
    /// named them.
    Corrupt {
        /// What was being read.
        what: &'static str,
        /// The id that named it.
        id: GrainId,
    },
    /// The root at `seq` names a different volume, or carries a
    /// different seq, than the key it was fetched from.
    Mismatch {
        /// What disagreed — `"volume"` or `"seq"`.
        what: &'static str,
        /// The key's value, rendered.
        key: String,
        /// The document's value, rendered.
        doc: String,
    },
    /// The same id appears in two shards.
    DuplicateEntry {
        /// The id filed twice.
        id: GrainId,
    },
    /// An entry's `bin_ordinal` is past the bin table.
    BadOrdinal {
        /// The entry's id.
        id: GrainId,
        /// The ordinal it carried.
        ordinal: u32,
    },
    /// A range read returned fewer bytes than the extent claims — the
    /// bin is shorter than the binmap says.
    ShortExtent {
        /// The object whose extent was read.
        id: GrainId,
        /// Bytes the extent claims.
        want: u32,
        /// Bytes the store produced.
        got: usize,
    },
    /// A frame did not decompress.
    Codec(CodecError),
    /// The head's manifest tree does not walk over the objects the
    /// binmap maps — a head referencing an absent or invalid node.
    Tree {
        /// The manifest root the walk started from.
        root: GrainId,
        /// What the walk found.
        source: ValidateError,
    },
    /// The tree references a grain the binmap does not map. The tree
    /// walk cannot catch this one: it fetches manifest NODES, and an
    /// inline grain reference is a leaf it never opens.
    UnmappedGrain {
        /// The grain the tree names.
        id: GrainId,
        /// The manifest node that names it.
        node: GrainId,
    },
    /// A grain's bytes are not the length the manifest declares for it.
    /// Nothing below this sees the disagreement: a file's `size` is
    /// checked against the sum of its declared lengths and a grain
    /// list's cumulative fields against its members', but both are
    /// agreements AMONG manifest nodes, and the walk never fetches the
    /// grain. A reader trusting the declaration assembles the file at
    /// offsets its bytes do not reach.
    GrainLenMismatch {
        /// The grain whose length disagrees.
        id: GrainId,
        /// The manifest node that declared it.
        node: GrainId,
        /// Bytes the manifest declares.
        want: u32,
        /// Bytes the object holds.
        got: usize,
    },
    /// A grain that holds MORE bytes than every position naming it
    /// declared — caught by the fetcher itself
    /// (`FetchError::OverDeclared`'s own doc), before the bytes are ever
    /// held by a caller, rather than at [`Self::GrainLenMismatch`]'s own
    /// drain-time check. Not "before they are cached": that is true of
    /// the WIRE path, where `finish()` refuses ahead of its own
    /// `cache.insert`, but the refusal also fires for a CACHE HIT, where
    /// the object was read from the cache and stays there — the id is
    /// honest and the bytes hash to it, so nothing is evicted; only this
    /// want's declaration is a lie. A sibling of that variant rather
    /// than a reuse of it: `GrainLenMismatch` names the ONE declaring
    /// node a mismatched POSITION traces back to, which this refusal
    /// does not have — it fires against the want's own admission charge
    /// (the MAX across every position naming a duplicate id,
    /// `grain_span_facts`), not any single position's declaration, so
    /// there is no one `node` to name here.
    OverDeclared {
        /// The grain whose frame over-decompressed.
        id: GrainId,
        /// The declared length admission charged it at.
        declared: u32,
        /// The actual decompressed length.
        got: usize,
    },
    /// The commit record describes a different manifest root than the
    /// root naming it. Content addressing cannot catch this: it proves
    /// the sheaf is intact, never that it belongs to this root.
    SheafTreeMismatch {
        /// The manifest root the root document names.
        root: GrainId,
        /// The manifest root the sheaf names.
        sheaf: GrainId,
    },
    /// The root at `seq` names a parent that is not the root stored at
    /// `seq - 1`. Content addressing cannot catch this: the parent id is
    /// a CLAIM about ancestry, intact bytes either way, and every check
    /// below this one is confined to a single seq.
    ParentMismatch {
        /// The seq whose root carries the wrong parent.
        seq: u64,
        /// The id of the root actually stored at `seq - 1`.
        expected: GrainId,
        /// The parent the root names.
        found: Option<GrainId>,
    },
    /// The sheaf at `seq` names a parent that is not the `sheaf_head` of
    /// the root at `seq - 1` — the commit chain forking underneath an
    /// intact root chain.
    SheafChainMismatch {
        /// The seq whose sheaf carries the wrong parent.
        seq: u64,
        /// The sheaf head of the root at `seq - 1`; `None` at seq 1,
        /// where a first commit must be parentless.
        expected: Option<GrainId>,
        /// The parent the sheaf names.
        found: Option<GrainId>,
    },
    /// An ancestor root the chain requires is not there. Never
    /// [`ResolveError::NoHead`]: a truncated chain is a BROKEN volume,
    /// and `NoHead` is the shape a legitimately unpublished volume has —
    /// collapsing the two would let a truncated chain pass a crash
    /// sweep's "resolves completely or has no head" property.
    ChainBroken {
        /// The absent ancestor's seq.
        seq: u64,
    },
    /// The root at `seq` carries no signature slot the configured
    /// [`RootVerifier`] holds a key for. Never "the signature is wrong" —
    /// a root signed by a stranger and a root signed by nobody are the
    /// same state to a reader that trusts one key, and both are refused
    /// here rather than at the crypto call.
    UnknownSigner {
        /// The seq whose root no configured key signed.
        seq: u64,
    },
    /// The configured key's slot is there and its signature does
    /// not verify over the root's own [`granary_core::root::signed_prefix`].
    BadSignature {
        /// The seq whose signature failed.
        seq: u64,
    },
    /// A `BinRange`/`Meta` fetch failed for a reason [`Missing`](Self::Missing),
    /// [`Corrupt`](Self::Corrupt), [`Remote`](Self::Remote),
    /// [`ShortExtent`](Self::ShortExtent) and [`Codec`](Self::Codec) do
    /// not already cover — the fetcher's own pre-admission refusals
    /// (`OverBudget`, `OverFrameBound`), reachable only from a shard
    /// entry naming an impossible extent.
    Fetch {
        /// What role the object plays.
        what: &'static str,
        /// The fetcher's own refusal, rendered — `FetchError`
        /// itself is `pub(crate)` (the crate's curated surface),
        /// so this crosses the boundary as text rather than
        /// leaking a private type through a public one.
        message: String,
    },
    /// Retained metadata (binmap shard bytes, the binmap entry count,
    /// manifest structure node bytes, and those nodes' modelled
    /// per-node overhead) would cross
    /// `METADATA_BUDGET_BYTES` — refused BEFORE the fetch that would
    /// cross it, never after.
    MetadataBudgetExceeded {
        /// The running charge this fetch would have produced, had it
        /// been allowed to proceed.
        attempted: u64,
    },
    /// The target [`ResolveOutcome`] is asked to emit does not exist in
    /// the verified tree — a directory component that is not a
    /// directory, a name absent from a directory, a symlink or special
    /// file this walk does not follow, or a path deeper than the
    /// format's own bound. **Not "the volume is broken"** — one of
    /// several variants that are not: the tree validated completely; the
    /// caller simply named something it does not contain.
    NoSuchTarget {
        /// What the caller asked for and why it could not be served.
        message: String,
    },
    /// The caller's sink refused a range of bytes this resolve tried to
    /// emit — not a volume defect: the sink is the caller's own
    /// downstream (`gran cat`'s stdout, a test collector), never the
    /// remote.
    Sink {
        /// The sink's own complaint.
        message: String,
    },
    /// `emit_file` finished — every want in a file's grain list
    /// answered, none erroring — without its position cursor reaching
    /// the last ref. Unreachable in practice: completion with no error
    /// guarantees every position drained (`emit_file`'s own doc); typed
    /// rather than asserted, on this crate's rule against panicking on
    /// anything reachable from a stored object.
    IncompleteDrain {
        /// Positions in the file's own grain list.
        positions: usize,
        /// How many positions the drain actually reached.
        drained: usize,
    },
    /// A file's grain refs name a duplicate whose IN-ORDER emission
    /// would require holding more than the whole in-flight budget
    /// resident at once — computed statically from edge-derived facts,
    /// before any wire call or cache read (`emit_file`'s own doc explains
    /// the sweep). Duplicate references are ordinary and legal (a file of
    /// repeated blocks dedups to repeated refs); this refuses only the
    /// degenerate shape where the SPAN between a duplicate's first and
    /// last position, summed against every OTHER duplicate whose span
    /// overlaps it, exceeds what this fetcher can ever hold at once —
    /// no admission ordering could stream such a file without retaining
    /// more than the budget.
    DuplicateSpanExceedsBudget {
        /// The peak concurrent duplicate-holdback the file's own
        /// positions would force.
        need: u64,
        /// The whole in-flight budget it is measured against.
        budget: u64,
    },
    /// Head DISCOVERY landed on a candidate below the cache dir's
    /// per-volume freshness anchor — a store replaying an older,
    /// possibly validly-signed head, refused before a single binmap
    /// object is fetched. Never produced by [`resolve_at`]/
    /// [`resolve_at_verified`]: an explicit seq is a user COMMAND, not
    /// the store's own claim about the head, so the floor binds
    /// discovery's answer only (`head.rs`'s module doc).
    StaleHead {
        /// The seq discovery landed on.
        candidate: u64,
        /// The floor it fell below.
        anchor: u64,
    },
    /// The transport is unusable and the cache does not hold what a
    /// degraded read still needs. Carries BOTH the gap and the transport
    /// failure that made the cache the only source: a degraded read that
    /// cannot finish names the real reason and never accuses the volume of
    /// being broken ([`Self::ChainBroken`]) or empty ([`Self::NoHead`]),
    /// which is what the wire-shaped arms would otherwise have said.
    Degraded {
        /// What the cache did not hold, in the resolve's own vocabulary
        /// (`"ancestor root at seq 7"`, `"content grain {id}"`).
        missing: String,
        /// The transport failure that sent this read to the cache.
        source: RootStoreError,
    },
    /// A whole-tree resolve would take more EXPANDED ACTIONS (directory
    /// descents and file emissions) than the walk was given
    /// (`WHOLE_TREE_PATH_BUDGET` on the production path) — refused
    /// before the action that would cross it. A directory DAG that
    /// shares subtrees is linear in objects and exponential in paths;
    /// this bounds the second, and it counts descents because a DAG of
    /// EMPTY directories expands exponentially while emitting nothing.
    PathBudgetExceeded {
        /// The action the walk was refused AT — always `budget + 1`,
        /// because the counter rises by one and the guard fires the
        /// first time it reaches `budget`. It is a property of the
        /// BUDGET, never of the tree: a resolve needing nineteen
        /// million actions reports the same number as one needing a
        /// million and one. Do not size a retry from it.
        attempted: usize,
        /// The budget `attempted` was measured against — the value the
        /// walk actually ran under, never the constant.
        /// `walk_all_files` takes its budget as an ARGUMENT (its own
        /// rows drive it with small ones), so a rendering that reached
        /// for `WHOLE_TREE_PATH_BUDGET` instead would name a bound this
        /// refusal was never measured against.
        budget: usize,
    },
}

impl std::fmt::Display for ResolveError {
    #[expect(
        clippy::too_many_lines,
        reason = "one match arm per ResolveError variant, each a short rendering — splitting \
                  this would scatter the error text away from the enum it renders, which is \
                  what a reader actually needs beside it"
    )]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoHead => write!(f, "the volume has no head"),
            Self::Remote(e) => write!(f, "remote: {e}"),
            Self::Missing { what, id } => write!(f, "{what} {id} is missing"),
            Self::Decode { what, source } => write!(f, "decode {what}: {source}"),
            Self::Corrupt { what, id } => {
                write!(f, "{what} {id} does not hash to the id that named it")
            }
            Self::Mismatch { what, key, doc } => write!(
                f,
                "root at {what} {key} carries {what} {doc} (cross-volume replay or a misplaced root)"
            ),
            Self::DuplicateEntry { id } => write!(f, "id {id} is filed in two shards"),
            Self::BadOrdinal { id, ordinal } => {
                write!(f, "entry {id} names bin ordinal {ordinal}, past the table")
            }
            Self::ShortExtent { id, want, got } => write!(
                f,
                "extent for {id} claims {want} bytes and the bin produced {got}"
            ),
            Self::Codec(e) => write!(f, "codec: {e}"),
            Self::Tree { root, source } => {
                write!(f, "manifest tree {root} does not resolve: {source}")
            }
            Self::UnmappedGrain { id, node } => write!(
                f,
                "manifest node {node} references grain {id}, which the binmap does not map"
            ),
            Self::GrainLenMismatch {
                id,
                node,
                want,
                got,
            } => write!(
                f,
                "manifest node {node} declares grain {id} as {want} bytes and the object holds {got}"
            ),
            Self::OverDeclared { id, declared, got } => write!(
                f,
                "grain {id} was charged {declared} bytes and decompressed to {got}"
            ),
            Self::SheafTreeMismatch { root, sheaf } => write!(
                f,
                "the root names manifest root {root} and its sheaf names {sheaf}"
            ),
            Self::ParentMismatch {
                seq,
                expected,
                found,
            } => write!(
                f,
                "the root at seq {seq} names parent {} and the root below it is {expected}",
                or_none(*found)
            ),
            Self::SheafChainMismatch {
                seq,
                expected,
                found,
            } => write!(
                f,
                "the sheaf at seq {seq} names parent {} and the seq below it commits {}",
                or_none(*found),
                or_none(*expected)
            ),
            Self::ChainBroken { seq } => {
                write!(f, "the chain needs the root at seq {seq} and it is absent")
            }
            Self::UnknownSigner { seq } => write!(
                f,
                "the root at seq {seq} carries no signature from a configured signing key"
            ),
            Self::BadSignature { seq } => write!(
                f,
                "the root at seq {seq} carries a signature from a configured key that does not verify"
            ),
            Self::Fetch { what, message } => write!(f, "{what}: {message}"),
            Self::MetadataBudgetExceeded { attempted } => write!(
                f,
                "resolving would retain {attempted} bytes of metadata, over the \
                 {METADATA_BUDGET_BYTES} byte budget"
            ),
            Self::NoSuchTarget { message } => write!(f, "{message}"),
            Self::Sink { message } => write!(f, "sink: {message}"),
            Self::IncompleteDrain { positions, drained } => write!(
                f,
                "a file of {positions} grains only drained {drained} before completion"
            ),
            Self::DuplicateSpanExceedsBudget { need, budget } => write!(
                f,
                "a duplicated grain's in-order emission would hold {need} bytes at once, \
                 over the {budget} byte in-flight budget"
            ),
            Self::StaleHead { candidate, anchor } => write!(
                f,
                "discovery landed on seq {candidate}, below the freshness anchor at seq \
                 {anchor} — refused as a rollback"
            ),
            Self::Degraded { missing, source } => write!(
                f,
                "degraded read: the cache does not hold {missing}, and the transport that sent \
                 this read to the cache said: {source}"
            ),
            // `attempted` is invariantly `budget + 1` — the guard fires
            // on the action that would cross — so it is the point of
            // refusal and NEVER the tree's size. A message shaped as
            // "would expand {attempted} actions" reads as the latter and
            // invites an operator to raise the budget by one and be
            // refused again identically; this one says only that the
            // resolve needs MORE than the budget allows.
            Self::PathBudgetExceeded { attempted, budget } => write!(
                f,
                "resolving the whole tree needs more than the {budget} expanded actions \
                 (directory descents and file emissions) it is allowed; refused at action \
                 {attempted}"
            ),
        }
    }
}

/// An optional id as an error renders it. `None` is a VALUE here — the
/// parentless shape a first commit legitimately has — never a failure to
/// look one up.
fn or_none(id: Option<GrainId>) -> String {
    id.map_or_else(|| "none".to_owned(), |id| id.to_string())
}

impl std::error::Error for ResolveError {}

impl From<RootStoreError> for ResolveError {
    fn from(e: RootStoreError) -> Self {
        Self::Remote(e)
    }
}

impl From<CodecError> for ResolveError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

fn decode_err(what: &'static str) -> impl FnOnce(DecodeError) -> ResolveError {
    move |source| ResolveError::Decode { what, source }
}

/// The reader's root-signature trust anchor, decided ONCE.
///
/// **Constructed, never chosen per call.** A `resolve_at(.., Option<&Key>)`
/// would put the accept set in the caller's hands — every call site free
/// to pass `None`, and the gate is then a property of the busiest call
/// site rather than of the reader. So the anchor is a value a reader
/// builds at configuration time and threads: [`resolve_at_verified`]
/// takes one and always consults it, and the unverified path is spelled
/// by handing it [`RootVerifier::unverified`] rather than by omitting an
/// argument.
///
/// **The unverified anchor is a real state, not a hole.** `resolve.rs`'s
/// module docs record why: a reader does not necessarily hold the
/// publishing key, and the ORACLE's structural properties hold with or
/// without one. What changes is what "resolves" then means, and that is
/// exactly what the constructor makes visible at the call site.
#[derive(Debug, Clone)]
pub struct RootVerifier {
    anchor: Option<TrustedKeys>,
}

/// Why a value was refused as a root-signing trust anchor.
///
/// The mirror of `granary_net::pin::PinSetError` on the signing-key
/// side: both the transport-pin and root-signing-key configurations refuse
/// the all-zero value, for the same stated reason. (Not an intra-doc
/// link: this crate does not depend on `granary-net`; the transport-pin
/// and root-signature consumers must stay unreachable from one another.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorError {
    /// The all-zero public key was supplied as a trust anchor.
    ///
    /// **It is exactly what an unset, zeroed configuration field looks
    /// like — so accepting it is how a fail-open default reaches
    /// production**, which is verbatim the argument
    /// `granary_net::pin::PinSetError::ZeroPin` makes for the digest
    /// half.
    ///
    /// Here it is worse than a dead anchor, because a zeroed key does
    /// not refuse everything. The all-zero encoding decodes to `y = 0`,
    /// whose `x² = -1` has a root in `F_p` — a VALID curve point, of
    /// ORDER 4. Under RFC 8032's non-cofactored verification equation
    /// `[S]B = R + [h]A`, an all-zero signature gives `identity = R +
    /// [h]A` with both terms inside that order-4 subgroup, which holds
    /// for roughly one message in four. So a zeroed anchor ACCEPTS a
    /// root forged by anyone — one signature slot carrying the publicly
    /// computable `key_id` `SHA256(32 zero bytes)` and 64 zero bytes as
    /// the signature, with no private key anywhere.
    ///
    /// Only the all-zero value is refused here. The general
    /// low-order-key class remains outside this refusal: an attacker who can
    /// choose the operator's configured key already controls trust and
    /// gains nothing from a small-order point over their own real key,
    /// whereas the zeroed field arrives by accident.
    ZeroKey,
}

impl std::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroKey => f.write_str(
                "the all-zero public key is not a trust anchor: it is a valid \
                 order-4 curve point, so an all-zero signature verifies under \
                 it for about one root in four",
            ),
        }
    }
}

impl std::error::Error for AnchorError {}

impl RootVerifier {
    /// A reader holding no key: every root's signature slot is carried
    /// through unread, exactly as Part I's oracle did.
    #[must_use]
    pub const fn unverified() -> Self {
        Self { anchor: None }
    }

    /// A reader trusting exactly one root-signing public key.
    ///
    /// # Errors
    /// [`AnchorError::ZeroKey`] — the all-zero key is a fail-open
    /// sentinel, not an anchor; see the variant for what it admits.
    pub fn trusting(public: [u8; crypto::PUBLIC_KEY_LEN]) -> Result<Self, AnchorError> {
        // The mirror of `granary_net::pin::PinnedServerVerifier::new`'s
        // `ZeroPin`, applied here to the root-signing key. The pin side
        // shipped with this refusal and this side did not.
        //
        // The all-zero refusal lives in `TrustedKeys::new`.
        let keys = match TrustedKeys::new([public]) {
            Ok(keys) => keys,
            // `Empty` is refused only for an iterator that yields no key, and
            // this one yields exactly one, so it cannot occur. Reporting it
            // as the zero-key refusal keeps the refusal closed (no anchor is
            // built) without a panic path.
            Err(TrustedKeysError::ZeroKey | TrustedKeysError::Empty) => {
                return Err(AnchorError::ZeroKey);
            }
        };
        Ok(Self { anchor: Some(keys) })
    }

    /// Is this verifier going to check anything? A row asserting a
    /// refusal needs to know it is not asserting over the empty anchor.
    #[must_use]
    pub const fn is_verifying(&self) -> bool {
        self.anchor.is_some()
    }

    /// Decode the root at `seq` from its stored bytes and, when this
    /// verifier holds an anchor, verify it as a head: strict decode, the
    /// volume, the seq and the anchor's signature, in that order. With no
    /// anchor the signature is carried through unread.
    ///
    /// The signature is checked over the bytes AS STORED
    /// ([`crypto::check_head`] takes `root_bytes` and borrows the signed
    /// prefix from that buffer), never over a re-encoding of the decoded
    /// document.
    ///
    /// **ONE signature authenticates the WHOLE CHAIN, transitively, and
    /// that is why nothing below re-checks one.** This method verifies the
    /// resolved root and no ancestor, which is sufficient only because
    /// [`check_chain`] binds each ancestor to its child by
    /// `GrainId::of(&parent_bytes)` against the child's `parent` field
    /// — and `parent` sits INSIDE the signed prefix (verified: for a
    /// seq-2 root the parent's 33 encoded bytes fall within the
    /// 256-byte prefix of a 356-byte object, and `decode_header`, the
    /// one function `signed_prefix` and `decode_root` share, reads it).
    /// So the head's signature covers the id of the bytes one seq down,
    /// whose own `parent` is covered by the same argument, all the way
    /// to seq 1. The sheaf chain rides on it identically: `sheaf_head`
    /// is inside the prefix too, and each `SheafDoc::parent` is read out
    /// of bytes `fetch_meta` content-address-checked.
    ///
    /// **What would break it silently.** Any loosening of that preimage
    /// comparison — hashing a re-encoding of the decoded ancestor,
    /// comparing a prefix of the id, or trusting the ancestor's own
    /// `seq`/`volume` in its place — severs authenticity from every
    /// ancestor while leaving this signature check green and every
    /// existing row passing. The chain is only as authenticated as
    /// `GrainId::of` over the STORED ancestor bytes.
    pub(crate) fn check_head(
        &self,
        volume: &str,
        seq: u64,
        root_bytes: &[u8],
    ) -> Result<RootDoc, ResolveError> {
        match self.anchor.as_ref() {
            Some(keys) => {
                crypto::check_head(root_bytes, volume, seq, keys).map_err(|e| head_err(seq, e))
            }
            None => root::decode_expected(root_bytes, volume, seq).map_err(identity_err),
        }
    }
}

/// Map a shared root-identity failure onto the reader's own error values:
/// the decode keeps its `root` role, and a volume or seq disagreement is
/// [`ResolveError::Mismatch`] with the key the caller asked for.
fn identity_err_as(what: &'static str, e: RootIdentityError) -> ResolveError {
    match e {
        RootIdentityError::Decode(source) => ResolveError::Decode { what, source },
        RootIdentityError::VolumeMismatch { expected, found } => ResolveError::Mismatch {
            what: "volume",
            key: expected,
            doc: found,
        },
        RootIdentityError::SeqMismatch { expected, found } => ResolveError::Mismatch {
            what: "seq",
            key: expected.to_string(),
            doc: found.to_string(),
        },
    }
}

fn identity_err(e: RootIdentityError) -> ResolveError {
    identity_err_as("root", e)
}

/// Map a failed root link at child seq `s` onto the reader's error values.
fn link_err(s: u64, e: LinkError) -> ResolveError {
    match e {
        LinkError::ParentMismatch { expected, found } => ResolveError::ParentMismatch {
            seq: s,
            expected,
            found,
        },
        LinkError::Identity(e) => identity_err_as("ancestor root", e),
    }
}

fn head_err(seq: u64, e: HeadError) -> ResolveError {
    match e {
        HeadError::Identity(e) => identity_err(e),
        HeadError::NoTrustedSlot => ResolveError::UnknownSigner { seq },
        HeadError::BadSignature { .. } => ResolveError::BadSignature { seq },
    }
}

// The whole-read deadline (`RESOLVE_DEADLINE`) and its `under_resolve_
// deadline` wrapper are GONE, for the same reason `crate::publish`'s
// whole-publish deadline is: a fixed total over the whole flow is REPLACED
// by a per-call deadline on every seam call
// (`crate::http_store::SEAM_DEADLINE_BASE`/`seam_deadline`). A resolve's
// request count is a property of the volume rather than of the command —
// this module's own note on that stands — and the per-call form is what
// makes a large but honest volume completable at all: every call is
// individually bounded, so a long ancestor walk whose every `get_root` and
// sheaf `get_meta` finishes inside its own deadline now completes, where
// the one-hour total this constant held would have refused a head past
// roughly seq 36 000 with nothing wrong on the wire.

mod budget;

// Re-exported because NON-TEST code outside this module names them:
// `mount.rs` builds a `MetadataBudget`, `structure.rs` takes one, and
// `METADATA_BUDGET_BYTES` is read by a `Display` arm here — through an INLINE
// FORMAT CAPTURE (`{METADATA_BUDGET_BYTES} byte budget`), which rustc counts
// as a use and which a comment/string-stripping scan cannot see. Decision
// 4(a): the parent re-exports what it always exported, so every
// `crate::resolve::<name>` path keeps working. `ENTRY_COST_BYTES` and
// `NODE_COST_BYTES` are NOT here — their only consumers are test modules,
// which reach `budget` directly as descendants of this one, and re-exporting
// them would be `unused_imports` in a non-test build. Contrast
// `WHOLE_TREE_PATH_BUDGET` at the emission cut, where the re-export had no
// consumer at all and the compiler refused it outright.
pub(crate) use budget::{METADATA_BUDGET_BYTES, MetadataBudget};

/// Map one [`FetchError`] back into a role-scoped [`ResolveError`],
/// keeping the richness a direct `RootStoreError` match would carry:
/// a `NotFound` is
/// [`ResolveError::Missing`], a hash failure is
/// [`ResolveError::Corrupt`], a short range read is
/// [`ResolveError::ShortExtent`], a decompression failure is
/// [`ResolveError::Codec`], an over-declared decompression is
/// [`ResolveError::OverDeclared`] (a lying-manifest failure, like
/// [`ResolveError::GrainLenMismatch`] — this resolve still fails on
/// such an input, correctly; only the memory the failure cost is now
/// bounded), and everything else the fetcher's own pre-admission gates
/// can raise (reachable only from an impossible binmap extent) is
/// [`ResolveError::Fetch`].
fn map_fetch_err(what: &'static str, id: GrainId, e: FetchError) -> ResolveError {
    match e {
        FetchError::Remote(RootStoreError::NotFound) => ResolveError::Missing { what, id },
        FetchError::Corrupt { .. } => ResolveError::Corrupt { what, id },
        FetchError::Remote(other) => ResolveError::Remote(other),
        FetchError::ShortExtent { want, got, .. } => ResolveError::ShortExtent { id, want, got },
        FetchError::Codec(source) => ResolveError::Codec(source),
        FetchError::OverDeclared { declared, got, .. } => {
            ResolveError::OverDeclared { id, declared, got }
        }
        FetchError::OverBudget { .. } | FetchError::OverFrameBound { .. } => ResolveError::Fetch {
            what,
            message: e.to_string(),
        },
    }
}

/// Whether `e` means the store produced NO ANSWER to the head
/// question — the ONLY condition that ever sends a head-resolve
/// to the degraded (cache-only) fallback. Written as an
/// exhaustive match with no wildcard arm so a new
/// [`RootStoreError`] variant must be classified here rather than
/// silently joining whichever side happens to be convenient.
///
/// **The axis is "did the store answer THE QUESTION", not "did any byte
/// arrive".** A store that ANSWERED — `NotFound`, `Precondition`,
/// `AlreadyExists`, `RangeOverflow`, `InvalidVolume`, **and a `429` or `503`
/// ([`RootStoreError::Unavailable`])** — is never transport-down: the
/// read reached the store and the store said something, which a degraded
/// fallback must not paper over by substituting a stale cached answer
/// for it. A `429` or `503` is an explicit transient refusal. The fetcher's
/// backpressure handles it and surfaces `Unavailable` to the caller;
/// treating it as transport-down could silently pin a warm reader to a
/// stale anchor.
///
/// **`RefusedResponse` splits by [`RefusalKind`], because the four kinds
/// do not sit on one side of the axis.** `OverCap` and `Extent` are the
/// store answering — an object over a size cap, or a ranged answer that
/// does not match its own extent, is a fact about what the store SENT,
/// same as `NotFound` — so they stay `false`. `Framing` and `NoProgress`
/// are a fact about the TRANSPORT itself misbehaving (a second trailer
/// frame, a flood with no byte of progress), not about anything the
/// store said, so they degrade exactly like `Backend`/`Elapsed`.
///
/// Otherwise, only a store that produced no answer at all degrades: a
/// wedged peer cut by its own per-seam deadline
/// ([`RootStoreError::Elapsed`]), or a transport-level failure that
/// never became a response ([`RootStoreError::Backend`] — connection
/// refused, TLS failure, a dropped request).
///
/// **`UnexpectedStatus` is an *answered* status, classified generously and
/// knowingly.** `HttpStore::unmapped` types an unmapped HTTP status (a
/// proxy's `500`) as its own variant, which by the axis above is the
/// store answering. No granary server produces those on a read path — the
/// `unmapped` row exists for a status "an intermediary supplies" — so it
/// degrades like the no-answer transport failures, exactly as the
/// free-text `Backend` it replaced did.
pub(crate) fn is_transport_down(e: &RootStoreError) -> bool {
    match e {
        RootStoreError::Backend(_)
        | RootStoreError::UnexpectedStatus { .. }
        | RootStoreError::Elapsed { .. } => true,
        RootStoreError::RefusedResponse { kind, .. } => match kind {
            RefusalKind::Framing | RefusalKind::NoProgress => true,
            RefusalKind::OverCap | RefusalKind::Extent => false,
        },
        RootStoreError::Unavailable { .. }
        | RootStoreError::AlreadyExists
        | RootStoreError::Precondition
        | RootStoreError::NotFound
        | RootStoreError::RangeOverflow
        | RootStoreError::InvalidVolume { .. } => false,
    }
}

/// The ONE read path for a root, head or ancestor alike —
/// see [`check_chain`]'s own doc for why sharing this one
/// function is load-bearing rather than a style preference.
///
/// `degraded: None` is today's behaviour unchanged: read the wire,
/// `?`-propagating a transport failure through
/// [`ResolveError`]'s `From<RootStoreError>` impl. `degraded:
/// Some(transport_err)` never touches the wire at all: a cache hit
/// answers `Ok(Some(bytes))` — UNVERIFIED here, exactly like a wire
/// root's bytes are unverified here, because every caller of this
/// function re-verifies through the same decode/cross-check/signature
/// path either source takes. A miss is [`ResolveError::Degraded`],
/// never `Ok(None)`: `Ok(None)` is what `resolve_at_verified_impl`
/// reads as [`ResolveError::NoHead`] and what `check_chain` reads as
/// [`ResolveError::ChainBroken`] — both wire-shaped claims about the
/// VOLUME that a degraded cache miss must never make, since a cache
/// miss says only that THIS cache dir does not hold the answer.
async fn read_root_bytes<R: RootStore>(
    remote: &R,
    cache: Option<&Cache>,
    degraded: Option<&RootStoreError>,
    volume: &str,
    seq: u64,
) -> Result<Option<Vec<u8>>, ResolveError> {
    let Some(transport_err) = degraded else {
        return Ok(remote.get_root(volume, seq).await?);
    };
    // An unparseable `volume` cannot be a cache key either — treated the
    // same as a miss, never a panic (this crate's rule against
    // panicking on anything reachable from a stored/caller-supplied
    // value).
    let hit = VolumeName::new(volume.to_owned())
        .ok()
        .and_then(|vol| cache.and_then(|c| c.get_root_bytes(&vol, seq)));
    match hit {
        Some(bytes) => Ok(Some(bytes)),
        None => Err(ResolveError::Degraded {
            missing: format!("root at seq {seq}"),
            source: transport_err.clone(),
        }),
    }
}

/// The sink a resolve hands `target`'s bytes to, in manifest-walk
/// order, DURING the resolve — see the module doc's emission section.
/// `(id, bytes)`: for [`ResolveTarget::WholeTree`] `id` is the object's
/// own id (structure node or content grain); for
/// [`ResolveTarget::Path`] every call is the target file's content, in
/// file order, and `id` is that grain's id.
pub type EmitSink<'a> = dyn FnMut(GrainId, &[u8]) -> Result<(), String> + 'a;

/// What a resolve should emit, and to whom. A caller-selected target
/// replaces eagerly materialising every mapped object into
/// `ResolveOutcome.objects` regardless of what the caller wanted.
#[derive(Debug, Clone, Copy)]
pub enum ResolveTarget<'a> {
    /// Every file's bytes, in manifest-walk order, PLUS every manifest
    /// structure node as it is fetched — the closest equivalent to a
    /// whole-tree object map, and what the oracle/tests use.
    ///
    /// **This target's path enumeration is bounded, not left open: at
    /// most 1,048,576 (2^20) EXPANDED ACTIONS per resolve.** The walk
    /// enumerates every FILE PATH, not every distinct object; a
    /// directory DAG (many names sharing one child id, which validation
    /// permits) makes that enumeration exponential in nesting depth even
    /// though structural validation — memoized by id — stays linear over
    /// the same tree. The resolve refuses with
    /// [`ResolveError::PathBudgetExceeded`] before the action that would
    /// cross that budget, having emitted nothing.
    ///
    /// **What the budget bounds is the ACTION COUNT — directory
    /// descents plus file emissions — and only that.** That is what
    /// closes the exponential path-enumeration axis. It does NOT bound
    /// the BYTES a whole-tree resolve holds: every emitted path carries
    /// its own copy of that file's inline grain refs (up to
    /// [`granary_core::manifest::FILE_INLINE_MAX_REFS`] of them,
    /// re-decoded from the directory entry once per path), so retained
    /// bytes scale with the resolved files' inline REF counts, not with
    /// the descriptor count. Measured on this target: the worst legal
    /// emission is 5,200 bytes, so the ceiling the action budget admits
    /// is about 5.08 GiB — GIGABYTES, not megabytes — and an ~8 KB
    /// manifest is enough to reach the order of a gigabyte. **A
    /// consumer that resolves a whole tree it does not control must
    /// size that byte ceiling itself; this budget will not do it.**
    WholeTree,
    /// One file's bytes only, named by path from the manifest root —
    /// `gran cat`'s shape. The whole tree STRUCTURE is still walked and
    /// validated exactly as strictly as [`WholeTree`](Self::WholeTree)
    /// walks it (a change in SCOPE, not a
    /// weakening); structure nodes are fetched for that but never
    /// handed to the sink.
    Path(&'a [Name]),
}

/// Resolve the volume's HEAD, completely.
///
/// The head comes from hint-first discovery (`head.rs`: a fresh
/// persisted hint, else a revalidated one forward-probed, else
/// `max_seq`), never from a bare, unrevalidated hint alone — see that
/// module's doc for the full order and the per-volume freshness floor it
/// applies.
///
/// `head_ctx` supplies the `Clock`/`Rng` seams discovery's hint poll needs
/// and the single-flight map that coalesces concurrent callers — never
/// constructed internally (see `head.rs`'s purity section); build one
/// with [`HeadContext::new`]. `cache` is optional (`None` is today's
/// cacheless behaviour, and also the shape a reader with no cache dir
/// gets: no anchor, no persisted hint, full discovery every time —
/// `head.rs`'s own self-check). `sink` is invoked with `target`'s bytes,
/// in manifest-walk order, DURING the resolve — see the module doc's
/// emission section.
///
/// **This keyless wrapper never degrades.** [`RootVerifier::unverified`]
/// carries no key to check a transport-down cache serve against,
/// so a transport failure here always returns the
/// transport error itself, regardless of what the cache holds; a caller
/// that wants server-down reads to keep working from the cache needs
/// [`resolve_head_verified`] with a [`RootVerifier::trusting`] anchor.
///
/// # Errors
/// [`ResolveError::NoHead`] when the volume has no roots at all — a
/// legitimate state, not a defect. [`ResolveError::StaleHead`] when
/// discovery's candidate sits below the cache dir's anchor floor. Any
/// other variant means the volume is broken unless that
/// variant's own doc says otherwise, and several do; see
/// [`ResolveError`].
pub async fn resolve_head<R: RootStore + BinStore>(
    remote: &R,
    volume: &str,
    head_ctx: &HeadContext,
    cache: Option<&mut Cache>,
    target: ResolveTarget<'_>,
    sink: &mut EmitSink<'_>,
) -> Result<ResolveOutcome, ResolveError> {
    resolve_head_verified(
        remote,
        volume,
        &RootVerifier::unverified(),
        head_ctx,
        cache,
        target,
        sink,
    )
    .await
}

/// A sink that collects every `(id, bytes)` pair into `collected` — the
/// shape [`resolve_head_collecting`] and [`resolve_at_collecting`] both
/// need, built ONCE here instead of once per wrapper.
fn collecting_sink(
    collected: &mut BTreeMap<GrainId, Vec<u8>>,
) -> impl FnMut(GrainId, &[u8]) -> Result<(), String> + '_ {
    move |id: GrainId, bytes: &[u8]| -> Result<(), String> {
        collected.insert(id, bytes.to_vec());
        Ok(())
    }
}

/// A collector convenience over [`resolve_head`]: whole tree, no cache,
/// every emitted `(id, bytes)` pair collected into a map — the shape
/// tests and the sim oracle use in place of the removed
/// `ResolveOutcome.objects` field. Materialisation is the CALLER's
/// choice (the module doc); this function is that choice, packaged.
///
/// # Errors
/// As [`resolve_head`].
pub async fn resolve_head_collecting<R: RootStore + BinStore>(
    remote: &R,
    volume: &str,
    head_ctx: &HeadContext,
) -> Result<(ResolveOutcome, BTreeMap<GrainId, Vec<u8>>), ResolveError> {
    let mut collected = BTreeMap::new();
    let mut sink = collecting_sink(&mut collected);
    let outcome = resolve_head(
        remote,
        volume,
        head_ctx,
        None,
        ResolveTarget::WholeTree,
        &mut sink,
    )
    .await?;
    drop(sink);
    Ok((outcome, collected))
}

/// [`resolve_head`], checking the head's signature
/// against `verifier`.
///
/// **The head hint is persisted here, once the WHOLE resolve verifies —
/// never by discovery alone.** `head.rs`'s discovery only ever ANSWERS a
/// candidate seq; it never writes to the cache itself. Only once
/// [`resolve_at_verified`]'s underlying body has independently proven
/// that candidate resolves does this function make the ONE combined
/// commit below (floor + hint together, not two separate writes) — the
/// persisted hint's seq therefore equals the just-raised floor "by
/// construction" (`crate::cache::PersistedHint`'s own doc): an
/// unverified wire value never gets a chance to seed or move the floor
/// on its own, and a broken candidate's hint is never persisted at all.
/// See `resolve_at_verified_impl`'s own doc for the ordering-invariant
/// statement this restructuring preserves.
///
/// **A HINT-DERIVED candidate that resolves to NO ROOT AT ALL is
/// retried ONCE**, with the hint path forced off (`head`'s internal
/// `discover_head_forced_max_seq`) — see `head`'s internal
/// `Discovered::hint_derived` for why a hint can name a seq the store
/// has no root for. A max_seq-derived candidate that still fails to
/// resolve is a genuinely empty (or genuinely
/// rolled-back-below-the-floor) volume, answered as such — never a
/// second retry.
///
/// # Errors
/// As [`resolve_head`], plus [`ResolveError::UnknownSigner`] and
/// [`ResolveError::BadSignature`].
pub async fn resolve_head_verified<R: RootStore + BinStore>(
    remote: &R,
    volume: &str,
    verifier: &RootVerifier,
    head_ctx: &HeadContext,
    mut cache: Option<&mut Cache>,
    target: ResolveTarget<'_>,
    sink: &mut EmitSink<'_>,
) -> Result<ResolveOutcome, ResolveError> {
    // The no-re-emit guard. `emitted` latches the moment
    // ANY byte reaches the caller's `sink` — never reset, never
    // consulted for anything but "did the normal attempt already leak
    // bytes past this function's own `?`". `counting` is a non-`move`
    // closure, so it borrows `sink` and `emitted` rather than
    // consuming either: both are usable again, unborrowed, the moment
    // this block ends (before the degraded branch below needs them).
    let mut emitted = false;
    let normal = {
        let mut counting = |id: GrainId, bytes: &[u8]| -> Result<(), String> {
            emitted = true;
            sink(id, bytes)
        };
        resolve_head_verified_normal(
            remote,
            volume,
            verifier,
            head_ctx,
            cache.as_deref_mut(),
            target,
            &mut counting,
        )
        .await
    };

    match normal {
        // The trigger is the WHOLE normal attempt — discovery
        // through `resolve_at_verified_impl`'s tail — not discovery
        // alone. Whichever step inside `resolve_head_verified_normal`
        // actually touched the wire and got refused, its error surfaces
        // here as this SAME `ResolveError::Remote` shape (every
        // wire-facing step in that function propagates through `?`), so
        // one check here covers all of them.
        Err(ResolveError::Remote(source)) if !emitted && is_transport_down(&source) => {
            resolve_head_degraded(
                remote, volume, verifier, head_ctx, cache, target, sink, source,
            )
            .await
        }
        other => other,
    }
}

/// [`resolve_head_verified`]'s normal, wire-first attempt: hint-first
/// discovery, the HINT-DERIVED `NoHead` retry, and the ONE combined
/// anchor+hint commit on success. A function of its own so
/// [`resolve_head_verified`] can wrap
/// exactly this (and only this) in the transport-down catch that
/// decides whether [`resolve_head_degraded`] runs.
async fn resolve_head_verified_normal<R: RootStore + BinStore>(
    remote: &R,
    volume: &str,
    verifier: &RootVerifier,
    head_ctx: &HeadContext,
    mut cache: Option<&mut Cache>,
    target: ResolveTarget<'_>,
    sink: &mut EmitSink<'_>,
) -> Result<ResolveOutcome, ResolveError> {
    let discovered = head::discover_head(head_ctx, remote, volume, cache.as_deref_mut()).await?;
    let first = resolve_at_verified_impl(
        remote,
        volume,
        discovered.seq,
        verifier,
        cache.as_deref_mut(),
        target,
        sink,
        false, // the combined commit below is the one floor write, not the tail's own
        None,  // this is the normal, wire-first attempt
    )
    .await;

    let (discovered, outcome) = match first {
        Err(ResolveError::NoHead) if discovered.hint_derived => {
            // Bounded to EXACTLY one retry — `discover_head_forced_
            // max_seq`'s own `Discovered` always carries
            // `hint_derived: false`, so this arm can never fire again
            // for the SAME resolve, even if the retried candidate also
            // fails to resolve.
            let retried =
                head::discover_head_forced_max_seq(remote, volume, cache.as_deref_mut()).await?;
            let outcome = resolve_at_verified_impl(
                remote,
                volume,
                retried.seq,
                verifier,
                cache.as_deref_mut(),
                target,
                sink,
                false,
                None,
            )
            .await?;
            (retried, outcome)
        }
        other => (discovered, other?),
    };

    if let Some(cache) = cache {
        // The persisted stamp is the WIRE-confirmation reading
        // `discovered` already carries (captured inside discovery, at
        // the `read_hint` 304/200 itself) — never a fresh `now()` taken
        // here, after the whole resolve above has run.
        let hint_update = match discovered.wire_confirmation {
            Some(confirmation) => HintUpdate::Replace(PersistedHint {
                seq: outcome.seq,
                token: confirmation.token.0,
                stamp_secs: confirmation.stamp_secs,
            }),
            None => HintUpdate::Unchanged,
        };
        // The ONE combined commit — floor and hint together, with
        // `raise_anchor`'s own no-change short-circuit skipping the
        // rename entirely when neither actually moved.
        cache.raise_anchor(&outcome.doc.volume, Some(outcome.seq), hint_update);
    }
    Ok(outcome)
}

/// [`resolve_head_verified`]'s fallback: the normal attempt
/// above failed on a transport-down error before a single
/// byte reached the sink. Serve entirely from the cache, at
/// the anchor floor, and never touch the wire again.
///
/// **Rule (e): a verifying [`RootVerifier`] is required, checked FIRST
/// and before any cache-dir file is opened.** A transport-down read has
/// no live channel, so it can only REPLAY trust established earlier.
/// Content objects re-hash against the ids that name them, but those
/// ids descend from the head root, and a cached root is PATH-KEYED
/// bytes with no self-verification of its own
/// ([`Cache::get_root_bytes`]'s own doc: no hash or signature check
/// happens there). The only trust replayable offline that is
/// independent of the medium holding the replay is the root
/// signature — so a reader holding no key has nothing to check a served
/// root against and must refuse before reading one, never after. The
/// check sits ahead of `read_anchor`/`get_root_bytes` for exactly that
/// reason: parsing an untrusted cache-dir file on a path that is going
/// to refuse anyway serves no purpose and only widens what a hostile
/// file gets to touch.
///
/// **The candidate is the anchor floor, and there is no other.**
/// `cache.read_anchor` absent, or its own root absent
/// from the cache, means this cache dir cannot answer the head question
/// at all — the demo's `--wipe-cache` negative proof — so the ORIGINAL
/// transport error is returned unchanged rather than a `Degraded` about
/// a candidate this cache dir never had. Rule (b) (never below the
/// anchor floor) then holds BY CONSTRUCTION: the candidate IS the
/// floor, never a value compared against it after the fact.
///
/// **Raises nothing.** `raise_floor: false`, and this
/// function makes no `cache.raise_anchor` call of its own on success —
/// a degraded resolve learned nothing from the wire, so neither the
/// floor nor the hint moves. `resolve_at_verified_impl`'s own
/// `put_root_bytes` calls still run (head and every ancestor
/// `check_chain` reads), but against bytes the cache already holds —
/// `put_root_bytes` is put-if-absent, so this is a no-op, not a second
/// write.
#[expect(
    clippy::too_many_arguments,
    reason = "one more than resolve_head_verified_normal's own 7 — source (the transport error \
              that triggered this fallback) is this function's only addition, and every other \
              parameter is already load-bearing"
)]
async fn resolve_head_degraded<R: RootStore + BinStore>(
    remote: &R,
    volume: &str,
    verifier: &RootVerifier,
    head_ctx: &HeadContext,
    cache: Option<&mut Cache>,
    target: ResolveTarget<'_>,
    sink: &mut EmitSink<'_>,
    source: RootStoreError,
) -> Result<ResolveOutcome, ResolveError> {
    let Some(cache) = cache else {
        return Err(ResolveError::Remote(source));
    };

    // Rule (e), checked FIRST: before `read_anchor`, before
    // `get_root_bytes`, before any cache-dir file is parsed. See this
    // function's own doc for why the ordering is load-bearing rather
    // than a style choice — a keyless reader has nothing to verify a
    // served root against, so it refuses before touching untrusted
    // cache-dir bytes at all, not after.
    if !verifier.is_verifying() {
        crate::observe::OperatorDiagnostic::a_cache_dir_is_present_but_a_transport_down().emit();
        return Err(ResolveError::Remote(source));
    }

    let Ok(vol) = VolumeName::new(volume.to_owned()) else {
        return Err(ResolveError::Remote(source));
    };
    let Some(anchor) = cache.read_anchor(&vol) else {
        return Err(ResolveError::Remote(source));
    };
    if cache.get_root_bytes(&vol, anchor.seq).is_none() {
        return Err(ResolveError::Remote(source));
    }

    announce_degraded(head_ctx, &anchor, volume);

    resolve_at_verified_impl(
        remote,
        volume,
        anchor.seq,
        verifier,
        Some(cache),
        target,
        sink,
        false,
        Some(&source),
    )
    .await
}

/// Rule (c): the one typed warning a degraded FALLBACK announces
/// itself with, naming the volume, the candidate seq it is falling back
/// to from the cache, and the age of the anchor's last WIRE
/// confirmation. It marks the degradation EVENT — that the transport
/// gave no answer and this resolve is now cache-only — not a guaranteed
/// completed serve: a fallback whose cache cannot fully satisfy the
/// target still fails closed with the transport error afterwards (rule
/// (d)), and the warn has already, correctly, announced the degradation.
///
/// **The age is COMPUTED, never guessed.** `age = now.secs -
/// hint.stamp_secs`, via checked arithmetic. When the anchor carries no
/// hint at all, or the subtraction would be negative (a stepped wall
/// clock — the hint's stamp reads AFTER `now()`), the age is reported as
/// `"unknown"` rather than a fabricated figure.
fn announce_degraded(head_ctx: &HeadContext, anchor: &HeadAnchor, volume: &str) {
    let age = anchor
        .hint
        .as_ref()
        .and_then(|hint| head_ctx.now().secs.checked_sub(hint.stamp_secs))
        .filter(|&secs| secs >= 0)
        .and_then(|secs| u64::try_from(secs).ok())
        .map_or(crate::observe::Age::Unknown, crate::observe::Age::Seconds);
    if let Ok(volume) = VolumeName::new(volume.to_owned()) {
        crate::LocalReport::degraded(volume, anchor.seq, age).emit();
    }
    crate::observe::OperatorDiagnostic::the_transport_gave_no_answer_falling_back_to_the(
        anchor.seq, age,
    )
    .emit();
}

/// Resolve `volume` at exactly `seq`.
///
/// # Errors
/// [`ResolveError::NoHead`] when no root sits at `seq`. Any other
/// variant means the volume is broken unless that
/// variant's own doc says otherwise, and several do; see
/// [`ResolveError`].
pub async fn resolve_at<R: RootStore + BinStore>(
    remote: &R,
    volume: &str,
    seq: u64,
    cache: Option<&mut Cache>,
    target: ResolveTarget<'_>,
    sink: &mut EmitSink<'_>,
) -> Result<ResolveOutcome, ResolveError> {
    resolve_at_verified(
        remote,
        volume,
        seq,
        &RootVerifier::unverified(),
        cache,
        target,
        sink,
    )
    .await
}

/// As [`resolve_head_collecting`], over [`resolve_at`].
///
/// # Errors
/// As [`resolve_at`].
pub async fn resolve_at_collecting<R: RootStore + BinStore>(
    remote: &R,
    volume: &str,
    seq: u64,
) -> Result<(ResolveOutcome, BTreeMap<GrainId, Vec<u8>>), ResolveError> {
    let mut collected = BTreeMap::new();
    let mut sink = collecting_sink(&mut collected);
    let outcome = resolve_at(
        remote,
        volume,
        seq,
        None,
        ResolveTarget::WholeTree,
        &mut sink,
    )
    .await?;
    drop(sink);
    Ok((outcome, collected))
}

/// [`resolve_at`], checking the root's signature
/// against `verifier`.
///
/// **The check sits at the CHEAPEST point that has what it needs**: the
/// root has decoded and its volume/seq cross-checks have passed, and not
/// one binmap object has been fetched. A reader given a root no
/// configured key signed does no store work on its account.
///
/// **The structural validation below the last fetch is SYNCHRONOUS, and
/// therefore outside every per-call seam deadline this flow's fetches
/// run under.** A `tokio::time::timeout` fires at an await point and
/// there is none left once an object is in hand, so `validate_dir_tree`,
/// `check_reachable_grains` and the sheaf cross-checks run to
/// completion however long they take — and their cost is set by the
/// tree's REF count, which a valid tree may inflate far past its object
/// count. Bounding that is a bound on the walk, not on any clock; see
/// `crate::http_store::SEAM_DEADLINE_BASE`, which bounds only the fetches
/// this flow makes on the way in, never the validation after the last
/// one.
///
/// # Errors
/// As [`resolve_at`], plus [`ResolveError::UnknownSigner`] and
/// [`ResolveError::BadSignature`].
pub async fn resolve_at_verified<R: RootStore + BinStore>(
    remote: &R,
    volume: &str,
    seq: u64,
    verifier: &RootVerifier,
    cache: Option<&mut Cache>,
    target: ResolveTarget<'_>,
    sink: &mut EmitSink<'_>,
) -> Result<ResolveOutcome, ResolveError> {
    // An explicit seq is an instruction, never a recovery —
    // NO degraded fallback here, ever. `degraded: None` is
    // this call's whole statement of that; see `resolve_head_verified`
    // for the only call site that ever passes `Some`.
    resolve_at_verified_impl(
        remote, volume, seq, verifier, cache, target, sink, true, None,
    )
    .await
}

/// Fetch the root bytes, decode them, cross-check volume and
/// seq, and run the verifier — and RETURN before anything is
/// fetched on the strength of `doc`'s contents. The split point:
/// everything above this line depends only on the SEQ the caller
/// asked for and the verifier's own trust anchor; everything
/// below (fetching the binmap, the sheaf, the tree) trusts what
/// `doc` claims, so a caller with its own pre-condition on `doc`
/// (the mount's `--manifest-root` pin) gets to
/// check it here, before paying for any of that work.
///
/// # Errors
/// [`ResolveError::NoHead`] when there is no root at `seq`;
/// [`ResolveError::Mismatch`] when the decoded root's own volume or seq
/// disagrees with what was asked for; otherwise whatever
/// [`granary_core::root::decode_root`] or [`RootVerifier::check_head`] produced.
pub(crate) async fn resolve_root<R: RootStore>(
    remote: &R,
    cache: Option<&Cache>,
    degraded: Option<&RootStoreError>,
    volume: &str,
    seq: u64,
    verifier: &RootVerifier,
) -> Result<(Vec<u8>, RootDoc), ResolveError> {
    let Some(root_bytes) = read_root_bytes(remote, cache, degraded, volume, seq).await? else {
        return Err(ResolveError::NoHead);
    };
    // A root is signed over its own contents, and the signature says who
    // wrote it — never what key it was stored at. The volume and seq
    // cross-checks are the reader's.
    let doc = verifier.check_head(volume, seq, &root_bytes)?;
    Ok((root_bytes, doc))
}

/// Everything from [`resolve_root`]'s return up to and including
/// [`check_reachable_grains`]: fetch and validate the binmap index,
/// table and every shard, fetch the head sheaf and cross-check it
/// against the root, walk and validate the whole manifest tree, and
/// check every reachable grain ref maps to a binmap entry. Takes the
/// already-decoded `doc` (and the `root_bytes` it was decoded from)
/// rather than fetching the root itself — [`resolve_root`] is the
/// caller's job.
///
/// **Not `check_chain` and not emission** — see [`Preamble`]'s own doc
/// for why the split sits exactly here.
///
/// `fetcher` and `budget` are the caller's, for two different reasons.
/// ONE [`Fetcher`] spans the whole resolve — this function's fetches,
/// `check_chain`'s ancestor sheaves and `emit_target`'s content grains
/// all take it. The [`MetadataBudget`] does NOT: neither `check_chain`
/// nor `emit_target` takes one, so it covers this function's metadata
/// fetches alone. It is still the caller's rather than created here,
/// because a second budget for this half would let these fetches go
/// unaccounted against the caller's running total, which is exactly
/// the divergence the module doc's budget section exists to rule out.
///
/// # Errors
/// [`ResolveError::SheafTreeMismatch`] if the sheaf's own manifest root
/// disagrees with the root's; otherwise whatever the binmap decode,
/// [`fetch_meta_budgeted`], [`fetch_tree_structure`] or
/// [`check_reachable_grains`] produced.
pub(crate) async fn preamble<R: BinStore>(
    fetcher: &mut Fetcher<'_, R>,
    mut cache: Option<&mut Cache>,
    volume: &str,
    root_bytes: Vec<u8>,
    doc: RootDoc,
    budget: &mut MetadataBudget,
) -> Result<Preamble, ResolveError> {
    let index_bytes = fetch_meta_budgeted(
        fetcher,
        cache.as_deref_mut(),
        volume,
        "binmap index",
        &doc.binmap_index,
        budget,
    )
    .await?;
    let index = binmap::decode_binmap_index(&index_bytes).map_err(decode_err("binmap index"))?;
    let table_bytes = fetch_meta_budgeted(
        fetcher,
        cache.as_deref_mut(),
        volume,
        "bin table",
        &index.bin_table,
        budget,
    )
    .await?;
    let bins = binmap::decode_bin_table(&table_bytes).map_err(decode_err("bin table"))?;
    let bin_count = u32::try_from(bins.len()).unwrap_or(u32::MAX);

    let mut entries: BTreeMap<GrainId, ShardEntry> = BTreeMap::new();
    for (shard_index, shard_id) in index.shards.iter().enumerate() {
        let shard_bytes = fetch_meta_budgeted(
            fetcher,
            cache.as_deref_mut(),
            volume,
            "binmap shard",
            shard_id,
            budget,
        )
        .await?;
        let shard = binmap::decode_shard(&shard_bytes).map_err(decode_err("binmap shard"))?;
        // The two bounds a shard cannot check alone: ordinals against
        // the table it does not carry, and routing against a position it
        // does not know.
        binmap::validate_ordinals(&shard, bin_count).map_err(decode_err("binmap shard"))?;
        binmap::validate_routing(&shard, index.prefix_bits, shard_index)
            .map_err(decode_err("binmap shard"))?;
        let shard_len = shard.len();
        for e in shard {
            if entries.insert(e.id, e).is_some() {
                return Err(ResolveError::DuplicateEntry { id: e.id });
            }
        }
        budget.bump_entries(shard_len);
    }

    // The commit record is a DIRECTLY-ADDRESSED meta object, never a
    // binmap entry: `get_meta`, content-checked, like the index and the
    // table above it.
    let sheaf_bytes = fetch_meta_budgeted(
        fetcher,
        cache.as_deref_mut(),
        volume,
        "sheaf",
        &doc.sheaf_head,
        budget,
    )
    .await?;
    let sheaf = sheaf::decode_sheaf(&sheaf_bytes).map_err(decode_err("sheaf"))?;
    // Hashing to the id that named it proves the record is INTACT, never
    // that it belongs to this root — the same gap the root's own
    // volume/seq cross-checks close. Without this, a valid commit record
    // for another published tree resolves as this one's.
    if sheaf.manifest_root != doc.manifest_root {
        return Err(ResolveError::SheafTreeMismatch {
            root: doc.manifest_root,
            sheaf: sheaf.manifest_root,
        });
    }

    // Every manifest STRUCTURE node the walk visits, fetched on demand
    // and retained for the walk's duration (never the grain CONTENT —
    // oracle hole 2 closes here: an object mapped in the binmap but not
    // referenced by this tree is never asked for). "Resolves completely"
    // is a claim about the HEAD'S TREE, not about the binmap's own
    // bookkeeping — a head whose manifest root is not mapped at all is
    // precisely the shape an out-of-order upload produces, since the
    // root is written last.
    // Last use of `cache` in this function: passed by value, not
    // `.as_deref_mut()` — nothing below needs it again (clippy
    // `needless_option_as_deref`).
    let (nodes, tree, visited) = fetch_tree_structure(
        fetcher,
        cache,
        &entries,
        &bins,
        &doc.manifest_root,
        budget,
        #[cfg(test)]
        None,
    )
    .await?;

    // Cheap and unconditional over the WHOLE tree (no fetch: every
    // reachable grain ref is checked for binmap membership only) —
    // see `check_reachable_grains`'s doc for why the LENGTH half of
    // this check moved to emission.
    check_reachable_grains(&visited, &nodes, &entries)?;

    Ok(Preamble {
        root_bytes,
        doc,
        prefix_bits: index.prefix_bits,
        bin_table: index.bin_table,
        bins,
        entries,
        shard_ids: index.shards,
        sheaf,
        nodes,
        tree,
    })
}

/// [`resolve_at_verified`]'s real body, plus a `raise_floor` switch:
/// `true` for every PUBLIC caller ([`resolve_at_verified`] itself, and
/// therefore [`resolve_at`]), which keeps its own single floor-only
/// commit exactly as before (candidate = `seq`, hint = `Unchanged`).
/// [`resolve_head_verified`] passes `false` — it needs the floor raised
/// and the hint replaced TOGETHER, in the ONE combined commit it makes
/// itself once this function returns `Ok`, never as two separate
/// `Cache::raise_anchor` calls. The PUBLIC signatures above stay
/// byte-identical; only this private body gained the parameter.
///
/// **`degraded`**: `None` for every ordinary call — including EVERY
/// call an explicit seq ever makes (`resolve_at`/
/// `resolve_at_verified` never pass `Some`). `Some(transport_err)`
/// only from `resolve_head_degraded`'s own retry, once the normal
/// head-resolve has already failed on that exact transport error
/// with nothing emitted yet. It threads through unchanged to
/// [`check_chain`] so the head root and every ancestor root answer
/// from the SAME source by the SAME rule — see [`read_root_bytes`].
///
/// **The split.** This body runs the fallible stages
/// [`resolve_root`], the fetcher's `FetchState::new`, [`preamble`],
/// [`check_chain`] and [`emit_target`] in that order, each behind its
/// own `?`, then the
/// best-effort cache writes (`put_root_bytes`, and the floor raise
/// when `raise_floor`), which return nothing and cannot fail the
/// resolve. The mount
/// calls [`resolve_root`] then [`preamble`] and stops there, which
/// is what makes "the mount validates less" a fact about the call
/// graph rather than a flag this function has to branch on.
#[expect(
    clippy::too_many_arguments,
    reason = "two parameters more than resolve_at_verified's own 7 — raise_floor and degraded \
              are this private body's only additions over its public callers' signature, and \
              every other parameter is already load-bearing (see the function's own doc)"
)]
async fn resolve_at_verified_impl<R: RootStore + BinStore>(
    remote: &R,
    volume: &str,
    seq: u64,
    verifier: &RootVerifier,
    mut cache: Option<&mut Cache>,
    target: ResolveTarget<'_>,
    sink: &mut EmitSink<'_>,
    raise_floor: bool,
    degraded: Option<&RootStoreError>,
) -> Result<ResolveOutcome, ResolveError> {
    let (root_bytes, doc) =
        resolve_root(remote, cache.as_deref(), degraded, volume, seq, verifier).await?;

    let mut fetch_state = FetchState::new().map_err(|e| ResolveError::Fetch {
        what: "fetcher init",
        message: e.to_string(),
    })?;
    let mut fetcher = Fetcher::new(remote, &mut fetch_state);
    // The one running budget threaded through every metadata fetch below
    // AND through the tree walk's own structure-node fetches — see the
    // module doc's budget section.
    let mut budget = MetadataBudget::default();

    let pre = preamble(
        &mut fetcher,
        cache.as_deref_mut(),
        volume,
        root_bytes,
        doc,
        &mut budget,
    )
    .await?;

    // LAST among the VALIDATION checks, deliberately — see `check_chain`'s
    // own doc for why hoisting it would let a broken ancestor mask the
    // head's own `ResolveError::Tree`/`SheafTreeMismatch`.
    //
    // **BEFORE emission, deliberately.** Emission is the one step that
    // reaches an external consumer (`gran cat`'s stdout, a collector) —
    // nothing about "resolves completely" may be handed out before the
    // WHOLE resolve, ancestor history included, has verified. Emission
    // running INSIDE the resolve means nothing else gates it — without
    // this ordering, a `gran cat` could stream a file to stdout and
    // only THEN report a broken ancestor chain — so `check_chain` must
    // run before the one call that can leak bytes past a `?`.
    check_chain(
        &mut fetcher,
        cache.as_deref_mut(),
        volume,
        seq,
        &pre.doc,
        &pre.sheaf,
        degraded,
    )
    .await?;

    emit_target(
        &mut fetcher,
        cache.as_deref_mut(),
        &pre.entries,
        &pre.bins,
        &pre.doc.manifest_root,
        &pre.nodes,
        target,
        sink,
        degraded,
    )
    .await?;

    // Every ancestor root `check_chain` read is already written through
    // `put_root_bytes` inside it, into the client cache; the head
    // root is the one write left to this function, on a resolve that
    // reached this line — every check the caller's verifier demands has
    // passed. Under `RootVerifier::unverified()` that is NOT a signature
    // (the anchor, not the cache, is the rollback defence there),
    // and the cache stores bytes, never trust: a future reader of these
    // bytes re-verifies through the same `RootVerifier` path the wire
    // takes.
    //
    // **The anchor floor is raised here too, unconditionally, on EVERY
    // successful verified resolve — including an explicit `resolve_at`
    // seq.** The floor must never decrease: this `Some(seq)` call and
    // `WriterState::raise_anchor`'s own `existing.max(candidate)` are
    // the ONLY write site for this field in the crate; there is no
    // path that ever passes a value lower than what is already stored,
    // so there is no path that can lower it. `HintUpdate::Unchanged`:
    // the hint half is `resolve_head_verified`'s own write, made
    // separately once it also knows whether a wire confirmation
    // happened this call (a bare `resolve_at`/`resolve_at_verified`
    // call never touches the hint at all). Last use of `cache` in this
    // function, so no further reborrow is needed.
    //
    // **`raise_floor`: `resolve_head_verified` passes `false`
    // here.** It still gets `put_root_bytes` (the cache stores bytes
    // regardless), but skips this floor-only raise — it makes its OWN
    // single combined commit (floor + hint together) once this function
    // returns `Ok`, so the floor is not raised TWICE for one resolve.
    // The CRITICAL ORDERING INVARIANT is unaffected either way: whether
    // the floor is raised HERE or by the caller immediately after, it
    // only ever happens after every check above this line — decode,
    // signature, budgeted metadata, tree walk, reachability, chain —
    // has already returned `Ok`. An unverified wire seq never reaches
    // either write site on its own.
    if let Some(cache) = cache {
        cache.put_root_bytes(&pre.doc.volume, seq, &pre.root_bytes);
        if raise_floor {
            cache.raise_anchor(&pre.doc.volume, Some(seq), HintUpdate::Unchanged);
        }
    }

    Ok(ResolveOutcome {
        seq,
        root_bytes: pre.root_bytes,
        doc: pre.doc,
        prefix_bits: pre.prefix_bits,
        bin_table: pre.bin_table,
        bins: pre.bins,
        entries: pre.entries,
        shard_ids: pre.shard_ids,
        sheaf: pre.sheaf,
        tree: pre.tree,
    })
}

/// Fetch a meta object through `fetcher`, pre-charging
/// [`METADATA_BUDGET_BYTES`] at [`granary_store::bounds::META_MAX_BYTES`]
/// (the worst case: no format field declares an object's size ahead of
/// fetching it) before the wire call, then folding the ACTUAL bytes into
/// `retained_bytes`. Used for the binmap index/table/shards and the head
/// sheaf. Manifest STRUCTURE nodes do NOT come through here: they are
/// bin-packed, so [`fetch_tree_structure`] fetches them as
/// `Want::BinRange` against the same budget at their own tighter worst
/// case, [`granary_core::manifest::MANIFEST_NODE_MAX_BYTES`]. Ancestor
/// roots/sheaves in
/// `check_chain` do not call this either: they are read one at a time
/// and never retained past the loop iteration that reads them (the
/// module doc's budget section).
///
/// # Errors
/// [`ResolveError::MetadataBudgetExceeded`] before the wire call if this
/// fetch's worst case would cross the budget; otherwise
/// [`map_fetch_err`]'s mapping of whatever the fetch itself produced.
async fn fetch_meta_budgeted<R: BinStore>(
    fetcher: &mut Fetcher<'_, R>,
    cache: Option<&mut Cache>,
    volume: &str,
    what: &'static str,
    id: &GrainId,
    budget: &mut MetadataBudget,
) -> Result<Vec<u8>, ResolveError> {
    budget.charge_before_fetch(META_MAX_BYTES)?;
    let bytes = fetch_meta(fetcher, cache, volume, what, id).await?;
    budget.fold(bytes.len());
    Ok(bytes)
}

mod structure;

// The parent calls INTO the child:
// `fetch_tree_structure` was private and becomes `pub(super)` — never
// wider, and it is the ONE inbound name the seam measurement found.
use structure::fetch_tree_structure;

/// Walk the chain from `seq` down to 1: each root's `parent` against the
/// bytes actually stored one seq below it, each sheaf's `parent` against
/// the `sheaf_head` of the root one seq below it, and the base of both —
/// a first commit descends from nothing.
///
/// Ancestry ONLY. Epoch monotonicity, the timestamps and `sheaf.ops`
/// against the tree are not checked here or anywhere.
///
/// **It runs LAST, and the order is normative.** Every check above it is
/// confined to the seq the caller asked for, and their errors describe
/// THAT volume state; this one reads other seqs, so what it finds is a
/// defect in the history behind the head. Hoisting it would let a broken
/// ancestor mask the head's own [`ResolveError::Tree`] or
/// [`ResolveError::SheafTreeMismatch`], and it would put a `get_root` of
/// another seq ahead of the fetch that decides [`ResolveError::NoHead`],
/// which must keep meaning "no root at the seq asked for".
///
/// **A missing ancestor is [`ResolveError::ChainBroken`], never
/// `NoHead`.** `NoHead` is the shape a legitimately unpublished volume
/// has, and a crash sweep's property is "resolves completely **or** has
/// no head" — so collapsing the two would let a volume with published
/// roots still in the bucket pass that property as an empty one.
///
/// **This walk is what makes the resolved root's ONE signature authenticate the
/// whole history, and no row here would notice if it stopped.**
/// [`RootVerifier::check_head`] verifies the resolved root only. That is
/// sufficient because the comparison below is `GrainId::of` over the
/// ancestor's STORED BYTES against the child's `parent` field, and
/// `parent` is inside the signed prefix — so authenticity propagates
/// down the chain by preimage, one link at a time, from a single
/// signature (see [`RootVerifier::check_head`] for the verification of that
/// placement, and the same argument for the sheaf chain).
///
/// The consequence is that the two comparisons in this loop are
/// SECURITY checks and not merely structural ones. A later change that
/// made either cheaper — re-encoding the ancestor before hashing it,
/// comparing a prefix of the id, accepting the ancestor's self-reported
/// `seq` in place of the preimage — would leave every ancestor
/// unauthenticated with nothing anywhere going red, because the head's
/// own signature check is unaffected by it.
///
/// **Roots and sheaves here are NEVER Want-able and never budgeted:**
/// on the ORDINARY (non-degraded) path, ancestor roots stay direct
/// [`RootStore::get_root`] reads (not content-addressed by a `GrainId`
/// the fetcher's single-flight map could key on) — see the `degraded`
/// paragraph immediately below for the one case where that is no
/// longer true — and ancestor sheaves ride the fetcher's `Want::Meta`
/// for its cache/backpressure but are read ONE AT A TIME and never
/// retained past the loop iteration that reads them — so nothing here
/// accumulates against [`METADATA_BUDGET_BYTES`]. When `cache` is
/// present, every ancestor root this walk reads is written through
/// `Cache::put_root_bytes` — the walk's reads ARE the write set, and
/// roots are never swept.
///
/// **`degraded`**: threaded straight from
/// [`resolve_at_verified_impl`], unchanged — see [`read_root_bytes`],
/// which every ancestor root read in this loop goes through, exactly
/// the way the head root itself does. The requirement is
/// ONE helper, so the head read and every ancestor read can never
/// drift on where a degraded read is allowed to answer from.
async fn check_chain<R: RootStore + BinStore>(
    fetcher: &mut Fetcher<'_, R>,
    mut cache: Option<&mut Cache>,
    volume: &str,
    seq: u64,
    doc: &RootDoc,
    sheaf: &SheafDoc,
    degraded: Option<&RootStoreError>,
) -> Result<(), ResolveError> {
    // What the link one seq up claims about the seq being examined.
    let mut child_root_parent = doc.parent;
    let mut child_sheaf_parent = sheaf.parent;
    // `prev` is `s - 1` by CONSTRUCTION rather than by subtraction: two
    // descending ranges of equal length offset by one, so the pairs are
    // (seq, seq-1) … (2, 1) and neither end can underflow. Both are
    // empty at `seq == 1`, where the only rule is the base below.
    for (s, prev) in (2..=seq).rev().zip((1..seq).rev()) {
        let remote = fetcher.remote();
        let Some(parent_bytes) =
            read_root_bytes(remote, cache.as_deref(), degraded, volume, prev).await?
        else {
            return Err(ResolveError::ChainBroken { seq: prev });
        };
        // The id of the bytes AS STORED — the same preimage the
        // publisher hashed, never a re-encoding of the decoded document.
        // An ancestor earns the same volume and seq cross-checks as the
        // head: being hash-linked from above proves which BYTES were
        // committed to, never that those bytes were this volume's root at
        // this seq. No signature is read: the head's covers the chain.
        let parent_doc = root::check_link(child_root_parent, &parent_bytes, volume, prev)
            .map_err(|e| link_err(s, e))?;
        // The second chain. The roots can link perfectly while the
        // commit records fork underneath them: the two are separate
        // hash chains, and only the root at `prev` says which sheaf
        // belongs at `prev`.
        if child_sheaf_parent != Some(parent_doc.sheaf_head) {
            return Err(ResolveError::SheafChainMismatch {
                seq: s,
                expected: Some(parent_doc.sheaf_head),
                found: child_sheaf_parent,
            });
        }
        // The ancestor's own commit record, so the next link down has
        // something to compare against. `fetch_meta` content-address-
        // checks it, which is what makes its `parent` field trustworthy
        // enough to carry into that comparison. Never budgeted or
        // retained beyond this iteration — see the doc above.
        let sheaf_bytes = fetch_meta(
            fetcher,
            cache.as_deref_mut(),
            volume,
            "ancestor sheaf",
            &parent_doc.sheaf_head,
        )
        .await?;
        let parent_sheaf =
            sheaf::decode_sheaf(&sheaf_bytes).map_err(decode_err("ancestor sheaf"))?;
        child_root_parent = parent_doc.parent;
        child_sheaf_parent = parent_sheaf.parent;

        // Written through on every read, cache present or not is the
        // no-op case (`put_root_bytes` is itself a silent no-op with no
        // cache): this walk's reads ARE the
        // write set, alongside the head (written by the caller once
        // this whole resolve verifies).
        if let Some(cache) = cache.as_deref_mut() {
            cache.put_root_bytes(&parent_doc.volume, prev, &parent_bytes);
        }
    }

    // The base of the chain. The ROOT at seq 1 needs nothing here —
    // `decode_root`'s parent/seq cross-rule already refuses a seq-1 root
    // carrying a parent, and every root above went through that decoder.
    // No decoder can say the same for a SHEAF: the format admits a
    // parent at any position, so "a first commit descends from nothing"
    // is enforceable only from here, and without it the walk stops one
    // link short of the bottom on every volume.
    if child_sheaf_parent.is_some() {
        return Err(ResolveError::SheafChainMismatch {
            seq: 1,
            expected: None,
            found: child_sheaf_parent,
        });
    }
    Ok(())
}

/// Check every grain the reachable manifest STRUCTURE nodes reference:
/// that the binmap maps it at all. Whole-tree, unconditional on target,
/// and cheap — no fetch, `entries` is already resident.
///
/// **The LENGTH half of this check lives at emission, not here.** An
/// eagerly-fetched walk would have every mapped object's bytes in hand
/// already, letting a grain's declared length be checked against the
/// whole tree in one pass here; under on-demand content fetch only the
/// EMITTED grains' bytes are ever in hand, so their length is checked
/// where they are fetched
/// (`emit_target`'s per-file streaming, `ResolveError::GrainLenMismatch`)
/// instead. The length check follows the emission scope: a `gran cat` of
/// the whole current tree still checks every grain's length, because it
/// emits every grain; a path-scoped `gran cat` proves the file it reads,
/// not every OTHER file in the volume — the same "current tree only,
/// nothing unreachable" scope oracle hole 2 closes for content, applied
/// to the length claim of content this resolve never touches.
///
/// Both checks belong HERE (existence) and at emission (length) and
/// nowhere else. The tree walk fetches manifest NODES, and an inline
/// grain reference is a leaf it never opens — so an unmapped grain
/// survives it. `visited` is exactly the reachable node set, which is
/// what keeps this from failing a volume over an UNREACHABLE node left
/// behind by an earlier tree.
fn check_reachable_grains(
    visited: &BTreeSet<GrainId>,
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    entries: &BTreeMap<GrainId, ShardEntry>,
) -> Result<(), ResolveError> {
    for node in visited {
        let Some(bytes) = nodes.get(node) else {
            continue;
        };
        for r in grain_refs(bytes)? {
            if !entries.contains_key(&r.id) {
                return Err(ResolveError::UnmappedGrain {
                    id: r.id,
                    node: *node,
                });
            }
        }
    }
    Ok(())
}

/// Every grain a manifest node references directly, WITH the length the
/// node declares for it — the id alone cannot answer whether the object
/// it names is the size the manifest promised.
///
/// The match has no wildcard arm: a new object type must be classified
/// here rather than silently contributing no references.
fn grain_refs(bytes: &[u8]) -> Result<Vec<GrainRef>, ResolveError> {
    let (ty, cursor) = encoding::open_envelope(bytes).map_err(decode_err("manifest node"))?;
    let mut out = Vec::new();
    match ty {
        ObjectType::DirLeaf => {
            for entry in manifest::decode_dir_leaf(cursor).map_err(decode_err("dir leaf"))? {
                if let EntryKind::File {
                    grains: FileGrains::Inline(refs),
                    ..
                } = entry.kind
                {
                    out.extend(refs);
                }
            }
        }
        ObjectType::GrainListLeaf => {
            for r in
                manifest::decode_grain_list_leaf(cursor).map_err(decode_err("grain-list leaf"))?
            {
                out.push(r);
            }
        }
        // Interior nodes name children, never grains, and the walk
        // reaches those children itself. The rest are not manifest
        // nodes: the walk would have refused them already.
        ObjectType::DirInterior
        | ObjectType::GrainListIndex
        | ObjectType::Bin
        | ObjectType::BinmapIndex
        | ObjectType::BinTable
        | ObjectType::BinmapShard
        | ObjectType::Root
        | ObjectType::Sheaf => {}
    }
    Ok(out)
}

/// Fetch a meta object through `fetcher` and check it against the id
/// that named it — content addressing is a guarantee only where someone
/// checks it. A missing object is refused BY ROLE rather than as a bare
/// `NotFound` that names neither the object nor what it was for.
///
/// Unbudgeted: callers that RETAIN the result for the resolve's duration
/// go through [`fetch_meta_budgeted`] instead; this is the primitive
/// both share, and `check_chain`'s ancestor-sheaf reads (never retained
/// past one loop iteration) call it directly.
async fn fetch_meta<R: BinStore>(
    fetcher: &mut Fetcher<'_, R>,
    cache: Option<&mut Cache>,
    volume: &str,
    what: &'static str,
    id: &GrainId,
) -> Result<Vec<u8>, ResolveError> {
    let want = Want::Meta {
        volume: volume.to_owned(),
        id: *id,
    };
    let mut result = fetcher
        .fetch(cache, [want])
        .await
        .map_err(|e| map_fetch_err(what, *id, e))?;
    result
        .remove(id)
        .unwrap_or(Err(FetchError::Remote(RootStoreError::NotFound)))
        .map_err(|e| map_fetch_err(what, *id, e))
}

mod emission;

// The parent calls INTO the child: `emit_target`
// was private and becomes `pub(super)` — never wider — and is imported by
// name so that an unused one is `unused_imports`. Nothing else of the
// child's is used by the parent's PRODUCTION code; the four names the
// parent's own test rows still touch are imported in `tests.rs`, which is
// `#[cfg(test)]` and so raises no unused import in a production build.
use emission::emit_target;

#[cfg(test)]
mod tests;
