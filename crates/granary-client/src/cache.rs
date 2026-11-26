// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
// @file-disposition-lines: 2665
// @file-disposition: SPLIT — DISCHARGED. All five children landed (paths, write,
// marker, anchor, index_load); cache.rs is under the 3,000-line trigger and
// owes no directive. Kept to say the split is finished rather than pending.

//! The client cache: a persistent, crash-safe,
//! single-writer/lockless-reader disk cache of fetched objects, roots and
//! (directory-only, here) anchors.
//! The index format this cache consumes is
//! `granary_core::cacheindex`.
//!
//! **Extends `crate::store`'s write discipline** (temp+rename via
//! `txn/`, hash-verify on read) with a journaled index, a disk quota
//! plus watermark, a crash guard, and a lockless read path. Diverges
//! from it in exactly two ways: the index is
//! journaled (the harvest store never evicts, so it never needed one),
//! and reads take no lock at all (the harvest store is single-writer
//! AND single-reader by construction).
//!
//! **The cache accepts a single-object crash window.** A crash between
//! an object's rename landing in `objects/` and its insert record
//! becoming durable leaves an unindexed-but-present, still
//! hash-verifiable object. REPORTING that window by walking
//! `objects/` and comparing against the index is `gran verify`'s job
//! (it repairs nothing)
//! (`verify_reports_adopted_and_dropped_without_touching_the_index`,
//! in the `verify` module's tests, is the row for it, not this module).
//!
//! **A read-only-filesystem mount is unsupported.** `open` always
//! creates the layout scaffolding and the `lock` file unconditionally,
//! for winner and loser alike, before deciding writer-vs-degraded —
//! read-only-degraded mode exists for LOCK CONTENTION (another process
//! already holds it), not for read-only media; a genuinely read-only
//! mount fails `open` with an I/O error rather than degrading.
//!
//! **Compaction cannot depend only on `close` for a long-lived client.**
//! A one-shot CLI opens, serves bounded work, and exits; a daemon can
//! keep its journal open for days. `WriterState::append_journal_record`
//! therefore checks compaction thresholds after every tracked record,
//! including cache-hit touches, through `maybe_compact_throttled`.
//! `Cache::maintain` flushes and attempts compaction without closing;
//! `Cache::close` also attempts compaction when the invocation ends.
//! The automatic path throttles retries after a failed attempt.
//!
//! **This cache assumes the cache directory lives in the
//! operator's own trust domain.** Two residuals follow from that
//! and are DEFERRED rather than closed: a structural-path TOCTOU,
//! and the flock-vs-unlink race. Neither is defended against here,
//! and a directory outside that trust domain is out of contract.

use std::collections::BTreeMap;
use std::fs::{self, File, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use granary_core::cacheindex::{self, IndexState, Record};
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::root::VolumeName;
use granary_core::rootstore::is_reserved_seq;
use granary_core::support::BundleCache;
use granary_net::pin::{PIN_LEN, SpkiPin};
use granary_store::bounds::{META_MAX_BYTES, ROOT_MAX_BYTES};

use crate::fsguard;

/// Not part of the curated crate surface (unlike `store::MARKER_NAME`)
/// — nothing outside this module needs the marker's file name today.
pub(crate) const MARKER_NAME: &str = "granary-cache";

/// Persistent cache-marker format version exported for support metadata.
pub const CACHE_MARKER_VERSION: u32 = marker::CACHE_VERSION;

/// Watermark floor (mountpoint-s3's ongoing-5% precedent, floored).
const WATERMARK_MIN_BYTES: u64 = 1024 * 1024 * 1024;
/// Watermark percentage of filesystem capacity; `/ 20` below rather
/// than `* 5 / 100` — the same rational number, computed without ever
/// multiplying a filesystem-capacity-scale `u64` first.
const WATERMARK_PERCENT_DIVISOR: u64 = 20;

/// Journal writes are group-committed: buffered up to this many bytes,
/// or flushed unconditionally at `close`.
const JOURNAL_GROUP_FLUSH_BYTES: usize = 4 * 1024;
/// Compaction thresholds (either one fires it).
const JOURNAL_COMPACT_BYTES: u64 = 4 * 1024 * 1024;
/// `pub(crate)`, not private like its byte-threshold sibling above:
/// `mount.rs`'s own test module needs it to build a raw, already-over-threshold
/// journal fixture, the same way this
/// module's own `seed_cache_over_the_compaction_threshold` fixture does.
pub(crate) const JOURNAL_COMPACT_RECORDS: u64 = 65_536;

/// Bound on `journal_buf` itself (16× [`JOURNAL_GROUP_FLUSH_BYTES`]) —
/// under a SUSTAINED free-space refusal, every flush attempt keeps
/// failing while touches/inserts/evicts keep appending, so the buffer
/// would otherwise grow without bound: a control added for one
/// denial-of-service (the watermark refusing writes it cannot afford)
/// creating another
/// (unbounded process memory). Past this cap the buffer is dropped, not
/// grown further — see `flush_journal_buffer`'s refusal branch.
const JOURNAL_BUF_MAX_BYTES: usize = 16 * JOURNAL_GROUP_FLUSH_BYTES;

/// Bound on how many bytes `load_index` will read from EITHER
/// `index/snapshot` or `index/journal` before treating the file
/// as untrustworthy — both are attacker-writable disk, and a bare
/// `fs::read` otherwise allocates proportionally to whatever is
/// there (the exact class of read-path memory-exhaustion defect
/// this repo shipped once, on the wire rather than on disk).
/// Headroom, not a tight fit: at the ~400,000-entry cache-scale
/// estimate a maximal snapshot is ~14.4 MiB (400,000 ×
/// `cacheindex`'s 36-byte wire stride per entry), so 64 MiB is >= 4×
/// that; it is also >= 16× `JOURNAL_COMPACT_BYTES` (4 MiB) — a
/// LEGITIMATE journal exceeds that threshold only across repeated
/// refused compactions (a sustained free-space watermark refusal), and
/// 64 MiB of headroom comfortably covers that accumulation. Over the
/// cap is the SAME foreign/tampered trust class as a failed decode —
/// never read, walked instead.
const INDEX_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Max entries the cold rebuild walk will ADOPT, sized so the
/// rewritten snapshot itself never exceeds [`INDEX_FILE_MAX_BYTES`] — a
/// walk that adopted more would write a snapshot the NEXT open's own
/// bounded read refuses, walking again every time, forever (a
/// self-wedge). Mirrors `cacheindex`'s own (private, format-internal)
/// snapshot-body layout — count field (`SNAPSHOT_COUNT_FIELD_LEN`, a
/// `u64` BE) plus one `SNAPSHOT_ENTRY_LEN`-byte entry per grain
/// (32-byte digest + 4-byte size) — restated here rather than
/// re-exported, tied to the format by `cacheindex`'s own doc comment
/// (magic/version/kind + count + entries), not duplicated blindly.
const SNAPSHOT_COUNT_FIELD_LEN: u64 = 8;
const SNAPSHOT_ENTRY_LEN: u64 = DIGEST_LEN as u64 + 4;

/// The walk is already best-effort/lossy (cold order, foreign-file
/// skipping) — a bounded adoption is consistent with that, not a new
/// compromise. Past the cap, admitted entries stop being adopted
/// (warned with the dropped count) and their files stay on
/// disk, hash-verifiable by path and servable to any reader that asks
/// for one by digest.
///
/// **They are NOT re-indexed by ordinary reads.** A `get` for an
/// unindexed-but-HEALTHY object hits
/// and returns the bytes, but its recency touch goes through
/// `WriterState::touch_id`, which is a no-op for an id the index does
/// not track, and `WriterState::insert` returns early because the
/// destination file already exists. So the object stays outside quota
/// and LRU accounting until a cold rebuild. (A CORRUPT or OVERSIZED
/// one is different and does self-heal: `Cache::get` unlinks it and
/// the next fetch inserts it fresh.) `gran verify` REPORTS such an
/// object as `adopted` but does not index it either — it ships
/// diagnostic-only: it reports, and repairs nothing.
pub(crate) fn walk_adoption_cap() -> usize {
    let usable = INDEX_FILE_MAX_BYTES
        .saturating_sub((cacheindex::ENVELOPE_LEN as u64).saturating_add(SNAPSHOT_COUNT_FIELD_LEN));
    usize::try_from(usable / SNAPSHOT_ENTRY_LEN).unwrap_or(usize::MAX)
}

/// Bound on the marker file read — a real marker is ~200 bytes; 64 KiB
/// is generous headroom. The marker read is bounded like every other
/// read in this module (index files, objects and roots all bound their
/// reads the same way).
const MARKER_MAX_BYTES: u64 = 64 * 1024;

/// Bound on the `anchors/<volume>` read — a real anchor
/// file is well under 600 bytes (two lines, the longer one holding a
/// 512-byte token); 4 KiB is headroom, not a tight fit. Same
/// take()-bounded discipline as [`Cache::get_root_bytes`]: over the cap
/// is refused as absent before any content is trusted, never an
/// unbounded read of attacker-writable disk.
pub(crate) const ANCHOR_FILE_MAX_BYTES: u64 = 4096;

/// What binds a cache directory to the server it was populated from.
/// `pin_set_digest` is BLAKE3 over the canonicalized (sorted, deduplicated) pin set;
/// `root_key_id` is `Some` iff `--root-key` was supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheOrigin {
    pub endpoint_url: String,
    pub pin_set_digest: [u8; 32],
    pub root_key_id: Option<[u8; 32]>,
}

impl CacheOrigin {
    /// The pin-set half of a CLI-composed origin —
    /// `GrainId::of` (BLAKE3, no domain separation of its own) over a
    /// DOMAIN-SEPARATED preimage, so this digest can never collide with
    /// one built for a different purpose from the same bytes. Mirrors
    /// `publish.rs`'s `writer_uuid` precedent rather than pulling in a
    /// dependency for a digest this crate can already compute.
    ///
    /// **Order-independence and dedup are the CANONICALIZATION's job, not
    /// the hash's**: `pins` is sorted and deduplicated before the
    /// preimage is built, so two invocations naming the same pins in a
    /// different order, or with one repeated, digest identically.
    /// Preimage: `b"granary-cache-origin-pins-v1"`
    /// ++ the canonicalized count (`u64` BE) ++ each pin's 32 bytes, in
    /// sorted order.
    #[must_use]
    pub fn pin_set_digest(pins: &[SpkiPin]) -> [u8; 32] {
        let mut sorted: Vec<SpkiPin> = pins.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut seed = Vec::with_capacity(28 + 8 + sorted.len() * PIN_LEN);
        seed.extend_from_slice(b"granary-cache-origin-pins-v1");
        seed.extend_from_slice(&(sorted.len() as u64).to_be_bytes());
        for pin in &sorted {
            seed.extend_from_slice(pin);
        }
        *GrainId::of(&seed).digest()
    }

    /// The root-key half — `GrainId::of` over a
    /// DOMAIN-SEPARATED preimage of the 32 raw public-key bytes. The
    /// caller supplies `public` directly from the key it holds
    /// (`SigningKey::public_key()` on the publish side, the parsed
    /// `--root-key` on the read side) — never re-read from a sidecar file
    /// and never the SAME digest a pin set of the same bytes
    /// would produce (a distinct leading separator).
    #[must_use]
    pub fn root_key_digest(public: &[u8; 32]) -> [u8; 32] {
        let mut seed = Vec::with_capacity(32 + 32);
        seed.extend_from_slice(b"granary-cache-origin-rootkey-v1");
        seed.extend_from_slice(public);
        *GrainId::of(&seed).digest()
    }
}

/// Cache failure. Every mutating cache operation past `open` is
/// infallible by design (a cache is best-effort: a failed insert never
/// fails the caller's read) — this type is reachable only from `open`,
/// `close` and the roots API.
#[derive(Debug)]
pub enum CacheError {
    Io {
        context: String,
        source: io::Error,
    },
    /// The marker's tuple or origin line disagrees with this build/this
    /// invocation's `CacheOrigin` — a mismatch on ANY line, in either
    /// writer or read-only-degraded mode.
    Incompatible {
        detail: String,
    },
}

/// The per-volume freshness floor plus the persisted head hint the
/// head-discovery poll consults before any wire call — the parsed contents of
/// `anchors/<volume>`. Read and raised through [`Cache::read_anchor`] and
/// [`Cache::raise_anchor`] only.
///
/// **Not the root-signing trust anchor.** That is the key a
/// [`crate::resolve::RootVerifier`] holds — an unrelated sense of the
/// same English word. `head.rs`'s
/// module docs restate the distinction where the two senses are closest
/// together (the discovery flow uses both in the same few lines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadAnchor {
    /// The highest seq this cache dir has ever observed for the volume
    /// through a SUCCESSFUL VERIFIED resolve. A discovery candidate
    /// below this is a rollback, refused as `ResolveError::StaleHead`
    /// — see [`Cache::raise_anchor`] for the one write site and why it
    /// can only ever raise this value.
    pub seq: u64,
    /// The last hint the head-discovery poll persisted — absent until the first
    /// wire confirmation lands, and never touched by a candidate that
    /// only ever cleared the fresh-hint shortcut without a wire call.
    pub hint: Option<PersistedHint>,
}

/// The `hint` half of [`HeadAnchor`] — one wire confirmation the
/// head-discovery poll can revalidate cheaply next time, or trust outright while it
/// stays inside the jittered TTL (`head.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedHint {
    /// The discovery's accepted head at the moment this was written —
    /// equal to the just-raised floor by construction (`head.rs`'s
    /// module docs): never an unverified wire value on its own.
    pub seq: u64,
    /// The store's own hint `ETag`, echoed verbatim — never derived,
    /// never compared to anything but a token the store gave back
    /// (mirrors [`granary_core::rootstore::HintToken`]'s own rule).
    pub token: String,
    /// Unix seconds at the last WIRE confirmation (a 304 or a 200) —
    /// never advanced by a no-wire fresh-path resolve.
    pub stamp_secs: i64,
}

/// What [`Cache::raise_anchor`] should do to the persisted hint line:
/// leave it exactly as stored, or replace it outright. Never a partial
/// merge — the caller owns the whole new value, because the two halves
/// of a hint (seq, token) only ever change together (a `NotModified`
/// keeps both and only advances the stamp; a `Current` replaces both).
#[derive(Debug, Clone)]
pub enum HintUpdate {
    /// No wire confirmation happened this call — leave the persisted
    /// hint (if any) exactly as it was.
    Unchanged,
    /// A wire confirmation happened — replace the persisted hint with
    /// this value outright.
    Replace(PersistedHint),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::Incompatible { detail } => write!(f, "incompatible cache: {detail}"),
        }
    }
}

impl std::error::Error for CacheError {}

impl CacheError {
    /// The closed class this error reports under, derived from the error itself.
    pub(crate) fn failure_class(&self) -> crate::FailureClass {
        match self {
            Self::Io { .. } => crate::FailureClass::Io,
            Self::Incompatible { .. } => crate::FailureClass::Refused,
        }
    }
}

mod paths;
use paths::{
    anchor_path, create_structural_dir, io_err, mount_anchor_path, refuse_foreign_object_fanout,
    refuse_symlinked_structural_dir, root_bytes_path, unlink_object_leaf,
};
pub(crate) use paths::{decode_hex_digest, is_lower_hex, object_path};

mod space;
#[cfg(test)]
use space::watermark_bytes;
pub use space::{FreeSpace, FreeSpaceInfo};
use space::{SystemFreeSpace, free_space_precheck};

mod write;
use write::{StagedWrite, atomic_write, fsync_directory, fsync_file};

mod marker;
pub(crate) use marker::probe_cache_marker;
use marker::{
    check_marker, check_marker_for_verify, marker_contents, sweep_orphaned_txn_files,
    validate_origin_grammar,
};

mod anchor;
#[cfg(test)]
use anchor::{
    ANCHOR_SEQ_WIDTH, ANCHOR_TOKEN_MAX_BYTE, ANCHOR_TOKEN_MAX_LEN, ANCHOR_TOKEN_MIN_BYTE,
    PATH_READ_POST_STAT_HOOKS, PathReadPostStatHook, run_path_read_post_stat_hook,
};
pub(crate) use anchor::{parse_anchor_bytes, render_anchor_bytes};
use anchor::{persistable_anchor_hint, read_and_parse_anchor, read_and_parse_mount_anchor};

mod index_load;
use index_load::{
    JournalOpenPlan, empty_journal_bytes, encode_snapshot_err, load_index, load_index_read_only,
};
// These three have no production caller left in the parent — their only
// consumers are its own test rows, reaching them through `use super::*`.
#[cfg(test)]
use index_load::{IndexFileRead, cold_rebuild_walk_capped, read_index_file_bounded};

/// Every live id's recency `seq` and size — see [`WriterState::live`].
type LiveMap = BTreeMap<GrainId, (u64, u32)>;
/// The inverse of [`LiveMap`]'s recency half — see
/// [`WriterState::by_seq`].
type BySeqMap = BTreeMap<u64, GrainId>;

/// The writer's mutable session state: the exclusive lock, the live
/// index, the journal's open handle and buffer, and the free-space
/// seam. Boxed inside [`Mode::Writer`] so [`Mode::ReadOnlyDegraded`]
/// (zero-sized) does not size the enum to the writer's full state.
///
/// **The live index is TWO maps, not the `Vec<(GrainId, u32)>`
/// `cacheindex::IndexState` uses at the load/save boundary** —
/// `live`/`by_seq` mirror `cacheindex::fold`'s own `BTreeMap`
/// shape rather than a linear scan: a `Vec`-backed touch/evict
/// was measured at 601 µs per touch at 100,000 entries (debug
/// build), contrary to the cache's goal of keeping the read path cheap.
/// `IndexState` stays the seed/save FORMAT (what `load_index`,
/// `cold_rebuild_walk` and `compact` exchange with `cacheindex`); these
/// two maps are the per-session RUNTIME representation only.
#[cfg_attr(
    test,
    expect(
        clippy::struct_excessive_bools,
        reason = "only 2 plain bools (journal_broken, journal_broken_warned) exist in a real \
                  build; the other 2 that push this over the pedantic threshold of 3 \
                  (compact_snapshot_write_fail, journal_reopen_fail) are #[cfg(test)] \
                  deterministic-fault seams, matching journal_write_fail_after's own idiom — a \
                  state machine here would be test-only ceremony around production fields that \
                  do not vary together"
    )
)]
struct WriterState {
    _lock: File,
    /// The SAME path `Cache::root` holds for the `Cache` this state
    /// belongs to — set once, in `build_writer_state`, from that exact
    /// function's own `root: &Path` parameter (`Cache::open_with_free_space`'s
    /// `root.to_owned()`, one call site, one path). It cannot diverge by
    /// coincidence: `build_writer_state` is the ONLY place a `WriterState`
    /// is constructed, nothing ever rebinds this field afterward, and a
    /// `WriterState` never moves to a different `Cache`. It exists so
    /// `append_journal_record` — a `WriterState` method that has no
    /// `root` parameter of its own — can trigger `maybe_compact` from
    /// every tracked touch/evict/insert, not only from `Cache::close`,
    /// which is the one caller that already threads `root` down as an
    /// argument.
    root: PathBuf,
    quota_bytes: u64,
    free_space: Box<dyn FreeSpace>,
    /// Every live id's recency `seq` and size. INVARIANT: bijects with
    /// `by_seq` — every key here has exactly one entry in `by_seq`
    /// (its `seq`, pointing back to this same id), and vice versa;
    /// checked in debug builds by `debug_assert_index_invariant`.
    live: LiveMap,
    /// The inverse of `live`'s recency half: `seq -> id`, so the
    /// least-recently-used id is `by_seq`'s FIRST entry — O(log n) to
    /// find, versus the `Vec`'s O(n) `entries.first()` this replaced.
    by_seq: BySeqMap,
    /// Next recency value to hand out; strictly increasing, never
    /// reused (mirrors `cacheindex::fold`'s own counter).
    next_seq: u64,
    /// Sum of `live`'s sizes — maintained incrementally, never derived
    /// by summing `live` (that would be the O(n) cost this restructure
    /// exists to remove).
    total_bytes: u64,
    journal_file: File,
    /// Current on-disk journal file length (envelope + body), updated
    /// only when `journal_buf` is actually flushed.
    journal_len: u64,
    /// Bytes not yet flushed to `journal_file`, bounded by
    /// [`JOURNAL_BUF_MAX_BYTES`] under sustained refusal.
    journal_buf: Vec<u8>,
    /// Records currently sitting in `journal_buf` — tracked separately
    /// from `journal_total_records` so a buffer DROP (the
    /// `JOURNAL_BUF_MAX_BYTES` cap) can subtract exactly the dropped
    /// records from that total, not just clear the byte buffer.
    journal_buf_records: u64,
    /// Records currently represented on disk plus buffered — the
    /// compaction-threshold count (records, not bytes).
    journal_total_records: u64,
    /// The LATCH on `compact`
    /// leaving without having compacted. `None` until the first such
    /// exit; thereafter `Some(journal_len)` for the `journal_len`
    /// that was current AT that exit. `maybe_compact_throttled` skips
    /// calling `compact` again while this still matches the CURRENT
    /// `journal_len` — the field changes only when a flush actually
    /// reaches disk (`flush_journal_buffer`'s success path, or
    /// `compact`'s own success path), which is precisely the one
    /// event that could have changed the free-space situation,
    /// because this process just wrote. That bounds the retries to
    /// exactly one attempt per flush, without a clock and without a
    /// separate counter. Without the latch, every tracked
    /// touch/evict/insert under a sustained refusal would re-run the
    /// WHOLE `compact` body (a full snapshot encode plus two free-space
    /// queries, and — past the first precheck — a stage, write, fsync
    /// and rename too), turning ordinary cache HITS into unbounded
    /// O(live) work per hit: the compaction that bounds journal growth
    /// would itself become an unbounded cost.
    ///
    /// **Set on EVERY way `compact` leaves without having
    /// compacted, not only the two free-space refusals.** A genuine
    /// `Err` return (`EDQUOT`, `EROFS`, `EACCES` on `index/`, a failed
    /// journal reopen, anything `statfs` does not predict) latches
    /// exactly as a refusal does. A latch set only on the refusal
    /// paths would leave every tracked touch/evict/insert after an
    /// `Err` re-running the whole `compact` body — the exact unbounded
    /// per-hit cost this latch exists to bound, reached through the
    /// error door instead of the refusal door. The name says "stalled",
    /// not "refused", because the field records EVERY way `compact`
    /// can leave without having compacted —
    /// see `maybe_compact`'s own doc for where that is decided, in
    /// exactly one place: its match over `compact`'s three outcomes,
    /// two of which latch.
    ///
    /// This latch bounds a HOT-PATH retry
    /// storm and nothing else. The unlatched `maybe_compact`
    /// (`Cache::maintain`/`Cache::close`) ignores this field outright —
    /// an explicit caller is information the latch cannot have, so it
    /// must never be gagged by an outcome decided before the caller
    /// asked; it still overwrites the field with whatever ITS OWN attempt
    /// decides, exactly like every other call through `maybe_compact`.
    compaction_stalled_at: Option<u64>,
    /// A ONE-WAY state. `compact`'s
    /// post-truncate journal reopen (`fsguard::open_regular_append`) can
    /// fail after the fresh empty envelope has already been renamed over
    /// `index/journal` — `journal_file` then still points at the OLD,
    /// now-unlinked inode, and every further write through it would
    /// vanish silently into a hole nobody will ever read. Once this is
    /// `true`, `append_journal_record` and `flush_journal_buffer` both
    /// refuse to write into that hole (see their own docs), and
    /// `Cache::close` reports it as an `Err` rather than staying silent.
    /// Nothing in this module ever resets it back to `false` — even if a
    /// LATER explicit `compact` retry happens to reopen successfully,
    /// this crate does not try to be clever about that; the records
    /// already dropped during the broken window stayed dropped, and
    /// `Cache::close`'s report is what tells the operator the on-disk
    /// journal for this session cannot be trusted, full stop. The
    /// in-memory index (`live`/`by_seq`) and the objects on disk both
    /// stay correct regardless — this is the same documented crash
    /// window this cache already accepts, now detected and reported
    /// instead of discovered only at the next open.
    journal_broken: bool,
    /// Paired with `journal_broken`: `append_journal_record` warns
    /// exactly ONCE when it first finds the journal broken, not once per
    /// subsequent record — this is what makes that true regardless of
    /// how many more tracked touch/evict/insert calls arrive before the
    /// session ends.
    journal_broken_warned: bool,
    /// Test-only deterministic partial-write fault: write this many
    /// bytes of the next journal flush, then return an I/O error.
    #[cfg(test)]
    journal_write_fail_after: Option<usize>,
    /// Test-only deterministic fault, same style as `journal_write_fail_after`:
    /// force `compact`'s SNAPSHOT `atomic_write` to fail — a genuine `Err` that
    /// is neither of the two free-space refusals NOR the reopen failure
    /// `journal_broken` latches onto, so a test can probe the
    /// non-success latch (`compaction_stalled_at`) in isolation from
    /// the separate `journal_broken` gate.
    #[cfg(test)]
    compact_snapshot_write_fail: bool,
    /// Test-only deterministic fault, same style as
    /// `journal_write_fail_after`: force `compact`'s post-truncate
    /// journal reopen (`fsguard::open_regular_append`) to fail — the
    /// trigger for `journal_broken`, with no real
    /// filesystem condition needed to reach it deterministically.
    #[cfg(test)]
    journal_reopen_fail: bool,
    txn_counter: AtomicU64,
    /// Directory-read counter on the cold-rebuild-walk path, test-
    /// visible via direct field access from this module's own `tests`
    /// submodule (no accessor needed: a child module sees a parent
    /// module's private fields). Never read by production code — its
    /// whole purpose is the no-rescan TDD row's assertion.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read only by this module's own #[cfg(test)] mod tests via direct field \
                      access, never by production code — the field itself is written \
                      unconditionally so counting stays accurate whether or not a test ever \
                      reads it"
        )
    )]
    walk_reads: AtomicU64,
    /// How many times `raise_anchor` has actually renamed a new
    /// `anchors/<volume>` file into place this session — test-visible
    /// via `Cache::anchor_write_count` (a `#[cfg(test)]` accessor,
    /// invisible to a non-test rustdoc build — plain text, not an
    /// intra-doc link, or `cargo doc` without `--cfg test` cannot
    /// resolve it). A no-write-when-unchanged
    /// guard needs a positive control: a test that only inspects the
    /// file's bytes cannot tell "skipped" from "wrote the identical
    /// bytes again". Written unconditionally by `raise_anchor` itself
    /// (production code), so no `dead_code` exception is needed here —
    /// unlike `walk_reads` above, this field IS accessed outside tests.
    anchor_writes: AtomicU64,
    /// The same counter for `anchors/<volume>.mount`, and it is separate
    /// on purpose: `anchor_writes` is documented as counting
    /// `raise_anchor`'s renames of the SHARED file, and existing tests
    /// assert over it. `raise_mount_anchor` carries its own
    /// no-write-when-unchanged skip, which needs its own positive control
    /// for the reason the field above states — bytes on disk cannot tell
    /// "skipped" from "wrote the identical bytes again".
    mount_anchor_writes: AtomicU64,
    /// Successful destination-directory fsyncs following anchor
    /// replacement, observable only by this module's tests.
    #[cfg(test)]
    anchor_directory_fsyncs: AtomicU64,
    /// How many times `compact`'s body
    /// has actually run this session (entered, whether it went on to
    /// succeed or was refused) — never how many `free_space` queries
    /// happened, which conflates `compact`'s two prechecks with the
    /// unrelated ones every ordinary write already makes. Test-visible
    /// via direct field access from this module's own `tests`
    /// submodule, matching `walk_reads`/`anchor_writes`' own idiom.
    #[cfg(test)]
    compaction_attempts: AtomicU64,
    /// How many times [`Cache::maintain`]
    /// has actually reached `Mode::Writer` this session — distinct from
    /// `compaction_attempts` (which counts `compact` entries from ANY
    /// caller, including `append_journal_record`'s own inline trigger) so
    /// a test can pin `MountSession::open`'s wiring specifically, not
    /// merely observe an on-disk effect inline compaction could
    /// have produced on its own.
    #[cfg(test)]
    maintain_calls: AtomicU64,
}

/// What [`WriterState::compact`]'s fallible core actually did — the
/// result used for latching every
/// non-success exit in exactly one place ([`WriterState::maybe_compact`]'s
/// match on this). `compact` itself never sets or clears the latch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompactOutcome {
    /// The snapshot and journal were both rewritten and the journal
    /// reopened for append — a genuinely fresh, empty journal.
    Compacted,
    /// A free-space precheck declined; nothing on disk changed.
    Refused,
}

impl WriterState {
    fn write_journal_buffer(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if let Some(prefix_len) = self.journal_write_fail_after.take() {
            let prefix = self.journal_buf.get(..prefix_len).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "journal partial-write fault exceeds the buffered length",
                )
            })?;
            self.journal_file.write_all(prefix)?;
            return Err(io::Error::other("simulated partial journal write"));
        }
        self.journal_file.write_all(&self.journal_buf)
    }

    /// Seed `live`/`by_seq` from a loaded [`IndexState`] — `entries` is
    /// least → most recent, so `seq` assigned in that same order
    /// (0..n) preserves it exactly.
    fn seed_index(loaded: IndexState) -> (LiveMap, BySeqMap, u64) {
        let mut live = BTreeMap::new();
        let mut by_seq = BTreeMap::new();
        let mut next_seq: u64 = 0;
        for (id, size) in loaded.entries {
            live.insert(id, (next_seq, size));
            by_seq.insert(next_seq, id);
            next_seq = next_seq.saturating_add(1);
        }
        (live, by_seq, next_seq)
    }

    /// `live` and `by_seq` must biject: every live id has exactly one
    /// `seq`, and every `seq` names exactly one live id. A broken
    /// invariant here would silently corrupt LRU order or double-count
    /// `total_bytes` — cheap to check, checked after every mutation.
    fn debug_assert_index_invariant(&self) {
        debug_assert_eq!(
            self.live.len(),
            self.by_seq.len(),
            "live/by_seq bijection broken"
        );
    }

    /// Least-recently-used order (the same shape `IndexState.entries`
    /// had) — introspection only; the hot paths (touch/evict/insert)
    /// operate on `live`/`by_seq` directly at O(log n) and never
    /// materialize this `Vec`.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read only by this module's own #[cfg(test)] mod tests — production code \
                      never needs the whole ordered Vec, only the O(log n) first/lookup \
                      operations live/by_seq already provide directly"
        )
    )]
    fn entries_lru(&self) -> Vec<(GrainId, u32)> {
        self.by_seq
            .values()
            .filter_map(|id| self.live.get(id).map(|&(_, size)| (*id, size)))
            .collect()
    }

    fn touch_id(&mut self, id: &GrainId) {
        // An id the index does not track (the single-object crash
        // window's unindexed object, or one never inserted this
        // session) is a valid no-op — touching what is not tracked for
        // eviction has no effect to record.
        let Some(&(old_seq, size)) = self.live.get(id) else {
            return;
        };
        self.by_seq.remove(&old_seq);
        let new_seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.by_seq.insert(new_seq, *id);
        self.live.insert(*id, (new_seq, size));
        self.debug_assert_index_invariant();
        self.append_journal_record(&Record::Touch { id: *id });
    }

    /// Drop an id from the live index and refund its bytes. The index
    /// entry and the charge always go together: `total_bytes` is the
    /// sum of `live`'s sizes, and an entry removed without its refund
    /// makes that untrue.
    ///
    /// Both callers — `get`'s hash-mismatch path and `evict_oversized`
    /// — reach here having already proven the object unusable, and the
    /// unlink they attempted first may have failed. When it did, the
    /// file stays on disk as a RESIDUE that no index entry names, and
    /// `gran verify`'s independent on-disk scan is what reports it: as
    /// `corrupt`/`oversized` when the file's own content fails
    /// verification — which is why it was evicted here — as `adopted`
    /// when the content verifies and verify can enumerate the fanout
    /// while holding the index, and not at all under a fanout verify
    /// cannot enumerate, where it reports that FANOUT as `foreign` and
    /// names nothing beneath it. Until a cold rebuild re-adopts the file
    /// or an operator removes it, this cache's accounting under-counts
    /// by its size. That is the same trade `evict_to_fit` makes, for the
    /// same reason — nothing here can retry the unlink, and an entry
    /// pointing at unusable bytes is worse than none.
    fn evict_id(&mut self, id: &GrainId) {
        if let Some((seq, size)) = self.live.remove(id) {
            self.by_seq.remove(&seq);
            self.total_bytes = self.total_bytes.saturating_sub(u64::from(size));
        }
        self.debug_assert_index_invariant();
        self.append_journal_record(&Record::Evict { id: *id });
    }

    /// The trigger for mid-session compaction: a mount runs for days and
    /// never calls `Cache::close` until it exits, so a cadence counted
    /// only at `close` (or only at inserts) leaves a fully-warm, read-only
    /// mount's journal growing without bound — every cache HIT reaches
    /// here through `touch_id`. Calling `maybe_compact_throttled`
    /// unconditionally on every record is cheap in the common case: it is
    /// one two-integer comparison against thresholds this function's
    /// caller already pays to maintain, and it returns immediately below
    /// them. This is the AUTOMATIC, hot-path trigger — a background
    /// best-effort attempt — so it goes through the THROTTLED form, not
    /// the unlatched [`WriterState::maybe_compact`] that `Cache::maintain`
    /// and `Cache::close` use: those are a caller explicitly saying "try
    /// now", which this inline trigger never is. Nothing is ALLOCATED on
    /// the common path: the throttled form takes no `root` and clones
    /// `self.root` only once it is committed to compacting, which is what
    /// makes the "one two-integer comparison" above true.
    /// **Refuses outright
    /// once `journal_broken` is set.** A prior `compact` reopen
    /// failure left `journal_file` pointing at an orphaned,
    /// unlinked inode — encoding and buffering this record would
    /// only grow a buffer that can never reach a real file, and
    /// the throttled compaction attempt below would only fail
    /// the same way again. One typed warning fires the FIRST
    /// time this is seen (`journal_broken_warned` guards it),
    /// never once per record — see that field's own doc.
    fn append_journal_record(&mut self, record: &Record) {
        if self.journal_broken {
            if !self.journal_broken_warned {
                self.journal_broken_warned = true;
                crate::observe::OperatorDiagnostic::cache_journal_is_broken_after_a_failed_reopen_mid().emit();
            }
            return;
        }
        cacheindex::encode_record_into(&mut self.journal_buf, record);
        self.journal_total_records = self.journal_total_records.saturating_add(1);
        self.journal_buf_records = self.journal_buf_records.saturating_add(1);
        if self.journal_buf.len() >= JOURNAL_GROUP_FLUSH_BYTES
            && let Err(e) = self.flush_journal_buffer()
        {
            crate::observe::OperatorDiagnostic::cache_journal_flush_failed_records_stay_buffered(
                e.failure_class(),
            )
            .emit();
        }
        if let Err(e) = self.maybe_compact_throttled() {
            crate::observe::OperatorDiagnostic::cache_compaction_failed_journal_left_uncompacted(
                e.failure_class(),
            )
            .emit();
        }
    }

    /// Flush buffered journal bytes, behind the same free-space
    /// precheck every write under the cache root takes. A REFUSAL
    /// (not enough room) keeps the records buffered and only
    /// typed debug events — the object files are the durability root;
    /// the index diverges until a cold rebuild (`gran verify` REPORTS the
    /// divergence and repairs nothing) — UNLESS the
    /// buffer has grown past [`JOURNAL_BUF_MAX_BYTES`] (a SUSTAINED
    /// refusal), in which case it is dropped outright with one
    /// a typed warning: semantically identical to the documented
    /// single-object crash window — the in-memory index (`live`/
    /// `by_seq`) is untouched and stays correct, the object files remain
    /// the durability root, and a cold rebuild recovers whatever the
    /// dropped records would have journaled (`gran verify` REPORTS the
    /// divergence but repairs nothing).
    /// Returns `Err`
    /// only for a genuine I/O failure writing or fsyncing.
    ///
    /// **Refuses rather than writing
    /// into the orphan.** Once `journal_broken` is set, `journal_file`
    /// points at an unlinked inode a prior `compact` reopen failure left
    /// behind — writing into it would succeed at the syscall level and
    /// vanish, which is worse than leaving the bytes buffered (still
    /// visible in `journal_buf`, at least). `append_journal_record`'s
    /// own early return already covers the hot path and warns once; this
    /// guard is what keeps `Cache::maintain`/`Cache::close`'s own direct
    /// calls from writing into the hole too, silently.
    fn flush_journal_buffer(&mut self) -> Result<(), CacheError> {
        if self.journal_broken {
            return Ok(());
        }
        if self.journal_buf.is_empty() {
            return Ok(());
        }
        let len = self.journal_buf.len() as u64; // usize -> u64: always widening on real targets
        if !free_space_precheck(self.free_space.as_ref(), len) {
            if self.journal_buf.len() > JOURNAL_BUF_MAX_BYTES {
                let dropped_records = self.journal_buf_records;
                let dropped_bytes = self.journal_buf.len();
                self.journal_total_records =
                    self.journal_total_records.saturating_sub(dropped_records);
                self.journal_buf.clear();
                self.journal_buf_records = 0;
                crate::observe::OperatorDiagnostic::cache_journal_buffer_exceeded_its_cap_under_sustained_free(dropped_records, dropped_bytes as u64).emit();
                return Ok(());
            }
            crate::observe::OperatorDiagnostic::cache_journal_flush_refused_by_the_free_space_watermark().emit();
            return Ok(());
        }
        if let Err(write_error) = self.write_journal_buffer() {
            self.journal_file
                .set_len(self.journal_len)
                .map_err(|e| CacheError::Io {
                    context: format!(
                        "roll back partial journal write after append failed: {write_error}"
                    ),
                    source: e,
                })?;
            fsync_file(&self.journal_file).map_err(|e| CacheError::Io {
                context: format!("fsync rolled-back journal after append failed: {write_error}"),
                source: e,
            })?;
            return Err(io_err("append journal")(write_error));
        }
        fsync_file(&self.journal_file).map_err(io_err("fsync journal"))?;
        self.journal_len = self.journal_len.saturating_add(len);
        self.journal_buf.clear();
        self.journal_buf_records = 0;
        Ok(())
    }

    /// Whether either compaction threshold has been crossed. ONE
    /// predicate, because both entry points below ask the same question
    /// and a second copy would be free to drift from this one.
    fn compaction_thresholds_crossed(&self) -> bool {
        self.journal_len > JOURNAL_COMPACT_BYTES
            || self.journal_total_records > JOURNAL_COMPACT_RECORDS
    }

    /// The EXPLICIT-call form, for `Cache::maintain`/`Cache::close`: a
    /// caller is saying "try now", which is information the latch cannot
    /// have — the world may have changed (another process freed disk
    /// space, or whatever caused a genuine `Err` may have cleared) since
    /// whatever this latch last recorded, and a cache that served nothing
    /// in between never advances `journal_len` on its own to invalidate a
    /// stale entry. So this form ignores the latch outright on entry —
    /// the threshold check below is the only gate — and, having made its
    /// own attempt, unconditionally overwrites the latch with whatever
    /// THAT attempt decided, exactly the same way the throttled form's
    /// own attempts would.
    ///
    /// **The ONE place the latch is
    /// set, for every non-success exit.** `compact` itself never
    /// touches the latch at all: it reports what happened
    /// through [`CompactOutcome`], and this match is the only place that
    /// decides what the latch becomes — `Compacted` clears it, and both
    /// `Refused` and `Err` set it to the current `journal_len`. Because
    /// the match is exhaustive over `compact`'s only three possible
    /// outcomes, no future early return inside `compact` can leave
    /// without the latch being set here: it would have to return through
    /// one of these three arms, and two of them already latch.
    fn maybe_compact(&mut self, root: &Path) -> Result<(), CacheError> {
        if !self.compaction_thresholds_crossed() {
            return Ok(());
        }
        match self.compact(root) {
            Ok(CompactOutcome::Compacted) => {
                self.compaction_stalled_at = None;
                Ok(())
            }
            Ok(CompactOutcome::Refused) => {
                self.compaction_stalled_at = Some(self.journal_len);
                Ok(())
            }
            Err(e) => {
                self.compaction_stalled_at = Some(self.journal_len);
                Err(e)
            }
        }
    }

    /// The AUTOMATIC-trigger form, for `append_journal_record`'s hot
    /// path: a background best-effort attempt on every tracked
    /// touch/evict/insert, which must honour the latch — that is the
    /// whole point of the latch — because re-running the whole `compact`
    /// body for every later append while nothing on disk has changed
    /// cannot learn anything new; see `compaction_stalled_at`'s own doc.
    /// Delegates to the unlatched [`Self::maybe_compact`] once the latch
    /// itself says this attempt is worth making.
    fn maybe_compact_throttled(&mut self) -> Result<(), CacheError> {
        if self.compaction_stalled_at == Some(self.journal_len) {
            return Ok(());
        }
        // BOTH cheap checks before the `root` clone, not after it. This
        // runs on every journal record — every cache hit through
        // `touch_id`, every insert, every eviction — and the common case
        // must cost what this function's caller claims it costs: two
        // integer comparisons and a pointer comparison, no allocation.
        // `root` is cloned only once the call is committed to compacting,
        // because `compact` needs `&mut self` alongside it.
        if !self.compaction_thresholds_crossed() {
            return Ok(());
        }
        let root = self.root.clone();
        self.maybe_compact(&root)
    }

    /// Rewrite the snapshot (sorted canonically by id, since the snapshot
    /// format carries no recency), THEN empty the journal. This order is mandatory:
    /// the reverse order's crash window orphans a whole
    /// journal's worth of inserts at once, while THIS order's crash
    /// window merely re-replays an already-reflected journal, which is
    /// safe because replay is idempotent. Because the id-order snapshot
    /// carries no recency field, a reopen after this resets LRU to id
    /// order — an accepted limitation, not a bug: compaction does not
    /// preserve the session's LRU order across a reopen.
    ///
    /// **The fallible CORE only — never touches the latch.** The
    /// latch assignments all live in [`Self::maybe_compact`]'s
    /// own match, outside this function, so there is exactly one place
    /// that can forget to set `compaction_stalled_at`.
    /// This function's contract to its one caller is just: report which of
    /// the three things happened, via the `Result<CompactOutcome, _>`
    /// return — compacted, refused by free space, or a genuine `Err`.
    fn compact(&mut self, root: &Path) -> Result<CompactOutcome, CacheError> {
        #[cfg(test)]
        self.compaction_attempts.fetch_add(1, Ordering::Relaxed);
        // `live` is a `BTreeMap<GrainId, _>` — iterating it already
        // yields strictly-ascending id order, exactly what
        // `encode_snapshot` requires, so no sort is needed.
        let entries: Vec<(GrainId, u32)> = self
            .live
            .iter()
            .map(|(id, &(_, size))| (*id, size))
            .collect();
        let snapshot_bytes = cacheindex::encode_snapshot(&entries)
            .map_err(|e| encode_snapshot_err("encode snapshot during compaction", &e))?;

        let snapshot_path = root.join("index").join("snapshot");
        if !free_space_precheck(self.free_space.as_ref(), snapshot_bytes.len() as u64) {
            crate::observe::OperatorDiagnostic::cache_compaction_refused_by_the_free_space_watermark_snapshot().emit();
            return Ok(CompactOutcome::Refused);
        }
        #[cfg(test)]
        if self.compact_snapshot_write_fail {
            return Err(io_err(
                "simulated snapshot write failure (compaction test seam)",
            )(io::Error::other(
                "simulated snapshot write failure",
            )));
        }
        atomic_write(
            root,
            &snapshot_path,
            &snapshot_bytes,
            &self.txn_counter,
            0o644,
        )?;

        let empty_journal = empty_journal_bytes();
        let journal_path = root.join("index").join("journal");
        if !free_space_precheck(self.free_space.as_ref(), empty_journal.len() as u64) {
            crate::observe::OperatorDiagnostic::cache_compaction_refused_by_the_free_space_watermark_before().emit();
            return Ok(CompactOutcome::Refused);
        }
        atomic_write(
            root,
            &journal_path,
            &empty_journal,
            &self.txn_counter,
            0o644,
        )?;

        // The TWIN of the hardened append open, one function away.
        // Unguarded — not even `O_NOFOLLOW` — it would give the same
        // primitive: win the rename-then-reopen window with a symlink
        // and every subsequent journal record is written outside the
        // cache root. Hardening one open and not its twin leaves the
        // class open, so both go through the one helper.
        //
        // This reopen can fail with
        // the fresh envelope already renamed into place —
        // `journal_file` would then still name the OLD, now-unlinked
        // inode. `journal_broken` is a one-way state precisely for this
        // failure; see its own doc on why nothing here tries to recover
        // the old descriptor or re-rename, and why nothing clears it
        // even if a later retry happens to reopen successfully.
        #[cfg(test)]
        if self.journal_reopen_fail {
            self.journal_broken = true;
            return Err(io_err("reopen journal after compaction")(io::Error::other(
                "simulated journal reopen failure (compaction test seam)",
            )));
        }
        self.journal_file = match fsguard::open_regular_append(&journal_path) {
            Ok(f) => f,
            Err(e) => {
                self.journal_broken = true;
                return Err(io_err("reopen journal after compaction")(e));
            }
        };
        self.journal_len = cacheindex::ENVELOPE_LEN as u64; // usize -> u64: always widening on real targets
        self.journal_total_records = 0;
        self.journal_buf.clear();
        self.journal_buf_records = 0;
        Ok(CompactOutcome::Compacted)
    }

    /// Drop least-recently-used entries until `len` more bytes fit under
    /// the quota. `false` means the caller must DECLINE its insert:
    /// there is nothing left to evict and writing anyway would put the
    /// cache over quota.
    ///
    /// **Every iteration makes progress.** `by_seq`'s head is taken,
    /// its leaf unlink attempted, and then the entry is dropped from
    /// `live`/`by_seq`, its bytes refunded and its `Evict` record
    /// appended — on EVERY outcome. The outcome changes the log line
    /// and nothing else. Keeping an entry the unlink could not clear
    /// would decline not just this insert but every later one, because
    /// that same id is `by_seq`'s head again on the next call (and
    /// across restarts: the persisted index reloads it as the head).
    ///
    /// What a failed unlink leaves is the module's pre-existing,
    /// documented RESIDUE: a file on disk that no index entry names.
    /// `gran verify`'s independent on-disk scan reports it as
    /// `adopted` when it can enumerate the fanout and is holding the
    /// index, as `corrupt`/`oversized` when the file's own content
    /// fails verification, and not at all under a fanout verify cannot
    /// enumerate — there it reports that FANOUT as `foreign` and names
    /// nothing beneath it. Until a cold rebuild re-adopts the file or an
    /// operator removes it, this cache's accounting is an UNDER-count —
    /// it believes it has room the disk does not have. That is a disk
    /// cost; the alternative is a cache that stops caching.
    ///
    /// The loop terminates because every iteration removes one entry
    /// from `by_seq`, or returns, and `by_seq` is finite.
    fn evict_to_fit(&mut self, root: &Path, len: u64) -> bool {
        while self.total_bytes.saturating_add(len) > self.quota_bytes {
            let Some((lru_seq, lru_id)) = self.by_seq.first_key_value().map(|(&s, &i)| (s, i))
            else {
                crate::observe::OperatorDiagnostic::cache_eviction_found_nothing_left_to_evict_the_insert(self.total_bytes, self.quota_bytes).emit();
                return false;
            };
            let lru_path = object_path(root, &lru_id);
            // `lru_id` reaches here from an index loaded with no
            // filesystem revalidation at all, and `remove_file` follows
            // a symlinked INTERMEDIATE component, so the fanout is
            // classified non-followingly immediately before the unlink
            // (`unlink_object_leaf`, which carries its own `context` in
            // every warning it emits). Its outcomes differ only in what
            // is SAID about them, so nothing is branched on here: the
            // entry is dropped and its bytes refunded unconditionally
            // below, on every one of them.
            unlink_object_leaf(&lru_path, "cache eviction");
            self.by_seq.remove(&lru_seq);
            if let Some((_, lru_size)) = self.live.remove(&lru_id) {
                self.total_bytes = self.total_bytes.saturating_sub(u64::from(lru_size));
            }
            self.debug_assert_index_invariant();
            // The evict record follows the unlink, never precedes it. A crash between the
            // two leaves an index entry whose file is gone, which `get`
            // already treats as a clean miss.
            self.append_journal_record(&Record::Evict { id: lru_id });
        }
        true
    }

    // No `#[expect(disallowed_methods)]` on this fn. Its only bare call
    // is `fs::symlink_metadata`, the class's SAFE half (never banned —
    // see crates/granary-client/clippy.toml's header): an lstat of the
    // object leaf, run only after the fanout above it has been
    // classified non-followingly, so it describes an entry inside this
    // cache and nothing else. The one unlink this function can reach —
    // the LRU eviction's — goes through `unlink_object_leaf`, which is
    // licensed at its own definition and owns the fanout classification
    // it needs. There is no other deletion here: a foreign leaf is
    // replaced by the staged write's own rename, not erased first. The
    // LRU unlink is the one that matters: `lru_id` is NOT limited to an id this
    // insert call chain put there — `by_seq` can hold ids the
    // cold-rebuild walk ADOPTED from disk (they get the LOWEST seq, so
    // they are evicted first) and ids seeded from a persisted index,
    // which is loaded with no filesystem revalidation at all.
    //
    // WHAT THE QUOTA BOUNDS WHILE A STAGED WRITE IS OPEN. `quota_bytes`
    // bounds the INDEX, and the index gains an object only at its
    // rename. Between the staging below and that rename the DISK under
    // `<root>/` therefore holds up to quota plus that one object. The
    // bound on the excess is the object itself — one staged file per
    // call, removed on every path that declines — and the backstop is
    // the free-space watermark, which asks whether a watermark of room
    // REMAINS with those bytes already written. A crash inside the
    // window leaves the staged file behind as an unreferenced name
    // under `txn/`, which the next writer open's sweep clears if it can
    // unlink it and reports if it cannot (`sweep_orphaned_txn_files`
    // skips a name it cannot remove rather than failing the open), so an
    // unremovable residue can outlive any number of opens.
    //
    // AND WHAT THE ORDER COSTS. A write the watermark or the fanout
    // mkdir declines has by then paid a create, a write, an fsync and an
    // unlink, where a watermark check first would pay one `statfs` and
    // stop — on a filesystem persistently under the watermark, a
    // write-and-delete per cache MISS. It is bounded by the watermark itself: such a
    // cache admits nothing, so the cost is one object's I/O per attempt
    // and never accumulates on disk. That is the price of learning
    // whether this cache can write at all before spending what it
    // already holds.
    fn insert(&mut self, root: &Path, id: &GrainId, bytes: &[u8]) {
        let len = bytes.len() as u64; // usize -> u64: always widening on real targets
        let dest = object_path(root, id);
        // The fanout guard runs FIRST — before the leaf is classified or
        // touched at all. `symlink_metadata` does not follow its FINAL
        // component, but every path operation follows the INTERMEDIATE
        // ones, so a pre-planted `objects/<2hex>` link would otherwise
        // have this classify a name in someone else's tree. Non-creating
        // on purpose: the fanout is created further down, behind the
        // free-space watermark that every write under the cache root
        // takes (no small-write exemption — and a mkdir is a
        // write).
        let Some(fanout) = dest.parent() else {
            crate::observe::OperatorDiagnostic::cache_insert_the_object_path_has_no_fanout_parent()
                .emit();
            return;
        };
        if let Err(e) = refuse_foreign_object_fanout(fanout, "cache insert: stat object fanout") {
            crate::observe::OperatorDiagnostic::cache_insert_refused_the_object_fanout_is_not_a(
                e.failure_class(),
            )
            .emit();
            return;
        }
        // Put-if-absent's own decision point, and the only thing it
        // decides. It runs here, before the quota check, before
        // eviction and before the watermark, because a call that will
        // not write must not have spent anything on its way to writing
        // nothing. It classifies with `fs::symlink_metadata`, never
        // `dest.exists()`: `exists()` FOLLOWS the name, so a DANGLING
        // symlink reports its target as absent and the decision would
        // silently belong to a rename instead of to this function.
        //
        // Three answers, and no deletion primitive among them:
        //
        //   - a regular FILE is the ordinary present case — the object
        //     is already cached, so return (idempotent, matching
        //     store::put's precedent).
        //   - a DIRECTORY is the one foreign shape this write can never
        //     replace: `rename(2)` refuses a directory `dest` and no
        //     unlink clears one either. Decline here and say so; the
        //     cache evicts nothing and writes nothing.
        //   - ANY OTHER foreign entry (a symlink dangling or not, a
        //     FIFO, a socket) is replaced by the staged write's own
        //     final `rename`, which replaces a non-directory `dest`
        //     ATOMICALLY and never follows it — POSIX `rename(2)`
        //     replaces the link, not its target. So IF this call
        //     reaches the rename, the planted NAME goes and whatever it
        //     pointed at is untouched. This arm only warns, and the
        //     warn is CONDITIONAL: the size gate, the staging itself,
        //     the quota eviction and the watermark below can each still
        //     decline, and then nothing at the name has changed at all. The cache
        //     self-heals where the STORE reports: this is scratch any
        //     origin can refill, and declining would leave the object
        //     uncacheable FOREVER, since nothing in this module ever
        //     clears the name.
        match fs::symlink_metadata(&dest) {
            Ok(meta) if meta.is_file() => {
                return; // already cached — idempotent, matches store::put's precedent
            }
            Ok(meta) if meta.is_dir() => {
                crate::observe::OperatorDiagnostic::cache_insert_declined_a_directory_occupies_the_object_path().emit_paths(&[crate::observe::PathSlot::Path("path", crate::LogPath::file(&dest))]);
                return;
            }
            Ok(_) => {
                crate::observe::OperatorDiagnostic::cache_insert_a_foreign_entry_sits_at_the_object().emit_paths(&[crate::observe::PathSlot::Path("path", crate::LogPath::file(&dest))]);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                crate::observe::OperatorDiagnostic::cache_insert_failed_to_inspect_the_object_path(
                    crate::FailureClass::Io,
                )
                .emit();
                return;
            }
        }
        if len > self.quota_bytes {
            crate::observe::OperatorDiagnostic::cache_insert_refused_object_is_larger_than_the_whole(len, self.quota_bytes).emit();
            return;
        }
        // STAGE BEFORE ANYTHING IS SPENT. `txn/` unwritable is a real
        // state this cache does not detect at open (a `0o555` `txn/` is
        // the shape; `sweep_orphaned_txn_files`' doc names it), and
        // staging is the only honest answer to "can this cache write" —
        // an open-time probe answers for the wrong moment. Doing it
        // first is what keeps a cache that cannot write merely
        // non-caching instead of DRAINING: eviction below spends the
        // cache's contents, and it must never be spent on a write that
        // was never going to land. A staging failure here evicts
        // nothing, and `staged` removes its own name — best effort — on
        // every path out of this function that does not rename it.
        let staged = match StagedWrite::stage(root, bytes, &self.txn_counter, 0o444) {
            Ok(staged) => staged,
            Err(e) => {
                // NOT "nothing on disk changed", which would be false:
                // `stage` can fail AFTER its `create_new` succeeded (at
                // the write, the fsync or the chmod), and the guard's
                // removal of the staging name is itself best-effort, so
                // bytes may be left under `txn/` until the next writer
                // open sweeps them. What is unconditionally true, and
                // what the line says: nothing was evicted, and nothing
                // became visible at the object path.
                crate::observe::OperatorDiagnostic::cache_insert_failed_to_stage_the_object_nothing_was(e.failure_class()).emit();
                return;
            }
        };
        if !self.evict_to_fit(root, len) {
            return;
        }

        // Quota eviction still comes before the filesystem watermark
        // check: unlinking the LRU object can itself recover the room
        // this write needs, and checking first would make the only
        // eviction path unreachable precisely when reclamation is
        // useful.
        //
        // `0`, not `len`, and the two are the SAME question asked at a
        // different moment. The staged bytes are already on disk, so the
        // reading below already counts them: "is there still a watermark
        // of room now" is exactly "would there still be a watermark of
        // room after writing len" asked before the staging. What
        // changes is only the window — between the staging above and
        // this refusal the bytes occupy space, as they already do
        // between any staging and its rename — and the staged file goes
        // when `staged` drops.
        if !free_space_precheck(self.free_space.as_ref(), 0) {
            crate::observe::OperatorDiagnostic::cache_insert_refused_by_the_free_space_watermark(
                len,
            )
            .emit();
            return;
        }

        if let Err(e) = create_structural_dir(fanout, "create fanout dir") {
            crate::observe::OperatorDiagnostic::cache_insert_failed_to_create_its_fanout_directory(
                e.failure_class(),
            )
            .emit();
            return;
        }
        if let Err(e) = staged.rename_into(&dest) {
            crate::observe::OperatorDiagnostic::cache_insert_failed_to_write_the_object(
                e.failure_class(),
            )
            .emit();
            return;
        }

        let Ok(size) = u32::try_from(len) else {
            crate::observe::OperatorDiagnostic::cache_insert_object_too_large_to_index_the_file(
                len,
            )
            .emit();
            return;
        };
        // An id already live REPLACES: subtract its OLD size first, so
        // a re-insert (the `symlink_metadata` guard above only catches an
        // already-PRESENT object file — a walked/adopted id whose file
        // was since replaced out-of-band is not excluded by it) can
        // never double-count `total_bytes`.
        if let Some(&(old_seq, old_size)) = self.live.get(id) {
            self.by_seq.remove(&old_seq);
            self.total_bytes = self.total_bytes.saturating_sub(u64::from(old_size));
        }
        let new_seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.live.insert(*id, (new_seq, size));
        self.by_seq.insert(new_seq, *id);
        self.total_bytes = self.total_bytes.saturating_add(u64::from(size));
        self.debug_assert_index_invariant();
        self.append_journal_record(&Record::Insert { id: *id, size });
    }

    // Put-if-absent classifies with `fs::symlink_metadata`, never
    // `dest.exists()`. `exists()` FOLLOWS the name: a DANGLING symlink
    // at the leaf reports its target as absent, so put-if-absent would
    // proceed to write and the decision about the planted entry would
    // belong to `atomic_write`'s rename rather than to this function.
    // An lstat reports any entry as present, dangling link included.
    //
    // No `#[expect(disallowed_methods)]` on this fn. `symlink_metadata`
    // is the class's SAFE half and is never banned (see
    // crates/granary-client/clippy.toml's header); this function
    // performs no unlink at all. A foreign entry at the leaf is
    // replaced by `atomic_write`'s own final `rename`, which replaces a
    // non-directory `dest` atomically and never follows it — the
    // object twin of `insert`'s arm, and for the same reason:
    // declining forever made a planted link enough to keep one root
    // permanently uncacheable, since nothing in this module ever clears
    // the name. `create_structural_dir` and `atomic_write` are licensed
    // at their own definitions. The volume DIRECTORY is still
    // classified non-followingly FIRST, before the leaf is touched at
    // all, because every path operation below it follows an
    // intermediate symlink.
    fn put_root_bytes(&mut self, root: &Path, volume: &VolumeName, seq: u64, bytes: &[u8]) {
        let len = bytes.len() as u64; // usize -> u64: always widening on real targets
        let dest = root_bytes_path(root, volume, seq);
        // The volume directory FIRST, before the leaf below it is
        // classified. NOTHING here unlinks: the classification decides
        // whether to decline, and a foreign non-directory leaf that gets
        // past it is REPLACED by the staged write's own rename, never
        // erased first. Non-creating: the create still happens
        // further down, behind the free-space watermark every write
        // under this root takes (no small-write exemption —
        // and a mkdir is a write).
        let Some(volume_dir) = dest.parent() else {
            crate::observe::OperatorDiagnostic::cache_root_write_skipped_the_root_path_has_no(seq)
                .emit();
            return;
        };
        if let Err(e) =
            refuse_symlinked_structural_dir(volume_dir, "cache root write: stat volume dir")
        {
            crate::observe::OperatorDiagnostic::cache_root_write_skipped_the_volume_directory_is_not(seq, e.failure_class()).emit();
            return;
        }
        // Three answers, exactly as `build_writer_state` classifies the
        // journal — `.is_ok()` has only two and would fold every
        // NON-NotFound error into "absent". That is not a cosmetic
        // difference: nothing past this point re-checks the leaf, so a
        // leaf that merely could not be READ (ENOTDIR, EACCES, a
        // transient I/O failure) would go on to `atomic_write`, whose
        // `rename` REPLACES whatever name sits at `dest` if the
        // condition has cleared by the time it runs — put-if-absent
        // overwriting an existing root. It runs BEFORE the watermark,
        // because a call that will not write must not have decided
        // anything about the name on its way to writing nothing.
        match fs::symlink_metadata(&dest) {
            // A regular file is the ordinary present case: put-if-absent
            // (root.rs's own term for this chain's write rule) declines,
            // silently, because that is the expected steady state.
            Ok(meta) if meta.file_type().is_file() => return,
            // A DIRECTORY is the one foreign shape no write can
            // replace: `rename(2)` refuses a directory `dest`. Decline
            // and say so.
            Ok(meta) if meta.is_dir() => {
                crate::observe::OperatorDiagnostic::cache_root_write_skipped_a_directory_occupies_the_destination(seq).emit_paths(&[crate::observe::PathSlot::Path("path", crate::LogPath::file(&dest))]);
                return;
            }
            // Anything ELSE at the name — a symlink dangling or not, a
            // FIFO, a socket — is FOREIGN: the cache never creates one
            // there, and IF this call reaches the write,
            // `atomic_write`'s rename replaces that NAME atomically
            // without following it. The warn is CONDITIONAL for the
            // same reason `insert`'s is — the free-space watermark
            // below can still decline, and then nothing at the name
            // changed.
            Ok(_) => {
                crate::observe::OperatorDiagnostic::cache_root_write_a_foreign_entry_sits_at_the(
                    seq,
                )
                .emit_paths(&[crate::observe::PathSlot::Path(
                    "path",
                    crate::LogPath::file(&dest),
                )]);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                // Fail CLOSED, and say so: this is not "absent".
                crate::observe::OperatorDiagnostic::cache_root_write_skipped_the_destination_could_not_be(seq, crate::FailureClass::Io).emit();
                return;
            }
        }
        if !free_space_precheck(self.free_space.as_ref(), len) {
            crate::observe::OperatorDiagnostic::cache_root_write_refused_by_the_free_space_watermark(seq, len).emit();
            return;
        }
        if let Err(e) = create_structural_dir(volume_dir, "create root volume dir") {
            crate::observe::OperatorDiagnostic::cache_root_write_failed_to_create_its_volume_directory(e.failure_class()).emit();
            return;
        }
        if let Err(e) = atomic_write(root, &dest, bytes, &self.txn_counter, 0o444) {
            crate::observe::OperatorDiagnostic::cache_root_write_failed(seq, e.failure_class())
                .emit();
        }
    }

    /// The one write site for `anchors/<volume>`. `candidate` is
    /// `None` when this call carries no floor proposal at all (the
    /// head-discovery poll persisting a wire-confirmed hint before the resolve it names
    /// has verified — `head.rs`'s own doc explains why an unverified
    /// wire value must never seed or raise the floor on its own).
    ///
    /// **The floor can only ever RISE.** `new_seq` is computed ONCE,
    /// right here, as `existing.max(candidate)` when both are present,
    /// `candidate` alone when there was no existing anchor, or the
    /// existing value UNCHANGED when `candidate` is `None` — there is no
    /// other arm and no other write site in this module that touches
    /// this field (this function IS the single write site, and this
    /// match IS its max).
    ///
    /// The read-compare-rename happens entirely inside this one
    /// `&mut self` call. The writer's exclusive `flock` already makes this the
    /// only `WriterState` alive for the cache dir, so no additional
    /// mutex is needed to keep two concurrent raises from interleaving a
    /// lower floor over a higher one.
    ///
    /// **No-op when nothing changed.** If the computed `(new_seq,
    /// new_hint)` equals what is already on disk, the rename is skipped
    /// entirely — a repeat resolve of an unchanged head (the ordinary
    /// case once the persisted head hint is fresh) touches the anchor file zero
    /// times, not once with identical bytes.
    ///
    /// **Exempt from the free-space watermark**, unlike every other
    /// write under this cache root. See the write site's own comment.
    fn raise_anchor(
        &mut self,
        root: &Path,
        volume: &VolumeName,
        candidate: Option<u64>,
        hint: HintUpdate,
    ) {
        let path = anchor_path(root, volume);
        let current = read_and_parse_anchor(&path);
        let existing_seq = current.as_ref().map(|a| a.seq);
        let existing_hint = current.and_then(|a| a.hint);

        // An absent-class candidate (seq 0 or the
        // reserved `u64::MAX`) is REFUSED, never written: neither can
        // ever be a head, and a rendered `seq` line carrying one is a
        // line this module's own strict reader refuses — via the `max`
        // below, writing it would ERASE an existing (higher-trust)
        // floor on the next read rather than raise anything.
        let candidate = candidate.filter(|&c| {
            let persistable = !is_reserved_seq(c);
            if !persistable {
crate::observe::OperatorDiagnostic::anchor_floor_candidate_is_an_absent_class_seq_refusing(c).emit();
            }
            persistable
        });
        let new_seq = match (existing_seq, candidate) {
            (Some(existing), Some(c)) => existing.max(c),
            (Some(existing), None) => existing,
            (None, Some(c)) => c,
            (None, None) => return, // nothing to establish and nothing to raise
        };
        let new_hint = match hint {
            HintUpdate::Unchanged => existing_hint.clone(),
            HintUpdate::Replace(h) => {
                if persistable_anchor_hint(&h) {
                    Some(h)
                } else {
                    // An EMPTY token is the expected shape on an
                    // ETag-less backend (`granary-store`'s
                    // `HintToken(String::new())` fabrication when a
                    // backend omits an `ETag`) — not a warning. A
                    // genuinely MALFORMED non-empty token (bad bytes,
                    // over-length) or a bad stamp/seq still warns.
                    // Either way the prior GOOD hint is RETAINED, never
                    // erased by an unpersistable replacement.
                    if h.token.is_empty() {
                        crate::observe::OperatorDiagnostic::hint_token_is_empty_an_etag_less_backend_retaining().emit();
                    } else {
                        crate::observe::OperatorDiagnostic::hint_is_unpersistable_token_bytes_length_stamp_sign_or().emit();
                    }
                    existing_hint.clone()
                }
            }
        };

        // Nothing changed — skip the read-compare-rename cycle entirely
        // rather than re-render and re-write bytes identical to what is
        // already on disk (two back-to-back anchor writes on every
        // verified resolve, one of them a no-op, plus a documented crash
        // window between them).
        if existing_seq == Some(new_seq) && existing_hint == new_hint {
            return;
        }

        let bytes = render_anchor_bytes(new_seq, new_hint.as_ref());
        // Deliberately NOT behind `free_space_precheck`, unlike every
        // other write under this cache root. The anchor is a BOUNDED
        // (<= `ANCHOR_FILE_MAX_BYTES`) replace-in-place of the only
        // rollback defence in the unverified default — under a
        // full-LRU steady state (normal operation) the watermark refuses
        // ordinary object/root writes routinely, and gating the anchor
        // the same way lets the rollback floor silently stop rising
        // exactly when a hostile actor has filled the cache to force
        // that state. `atomic_write`'s own I/O-failure path below still
        // warns on a genuine ENOSPC.
        let Some(dir) = path.parent() else { return };
        // Sibling to `insert`'s fanout-dir create and `put_root_bytes`'s
        // volume-dir create just above — same symlinked-structural-dir
        // hazard (a planted `anchors -> elsewhere` would steer every
        // anchor write outside the cache root), same guarded helper.
        // This site was the one left on the bare form when the other
        // two gained the guard — the guard-one-site-and-not-its-siblings
        // shape this module has had to close more than once.
        if let Err(e) = create_structural_dir(dir, "create anchors/") {
            crate::observe::OperatorDiagnostic::cache_anchor_write_failed_to_create_its_directory(
                e.failure_class(),
            )
            .emit();
            return;
        }
        let durable_write =
            atomic_write(root, &path, &bytes, &self.txn_counter, 0o644).and_then(|()| {
                fsync_directory(dir).map_err(io_err(format!(
                    "fsync anchor destination directory {}",
                    dir.display()
                )))
            });
        if let Err(e) = durable_write {
            crate::observe::OperatorDiagnostic::cache_anchor_write_failed(e.failure_class()).emit();
        } else {
            #[cfg(test)]
            self.anchor_directory_fsyncs.fetch_add(1, Ordering::Relaxed);
            self.anchor_writes.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The mount-private counterpart to [`Self::raise_anchor`]:
    /// the same monotonic-`max` floor, at `anchors/<volume>.mount`
    /// instead of the shared `anchors/<volume>`, and with none of
    /// the hint machinery — this file is a floor and NEVER a hint,
    /// so there is no `HintUpdate` parameter to accept one
    /// through. Reuses [`read_and_parse_mount_anchor`] (which
    /// itself reuses [`read_and_parse_anchor`]'s bounded read and
    /// strict parse) and [`render_anchor_bytes`] (called with
    /// `hint: None`, always) — the same instruction not to keep a
    /// second parser or renderer in step with this one.
    ///
    /// **The floor can only ever RISE**, by the identical reasoning
    /// [`Self::raise_anchor`]'s own doc gives: `new_seq` is
    /// `existing.max(candidate)`, computed once, and there is no other
    /// write site for this field.
    ///
    /// **No-op when nothing changed** — same skip [`Self::raise_anchor`]
    /// takes, so a repeat resolve at an unchanged mount floor touches
    /// this file zero times.
    ///
    /// **Exempt from the free-space watermark**, for the same reason
    /// [`Self::raise_anchor`] is: a bounded replace-in-place of a
    /// rollback-floor file must not silently stop rising exactly when a
    /// full cache would refuse an ordinary write.
    fn raise_mount_anchor(
        &mut self,
        root: &Path,
        volume: &VolumeName,
        seq: u64,
    ) -> Result<(), String> {
        let path = mount_anchor_path(root, volume);
        let existing = read_and_parse_mount_anchor(&path);

        // Same absent-class refusal `Self::raise_anchor` applies to its
        // own candidate (seq 0 and the reserved
        // `u64::MAX`): neither can ever be a head, and persisting one
        // would erase an existing floor on the next read via the `max`
        // below rather than raise anything.
        if is_reserved_seq(seq) {
            crate::observe::OperatorDiagnostic::mount_anchor_floor_candidate_is_an_absent_class_seq(seq).emit();
            return Ok(());
        }

        let new_seq = existing.map_or(seq, |e| e.max(seq));
        if existing == Some(new_seq) {
            // Nothing changed — skip the read-compare-rename cycle
            // entirely, mirroring `Self::raise_anchor`'s own no-op skip.
            // The counter is what makes the skip OBSERVABLE: a test that
            // only inspects the file's bytes cannot tell "skipped" from
            // "wrote the identical bytes again", which is the reason
            // `anchor_writes` exists for the shared anchor.
            return Ok(());
        }

        let bytes = render_anchor_bytes(new_seq, None);
        let Some(dir) = path.parent() else {
            return Ok(());
        };
        // Same guarded directory creation `Self::raise_anchor` takes —
        // the mount anchor is a sibling file in the same `anchors/`
        // directory, so this is a defence-in-depth re-check, not a new
        // directory to create.
        if let Err(e) = create_structural_dir(dir, "create anchors/") {
            return Err(format!("cannot create anchors/: {e}"));
        }
        let durable_write =
            atomic_write(root, &path, &bytes, &self.txn_counter, 0o644).and_then(|()| {
                fsync_directory(dir).map_err(io_err(format!(
                    "fsync mount-anchor destination directory {}",
                    dir.display()
                )))
            });
        durable_write.map_err(|e| format!("cannot persist the mount-private floor: {e}"))?;
        self.mount_anchor_writes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// `gran mount --reset-floor`'s only effect — clear the
    /// mount-private floor at `anchors/<volume>.mount`
    /// entirely, rather than write a new value into it.
    /// Writing a zero or absent-class seq would not clear the
    /// floor: [`read_and_parse_mount_anchor`] refuses those on
    /// READ exactly as [`Self::raise_mount_anchor`] refuses
    /// them on write, so the file would stay PRESENT and
    /// unreadable — indistinguishable on disk from corruption.
    /// Absence is the only unambiguous "no floor" state this
    /// format has. The one bare call is `remove_file` by NAME
    /// at a fixed, known path under `anchors/` — the same path
    /// [`Self::raise_mount_anchor`] writes and
    /// [`read_and_parse_mount_anchor`] reads; unlink never
    /// follows its final path component. Absent is already the
    /// goal state, so `NotFound` is success, never an error.
    #[expect(
        clippy::disallowed_methods,
        reason = "remove_file by NAME of this writer's own mount-anchor file at a fixed, known \
                  path under anchors/ — the same path raise_mount_anchor writes and \
                  read_and_parse_mount_anchor reads; unlink never follows its final path \
                  component, and NotFound is the goal state, not a failure"
    )]
    fn reset_mount_anchor(root: &Path, volume: &VolumeName) -> Result<(), String> {
        let path = mount_anchor_path(root, volume);
        // Same intermediate-symlink reasoning as `evict_root_bytes`.
        if let Some(dir) = path.parent()
            && let Err(e) =
                refuse_symlinked_structural_dir(dir, "mount-anchor reset: stat anchors/")
        {
            return Err(format!("anchors/ is not a real directory: {e}"));
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("cannot remove {}: {e}", path.display())),
        }
        // The unlink is not durable until the DIRECTORY entry is, and
        // `raise_anchor`'s own replace path fsyncs for exactly this reason.
        // Without it a power loss after `--reset-floor` reported success can
        // bring the floor back, and the operator has been told it is gone.
        let Some(dir) = path.parent() else {
            return Ok(());
        };
        fsync_directory(dir).map_err(|e| format!("cannot fsync anchors/ after the unlink: {e}"))
    }

    /// Unlink a cached root that turned out NOT to verify
    /// under the reader's own trust anchor. [`Cache::get_root_bytes`]
    /// performs no signature and no hash check of its own, so a
    /// cached entry that fails the SAME verifier check the wire root
    /// just passed is local corruption, not a second publisher — the
    /// mount evicts it and proceeds on the wire bytes it already
    /// verified, rather than bricking forever on a copy nothing here
    /// ever re-checks (`Cache::put_root_bytes` is put-if-absent, so a
    /// stale entry would otherwise occupy this slot permanently). The
    /// one bare call is `remove_file` by NAME at a fixed, known path
    /// under `roots/<volume>/<seq>` — the same path
    /// [`Self::put_root_bytes`] writes and [`Cache::get_root_bytes`]
    /// reads; unlink never follows its final path component. Absent
    /// is the goal state: a caller that lost a race against a
    /// concurrent evictor sees the same `NotFound` as one that lost
    /// it to nobody.
    #[expect(
        clippy::disallowed_methods,
        reason = "remove_file by NAME of a cached root at a fixed, known path under roots/ — \
                  the same path put_root_bytes writes and get_root_bytes reads; unlink never \
                  follows its final path component, and NotFound is the goal state, not a \
                  failure"
    )]
    fn evict_root_bytes(root: &Path, volume: &VolumeName, seq: u64) {
        let path = root_bytes_path(root, volume, seq);
        // `unlink` does not follow its FINAL component, but it does follow
        // every INTERMEDIATE one — the same "a NOFOLLOW guard covers one
        // component, not the path" shape this repo already paid for on
        // `UMOUNT_NOFOLLOW`. `Cache::put_root_bytes` refuses a symlinked
        // volume directory before it writes; this refuses one before it
        // deletes, or a planted `roots/<volume>` symlink turns eviction into
        // the removal of a file outside the cache entirely.
        let Some(volume_dir) = path.parent() else {
            crate::observe::OperatorDiagnostic::cache_root_eviction_skipped_the_root_path_has_no(
                seq,
            )
            .emit();
            return;
        };
        if let Err(e) =
            refuse_symlinked_structural_dir(volume_dir, "cache root eviction: stat volume dir")
        {
            crate::observe::OperatorDiagnostic::cache_root_eviction_skipped_the_volume_directory_is_not(seq, e.failure_class()).emit();
            return;
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                crate::observe::OperatorDiagnostic::cache_root_eviction_failed_to_remove_the_file(
                    seq,
                    crate::FailureClass::Io,
                )
                .emit();
            }
        }
    }
}

enum Mode {
    Writer(Box<WriterState>),
    ReadOnlyDegraded,
}

/// An open client cache directory.
/// Writer when the exclusive lock is acquired; otherwise
/// read-only-degraded — hits are still served hash-verified, and
/// insert/touch/eviction are silent no-ops. Readers hold no lock at all
/// on the object read path.
pub struct Cache {
    root: PathBuf,
    mode: Mode,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("root", &self.root)
            .field(
                "mode",
                &match &self.mode {
                    Mode::Writer(_) => "writer",
                    Mode::ReadOnlyDegraded => "read-only-degraded",
                },
            )
            .finish_non_exhaustive()
    }
}

/// Builds the writer's [`WriterState`] once the exclusive lock is held
/// — extracted out of `Cache::open_with_free_space` (clippy's line-count
/// lint) rather than because it composes from elsewhere; the guard
/// create, sweep, index load and journal-file-open sequence below is
/// genuinely one linear procedure, just a long one.
#[expect(
    clippy::disallowed_methods,
    reason = "guard_path.exists() is the ONE banned call left in this function, and it is \
              diagnostic-only: its value logs a warning and reaches load_index as a hint that \
              is itself only logged. Path::exists() both FOLLOWS a link and folds EVERY \
              metadata error (a permission denial, an I/O error) into `false` — neither \
              matters here, because the worst outcome is a missing warning line. What gets \
              written is decided by the guarded fsguard::create_regular_lock open right \
              below, which runs either way. The journal's own presence check is NOT this \
              call: the journal's own presence check is fs::symlink_metadata (see the in-body \
              comment), because there the same two properties are load-bearing"
)]
fn build_writer_state(
    root: &Path,
    quota_bytes: u64,
    free_space: Box<dyn FreeSpace>,
    lock_file: File,
) -> Result<WriterState, CacheError> {
    let guard_path = root.join("guard");
    let guard_was_present = guard_path.exists();
    if guard_was_present {
        crate::observe::OperatorDiagnostic::cache_guard_present_at_open_the_previous_writer_did()
            .emit_paths(&[crate::observe::PathSlot::Path(
                "root",
                crate::LogPath::cache_root(root),
            )]);
    }
    // Same discipline as the `lock` open, and for the same reasons —
    // the cache never creates a symlink or a FIFO here, so either is
    // foreign; following one would truncate a file outside the root,
    // and an `O_WRONLY` open of a FIFO would BLOCK until a reader
    // appeared, wedging `Cache::open` with the flock already held.
    fsguard::create_regular_lock(&guard_path, false).map_err(io_err("create guard"))?;

    sweep_orphaned_txn_files(root)?;

    let txn_counter = AtomicU64::new(0);
    let walk_reads = AtomicU64::new(0);
    let (index, journal_plan, journal_total_records) = load_index(
        root,
        &walk_reads,
        &txn_counter,
        free_space.as_ref(),
        guard_was_present,
    )?;
    let total_bytes = index.total_bytes;
    let (live, by_seq, next_seq) = WriterState::seed_index(index);

    let journal_path = root.join("index").join("journal");
    // NOT `Path::exists()`. That call answers "does the TARGET of this
    // name exist", which conflates three states this decision needs
    // kept apart: a real file (present), no name at all (absent —
    // create it), and a name that IS there but whose target is not,
    // i.e. a DANGLING symlink. It also folds every metadata error — a
    // permission denial, an I/O error — into `false`, which would send
    // a failure down the CREATE path. `symlink_metadata` is an lstat:
    // it never follows, so ANY entry at the name (regular file, symlink
    // dangling or not, FIFO, directory) classifies as present, an
    // absent name is the only `false`, and any other error is
    // propagated rather than guessed at.
    //
    // `load_index` has already refused every non-regular entry at this
    // name (`refuse_foreign_index_entry`), which is where the refusal
    // has to live: the rebuild it would otherwise trigger writes over
    // the name before anything here runs. This check is not that
    // refusal and does not duplicate it — it is the absent/present
    // split for the creation write below, kept non-following so that a
    // foreign entry planted in the window between the two still skips
    // the creation write (whose `rename` would erase it) and reaches
    // `fsguard::open_regular_append`, which refuses a symlink
    // (O_NOFOLLOW) or a FIFO (O_NONBLOCK + fstat) and fails
    // `Cache::open` closed.
    let journal_present = match fs::symlink_metadata(&journal_path) {
        Ok(_) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(io_err("stat journal")(e)),
    };
    if !journal_present {
        // The cold rebuild walk's own journal-reset write is gated by the
        // free-space precheck and can
        // leave the journal ABSENT under a sustained watermark refusal
        // (a walk that started with no journal at all). This ~11-byte
        // envelope write is the same one-time creation-scaffolding
        // class that sentence carves out of the precheck — ungated, so
        // every subsequent append lands in a replayable file.
        // `atomic_write`, never a bare `.create(true)`: an envelope-less
        // empty file would be shorter than `ENVELOPE_LEN` and get
        // treated as untrustworthy (tamper class) at the NEXT open,
        // silently eating every record appended to it in between.
        atomic_write(
            root,
            &journal_path,
            &empty_journal_bytes(),
            &txn_counter,
            0o644,
        )?;
    }
    // `fsguard`, and it is load-bearing rather than defensive. The
    // presence check above classifies WITHOUT following, so any link
    // planted at `index/journal` — dangling or not — skips the
    // creation write and arrives here still in place; a plain open
    // would then append every cache journal record through it, outside
    // the cache root. A FIFO is the same hole by another route: a
    // plain O_WRONLY open blocks until a reader appears (hanging
    // `Cache::open`), and if one IS present the open succeeds and the
    // records go into a pipe. All of them fail here and `Cache::open`
    // refuses, which is the correct answer — no legitimate cache has
    // any of them at this name. Note what the creation write above
    // does NOT do: `atomic_write`'s `create_new` opens its own staging
    // name under `txn/`, and it is the `rename` onto `dest` that would
    // replace an entry here — which is why the classification, not the
    // open, is what has to refuse a planted link.
    let journal_file =
        fsguard::open_regular_append(&journal_path).map_err(io_err("open journal"))?;
    let mut journal_len = journal_file
        .metadata()
        .map_err(io_err("stat journal"))?
        .len();
    if let JournalOpenPlan::TruncateTo(trusted_len) = journal_plan
        && trusted_len < journal_len
    {
        journal_file
            .set_len(trusted_len)
            .map_err(io_err("truncate torn journal tail"))?;
        fsync_file(&journal_file).map_err(io_err("fsync truncated journal"))?;
        journal_len = trusted_len;
    }

    Ok(WriterState {
        _lock: lock_file,
        root: root.to_owned(),
        quota_bytes,
        free_space,
        live,
        by_seq,
        next_seq,
        total_bytes,
        journal_file,
        journal_len,
        journal_buf: Vec::new(),
        journal_buf_records: 0,
        journal_total_records,
        compaction_stalled_at: None,
        journal_broken: false,
        journal_broken_warned: false,
        #[cfg(test)]
        journal_write_fail_after: None,
        #[cfg(test)]
        compact_snapshot_write_fail: false,
        #[cfg(test)]
        journal_reopen_fail: false,
        txn_counter,
        walk_reads,
        anchor_writes: AtomicU64::new(0),
        mount_anchor_writes: AtomicU64::new(0),
        #[cfg(test)]
        anchor_directory_fsyncs: AtomicU64::new(0),
        #[cfg(test)]
        compaction_attempts: AtomicU64::new(0),
        #[cfg(test)]
        maintain_calls: AtomicU64::new(0),
    })
}

/// What [`Cache::open_for_verify`] returns — NEVER `Cache`/[`Mode`]
///: the verify pipeline creates nothing and takes none of
/// `open`'s side effects (no guard file, no directory creation, no
/// index repair), and its two modes have no analogue in [`Mode`] — a
/// lock-held verify never loads an index at ALL, which
/// `Mode::ReadOnlyDegraded` does not represent (that mode still serves
/// hash-verified reads from a loaded-nowhere index; verify's
/// report-only mode reports object-integrity findings only and never
/// touches the index files).
#[derive(Debug)]
pub(crate) enum VerifyCache {
    /// The writer lock was ACQUIRED, so the snapshot/journal pair can
    /// be read COHERENTLY against a concurrent compaction and the walk
    /// can report index findings (`adopted`, `dropped`,
    /// `size-mismatch`) on top of the object-integrity ones. The lock
    /// buys a coherent READ; nothing on this path writes.
    /// `_lock`: held only to keep the flock alive via RAII drop, never
    /// read as a value (matches `Store`/`WriterState`'s identical
    /// `_lock: File` convention).
    WithIndex { _lock: File, index: VerifyIndex },
    /// The writer lock is HELD by another process — object-integrity
    /// findings alone (snapshot+journal have no generation permitting
    /// a coherent lockless read during compaction), never index
    /// findings.
    ReportOnly,
}

/// What [`load_index_read_only`] could honestly conclude about the
/// on-disk index — **a tri-state, because collapsing it to "an empty
/// index" is a FALSE CLEAN.** A cache whose snapshot is corrupt and
/// whose `objects/` is empty would otherwise verify clean, exit 0,
/// silent, on an index that cannot be decoded at all.
#[derive(Debug)]
pub(crate) enum VerifyIndex {
    /// Decoded cleanly, or legitimately absent — index findings
    /// derived from it are trustworthy.
    Trusted(IndexState),
    /// Present and NOT decodable: over the byte bound, unreadable, not
    /// a regular file, or a failed decode. Nothing may be concluded by
    /// comparing against it — every `adopted` and `dropped` line such a
    /// comparison produced would be an artefact of the damage, not a
    /// finding — so the caller reports the index file ITSELF and falls
    /// back to the object-integrity walk.
    Untrusted {
        /// Root-relative, for the finding line. `&'static str`: it is
        /// one of exactly two literals, never a caller's bytes.
        rel_path: &'static str,
        /// Which way it failed, for the stderr diagnostic. The finding
        /// LINE keeps `-`/`-` in its expected/actual columns — those
        /// columns are digests-or-`-` in a machine-parsed format, and
        /// free text in one is a format defect.
        detail: &'static str,
    },
}

impl Cache {
    /// Open (or create) a cache directory at `root`, bound to `origin`
    /// and bounded to `quota_bytes`. Writer when the exclusive lock
    /// succeeds; otherwise read-only-degraded (one typed warning).
    ///
    /// **`quota_bytes` bounds the INDEX, not every byte under `root` at
    /// every instant.** An object enters the index at its rename, so
    /// while `WriterState::insert` is staging one, the disk holds up to
    /// the quota plus that one object; the free-space watermark is the
    /// backstop on the excess, and a crash inside that window leaves the
    /// staged file under `txn/` for the next writer open's sweep. Two
    /// further things the quota has never counted: `roots/` and
    /// `anchors/` (never charged, never evicted), and any object left on disk by an
    /// unlink the writer could not perform, which the accounting
    /// under-counts until a cold rebuild re-adopts it.
    ///
    /// # Errors
    /// [`CacheError::Incompatible`] when `origin.endpoint_url` is empty
    /// or contains a byte that would corrupt the marker's line-based
    /// grammar (checked before any disk touch), or when the marker's
    /// tuple or origin line disagrees with `origin` (in either mode);
    /// [`CacheError::Io`] for directory creation, locking, and index
    /// I/O failures.
    pub fn open(root: &Path, quota_bytes: u64, origin: &CacheOrigin) -> Result<Self, CacheError> {
        Self::open_with_free_space(
            root,
            quota_bytes,
            origin,
            Box::new(SystemFreeSpace::new(root.to_owned())),
        )
    }

    /// [`Self::open`] with an injected [`FreeSpace`] — the seam tests
    /// (and any future deterministic caller, matching the `Clock`/`Rng`
    /// precedent) use in place of the real filesystem query.
    ///
    /// # Errors
    /// Same as [`Self::open`].
    #[expect(
        clippy::disallowed_methods,
        reason = "root itself is deliberately unguarded (see the in-body comment just below): \
                  a symlinked --cache-dir is the caller's own explicit choice, and the publish \
                  path separately refuses one nested with the source via \
                  refuse_cache_dir_nesting; every structural SUBDIR created after this line \
                  goes through the guarded create_structural_dir"
    )]
    pub fn open_with_free_space(
        root: &Path,
        quota_bytes: u64,
        origin: &CacheOrigin,
        free_space: Box<dyn FreeSpace>,
    ) -> Result<Self, CacheError> {
        validate_origin_grammar(origin)?;

        fs::create_dir_all(root).map_err(io_err(format!("create {}", root.display())))?;
        // Structural SUBDIRS refuse a pre-planted symlink (create_dir_all
        // would follow one into a dir outside the cache root) — see
        // `create_structural_dir`. `root` itself is not guarded here: a
        // symlinked `--cache-dir` is the caller's explicit choice, and the
        // publish path additionally refuses a cache dir nested with the
        // source via `refuse_cache_dir_nesting` (which canonicalizes it).
        //
        // Every structural directory, including txn/, shares the same
        // pre-existing-symlink refusal. The sweep rechecks txn/ after the
        // writer lock is acquired; these checks leave open only an ACTIVE
        // replacement between a successful check and subsequent use.
        create_structural_dir(&root.join("objects"), "create objects/")?;
        create_structural_dir(&root.join("txn"), "create txn/")?;
        create_structural_dir(&root.join("index"), "create index/")?;
        create_structural_dir(&root.join("anchors"), "create anchors/")?;
        create_structural_dir(&root.join("roots"), "create roots/")?;

        let expected_marker = marker_contents(origin);
        // O_NOFOLLOW on every structural open below: the cache never
        // creates a symlink at `lock`, `guard`, or a txn/ staging name,
        // so one there is foreign — following it would let `open`
        // truncate (or the sweep delete) a file OUTSIDE the cache root.
        // This narrows, but does not fully close, an ACTIVE TOCTOU where
        // the path is swapped between the check and the open; these
        // opens do not resolve every intermediate component by descriptor.
        let lock_file = fsguard::create_regular_lock(&root.join("lock"), false)
            .map_err(io_err("create lock"))?;

        match lock_file.try_lock() {
            Ok(()) => {
                check_marker(root, &expected_marker, true)?;
                let state = build_writer_state(root, quota_bytes, free_space, lock_file)?;
                Ok(Self {
                    root: root.to_owned(),
                    mode: Mode::Writer(Box::new(state)),
                })
            }
            Err(TryLockError::WouldBlock) => {
                crate::observe::OperatorDiagnostic::cache_lock_held_by_another_process_opening_read_only().emit_paths(&[crate::observe::PathSlot::Path("root", crate::LogPath::cache_root(root))]);
                check_marker(root, &expected_marker, false)?;
                Ok(Self {
                    root: root.to_owned(),
                    mode: Mode::ReadOnlyDegraded,
                })
            }
            Err(TryLockError::Error(e)) => Err(io_err("flock")(e)),
        }
    }

    /// `gran verify`'s own entry point — does NOT reuse
    /// [`Self::open_with_free_space`]'s pipeline. Creates NOTHING (a
    /// missing structural dir is a finding or cannot-open, never
    /// repaired). Refuses a symlinked `objects/` or `index/` before
    /// touching either (see [`paths::refuse_symlinked_structural_dir`]), opens
    /// `lock` READ-ONLY with `O_NOFOLLOW`, no create, no truncate, and
    /// only THEN tries the lock. Compares the marker's version/chunker/
    /// hash TUPLE byte-exactly and requires the origin line
    /// present-and-well-formed without comparing its VALUE — verify
    /// supplies no origin and needs none, since it reads content-
    /// addressed objects and COMPARES them against an index, never
    /// serving or writing trust-bearing state.
    ///
    /// **`File::try_lock` on a read-only handle: verified by execution,
    /// not assumed.** A throwaway harness confirmed on this platform
    /// (macOS/Darwin) that `try_lock` succeeds on a read-only `File`
    /// and that a second concurrent read-only `try_lock` correctly
    /// observes `WouldBlock` while the first holds it — `flock(2)`'s
    /// exclusivity does not require the descriptor to be open for
    /// writing.
    ///
    /// # Errors
    /// [`CacheError::Incompatible`] when the marker is absent, over the
    /// size bound, not UTF-8, or its tuple/origin-shape disagrees;
    /// [`CacheError::Io`] for anything else, including a symlinked
    /// `lock`, `objects/` or `index/`.
    pub(crate) fn open_for_verify(root: &Path) -> Result<VerifyCache, CacheError> {
        check_marker_for_verify(root)?;
        // A symlinked structural directory is a refusal here, before
        // `lock` is even opened: `objects/` is walked later by
        // `verify::scan_objects` and `index/` is read by
        // `load_index_read_only`. Both would follow a symlinked
        // INTERMEDIATE directory regardless of the `O_NOFOLLOW` their
        // own final-component file opens already carry, and reading
        // through one lets a planted link choose what verify REPORTS.
        refuse_symlinked_structural_dir(&root.join("objects"), "verify: stat objects/")?;
        refuse_symlinked_structural_dir(&root.join("index"), "verify: stat index/")?;
        // `txn/` too, and it is now the clearest case of the rule
        // rather than of a demonstrated primitive: verify writes
        // nothing at all, so it never stages anything under `txn/`. The
        // refusal stays because a cache root whose structural directory
        // is a symlink is TAMPERED, and blessing one with a clean
        // report is the wrong answer whichever directory it is. Every
        // structural directory gets the same treatment, uniformly,
        // whether or not an exploit has been written for it yet — the
        // one-at-a-time alternative is what recurred eight times.
        refuse_symlinked_structural_dir(&root.join("txn"), "verify: stat txn/")?;
        let lock = fsguard::open_regular_read(&root.join("lock")).map_err(io_err("open lock"))?;
        match lock.try_lock() {
            Ok(()) => Ok(VerifyCache::WithIndex {
                _lock: lock,
                index: load_index_read_only(root),
            }),
            Err(TryLockError::WouldBlock) => Ok(VerifyCache::ReportOnly),
            Err(TryLockError::Error(e)) => Err(io_err("flock")(e)),
        }
    }

    /// Read `id`, hash-verified. A miss is `None`, never an error — an
    /// absent object, an oversized file (checked BEFORE any content
    /// read, against [`META_MAX_BYTES`]) and a corrupt one (checked
    /// AFTER a full read) are all misses. The writer additionally
    /// unlinks an oversized or corrupt file and (for a corrupt one)
    /// journals its eviction; a hit in writer mode also buffers a
    /// recency touch. Takes no lock — safe by rename atomicity, `0444`
    /// permissions, hash-verification and POSIX unlink-while-open
    /// semantics.
    // No `#[expect(disallowed_methods)]` on this fn: the hash-mismatch
    // unlink goes through `unlink_object_leaf`, which is licensed at its
    // own definition and classifies the fanout for itself immediately
    // before the unlink — this function's own opening check is earlier
    // and belongs to the read path, and no unlink in this module relies
    // on a check made further up a caller. The read path itself goes
    // through `fsguard::open_regular_read` +
    // `refuse_symlinked_structural_dir`.
    pub fn get(&mut self, id: &GrainId) -> Option<Vec<u8>> {
        let path = object_path(&self.root, id);
        let fanout = path.parent()?;
        // A foreign fanout is a miss, and it SAYS SO. The miss on its
        // own is indistinguishable from an ordinary cold read, and the
        // condition is permanent for every object in that fanout —
        // silence leaves an operator with a cache that never warms and
        // no way to find out why.
        if let Err(e) = refuse_foreign_object_fanout(fanout, "cache get: stat object fanout") {
            crate::observe::OperatorDiagnostic::cache_read_refused_the_object_fanout_is_not_a(
                e.failure_class(),
            )
            .emit();
            return None;
        }
        // Test-only deterministic replacement immediately before the
        // open, the window a stat-then-open read would race in.
        // Production opens first; the hook lets the negative test prove
        // that this OPEN itself refuses the replacement.
        #[cfg(test)]
        run_path_read_post_stat_hook(&path);
        let f = fsguard::open_regular_read(&path).ok()?;
        // Size comes from the opened descriptor, never a path stat that
        // could describe a different entry from the one subsequently read.
        let meta = f.metadata().ok()?;
        if meta.len() > META_MAX_BYTES {
            self.evict_oversized(id, &path, meta.len());
            return None;
        }
        let mut buf = Vec::new();
        // Bounded read (the TOCTOU backstop): the descriptor size check
        // above is a cheap fast path on that same descriptor,
        // but an attacker sharing this trust domain could grow the file
        // between that fstat and this read. `take(CAP + 1)` bounds the
        // bytes actually read regardless of the file's real size, and
        // the `+ 1` is what lets the check below tell "exactly CAP"
        // (legal) from "over" (foreign) without ever reading past CAP
        // + 1 bytes.
        f.take(META_MAX_BYTES + 1).read_to_end(&mut buf).ok()?;
        if buf.len() as u64 > META_MAX_BYTES {
            self.evict_oversized(id, &path, buf.len() as u64);
            return None;
        }
        if GrainId::of(&buf) != *id {
            if let Mode::Writer(w) = &mut self.mode {
                crate::observe::OperatorDiagnostic::cache_object_failed_hash_verification_unlinking_and_evicting().emit();
                // The index entry and its charge both go: the bytes at
                // this name failed hash verification, so an entry
                // pointing at them is worse than none. If the unlink
                // failed, what stays is the residue `evict_id`'s doc
                // describes. `unlink_object_leaf` classifies the fanout
                // again for itself — not only at the top of `get` — so
                // no site depends on a check made earlier in some
                // caller.
                unlink_object_leaf(&path, "cache get: hash mismatch");
                w.evict_id(id);
            }
            return None;
        }
        if let Mode::Writer(w) = &mut self.mode {
            w.touch_id(id);
        }
        Some(buf)
    }

    /// Shared by `get`'s post-open, pre-read size check (the opened
    /// descriptor's own `f.metadata()`, never a path-based stat) and its
    /// post-read bounded-read backstop. `len` is only for the log line —
    /// which check caught it does not change what happens.
    ///
    /// **Writer mode only, unlink included** — the body scopes BOTH
    /// the unlink and the index eviction, not just the eviction. In
    /// writer mode: unlink the oversized file and evict
    /// the (possibly ghost) index entry so it stops counting against
    /// quota. In `Mode::ReadOnlyDegraded` this is a no-op by design —
    /// a degraded reader never mutates the cache directory,
    /// which is exactly what makes it safe to run without the writer
    /// lock. `get` still treats the object as a MISS either way, so a
    /// reader never serves the oversized bytes; the file simply stays
    /// on disk until some writer opens the cache and evicts it. In
    /// between, `gran verify` reports it — as `oversized`, its own
    /// classification for a file past `META_MAX_BYTES`, reached from
    /// `verify.rs`'s independent on-disk scan, which never trusts the
    /// in-memory index.
    ///
    /// The unlink reports nothing to branch on, and nothing here would
    /// branch on it: the file is over the bound whatever happened to the
    /// name, so the entry and its charge go either way, and an unlink
    /// that could not be performed leaves the residue `evict_id`'s doc
    /// describes.
    // No `#[expect(disallowed_methods)]` on this fn: the unlink goes
    // through `unlink_object_leaf`, licensed at its own definition,
    // which classifies the fanout non-followingly immediately before it.
    // Both callers reach here only after `get` already OPENED that exact
    // path through `fsguard::open_regular_read`; how much of the
    // descriptor was consumed does not matter to safety, and the
    // INTERMEDIATE component — which unlink follows even though it never
    // follows the final one — is what the helper is for.
    fn evict_oversized(&mut self, id: &GrainId, path: &Path, len: u64) {
        if let Mode::Writer(w) = &mut self.mode {
            crate::observe::OperatorDiagnostic::cache_object_exceeds_the_size_bound_treating_it_as(
                len,
            )
            .emit();
            // Same shape as the hash-mismatch unlink, and for the same
            // reason: the file is over the bound whatever happened to
            // the name, so the entry goes either way.
            unlink_object_leaf(path, "cache evict oversized");
            w.evict_id(id);
        }
    }

    /// Cache `bytes` under `id`. A silent no-op in read-only-degraded
    /// mode, and never fails the caller: a free-space refusal, an
    /// object larger than the whole quota, or a write failure all just
    /// skip the insert (each reported at DEBUG or WARN).
    /// See the module doc for the crash windows this accepts.
    pub fn insert(&mut self, id: &GrainId, bytes: &[u8]) {
        let root = self.root.clone();
        let Mode::Writer(w) = &mut self.mode else {
            return;
        };
        w.insert(&root, id, bytes);
    }

    /// Cache a verified root's bytes (writer only; a silent no-op in
    /// read-only-degraded mode). Put-if-absent, never evicted, never
    /// charged against the object quota, but still behind the same
    /// free-space precheck every write under the cache root takes — no
    /// small-write exemption.
    pub fn put_root_bytes(&mut self, volume: &VolumeName, seq: u64, bytes: &[u8]) {
        let root = self.root.clone();
        let Mode::Writer(w) = &mut self.mode else {
            return;
        };
        w.put_root_bytes(&root, volume, seq, bytes);
    }

    /// Raise the per-volume floor (max semantics, never lowered)
    /// and/or replace the persisted head-discovery hint — writer only, a silent
    /// no-op in read-only-degraded mode (matches `insert`'s pattern: a
    /// degraded reader never mutates the cache dir at all). UNLIKE every
    /// other cache write, this one is EXEMPT from the free-space
    /// precheck (a bounded replace-in-place of the only rollback defence).
    /// A WRITER-mode I/O failure still warns and never fails the caller (matches
    /// `put_root_bytes`'s own contract) — the floor then simply stays at
    /// its old, lower value.
    ///
    /// `candidate` is the floor VALUE this call proposes (never lowered
    /// — this method's own internal `max` is the one write site for the
    /// field, and its `max` is the whole story); `None` proposes no
    /// floor change at all — the shape the head-discovery poll uses to persist a
    /// wire-confirmed hint on its own, before (or entirely apart from)
    /// any resolve that would raise the floor.
    pub fn raise_anchor(&mut self, volume: &VolumeName, candidate: Option<u64>, hint: HintUpdate) {
        let root = self.root.clone();
        let Mode::Writer(w) = &mut self.mode else {
            return;
        };
        w.raise_anchor(&root, volume, candidate, hint);
    }

    /// Test-only: how many times [`Self::raise_anchor`] has actually
    /// renamed a new `anchors/<volume>` file into place this session —
    /// see [`WriterState`]'s `anchor_writes` field. `0` in
    /// read-only-degraded mode (a degraded process never writes one).
    #[cfg(test)]
    pub(crate) fn anchor_write_count(&self) -> u64 {
        match &self.mode {
            Mode::Writer(w) => w.anchor_writes.load(Ordering::Relaxed),
            Mode::ReadOnlyDegraded => 0,
        }
    }

    /// Test-only: how many times [`Self::maintain`] has actually
    /// reached `Mode::Writer` this session — see [`WriterState`]'s
    /// `maintain_calls` field. `0` in read-only-degraded mode, matching
    /// `maintain`'s own no-op contract there.
    #[cfg(test)]
    pub(crate) fn maintain_call_count(&self) -> u64 {
        match &self.mode {
            Mode::Writer(w) => w.maintain_calls.load(Ordering::Relaxed),
            Mode::ReadOnlyDegraded => 0,
        }
    }

    #[cfg(test)]
    fn anchor_directory_fsync_count(&self) -> u64 {
        match &self.mode {
            Mode::Writer(w) => w.anchor_directory_fsyncs.load(Ordering::Relaxed),
            Mode::ReadOnlyDegraded => 0,
        }
    }

    /// Read the per-volume anchor + persisted hint (both modes) — see
    /// [`HeadAnchor`]. Untrusted disk input: any parse deviation
    /// degrades the WHOLE file to `None` (absent), warned,
    /// never a hard error — extending the malformed-hint rule that
    /// invalid advisory input is treated as absent.
    #[must_use]
    pub fn read_anchor(&self, volume: &VolumeName) -> Option<HeadAnchor> {
        let path = anchor_path(&self.root, volume);
        read_and_parse_anchor(&path)
    }

    /// Raise the mount-private floor at `anchors/<volume>.mount` — max
    /// semantics, never lowered, writer only, a silent no-op in
    /// read-only-degraded mode. Same mechanism [`Self::raise_anchor`]
    /// uses to detect degraded mode (`Mode::Writer` vs
    /// `Mode::ReadOnlyDegraded`), so the two anchors can never diverge
    /// on what "degraded" means. Unlike [`Self::raise_anchor`] there
    /// is no hint to update and no `None`-candidate shape: this floor
    /// exists for exactly one mount session's own resolve, so every
    /// call proposes a concrete seq.
    ///
    /// # Errors
    /// The reason the floor could not be persisted. **This one is not
    /// best-effort**, unlike the cache's ordinary mutators: in the two modes
    /// that keep a floor it is the only rollback defence there is, and a
    /// mount that accepted seq N while silently storing nothing leaves the
    /// next discovery free to accept an authentic older seq. That is the
    /// same principle that applies to the degraded cache —
    /// *a mount that cannot persist its floor must not pretend to have one*.
    pub fn raise_mount_anchor(&mut self, volume: &VolumeName, seq: u64) -> Result<(), String> {
        let root = self.root.clone();
        let Mode::Writer(w) = &mut self.mode else {
            return Ok(());
        };
        w.raise_mount_anchor(&root, volume, seq)
    }

    /// Test-only: how many times [`Self::raise_mount_anchor`] actually
    /// renamed a new `anchors/<volume>.mount` file into place this session.
    #[cfg(test)]
    pub(crate) fn mount_anchor_write_count(&self) -> u64 {
        match &self.mode {
            Mode::Writer(w) => w.mount_anchor_writes.load(Ordering::Relaxed),
            Mode::ReadOnlyDegraded => 0,
        }
    }

    /// `gran mount --reset-floor`'s only effect: clear the
    /// mount-private floor at `anchors/<volume>.mount` — writer
    /// only, a silent no-op in read-only-degraded mode (matches
    /// every other mutating cache operation: a degraded process
    /// never touches the cache directory at all). Does NOT touch the
    /// SHARED anchor (`anchors/<volume>`) — that is `gran cat`'s own
    /// rollback defence, and clearing it here would be exactly the
    /// silent removal of the shared rollback defence this flag must never perform.
    ///
    /// # Errors
    /// The reason the floor could not be cleared. This one is NOT
    /// best-effort, unlike every other mutator here: `--reset-floor` exists
    /// to unblock a mount, and reporting success while the floor is still in
    /// place strands the operator believing the flag does not work. Failure
    /// to clear the mount-private floor must therefore be returned to the caller.
    pub fn reset_mount_anchor(&mut self, volume: &VolumeName) -> Result<(), String> {
        let root = self.root.clone();
        let Mode::Writer(_) = &mut self.mode else {
            // NOT the silent no-op every other mutator takes here. This
            // one's whole purpose is to clear a floor, and a degraded cache
            // cannot: reporting success would strand the operator believing
            // the flag does not work, which is the failure the doc above
            // names. `raise_mount_anchor`'s identical branch is defended at
            // its call site, where `MountSession::open` refuses a degraded
            // cache in both floor-keeping modes; this one has no such
            // caller, so the refusal belongs here.
            //
            // Its negative is
            // `resetting_the_mount_anchor_in_degraded_mode_is_refused_not_silent`,
            // which reaches the degraded state by opening the same directory
            // twice in ONE process — the same double-open
            // `maintain_is_a_no_op_in_read_only_degraded_mode` and
            // `raise_mount_anchor_is_a_no_op_in_read_only_degraded_mode` use.
            // The fixture measured green across fifteen full suite runs at
            // full nextest concurrency, on macOS only.
            return Err(
                "the cache opened read-only-degraded (another process holds its writer lock), \
                 so the mount-private floor was NOT cleared"
                    .to_owned(),
            );
        };
        WriterState::reset_mount_anchor(&root, volume)
    }

    /// Evict a cached root that failed the reader's own
    /// verifier — writer only, a silent no-op in read-only-degraded
    /// mode. See `WriterState::evict_root_bytes` (private) for the
    /// mechanism.
    pub fn evict_root_bytes(&mut self, volume: &VolumeName, seq: u64) {
        let root = self.root.clone();
        let Mode::Writer(_) = &mut self.mode else {
            return;
        };
        WriterState::evict_root_bytes(&root, volume, seq);
    }

    /// Read the mount-private floor (both modes) — see
    /// [`Self::raise_mount_anchor`]. `None` for an absent file,
    /// a file over `ANCHOR_FILE_MAX_BYTES`, a file that fails
    /// the shared anchor's strict grammar, OR a file that
    /// parses but carries a `hint` line — this floor is never a
    /// hint, so a hint's PRESENCE is itself a grammar deviation
    /// for this file (see `read_and_parse_mount_anchor`).
    #[must_use]
    pub fn read_mount_anchor(&self, volume: &VolumeName) -> Option<u64> {
        let path = mount_anchor_path(&self.root, volume);
        read_and_parse_mount_anchor(&path)
    }

    /// Read a cached root's raw bytes (both modes). The cache stores
    /// bytes, never trust: no hash or signature check happens here —
    /// the caller re-verifies through the same `RootVerifier` path a
    /// wire root takes. SIZE BOUND FIRST, the same [`ROOT_MAX_BYTES`] the wire read takes
    /// (`http_store`'s `GET root`) — `roots/` is attacker-writable
    /// disk, so an oversized file is a miss before any content read,
    /// never an unbounded allocation. Read-side only: roots are
    /// never swept, so this refusal does NOT unlink (unlike the
    /// object path). **A transport-down degraded consumer of these
    /// bytes (`resolve_head_degraded`) must hold a VERIFYING
    /// `RootVerifier`** — checked before this method is ever called
    /// on that path, since these bytes carry no self-verification of
    /// their own. In the unverified default
    /// (`RootVerifier::unverified`), these bytes never select a
    /// transport-down degraded serve at all: they inherit exactly
    /// the verification a wire root would have gotten under that
    /// same reader, which is none, and a degraded read is precisely
    /// the case where nothing else is left to check them.
    #[must_use]
    pub fn get_root_bytes(&self, volume: &VolumeName, seq: u64) -> Option<Vec<u8>> {
        let path = root_bytes_path(&self.root, volume, seq);
        #[cfg(test)]
        run_path_read_post_stat_hook(&path);
        let f = fsguard::open_regular_read(&path).ok()?;
        let meta = f.metadata().ok()?;
        if meta.len() > ROOT_MAX_BYTES {
            crate::observe::OperatorDiagnostic::cached_root_exceeds_the_size_bound_treating_it_as(
                seq,
                meta.len(),
            )
            .emit();
            return None;
        }
        let mut buf = Vec::new();
        // Bounded read (the TOCTOU backstop): see `get`'s identical
        // comment — the descriptor metadata check above is the fast
        // path, this is what actually bounds the bytes read regardless
        // of what the file grows to between the fstat and the read.
        f.take(ROOT_MAX_BYTES + 1).read_to_end(&mut buf).ok()?;
        if buf.len() as u64 > ROOT_MAX_BYTES {
            crate::observe::OperatorDiagnostic::cached_root_exceeds_the_size_bound_treating_it_as(
                seq,
                (buf.len()) as u64,
            )
            .emit();
            return None;
        }
        Some(buf)
    }

    /// The entry point a long-lived writer (a mount, which never calls
    /// [`Self::close`] until it exits) calls to flush the journal buffer
    /// and compact if either existing threshold (`JOURNAL_COMPACT_BYTES`,
    /// `JOURNAL_COMPACT_RECORDS`) is crossed — the same two operations
    /// [`Self::close`] already performs, reached here without consuming
    /// the cache. `WriterState::append_journal_record` also calls
    /// `maybe_compact` itself now, on every tracked touch/evict/insert
    /// (the dominant driver for a mount serving a warm cache is touches,
    /// which never go through this method or through `insert`) — this
    /// method exists for a caller that wants to force a flush of anything
    /// still buffered on its own cadence, without reaching into
    /// `WriterState`'s internals to do it.
    ///
    /// The fourth member of the terminal-method family alongside
    /// [`Self::close`]/[`Self::abandon`], and unlike both: `close(self)`
    /// flushes, compacts and removes the crash guard; `abandon(self)`
    /// does none of those and leaves the guard, for a caller that
    /// detected a crash and must preserve that signal. `maintain(&mut
    /// self)` neither consumes the cache nor touches the guard — it must
    /// leave the cache fully usable for the very next `get`/`insert`,
    /// because the caller keeps running.
    ///
    /// A no-op in `Mode::ReadOnlyDegraded`, matching every other
    /// mutator's contract there. Any failure — flushing or compacting —
    /// is logged and swallowed, never propagated: a failure here must
    /// not fail the read or write that led the caller to call this,
    /// matching every other cache write's existing contract. Only the
    /// FINAL `close()`'s own failure changes the process's exit code.
    pub fn maintain(&mut self) {
        let root = self.root.clone();
        let Mode::Writer(w) = &mut self.mode else {
            return;
        };
        #[cfg(test)]
        w.maintain_calls.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = w.flush_journal_buffer() {
            crate::observe::OperatorDiagnostic::cache_maintain_journal_flush_failed_skipping_compaction_this_cycle(e.failure_class()).emit();
            return;
        }
        if let Err(e) = w.maybe_compact(&root) {
            crate::observe::OperatorDiagnostic::cache_maintain_compaction_failed(e.failure_class())
                .emit();
        }
    }

    /// Flush buffered journal records, compact if either threshold is
    /// crossed (snapshot temp+fsync+rename FIRST, then the journal
    /// truncated via new-file+rename — the order is normative), then
    /// remove the crash guard. A no-op in read-only-degraded mode (it
    /// never held the guard). **Still returns `Ok` if the flush itself
    /// is refused by the free-space watermark**: any still-buffered
    /// records are silently dropped at that point — the object(s) they
    /// would have indexed stay on disk, hash-verifiable and UNINDEXED,
    /// the same single-object crash window this module accepts
    /// elsewhere. `gran verify` REPORTS them as `adopted`; nothing
    /// re-indexes them short of a cold rebuild; reporting an `adopted`
    /// finding does not itself update the index.
    ///
    /// # Errors
    /// [`CacheError::Io`] on a genuine failure flushing, compacting, or
    /// removing the guard — never for a free-space refusal, which is
    /// logged and skipped instead. Also [`CacheError::Io`], named
    /// distinctly, when a `compact` reopen failure earlier this session
    /// (or during this very call) left the journal `journal_broken`
    /// state: the in-memory index
    /// and the objects on disk both stayed correct, but the journal
    /// itself was silently unwritable from that point on, and the
    /// next `Cache::open` will rebuild the index from the last
    /// snapshot, losing journal records written since the failure.
    #[expect(
        clippy::disallowed_methods,
        reason = "remove_file by NAME of this writer's own guard file at a fixed, known path \
                  under root — the same file fsguard::create_regular_lock created at open; \
                  unlink never follows its final path component. Folding NotFound into Ok DOES \
                  mean a foreign removal in between is not distinguishable from this call's own \
                  — that is deliberate, not a gap: close()'s contract is about the END STATE \
                  (no guard present when it returns Ok), which NotFound already satisfies, not \
                  about attributing who removed it"
    )]
    pub fn close(mut self) -> Result<(), CacheError> {
        let root = self.root.clone();
        let Mode::Writer(w) = &mut self.mode else {
            return Ok(());
        };
        w.flush_journal_buffer()?;
        // The compaction result is captured rather than
        // `?`-propagated directly — a retried `compact` attempt CAN fail
        // again for the same reason (`journal_broken` gates nothing here on
        // purpose; see its own doc), and when it does, the specific, named
        // report below is what an operator needs to see, not compact's own
        // raw "reopen journal after compaction: <os error>" message. Any
        // OTHER genuine failure (one that never touched `journal_broken` at
        // all) still surfaces via `compact_result?` below.
        let compact_result = w.maybe_compact(&root);
        if w.journal_broken {
            return Err(CacheError::Io {
                context: "cache journal was lost mid-session after a failed reopen following \
                          compaction; the in-memory index and the objects on disk stayed \
                          correct, but the next open will rebuild the index from the snapshot \
                          and lose journal records written since the failure"
                    .to_string(),
                source: io::Error::other("cache journal reopen failed and was never recovered"),
            });
        }
        compact_result?;
        match fs::remove_file(root.join("guard")) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err("remove guard")(e)),
        }
    }

    /// Release this cache WITHOUT the clean-close sequence: no journal
    /// flush, no compaction, and the `guard` file is LEFT ON DISK. The
    /// deliberate counterpart of [`Self::close`], for a caller that has
    /// detected a crash and must preserve the one signal that says so.
    ///
    /// Consumes `self` and does nothing else: the descriptors it owns —
    /// the writer lock and the journal file — are closed by ordinary
    /// destruction, which releases the `flock`, and the buffered journal
    /// records are discarded unwritten. That is precisely a crash's own
    /// semantics, and it is why this is a NAMED method rather than a
    /// bare `drop`: the behaviour is a contract with a test, not an
    /// accident of `Cache` currently having no `Drop`.
    pub fn abandon(self) {
        drop(self);
    }

    /// Copy counters from the current mode without inspecting files or object names.
    #[must_use]
    pub fn bundle_projection(&self) -> BundleCache {
        match &self.mode {
            Mode::Writer(writer) => BundleCache::Writer {
                quota_bytes: writer.quota_bytes,
                total_bytes: writer.total_bytes,
                live_objects: writer.live.len() as u64,
                journal_bytes: writer.journal_len,
            },
            Mode::ReadOnlyDegraded => BundleCache::ReadOnlyDegraded,
        }
    }

    /// Whether this cache opened READ-ONLY-DEGRADED (another process holds
    /// the writer lock). Hits still serve hash-verified; every write —
    /// insert, touch, eviction, `put_root_bytes`, `raise_anchor` — is a
    /// silent no-op by the mode's contract. Callers that must TELL the
    /// operator a write was skipped (the publish write-through) read this
    /// rather than the writes' return values, which stay `()` by design.
    #[must_use]
    pub fn is_read_only_degraded(&self) -> bool {
        matches!(self.mode, Mode::ReadOnlyDegraded)
    }

    /// The cache's root directory — DIAGNOSTIC-only. [`Self::close`]
    /// consumes `self`, so a caller that must name which cache root a
    /// close failure belongs to (`granary-client`'s `MountSession`
    /// `Drop` backstop) has to
    /// read this BEFORE calling `close`. Never used to derive an
    /// on-disk path: every internal path derivation already has `root`
    /// in scope via `self.root` or a threaded parameter, so this exists
    /// purely to put the root in a log line.
    #[must_use]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests;
