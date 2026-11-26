// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Index recovery: rebuild or reload the cache index from what is on
//! disk, adopting only what the layout can vouch for.
//!
//! **What breaks when this module is wrong:** a cold rebuild or a journal
//! load adopts an entry it should have refused — a foreign name, a digest
//! that does not match its own fan-out, a file wider than its
//! declaration — and the index then asserts that unverified bytes are
//! this cache's content. The opposite failure is the same subject: a
//! recoverable index is discarded, or a truncated journal is replayed
//! past its last trustworthy record.
//!
//! It owns the bounded readers for both index files, the per-entry
//! admission rule, the capped walk, the journal open plan, and the two
//! load paths (writer and read-only). It does NOT own the index FORMAT —
//! that is `granary_core::cacheindex` — nor the quota and eviction the
//! index feeds, which are the cache's own state machine.
//!
//! It uses THREE siblings, in the order `paths` records:
//! `space` (`free_space_precheck`), `paths` (`io_err`, `is_lower_hex`,
//! `decode_hex_digest`) and `write` (`atomic_write`). Nothing here reaches
//! `marker` or `anchor`. It also names [`super::FreeSpace`], which is the
//! CRATE's public vocabulary — `pub` in `space`, re-exported by `cache` and
//! again by `lib.rs` — and so is a parent reach, not a sibling-private one.
//!
//! Out-of-line, and a child one flat
//! level under `cache/`, beside `paths`,
//! `write`, `marker` and `anchor`.

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use granary_core::cacheindex::{self, IndexState, JournalTail};
use granary_core::hash::{DIGEST_LEN, GrainId, HashAlgorithm};
use granary_store::bounds::META_MAX_BYTES;

use crate::fsguard;

use super::paths::{decode_hex_digest, io_err, is_lower_hex};
use super::space::free_space_precheck;
use super::write::atomic_write;
use super::{CacheError, FreeSpace, INDEX_FILE_MAX_BYTES, VerifyIndex, walk_adoption_cap};

/// The empty (zero-record) journal body: the shared envelope alone. `2`
/// is `cacheindex`'s journal-kind tag — frozen by that module's own
/// registry discipline (never reused, never renumbered) but not
/// exported as a named constant; pinned by
/// `an_empty_journal_round_trips_through_decode_journal` rather than by
/// this comment alone.
pub(super) fn empty_journal_bytes() -> Vec<u8> {
    let mut out = Vec::with_capacity(cacheindex::ENVELOPE_LEN);
    out.extend_from_slice(&cacheindex::MAGIC);
    out.extend_from_slice(&cacheindex::VERSION.to_be_bytes());
    out.push(2);
    out
}

pub(super) fn encode_snapshot_err(context: &str, e: &cacheindex::CacheIndexError) -> CacheError {
    CacheError::Io {
        context: context.to_owned(),
        source: io::Error::other(e.to_string()),
    }
}

/// On corrupt-index fallback, the cold rebuild walk adopts every self-identifying
/// leaf under `objects/` whose name parses as 64-hex AND matches its
/// containing 2-hex fanout directory, bounded by [`META_MAX_BYTES`] —
/// anything else is foreign, warned and skipped, never
/// adopted. Rewrites the snapshot (cold, id-ascending order — real LRU
/// order is not recoverable from the filesystem on either target
/// platform) and empties the journal, in that order (the same
/// compaction order `compact` uses). Bumps `walk_reads` once per
/// directory actually read, so a caller that must NOT have walked can
/// assert the counter stayed zero.
/// Admit (or refuse) one `objects/<dir_hex>/<name>` entry into the walk's
/// result: `None` on anything foreign (each case warned at
/// its own call site inside), `Some` only for a properly-fanned-out,
/// appropriately-sized, regular file.
fn admit_walk_entry(dir_hex: &str, file_entry: &fs::DirEntry) -> Option<(GrainId, u32)> {
    let file_name = file_entry.file_name();
    let Some(hex64) = file_name
        .to_str()
        .filter(|s| is_lower_hex(s, DIGEST_LEN * 2))
    else {
        crate::observe::OperatorDiagnostic::cold_rebuild_walk_skipping_a_non_digest_file_name()
            .emit_paths(&[crate::observe::PathSlot::Name(
                "name",
                crate::LogName::entry(&file_name),
            )]);
        return None;
    };
    if hex64.get(..2) != Some(dir_hex) {
        crate::observe::OperatorDiagnostic::cold_rebuild_walk_skipping_a_file_whose_name_does()
            .emit_paths(&[
                crate::observe::PathSlot::Name("name", crate::LogName::entry(&file_name)),
                crate::observe::PathSlot::Name(
                    "dir",
                    crate::LogName::entry(std::ffi::OsStr::new(dir_hex)),
                ),
            ]);
        return None;
    }
    let file_path = file_entry.path();
    // `DirEntry::metadata()`, and it is NOT interchangeable with
    // `fs::symlink_metadata(&file_path)` — the two differ in a way that
    // matters here, and the difference is not the symlink one.
    //
    // NON-FOLLOWING on every platform, which is the property the
    // symlinked-leaf refusal below rests on: std implements
    // `DirEntry::metadata` either as
    // `fstatat(dirfd(self.dir.dirp), name, AT_SYMLINK_NOFOLLOW)` or, on
    // the platforms outside that arm, as an `lstat` on the full path
    // (`library/std/src/sys/fs/unix.rs`:1064-1097 in the pinned 1.97.1
    // toolchain). Neither follows, so a symlinked leaf reports
    // `is_symlink()` and is refused rather than adopted.
    //
    // ANCHORED on some of them, and this is the property
    // `symlink_metadata(&file_path)` does not have anywhere. Where the
    // `fstatat` arm applies, the stat runs against the fanout directory
    // descriptor this walk already holds open, so the only component
    // resolved is the leaf NAME. A full-path stat re-resolves the whole
    // path — `objects/<2hex>` included — on every entry, so a fanout
    // directory swapped for a symlink between the `read_dir` and the
    // stat redirects it to an attacker-chosen file, whose size is then
    // adopted into the index for a digest whose bytes live elsewhere.
    //
    // **The anchored arm excludes MUSL.** Its `cfg` is a six-alternative
    // `any(...)` — `all(target_os = "linux", not(target_env = "musl"))`,
    // `target_os = "android"`, `"fuchsia"`, `"hurd"`, `"illumos"`, and
    // `target_vendor = "apple"` — conjoined with `not(miri)`. Musl is
    // excluded by the first alternative and named by none of the other
    // five, while CI ships `x86_64-unknown-linux-musl` and
    // `aarch64-unknown-linux-musl` release binaries. On those two targets this call is a path lstat
    // and the anchoring is simply absent; what remains there is the
    // non-following property; active replacement between classification
    // and use remains outside the protection, as on every other structural
    // path in this module. Using `DirEntry::metadata()` is still strictly
    // better than naming the full path: it is anchored where the
    // platform offers anchoring and never worse where it does not.
    //
    // `fs::metadata(entry.path())` — a DIFFERENT, FOLLOWING call one
    // easy edit away — is banned by this crate's own ban list, so that
    // edit cannot be made silently even though `DirEntry::metadata`
    // itself carries no ban row (the ban list names methods, and cannot
    // express "the non-following overload").
    let Ok(meta) = file_entry.metadata() else {
        crate::observe::OperatorDiagnostic::cold_rebuild_walk_skipping_an_entry_whose_metadata_could(crate::FailureClass::Io).emit_paths(&[crate::observe::PathSlot::Path("path", crate::LogPath::file(&file_path))]);
        return None;
    };
    if !meta.is_file() {
        crate::observe::OperatorDiagnostic::cold_rebuild_walk_skipping_a_non_regular_file_entry()
            .emit_paths(&[crate::observe::PathSlot::Path(
                "path",
                crate::LogPath::file(&file_path),
            )]);
        return None;
    }
    let len = meta.len();
    if len > META_MAX_BYTES {
        crate::observe::OperatorDiagnostic::cold_rebuild_walk_skipping_an_oversized_foreign_file(
            len,
        )
        .emit_paths(&[crate::observe::PathSlot::Path(
            "path",
            crate::LogPath::file(&file_path),
        )]);
        return None;
    }
    let digest = decode_hex_digest(hex64)?; // unreachable: is_lower_hex already validated shape
    let Ok(size) = u32::try_from(len) else {
        crate::observe::OperatorDiagnostic::cold_rebuild_walk_skipping_a_size_that_cannot_fit(len)
            .emit_paths(&[crate::observe::PathSlot::Path(
                "path",
                crate::LogPath::file(&file_path),
            )]);
        return None;
    };
    Some((GrainId::from_parts(HashAlgorithm::Blake3, digest), size))
}

fn cold_rebuild_walk(
    root: &Path,
    walk_reads: &AtomicU64,
    txn_counter: &AtomicU64,
    free_space: &dyn FreeSpace,
) -> Result<IndexState, CacheError> {
    cold_rebuild_walk_capped(
        root,
        walk_reads,
        txn_counter,
        free_space,
        walk_adoption_cap(),
    )
}

/// [`cold_rebuild_walk`] with the adoption cap as an explicit
/// parameter — production always calls it with [`walk_adoption_cap`];
/// tests inject a small cap to exercise the stop-adopting-and-warn
/// path without needing millions of planted files.
#[expect(
    clippy::disallowed_methods,
    reason = "the cold-start walk over the cache's OWN objects/ directory — the outer read_dir \
              enumerates fanout dirs, the inner one OPENS and reads each fanout dir's contents \
              (a directory open, not a file one). LEAVES are never opened: admit_walk_entry \
              classifies each one with DirEntry::metadata(), the leaf-level check. It does not \
              follow on ANY target, which is the property the symlinked-leaf refusal rests on. \
              It is also ANCHORED — the name resolved relative to the already-open directory \
              descriptor — on linux-gnu and on apple, but NOT on musl, which CI ships: there \
              std takes its full-path lstat arm, so the anchoring is simply absent. Neither \
              property anchors the later path-based eviction in any case; that is \
              unlink_object_leaf's job at the unlink itself. The \
              fanout-level filter is DirEntry::file_type(), which never follows a symlink \
              (a Path::is_dir() here WOULD follow one, which is what \
              cold_rebuild_never_adopts_through_a_symlinked_fanout_directory regression-tests \
              against) — so a fanout symlink PRESENT AT CLASSIFICATION TIME is refused, never \
              walked into. What is bounded is the ADOPTION COUNT (entries.len() < adoption_cap), \
              not the enumeration itself — scanning continues past the cap so every entry still \
              gets classified and counted as dropped, just not pushed. An ACTIVE replacement of \
              the fanout between this classification and the inner read_dir's open remains \
              outside this protection; this classification does not close that race"
)]
pub(super) fn cold_rebuild_walk_capped(
    root: &Path,
    walk_reads: &AtomicU64,
    txn_counter: &AtomicU64,
    free_space: &dyn FreeSpace,
    adoption_cap: usize,
) -> Result<IndexState, CacheError> {
    let objects_dir = root.join("objects");
    let mut entries: Vec<(GrainId, u32)> = Vec::new();
    let mut dropped: u64 = 0;

    walk_reads.fetch_add(1, Ordering::Relaxed);
    let top = match fs::read_dir(&objects_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(IndexState {
                entries: Vec::new(),
                total_bytes: 0,
            });
        }
        Err(e) => return Err(io_err(format!("read {}", objects_dir.display()))(e)),
    };

    for dir_entry in top {
        let dir_entry = dir_entry.map_err(io_err("read objects/ entry"))?;
        let dir_name = dir_entry.file_name();
        let Some(dir_hex) = dir_name.to_str().filter(|s| is_lower_hex(s, 2)) else {
            crate::observe::OperatorDiagnostic::cold_rebuild_walk_skipping_a_non_fanout_entry_under().emit_paths(&[crate::observe::PathSlot::Name("name", crate::LogName::entry(&dir_name))]);
            continue;
        };
        let dir_path = dir_entry.path();
        // `DirEntry::file_type()`, never `Path::is_dir()`: the latter
        // FOLLOWS a symlink whose target is a directory, so a
        // pre-planted `objects/<2hex> -> <outside dir>` was walked
        // straight through and everything inside it adopted.
        // `verify.rs::scan_objects` classifies the identical shape via
        // `file_type()` for exactly this reason. A symlink-to-directory
        // here reports `is_symlink()`, not `is_dir()`, and is skipped
        // like any other non-directory entry.
        let Ok(dir_file_type) = dir_entry.file_type() else {
            crate::observe::OperatorDiagnostic::cold_rebuild_walk_skipping_a_fanout_entry_whose_type(crate::FailureClass::Io).emit_paths(&[crate::observe::PathSlot::Path("path", crate::LogPath::file(&dir_path))]);
            continue;
        };
        if !dir_file_type.is_dir() {
            crate::observe::OperatorDiagnostic::cold_rebuild_walk_skipping_a_non_directory_entry_under().emit_paths(&[crate::observe::PathSlot::Path("path", crate::LogPath::file(&dir_path))]);
            continue;
        }

        walk_reads.fetch_add(1, Ordering::Relaxed);
        let sub =
            fs::read_dir(&dir_path).map_err(io_err(format!("read {}", dir_path.display())))?;
        for file_entry in sub {
            let file_entry = file_entry.map_err(io_err("read objects/ fanout entry"))?;
            if let Some(admitted) = admit_walk_entry(dir_hex, &file_entry) {
                if entries.len() < adoption_cap {
                    entries.push(admitted);
                } else {
                    // Self-wedge guard: adopting past the cap would
                    // write a snapshot the NEXT open's own bounded read
                    // refuses, walking again every time. The dropped
                    // file's bytes are untouched — still on disk,
                    // hash-verifiable by path, and a later `get()` for
                    // it still HITS — but that read does not
                    // re-index it (`touch_id` no-ops for an untracked
                    // id), so it stays outside quota accounting until
                    // the cap is raised or the directory is removed.
                    dropped = dropped.saturating_add(1);
                }
            }
        }
    }
    if dropped > 0 {
        crate::observe::OperatorDiagnostic::cold_rebuild_walk_the_adoption_cap_was_reached_the(
            dropped,
            adoption_cap as u64,
        )
        .emit();
    }

    entries.sort_unstable_by_key(|(id, _)| *id);

    let snapshot_bytes = cacheindex::encode_snapshot(&entries)
        .map_err(|e| encode_snapshot_err("encode snapshot during cold rebuild walk", &e))?;
    let snapshot_path = root.join("index").join("snapshot");
    let journal_path = root.join("index").join("journal");
    let empty_journal = empty_journal_bytes();
    // ONE precheck against the COMBINED footprint, gating both writes
    // together — never two independent, size-dependent prechecks.
    // Checked separately, free space could sit above the (tiny) journal
    // envelope's requirement and below the (much larger) snapshot's:
    // the snapshot rewrite would be skipped while the journal was still
    // reset EMPTY. In `load_index`'s (snapshot present-and-decodable,
    // journal untrustworthy) arm that leaves a VALID-but-stale snapshot
    // beside an empty journal, which the next open decodes as
    // authoritative — so no rebuild is triggered and every object
    // inserted since that snapshot is silently missing from the index.
    // Checked together, either both land or neither is touched and the
    // on-disk pair stays exactly the self-consistent state it already
    // was, deferred to the next open (which simply walks again).
    // `WriterState::compact` is the same shape by a different route: it
    // returns early on the first refusal.
    let combined_len = (snapshot_bytes.len() as u64).saturating_add(empty_journal.len() as u64);
    if free_space_precheck(free_space, combined_len) {
        atomic_write(root, &snapshot_path, &snapshot_bytes, txn_counter, 0o644)?;
        atomic_write(root, &journal_path, &empty_journal, txn_counter, 0o644)?;
    } else {
        crate::observe::OperatorDiagnostic::cold_rebuild_walk_snapshot_rewrite_and_journal_reset_refused().emit();
    }

    Ok(cacheindex::fold(entries, &[]))
}

/// How to (re)open the on-disk journal file after [`load_index`] has
/// decided the in-memory state.
pub(super) enum JournalOpenPlan {
    /// The on-disk journal is already exactly right (freshly written,
    /// or a clean-EOF existing one) — open for append at its current
    /// end.
    OpenAtEnd,
    /// An existing journal's tail was torn: truncate the physical file
    /// to this file-relative trusted length before appending anything
    /// new, so future appends land contiguously after valid data
    /// rather than after garbage a future replay would stop at.
    TruncateTo(u64),
}

/// One `index/snapshot` or `index/journal` read attempt, shared by
/// both files (the bomb-gate rule is identical for either): a bare
/// `fs::read` reserved for reads already known to fit
/// [`INDEX_FILE_MAX_BYTES`].
pub(super) enum IndexFileRead {
    Absent,
    /// Present but either unreadable, or over [`INDEX_FILE_MAX_BYTES`]
    /// — both fold into "cannot be trusted", the SAME class a failed
    /// decode is: an unreadable index file triggers corrupt-index
    /// fallback. The size cap applies that same rule before the read,
    /// rather than introducing a new trust class, and applies identically
    /// to the snapshot and the journal.
    Untrustworthy,
    Present(Vec<u8>),
}

/// `O_NOFOLLOW`: the cache never creates a symlink at
/// `index/snapshot` or `index/journal`, so one there is foreign —
/// following it would let a load (or the writer's own journal append)
/// read or write through to a file OUTSIDE the cache root,
/// matching the same `O_NOFOLLOW` protection `lock` and `guard` already
/// carry. `O_NONBLOCK` travels with it (see `fsguard`): a FIFO at
/// either name would otherwise BLOCK this open rather than fail it.
/// Opens FIRST (no separate path-based pre-stat, which would
/// itself follow a symlink) and gets the size from the OPEN
/// DESCRIPTOR's own metadata (fstat, matching `classify_object_file`'s
/// identical discipline) — still refusing an over-cap file before any
/// content read.
pub(super) fn read_index_file_bounded(path: &Path, what: &'static str) -> IndexFileRead {
    let f = match fsguard::open_regular_read(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return IndexFileRead::Absent,
        // Includes ELOOP (a symlink) and `InvalidData` (a FIFO, socket
        // or directory planted at the name — which would otherwise
        // BLOCK this open indefinitely rather than fail it; see
        // `fsguard`). All the SAME untrustworthy class any other
        // unreadable index file is.
        Err(_) => return IndexFileRead::Untrustworthy,
    };
    let Ok(meta) = f.metadata() else {
        return IndexFileRead::Untrustworthy;
    };
    if meta.len() > INDEX_FILE_MAX_BYTES {
        crate::observe::OperatorDiagnostic::cache_index_file_exceeds_the_size_bound_treating_it(
            meta.len(),
            crate::observe::IndexFileKind::from_adapter(what),
        )
        .emit_paths(&[crate::observe::PathSlot::Path(
            "path",
            crate::LogPath::file(path),
        )]);
        return IndexFileRead::Untrustworthy;
    }
    let mut buf = Vec::new();
    // Bounded read (the TOCTOU backstop): the `metadata` call above is
    // a cheap fast path on the SAME descriptor, but an attacker sharing
    // this trust domain could grow the file between that fstat and this
    // read. `take(CAP + 1)` bounds the bytes actually read regardless
    // of the file's real size.
    if f.take(INDEX_FILE_MAX_BYTES + 1)
        .read_to_end(&mut buf)
        .is_err()
    {
        return IndexFileRead::Untrustworthy;
    }
    if buf.len() as u64 > INDEX_FILE_MAX_BYTES {
        crate::observe::OperatorDiagnostic::cache_index_file_grew_past_the_size_bound_between(
            (buf.len()) as u64,
            crate::observe::IndexFileKind::from_adapter(what),
        )
        .emit_paths(&[crate::observe::PathSlot::Path(
            "path",
            crate::LogPath::file(path),
        )]);
        return IndexFileRead::Untrustworthy;
    }
    IndexFileRead::Present(buf)
}

/// Refuse a FOREIGN entry at `index/snapshot` or `index/journal`
/// BEFORE anything is allowed to write over it.
///
/// The cache only ever puts a regular file at either name, so a
/// symlink, FIFO, socket or directory there is tampered state that must
/// be REPORTED, never erased. Reporting it is not what happens by
/// default, and the reason is an ordering one: an unreadable entry
/// classifies as [`IndexFileRead::Untrustworthy`], which is precisely
/// the trigger for the cold rebuild — and the rebuild's own
/// snapshot+journal [`atomic_write`] finishes with a `rename` ONTO the
/// name, which replaces whatever entry sits there. The later
/// presence check in [`super::build_writer_state`] then finds the fresh
/// regular file the rebuild just made and everything looks clean. So
/// the classification has to run first, and has to refuse rather than
/// fall through.
///
/// `symlink_metadata` (lstat, the ban list's safe half) never follows,
/// so a dangling link is as visible as a live one. Absent is fine (the
/// creation paths below handle it); any other stat error fails closed.
fn refuse_foreign_index_entry(path: &Path, what: &'static str) -> Result<(), CacheError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(()),
        Ok(_) => Err(io_err(what)(io::Error::other(format!(
            "{} is not a regular file; the cache never creates anything else at this name, so \
             it is foreign — refusing rather than rebuilding over it",
            path.display()
        )))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(what)(e)),
    }
}

/// Load (or, on the amended triggers, cold-rebuild-walk) the index.
/// ALWAYS runs on a writer open, guard or no guard — the guard changes
/// only the warning/telemetry, never the load path itself.
///
/// Returns the folded state, how the caller should (re)open the
/// physical journal file, and the on-disk record count post any
/// truncation (for the compaction-threshold check).
pub(super) fn load_index(
    root: &Path,
    walk_reads: &AtomicU64,
    txn_counter: &AtomicU64,
    free_space: &dyn FreeSpace,
    guard_was_present: bool,
) -> Result<(IndexState, JournalOpenPlan, u64), CacheError> {
    let snapshot_path = root.join("index").join("snapshot");
    let journal_path = root.join("index").join("journal");

    // FIRST, before any read and long before any rebuild write: see
    // `refuse_foreign_index_entry`. Every arm below can reach a write
    // at one of these two names, and each of those writes ends in a
    // `rename` that would erase a planted entry.
    refuse_foreign_index_entry(&snapshot_path, "classify index/snapshot")?;
    refuse_foreign_index_entry(&journal_path, "classify index/journal")?;

    let snapshot_read = read_index_file_bounded(&snapshot_path, "snapshot");
    let journal_read = read_index_file_bounded(&journal_path, "journal");

    let walk = |root: &Path| cold_rebuild_walk(root, walk_reads, txn_counter, free_space);

    match (snapshot_read, journal_read) {
        (IndexFileRead::Absent, IndexFileRead::Absent) => {
            // Fresh cache: bootstrap both files empty, snapshot first
            // (the same order compaction always uses), so a creation
            // crash leaves absence, never a short file. The snapshot is
            // 15 bytes (`ENVELOPE_LEN` 7 + `COUNT_FIELD_LEN` 8) and the
            // journal is 7 (`MAGIC` 4 + `VERSION` 2 + kind tag 1); both
            // are deliberately OUTSIDE the
            // free-space precheck: the precheck's "no small-write
            // exemption" rule scopes the RECURRING writes (object,
            // root, anchor, journal record, snapshot compaction), not
            // this one-time creation scaffolding.
            let empty_snapshot = cacheindex::encode_snapshot(&[])
                .map_err(|e| encode_snapshot_err("encode empty snapshot", &e))?;
            atomic_write(root, &snapshot_path, &empty_snapshot, txn_counter, 0o644)?;
            atomic_write(
                root,
                &journal_path,
                &empty_journal_bytes(),
                txn_counter,
                0o644,
            )?;
            Ok((
                IndexState {
                    entries: Vec::new(),
                    total_bytes: 0,
                },
                JournalOpenPlan::OpenAtEnd,
                0,
            ))
        }
        (IndexFileRead::Absent, _) => {
            // Snapshot absent, journal present (or untrustworthy):
            // tamper class either way — walk.
            Ok((walk(root)?, JournalOpenPlan::OpenAtEnd, 0))
        }
        (IndexFileRead::Untrustworthy, _) => {
            // The snapshot itself cannot be trusted (unreadable, or
            // over INDEX_FILE_MAX_BYTES) — walk, regardless of the
            // journal's own state.
            Ok((walk(root)?, JournalOpenPlan::OpenAtEnd, 0))
        }
        (IndexFileRead::Present(snap_bytes), journal_read) => {
            match cacheindex::decode_snapshot(&snap_bytes) {
                Err(_) => Ok((walk(root)?, JournalOpenPlan::OpenAtEnd, 0)),
                Ok(snap_entries) => match journal_read {
                    IndexFileRead::Absent => {
                        if guard_was_present {
                            crate::observe::OperatorDiagnostic::cache_snapshot_present_with_no_journal_a_creation_crash().emit_paths(&[crate::observe::PathSlot::Path("root", crate::LogPath::cache_root(root))]);
                        }
                        atomic_write(
                            root,
                            &journal_path,
                            &empty_journal_bytes(),
                            txn_counter,
                            0o644,
                        )?;
                        Ok((
                            cacheindex::fold(snap_entries, &[]),
                            JournalOpenPlan::OpenAtEnd,
                            0,
                        ))
                    }
                    // An over-cap or otherwise unreadable journal is
                    // the SAME class as a failed envelope decode below
                    // — never replayed, never trusted, walk instead.
                    IndexFileRead::Untrustworthy => {
                        Ok((walk(root)?, JournalOpenPlan::OpenAtEnd, 0))
                    }
                    IndexFileRead::Present(journ_bytes) => {
                        match cacheindex::decode_journal(&journ_bytes) {
                            Err(_) => Ok((walk(root)?, JournalOpenPlan::OpenAtEnd, 0)),
                            Ok((records, tail)) => {
                                let record_count = records.len() as u64; // usize -> u64: always widening on real targets
                                let state = cacheindex::fold(snap_entries, &records);
                                let plan = match tail {
                                    JournalTail::CleanEof => JournalOpenPlan::OpenAtEnd,
                                    JournalTail::TruncatedAt(body_offset) => {
                                        // usize -> u64: always widening on real targets.
                                        let file_relative = (cacheindex::ENVELOPE_LEN as u64)
                                            .saturating_add(body_offset as u64);
                                        JournalOpenPlan::TruncateTo(file_relative)
                                    }
                                };
                                Ok((state, plan, record_count))
                            }
                        }
                    }
                },
            }
        }
    }
}

/// Read-only counterpart to [`load_index`], for
/// `Cache::open_for_verify`. Reads and decodes `index/snapshot` and
/// `index/journal` exactly as `load_index` does, but NEVER falls back
/// to [`cold_rebuild_walk`] — which WRITES a fresh snapshot+journal —
/// and never writes anything itself: a verify run repairs nothing, and
/// repairing would erase the very evidence it exists to report.
///
/// **The trust decision is PAIRWISE, and that is the whole point of
/// this function's return type.** Reading the snapshot first and
/// treating `Absent` as "an empty index" would call an absent snapshot
/// beside a journal full of inserts a clean, empty cache — which
/// `load_index` itself (its `(Absent, _)` arm) calls the TAMPER class
/// and rebuilds from. Only `(Absent, Absent)` is a legitimate
/// empty/bootstrap state; every other way of failing to decode the
/// pair is [`VerifyIndex::Untrusted`], reported as a finding rather
/// than silently audited against.
///
/// A missing journal beside a decodable snapshot can occur when
/// compaction crashes between installing the snapshot and writing the
/// journal. `load_index` repairs this state during recovery, and the
/// verified snapshot is authoritative on its own during the read-only
/// audit.
///
/// `pub(super)`: the parent's verify-open path is the only production
/// caller, and the only test rows are the parent's own. `mod index_load`
/// is private inside `cache`, so neither spelling lets a path outside
/// `cache` name this item DIRECTLY; what `pub(crate)` would buy is the
/// option of a `pub(crate) use` re-export from the parent, which compiles
/// against a `pub(crate)` item and is refused against a `pub(super)` one
/// (`E0364`). Nothing outside `cache` calls this function.
pub(super) fn load_index_read_only(root: &Path) -> VerifyIndex {
    let snapshot_path = root.join("index").join("snapshot");
    let journal_path = root.join("index").join("journal");

    // BOTH reads happen before the decision, exactly as `load_index`
    // does it — the pair is what is trustworthy or not, never one file
    // considered alone.
    let snapshot_read = read_index_file_bounded(&snapshot_path, "snapshot");
    let journal_read = read_index_file_bounded(&journal_path, "journal");

    let untrusted_snapshot = |detail: &'static str| VerifyIndex::Untrusted {
        rel_path: "index/snapshot",
        detail,
    };
    let untrusted_journal = |detail: &'static str| VerifyIndex::Untrusted {
        rel_path: "index/journal",
        detail,
    };

    let snap_entries = match snapshot_read {
        IndexFileRead::Absent => {
            return match journal_read {
                // The only legitimate empty state: nothing has ever
                // been written here. Every object on disk is then
                // reported `adopted`, which is TRUE.
                IndexFileRead::Absent => VerifyIndex::Trusted(IndexState {
                    entries: Vec::new(),
                    total_bytes: 0,
                }),
                // Snapshot gone, journal still there: `load_index`
                // calls this the tamper class and rebuilds. A verify
                // run has no rebuild, so it reports rather than
                // pretending the index is empty.
                _ => untrusted_snapshot("snapshot absent beside a present journal"),
            };
        }
        IndexFileRead::Untrustworthy => {
            return untrusted_snapshot("snapshot unreadable or over the size bound");
        }
        IndexFileRead::Present(bytes) => match cacheindex::decode_snapshot(&bytes) {
            Ok(entries) => entries,
            Err(_) => return untrusted_snapshot("snapshot failed to decode"),
        },
    };

    match journal_read {
        // The documented creation-crash window (snapshot present, no
        // journal) — the snapshot stands on its own.
        IndexFileRead::Absent => VerifyIndex::Trusted(cacheindex::fold(snap_entries, &[])),
        IndexFileRead::Untrustworthy => {
            untrusted_journal("journal unreadable or over the size bound")
        }
        IndexFileRead::Present(journ_bytes) => match cacheindex::decode_journal(&journ_bytes) {
            Err(_) => untrusted_journal("journal failed to decode"),
            // A TORN TAIL is not untrustworthy: `decode_journal`
            // reports exactly how far the clean prefix runs and the
            // fold uses only that. Nothing here truncates the file —
            // the torn tail is the next WRITER's business, and this
            // path has no writer.
            Ok((records, _tail)) => VerifyIndex::Trusted(cacheindex::fold(snap_entries, &records)),
        },
    }
}

#[cfg(test)]
mod tests;
