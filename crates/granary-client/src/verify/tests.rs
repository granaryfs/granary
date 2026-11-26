// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::verify` — `gran verify`'s store/cache walk and
//! re-hash against content address.
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;
use granary_core::cacheindex;
use std::os::unix::fs::PermissionsExt as _;

// ------------------------------------------------------- output format

#[test]
fn percent_encoding_leaves_the_safe_set_untouched() {
    let path = b"objects/ab/cdef.file_name-1".to_vec();
    assert_eq!(percent_encode_path(&path), "objects/ab/cdef.file_name-1");
}

/// A filename containing a TAB and a NEWLINE
/// must not inject a field or a line into the output.
#[test]
fn a_tab_and_a_newline_in_a_filename_do_not_break_the_line_format() {
    let mut path = b"objects/ab/".to_vec();
    path.extend_from_slice(b"cd\tef\n01");
    let f = finding(FindingKind::Foreign, path, "-", "-");
    let line = encode_finding_line(&f);
    assert!(
        !line.contains('\t') || line.matches('\t').count() == 3,
        "the encoded path must contribute no extra tabs beyond the three FIELD \
         separators: {line:?}"
    );
    assert!(
        !line.contains('\n'),
        "the encoded path must contribute no newline at all: {line:?}"
    );
    let fields: Vec<&str> = line.split('\t').collect();
    assert_eq!(
        fields.len(),
        4,
        "exactly four tab-separated fields, regardless of filename content: {line:?}"
    );
    assert!(
        fields[1].contains("%09") && fields[1].contains("%0A"),
        "the tab and newline bytes must be percent-encoded in the path field: {line:?}"
    );
}

#[test]
fn percent_encoding_is_reversible_over_arbitrary_bytes() {
    let path: Vec<u8> = (0u8..=255).collect();
    let encoded = percent_encode_path(&path);
    // Decode it back by hand and compare.
    let mut decoded = Vec::new();
    let bytes = encoded.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or_else(|e| panic!("{e}"));
            decoded.push(u8::from_str_radix(hex, 16).unwrap_or_else(|e| panic!("{e}")));
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    assert_eq!(decoded, path);
}

// -------------------------------------------------------------- fixtures

struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-verify-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cache_origin() -> crate::cache::CacheOrigin {
    crate::cache::CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x11; 32],
        root_key_id: None,
    }
}

/// Write a well-formed object directly under `<root>/objects/`,
/// bypassing `Store`/`Cache` entirely — the walk must find it by
/// filesystem shape alone. Returns its `GrainId`.
fn write_object(root: &Path, bytes: &[u8]) -> GrainId {
    let id = GrainId::of(bytes);
    let hex = id.digest_hex();
    let fanout = &hex[..2];
    fs::create_dir_all(root.join("objects").join(fanout)).unwrap_or_else(|e| panic!("{e}"));
    fs::write(root.join("objects").join(fanout).join(&hex), bytes)
        .unwrap_or_else(|e| panic!("{e}"));
    id
}

fn run_capture(root: &Path) -> (u8, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_verify_with(root, &mut out, &mut err);
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

// --------------------------------------------------- classify_object_file

#[test]
fn a_healthy_object_is_hashed_with_matching_digests() {
    let dir = ScratchDir::new();
    let id = write_object(&dir.0, b"healthy bytes");
    let hex = id.digest_hex();
    let path = dir.0.join("objects").join(&hex[..2]).join(&hex);
    let mut err = Vec::new();
    let outcome = classify_object_file(&path, id, &mut err, b"objects/xx/yy");
    match outcome {
        ScanOutcome::Hashed {
            claimed,
            actual_digest,
            actual_size,
        } => {
            assert_eq!(claimed, id);
            assert_eq!(actual_digest, id);
            assert_eq!(actual_size, "healthy bytes".len() as u64);
        }
        other => panic!("expected Hashed, got {other:?}"),
    }
    assert!(err.is_empty());
}

#[test]
fn a_corrupted_object_hashes_to_a_different_digest_than_claimed() {
    let dir = ScratchDir::new();
    let id = write_object(&dir.0, b"original bytes");
    let hex = id.digest_hex();
    let path = dir.0.join("objects").join(&hex[..2]).join(&hex);
    fs::write(&path, b"tampered!").unwrap_or_else(|e| panic!("{e}"));
    let mut err = Vec::new();
    let outcome = classify_object_file(&path, id, &mut err, b"objects/xx/yy");
    match outcome {
        ScanOutcome::Hashed {
            claimed,
            actual_digest,
            ..
        } => {
            assert_eq!(claimed, id);
            assert_ne!(actual_digest, id, "tampered content must hash differently");
        }
        other => panic!("expected Hashed (with mismatched digests), got {other:?}"),
    }
}

#[test]
fn an_oversized_object_is_classified_oversized_not_hashed() {
    let dir = ScratchDir::new();
    let bytes = vec![b'x'; usize::try_from(META_MAX_BYTES).unwrap_or(usize::MAX) + 1];
    let id = write_object(&dir.0, &bytes);
    let hex = id.digest_hex();
    let path = dir.0.join("objects").join(&hex[..2]).join(&hex);
    let mut err = Vec::new();
    let outcome = classify_object_file(&path, id, &mut err, b"objects/xx/yy");
    assert!(
        matches!(outcome, ScanOutcome::Oversized { .. }),
        "expected Oversized, got {outcome:?}"
    );
}

/// A path that never existed (simulating "vanished between
/// enumeration and open") must classify as `Vanished`, never
/// `Foreign` — and must note it on stderr, never emit a finding.
#[test]
fn a_vanished_path_is_classified_vanished_and_logged() {
    let dir = ScratchDir::new();
    let id = GrainId::of(b"never existed");
    let mut err = Vec::new();
    let outcome = classify_object_file(
        &dir.0.join("nonexistent"),
        id,
        &mut err,
        b"objects/ab/nonexistent",
    );
    assert!(matches!(outcome, ScanOutcome::Vanished));
    assert!(
        String::from_utf8_lossy(&err).contains("vanished"),
        "must diagnose the vanish on stderr"
    );
}

#[test]
fn scan_objects_marks_a_non_hex_name_and_a_mismatched_fanout_as_foreign() {
    let dir = ScratchDir::new();
    fs::create_dir_all(dir.0.join("objects").join("ab")).unwrap_or_else(|e| panic!("{e}"));
    fs::write(dir.0.join("objects").join("ab").join("not-a-digest"), b"x")
        .unwrap_or_else(|e| panic!("{e}"));
    // A well-formed 64-hex name, but filed under the WRONG fanout dir.
    let id = GrainId::of(b"fanout mismatch victim");
    let hex = id.digest_hex();
    fs::write(dir.0.join("objects").join("ab").join(&hex), b"anything")
        .unwrap_or_else(|e| panic!("{e}"));
    // A foreign top-level entry directly under objects/.
    fs::write(dir.0.join("objects").join("stray.txt"), b"y").unwrap_or_else(|e| panic!("{e}"));

    let mut err = Vec::new();
    let entries = scan_objects(&dir.0, &mut err).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        entries.len(),
        3,
        "all three foreign entries must be reported"
    );
    assert!(
        entries
            .iter()
            .all(|e| matches!(e.outcome, ScanOutcome::Foreign { claimed: None })),
        "every one of these must classify as Foreign with no derivable id (a malformed \
         name or a fanout mismatch never yields a real, indexable grain id)"
    );
}

// ------------------------------------------------------------- store mode

/// The spec-named negative, for a STORE root: a corrupted object
/// produces a finding line and exit 1 — and, per the store/cache
/// deletion asymmetry, the file is NEVER deleted (the store may
/// hold the sole copy).
#[test]
fn verify_reports_a_flipped_byte_and_exits_one_for_a_store() {
    let dir = ScratchDir::new();
    crate::store::Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let id = write_object(&dir.0, b"store object bytes");
    let hex = id.digest_hex();
    let path = dir.0.join("objects").join(&hex[..2]).join(&hex);
    // The store writes objects 0444 — chmod writable before tampering.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap_or_else(|e| panic!("{e}"));
    let mut bytes = fs::read(&path).unwrap_or_else(|e| panic!("{e}"));
    if let Some(b) = bytes.last_mut() {
        *b ^= 0xFF;
    }
    fs::write(&path, &bytes).unwrap_or_else(|e| panic!("{e}"));

    let (code, out, _err) = run_capture(&dir.0);
    assert_eq!(code, 1, "a corrupted object must exit 1");
    assert!(out.starts_with("corrupt\t"), "got {out:?}");
    assert!(path.exists(), "a store must NEVER delete a corrupt object");
}

#[test]
fn a_clean_store_exits_zero() {
    let dir = ScratchDir::new();
    crate::store::Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    write_object(&dir.0, b"one healthy object");
    let (code, out, _err) = run_capture(&dir.0);
    assert_eq!(code, 0);
    assert!(out.is_empty());
}

/// Degenerate construction: `objects/` exists but is a REGULAR FILE,
/// not a directory — `read_dir` on it fails with a non-`NotFound`
/// error. This must be cannot-open (exit 2), never a silent clean
/// (exit 0): a store whose object tree cannot even be listed has
/// told verify nothing, and a `0` exit would claim it told verify
/// everything was fine.
#[test]
fn an_objects_dir_that_is_a_regular_file_is_a_refusal_not_a_silent_clean() {
    let dir = ScratchDir::new();
    crate::store::Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    fs::remove_dir_all(dir.0.join("objects")).unwrap_or_else(|e| panic!("{e}"));
    fs::write(dir.0.join("objects"), b"not a directory").unwrap_or_else(|e| panic!("{e}"));

    let (code, out, err) = run_capture(&dir.0);
    assert_eq!(
        code, 2,
        "an unenumerable objects/ must be a refusal, never a silent clean: out={out:?} \
         err={err:?}"
    );
    assert!(
        out.is_empty(),
        "a refusal must never print findings as if the walk had completed: {out:?}"
    );
}

// ------------------------------------------------------------- cache mode

#[test]
fn a_clean_tree_exits_zero() {
    let dir = ScratchDir::new();
    let mut cache =
        Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}"));
    let (id, bytes) = (GrainId::of(b"clean object"), b"clean object".to_vec());
    cache.insert(&id, &bytes);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let (code, out, _err) = run_capture(&dir.0);
    assert_eq!(code, 0, "a clean cache must exit 0; stdout was {out:?}");
    assert!(out.is_empty());
}

/// The spec-named negative for a CACHE root: a corrupted object
/// produces a `corrupt` finding line and exits 1 — and is LEFT ON
/// DISK, byte-identical. That last clause is the inverse of what
/// this test asserted before the diagnostic-only decision, when a
/// cache DELETED a corrupt object because it is refetchable; it is
/// now the headline proof of the decision itself.
#[test]
fn verify_reports_a_flipped_byte_and_exits_one() {
    let dir = ScratchDir::new();
    let mut cache =
        Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}"));
    let (id, bytes) = (GrainId::of(b"corrupt me"), b"corrupt me".to_vec());
    cache.insert(&id, &bytes);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let hex = id.digest_hex();
    let path = dir.0.join("objects").join(&hex[..2]).join(&hex);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap_or_else(|e| panic!("{e}"));
    let mut on_disk = fs::read(&path).unwrap_or_else(|e| panic!("{e}"));
    if let Some(b) = on_disk.last_mut() {
        *b ^= 0xFF;
    }
    fs::write(&path, &on_disk).unwrap_or_else(|e| panic!("{e}"));

    let (code, out, _err) = run_capture(&dir.0);
    assert_eq!(code, 1, "got stdout {out:?}");
    assert!(out.starts_with("corrupt\t"), "got {out:?}");
    // EXACTLY ONE finding. The `Corrupt` arm does NOT return
    // before recording the id as SEEN — `seen_ids.insert(claimed)`
    // precedes the digest comparison — so an indexed-and-corrupt
    // object produces one line, not a second `dropped` one. This
    // assertion is what would catch a later edit that reversed
    // that order.
    assert_eq!(
        out.lines().count(),
        1,
        "an INDEXED corrupt object is one finding, not also `dropped`: {out:?}"
    );
    // THE HEADLINE ASSERTION OF THE DIAGNOSTIC-ONLY DECISION, and
    // it is the exact inverse of what this test asserted before
    // verify became diagnostic-only. Reclaiming the object means
    // naming it by a path rebuilt after the walk; verify reports
    // it and leaves it alone. The cache reclaims it on its own
    // next read of it.
    assert!(
        path.exists(),
        "verify must REPORT a corrupt object and leave it on disk — it repairs nothing"
    );
    assert_eq!(
        fs::read(&path).unwrap_or_else(|e| panic!("{e}")),
        on_disk,
        "and it must not have been rewritten either — the corrupt bytes stay exactly as \
         they were, so a second run reports the same finding"
    );
}

/// The spec-named test, both directions in ONE run: an orphaned
/// file (present on disk, absent from the index) is `adopted`; an
/// index entry whose file is gone is `dropped`. Under the
/// diagnostic-only decision it additionally pins the two things
/// that make those reports HONEST — the index files are
/// byte-identical afterwards, and a SECOND run says exactly the
/// same thing. A clean second run would mean the first run repaired
/// the index, which a diagnostic-only verify never does.
#[test]
fn verify_reports_adopted_and_dropped_without_touching_the_index() {
    let dir = ScratchDir::new();
    let mut cache =
        Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}"));
    let (dropped_id, dropped_bytes) =
        (GrainId::of(b"will be dropped"), b"will be dropped".to_vec());
    cache.insert(&dropped_id, &dropped_bytes);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    // Simulate the single-object crash window's OPPOSITE case: the
    // index entry survives but the file is deleted out-of-band.
    let dhex = dropped_id.digest_hex();
    fs::remove_file(dir.0.join("objects").join(&dhex[..2]).join(&dhex))
        .unwrap_or_else(|e| panic!("{e}"));

    // Simulate the documented crash window itself: a file present,
    // absent from the index.
    let adopted_id = write_object(&dir.0, b"will be adopted");

    let snapshot_path = dir.0.join("index").join("snapshot");
    let journal_path = dir.0.join("index").join("journal");
    let snapshot_before = fs::read(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));
    let journal_before = fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}"));

    let (code, out, _err) = run_capture(&dir.0);
    assert_eq!(code, 1, "got {out:?}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "exactly two findings: {out:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("dropped\t") && l.contains(&dropped_id.to_string())),
        "missing dropped finding: {out:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("adopted\t") && l.contains(&adopted_id.to_string())),
        "missing adopted finding: {out:?}"
    );

    // NOTHING WAS WRITTEN. Byte-identity on both index files is
    // the mechanical form of "verify repairs nothing" — an
    // assertion a degenerate implementation that quietly rewrote
    // the snapshot could not pass.
    assert_eq!(
        fs::read(&snapshot_path).unwrap_or_else(|e| panic!("{e}")),
        snapshot_before,
        "verify must not rewrite index/snapshot"
    );
    assert_eq!(
        fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}")),
        journal_before,
        "verify must not append to or truncate index/journal"
    );

    // And the findings REPEAT: there is no convergence, by design.
    // An operator re-running verify after reading its output must
    // see the same two lines, not a falsely clean run.
    let (code2, out2, _err2) = run_capture(&dir.0);
    assert_eq!(
        code2, 1,
        "the divergence persists until repair lands: {out2:?}"
    );
    let mut first: Vec<&str> = out.lines().collect();
    let mut second: Vec<&str> = out2.lines().collect();
    first.sort_unstable();
    second.sort_unstable();
    assert_eq!(
        first, second,
        "a second run must report exactly the same findings"
    );
}

/// A HEALTHY indexed object that transiently fails to open for a
/// reason other than `NotFound` (here: no read permission) must be
/// reported exactly ONCE, as `foreign` — never ALSO as `dropped`,
/// which would evict it from the index even though its bytes are
/// still sitting on disk, unread. Restoring readability and
/// re-verifying must find it still indexed (no `adopted`).
#[test]
fn a_transiently_unreadable_indexed_object_is_reported_once_and_never_evicted() {
    let dir = ScratchDir::new();
    let mut cache =
        Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}"));
    let (id, bytes) = (
        GrainId::of(b"healthy but locked out"),
        b"healthy but locked out".to_vec(),
    );
    cache.insert(&id, &bytes);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let hex = id.digest_hex();
    let path = dir.0.join("objects").join(&hex[..2]).join(&hex);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap_or_else(|e| panic!("{e}"));

    let (code, out, _err) = run_capture(&dir.0);
    assert_eq!(code, 1, "got {out:?}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "a transiently-unreadable indexed object must produce exactly ONE finding, not \
         also a spurious dropped: {out:?}"
    );
    assert!(lines[0].starts_with("foreign\t"), "got {out:?}");

    // Restore permissions and re-verify: the index must still know
    // this object — no `adopted` line, proving it was never evicted.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap_or_else(|e| panic!("{e}"));
    let (code2, out2, _err2) = run_capture(&dir.0);
    assert_eq!(
        code2, 0,
        "the healthy object must never have been evicted from the index: {out2:?}"
    );
    assert!(!out2.contains("adopted"), "got {out2:?}");
}

/// Degenerate construction: a whole FANOUT directory exists but
/// cannot be enumerated (chmod 000). This must be REPORTED (never
/// silently skipped — a `continue` on this `read_dir`
/// failure would drop it from the walk entirely) but must NOT drive a
/// `dropped` finding, and must NOT evict, the indexed object that
/// lives under it: the run never actually looked at that part of
/// the disk, so it has no evidence the object is gone.
#[test]
fn an_unreadable_fanout_dir_is_reported_but_never_falsely_drops_its_indexed_objects() {
    let dir = ScratchDir::new();
    let mut cache =
        Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}"));
    let (id, bytes) = (
        GrainId::of(b"trapped under an unreadable fanout"),
        b"trapped under an unreadable fanout".to_vec(),
    );
    cache.insert(&id, &bytes);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let hex = id.digest_hex();
    let fanout_dir = dir.0.join("objects").join(&hex[..2]);
    fs::set_permissions(&fanout_dir, fs::Permissions::from_mode(0o000))
        .unwrap_or_else(|e| panic!("{e}"));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_capture(&dir.0)));
    // Restore permissions BEFORE asserting, so a failed assertion
    // still leaves the scratch dir cleanly removable.
    fs::set_permissions(&fanout_dir, fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
    let (code, out, _err) = result.unwrap_or_else(|e| std::panic::resume_unwind(e));

    assert_eq!(
        code, 1,
        "an unreadable fanout dir must be a reported finding, not silence: {out:?}"
    );
    assert!(
        !out.contains("dropped"),
        "an unreadable fanout dir must never drive a false dropped/eviction: {out:?}"
    );
    assert!(
        out.contains("foreign\t"),
        "the unreadable fanout dir itself must be reported: {out:?}"
    );

    // A second run (now readable) must find the object still
    // indexed — no `adopted`, proving nothing was evicted on the
    // evidence of a directory this run could not read.
    let (code2, out2, _err2) = run_capture(&dir.0);
    assert_eq!(
        code2, 0,
        "the object under the once-unreadable fanout must never have been evicted: {out2:?}"
    );
    assert!(!out2.contains("adopted"), "got {out2:?}");
}

/// BOTH `read_dir` iteration sites in [`scan_objects`] must report an
/// errored `DirEntry`. A site that silently `continue`s — recording
/// neither a finding nor an `unreadable_fanouts` entry — lets
/// `find_dropped` report `dropped` for an indexed id it never
/// actually looked at, exactly the false finding
/// `ScanOutcome::FanoutUnreadable` exists to prevent. A genuine
/// per-`DirEntry` `read_dir` iteration failure (as opposed to
/// `read_dir` itself failing to open, which the sibling
/// `an_unreadable_fanout_dir_...` test above drives through chmod)
/// is an OS-level race with no deterministic, portable trigger, so
/// this exercises the accumulator directly with the outcome the
/// fixed call sites now produce.
///
/// The TOP-level site (line ~235) has no `dir_hex` at all — the
/// `DirEntry` itself failed before any name could be read — so its
/// `ScanOutcome::TopLevelUnreadable` must make `find_dropped` skip
/// EVERY indexed id this run, not just one prefix.
#[test]
fn a_top_level_unreadable_direntry_never_drives_a_false_dropped_eviction() {
    let indexed_id = GrainId::of(b"indexed but this run never actually saw the fanout list");
    let mut index_map = BTreeMap::new();
    index_map.insert(indexed_id, 64u32);

    let mut acc = AuditAccumulator::default();
    acc.handle_entry(
        ScanEntry {
            rel_path: b"objects/?".to_vec(),
            outcome: ScanOutcome::TopLevelUnreadable,
        },
        &index_map,
    );
    acc.find_dropped(Path::new("/unused"), &index_map);

    assert!(
        !acc.findings.iter().any(|f| f.kind == FindingKind::Dropped),
        "a top-level unreadable entry must never drive a dropped finding for an id this \
         run never looked for: {:?}",
        acc.findings
    );
    assert_eq!(
        acc.findings.len(),
        1,
        "the unreadable entry itself must still be reported: {:?}",
        acc.findings
    );
    assert_eq!(acc.findings[0].kind, FindingKind::Foreign);
    let _ = indexed_id;
}

/// The FILE-level site (line ~284) DOES still know its `dir_hex` —
/// the failure is one entry inside an otherwise-enumerable fanout
/// dir — so it is folded into the existing
/// `ScanOutcome::FanoutUnreadable { dir_hex }` outcome exactly as a
/// whole-fanout `read_dir` failure is, scoping the doubt to that one
/// prefix rather than the whole run.
#[test]
fn a_file_level_unreadable_direntry_scopes_the_false_dropped_guard_to_its_own_fanout() {
    let indexed_id = GrainId::of(b"indexed under the one fanout this run half-read");
    let hex = indexed_id.digest_hex();
    let mut index_map = BTreeMap::new();
    index_map.insert(indexed_id, 64u32);

    let mut acc = AuditAccumulator::default();
    let mut rel = b"objects/".to_vec();
    rel.extend_from_slice(&hex.as_bytes()[..2]);
    rel.push(b'/');
    rel.push(b'?');
    acc.handle_entry(
        ScanEntry {
            rel_path: rel,
            outcome: ScanOutcome::FanoutUnreadable {
                dir_hex: hex[..2].to_owned(),
            },
        },
        &index_map,
    );
    acc.find_dropped(Path::new("/unused"), &index_map);

    assert!(
        !acc.findings.iter().any(|f| f.kind == FindingKind::Dropped),
        "an id under an unreadable fanout must never be reported dropped: {:?}",
        acc.findings
    );
    assert!(!acc.top_level_unreadable);
}

/// The size a `Hashed` outcome carries is the length of the bytes
/// that were HASHED, not whatever an earlier `metadata` call saw.
/// A digest matching `claimed` pins the content and therefore its
/// length, so the two can only disagree when the file changed
/// between the stat and the read — exactly the case where trusting
/// the stat would record a size the verified bytes contradict.
#[test]
fn a_hashed_outcome_reports_the_length_of_the_bytes_it_actually_hashed() {
    let dir = ScratchDir::new();
    let body = b"the bytes that get hashed".to_vec();
    let id = write_object(&dir.0, &body);
    let path = crate::cache::object_path(&dir.0, &id);

    let mut err = Vec::new();
    match classify_object_file(&path, id, &mut err, b"objects/x") {
        ScanOutcome::Hashed {
            actual_digest,
            actual_size,
            ..
        } => {
            assert_eq!(actual_digest, id, "the planted bytes must verify");
            assert_eq!(
                actual_size,
                body.len() as u64,
                "the reported size must be the hashed buffer's length"
            );
        }
        other => panic!("a well-formed planted object must hash: {other:?}"),
    }
}

#[test]
fn a_recorded_size_that_disagrees_with_the_file_is_reported_and_not_corrected() {
    let dir = ScratchDir::new();
    let mut cache =
        Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}"));
    let (id, bytes) = (
        GrainId::of(b"size mismatch victim"),
        b"size mismatch victim".to_vec(),
    );
    cache.insert(&id, &bytes);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    // Forge the snapshot: same id, WRONG (understated) size.
    let snapshot_path = dir.0.join("index").join("snapshot");
    let forged = cacheindex::encode_snapshot(&[(id, 0)]).unwrap_or_else(|e| panic!("{e}"));
    fs::write(&snapshot_path, &forged).unwrap_or_else(|e| panic!("{e}"));
    let journal_path = dir.0.join("index").join("journal");
    fs::write(&journal_path, empty_journal_for_test()).unwrap_or_else(|e| panic!("{e}"));

    let (code, out, _err) = run_capture(&dir.0);
    assert_eq!(code, 1, "got {out:?}");
    assert!(out.starts_with("size-mismatch\t"), "got {out:?}");
    assert!(
        out.contains(&format!("\t0\t{}", bytes.len())),
        "got {out:?}"
    );

    // The forged snapshot is left EXACTLY as planted, and the
    // finding repeats. This test asserted the opposite before —
    // that the corrected size was durably written — and that
    // assertion was the reconciliation write, now removed.
    assert_eq!(
        fs::read(&snapshot_path).unwrap_or_else(|e| panic!("{e}")),
        forged,
        "verify must not correct the recorded size, only report it"
    );
    let (code2, out2, _err2) = run_capture(&dir.0);
    assert_eq!(
        code2, 1,
        "the mismatch persists until repair lands: {out2:?}"
    );
    assert!(out2.starts_with("size-mismatch\t"), "got {out2:?}");
}

#[test]
fn report_only_mode_never_mutates_and_reports_no_index_findings() {
    let dir = ScratchDir::new();
    let holder = Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}"));
    // holder keeps the writer lock ALIVE for the whole test.

    // An orphan AND a corrupt object both exist while the lock is held.
    let orphan = write_object(&dir.0, b"an orphan while locked");
    let corrupt_id = write_object(&dir.0, b"corrupt while locked");
    let chex = corrupt_id.digest_hex();
    let cpath = dir.0.join("objects").join(&chex[..2]).join(&chex);
    fs::write(&cpath, b"tampered").unwrap_or_else(|e| panic!("{e}"));

    let (code, out, err) = run_capture(&dir.0);
    assert_eq!(code, 1, "the corrupt object is still a finding: {out:?}");
    assert!(
        !out.contains("adopted"),
        "report-only must never report an index finding: {out:?}"
    );
    assert!(out.contains("corrupt\t"), "got {out:?}");
    assert!(
        err.contains("held by another process"),
        "must diagnose report-only mode on stderr: {err:?}"
    );
    // Never mutates: neither file was touched.
    let ohex = orphan.digest_hex();
    assert!(dir.0.join("objects").join(&ohex[..2]).join(&ohex).exists());
    assert!(
        cpath.exists(),
        "report-only must never delete, even a corrupt object"
    );

    drop(holder);
}

fn empty_journal_for_test() -> Vec<u8> {
    let mut out = Vec::with_capacity(cacheindex::ENVELOPE_LEN);
    out.extend_from_slice(&cacheindex::MAGIC);
    out.extend_from_slice(&cacheindex::VERSION.to_be_bytes());
    out.push(2); // journal kind
    out
}

// ------------------------------------------------- multi-entry snapshots

/// TWO orphans, not one, and it is not redundant with the
/// single-orphan cases: `find_dropped` and the adopted path both
/// iterate `BTreeMap`s, and a bug that reported only the first
/// entry of a multi-entry set would pass every one-entry test in
/// this file. It also pins the no-convergence property at more
/// than one entry — this test asserted CONVERGENCE before, which
/// was the reconciliation write, now removed.
#[test]
fn two_orphans_are_both_reported_on_every_run() {
    let dir = ScratchDir::new();
    drop(Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}")));
    let first = write_object(&dir.0, b"orphan alpha");
    let second = write_object(&dir.0, b"orphan beta");

    let snapshot_path = dir.0.join("index").join("snapshot");
    let journal_path = dir.0.join("index").join("journal");
    let snapshot_before = fs::read(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));
    let journal_before = fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}"));

    let (code, out, _err) = run_capture(&dir.0);
    assert_eq!(code, 1, "got {out:?}");
    let adopted: Vec<&str> = out.lines().filter(|l| l.starts_with("adopted\t")).collect();
    assert_eq!(
        adopted.len(),
        2,
        "both orphans must be reported adopted, not just the first: {out:?}"
    );
    assert!(
        adopted.iter().any(|l| l.contains(&first.to_string()))
            && adopted.iter().any(|l| l.contains(&second.to_string())),
        "both ids must appear by name: {out:?}"
    );

    assert_eq!(
        fs::read(&snapshot_path).unwrap_or_else(|e| panic!("{e}")),
        snapshot_before,
        "adoption is REPORTED, never written"
    );
    assert_eq!(
        fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}")),
        journal_before,
        "and no journal Insert is appended either"
    );

    let (code2, out2, _err2) = run_capture(&dir.0);
    assert_eq!(code2, 1, "the orphans are still orphans: {out2:?}");
    assert_eq!(
        out2.lines().filter(|l| l.starts_with("adopted\t")).count(),
        2,
        "a second run reports the same two, by design — nothing adopted them: {out2:?}"
    );
}

/// The hard-link disclosure primitive, closed IN ITS NO-RACE FORM
/// — the multiply-linked case, which is the one needing nothing
/// from the victim. The sole-link variant (link, then wait for the
/// original pathname to go) is NOT closed and is a register row;
/// this test does not claim otherwise. `link(2)` needs
/// search on the target's directory and write on the destination —
/// not read on the target, and not root — so an attacker who can
/// write into `objects/` links a file they CANNOT READ to a 64-hex
/// name of their choosing, and an operator's `gran verify` run
/// hashes it and prints the digest (a content-confirmation oracle)
/// or, past the size bound, its exact length.
///
/// It is fixed HERE rather than folded into the
/// descriptor-relative register row because that row's fix does not
/// close it: `openat(fanout_fd, name, O_NOFOLLOW)` opens a hard
/// link exactly as `open` does. Discharging the row would have
/// left this primitive live.
///
/// Mutation probe: drop the `nlink() > 1` arm and this test fails
/// with a `Hashed` outcome carrying the victim's digest.
#[test]
fn a_hard_linked_object_leaf_is_foreign_and_is_never_hashed() {
    let dir = ScratchDir::new();
    let secret = dir.0.join("a-file-the-attacker-cannot-read");
    let secret_bytes = b"the contents of somebody else's file".to_vec();
    fs::write(&secret, &secret_bytes).unwrap_or_else(|e| panic!("{e}"));
    let secret_digest = GrainId::of(&secret_bytes);

    // A 64-hex name the attacker CHOOSES — nothing constrains it to
    // relate to the linked file at all.
    let chosen = GrainId::of(b"any name at all");
    let hex = chosen.digest_hex();
    let fanout = dir.0.join("objects").join(&hex[..2]);
    fs::create_dir_all(&fanout).unwrap_or_else(|e| panic!("{e}"));
    let planted = fanout.join(&hex);
    fs::hard_link(&secret, &planted).unwrap_or_else(|e| panic!("hard_link: {e}"));

    let mut err = Vec::new();
    let outcome = classify_object_file(&planted, chosen, &mut err, b"objects/x");
    match outcome {
        ScanOutcome::Foreign { claimed } => assert_eq!(claimed, Some(chosen)),
        other => panic!(
            "a multiply-linked leaf must never be opened and hashed — it leaks the \
             digest of a file the attacker cannot read: {other:?}"
        ),
    }
    assert!(
        !format!("{outcome:?}").contains(&secret_digest.digest_hex()),
        "the victim's digest must not appear anywhere in the outcome"
    );

    // And a legitimate object — staged and renamed, so exactly one
    // link — must still hash normally. Without this the guard could
    // be satisfied by refusing everything.
    let honest = write_object(&dir.0, b"an ordinary object");
    let honest_path = crate::cache::object_path(&dir.0, &honest);
    assert!(
        matches!(
            classify_object_file(&honest_path, honest, &mut err, b"objects/y"),
            ScanOutcome::Hashed { .. }
        ),
        "a normal single-linked object must still be hashed"
    );
}

// ------------------------------------------- the whole-verb contract

/// **C13, and it is the test the others cannot substitute for.**
/// Every other case here drives ONE finding kind through the walk.
/// This drives all SIX in a single audit run and then asserts the
/// two properties that make the whole decision true at once: the
/// index files are byte-identical afterwards, and every object the
/// run complained about is still on disk.
///
/// The gap it closes, precisely: without this row, an
/// implementation that deleted oversized objects — the one kind no
/// end-to-end test covered — passed the entire suite.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the whole point is ONE run producing all six kinds — splitting the fixture \
              across helpers would let a kind stop firing while the test still passed, \
              which is the gap this test exists to close"
)]
fn a_run_producing_every_finding_kind_changes_nothing_on_disk() {
    let dir = ScratchDir::new();
    drop(Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}")));

    let healthy = write_object(&dir.0, b"healthy and correctly indexed");
    let corrupt = GrainId::of(b"claims to be this");
    let dropped = GrainId::of(b"indexed but its file is gone");
    let mismatch = write_object(&dir.0, b"indexed at the wrong size");
    let adopted = write_object(&dir.0, b"on disk, unknown to the index");

    // `corrupt`: a file AT its name whose bytes hash to something
    // else. Planted by hand, since `write_object` names by content.
    let chex = corrupt.digest_hex();
    fs::create_dir_all(dir.0.join("objects").join(&chex[..2])).unwrap_or_else(|e| panic!("{e}"));
    let corrupt_path = dir.0.join("objects").join(&chex[..2]).join(&chex);
    fs::write(&corrupt_path, b"but these are different bytes entirely")
        .unwrap_or_else(|e| panic!("{e}"));

    // `oversized`: past META_MAX_BYTES, so it is classified before
    // any hash is attempted. Its name is valid, which is what gets
    // it past `scan_objects`' admission checks.
    let over_id = GrainId::of(b"an object nobody will ever hash");
    let ohex = over_id.digest_hex();
    fs::create_dir_all(dir.0.join("objects").join(&ohex[..2])).unwrap_or_else(|e| panic!("{e}"));
    let over_path = dir.0.join("objects").join(&ohex[..2]).join(&ohex);
    let over_len = usize::try_from(META_MAX_BYTES + 1).unwrap_or_else(|e| panic!("{e}"));
    fs::write(&over_path, vec![0u8; over_len]).unwrap_or_else(|e| panic!("{e}"));

    // `foreign`: a name that is not a digest at all.
    let foreign_path = dir.0.join("objects").join(&chex[..2]).join("not-a-digest");
    fs::write(&foreign_path, b"whatever this is").unwrap_or_else(|e| panic!("{e}"));

    // Forge the index: healthy at its true size, mismatch at a
    // wrong one, dropped present with no file, corrupt indexed so
    // it is a corruption rather than an orphan.
    let mut entries: Vec<(GrainId, u32)> = vec![
        (
            healthy,
            u32::try_from(b"healthy and correctly indexed".len()).unwrap_or_else(|e| panic!("{e}")),
        ),
        (mismatch, 1), // deliberately wrong
        (dropped, 64),
        (corrupt, 38),
    ];
    entries.sort_unstable_by_key(|(id, _)| *id);
    let snapshot_path = dir.0.join("index").join("snapshot");
    let journal_path = dir.0.join("index").join("journal");
    fs::write(
        &snapshot_path,
        cacheindex::encode_snapshot(&entries).unwrap_or_else(|e| panic!("{e}")),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    fs::write(&journal_path, empty_journal_for_test()).unwrap_or_else(|e| panic!("{e}"));

    let snapshot_before = fs::read(&snapshot_path).unwrap_or_else(|e| panic!("{e}"));
    let journal_before = fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}"));
    let corrupt_before = fs::read(&corrupt_path).unwrap_or_else(|e| panic!("{e}"));
    let over_len_before = fs::metadata(&over_path)
        .unwrap_or_else(|e| panic!("{e}"))
        .len();

    let (code, out, _err) = run_capture(&dir.0);
    assert_eq!(code, 1, "got {out:?}");

    for kind in [
        "corrupt\t",
        "dropped\t",
        "adopted\t",
        "foreign\t",
        "oversized\t",
        "size-mismatch\t",
    ] {
        assert!(
            out.lines().any(|l| l.starts_with(kind)),
            "every finding kind must appear in one run; missing {kind:?} in {out:?}"
        );
    }
    assert!(
        out.lines().any(|l| l.contains(&adopted.to_string())),
        "the adopted orphan must be named: {out:?}"
    );

    // NOTHING CHANGED. The index pair byte-for-byte, the corrupt
    // object byte-for-byte, and the oversized object still at its
    // full length — the one that had no end-to-end coverage at all.
    assert_eq!(
        fs::read(&snapshot_path).unwrap_or_else(|e| panic!("{e}")),
        snapshot_before,
        "index/snapshot must be byte-identical"
    );
    assert_eq!(
        fs::read(&journal_path).unwrap_or_else(|e| panic!("{e}")),
        journal_before,
        "index/journal must be byte-identical"
    );
    assert_eq!(
        fs::read(&corrupt_path).unwrap_or_else(|e| panic!("{e}")),
        corrupt_before,
        "a corrupt object is reported and LEFT, never unlinked or rewritten"
    );
    assert_eq!(
        fs::metadata(&over_path)
            .unwrap_or_else(|e| panic!("{e}"))
            .len(),
        over_len_before,
        "an OVERSIZED object is reported and LEFT — the kind no other test covers"
    );
    assert!(
        foreign_path.exists(),
        "a foreign file is reported, not removed"
    );
    for (what, id) in [
        ("adopted", adopted),
        ("size-mismatch", mismatch),
        ("healthy", healthy),
    ] {
        assert!(
            crate::cache::object_path(&dir.0, &id).exists(),
            "the {what} object must survive too — asserting only that CORRUPT and \
             OVERSIZED survive leaves every other path free to delete"
        );
    }

    // A SECOND RUN reports the same six kinds. That is what closes
    // what a single run leaves open: an
    // implementation that removed or rewrote the adopted or
    // mismatched object AFTER recording its first finding satisfies
    // every assertion above and diverges on the next run.
    let (code2, out2, _err2) = run_capture(&dir.0);
    assert_eq!(code2, 1, "the divergence persists: {out2:?}");
    let mut first: Vec<&str> = out.lines().collect();
    let mut second: Vec<&str> = out2.lines().collect();
    first.sort_unstable();
    second.sort_unstable();
    assert_eq!(
        first, second,
        "a second run must report exactly the same findings — no convergence, by design"
    );
}

// --------------------------------------------------- the standing gate

/// **The decision, mechanically enforced instead of asserted in
/// prose.** Every other test here checks a BEHAVIOUR at one input;
/// this checks the STRUCTURAL property the whole diagnostic-only
/// decision rests on — that nothing in this module's production
/// half can mutate the filesystem — and it is the form that
/// survives a later edit.
///
/// The failure mode this guards against is a defect class that
/// recurs, each fix closing only the instance last named. A
/// behavioural test proves one path does not
/// delete; only this proves no path does, including one added
/// later by someone unaware that verify must only report. If repair
/// legitimately returns using descriptor-relative filesystem operations, whoever
/// lands it will have to delete this test deliberately — which is
/// the point: it makes the decision visible at the moment it is
/// reversed, rather than letting it erode.
///
/// **What it does NOT prove, stated so a green run is not read as
/// more than it is.** It scans THIS module's source, so a mutation
/// routed through a helper in another module — some future
/// `cache::commit_whatever(root)` called from here — passes it
/// cleanly. The current call graph was traced and is clean, but a
/// trace is a fact about today and this is a tripwire for the
/// DIRECT form, which is the form all eight recurrences of this
/// defect actually took. Reading what the callees do is still a
/// human job.
#[test]
fn the_production_half_of_this_module_cannot_mutate_the_filesystem() {
    const SRC: &str = include_str!("../verify.rs");
    // Widened once: the first pass listed the nine obvious
    // mutators and missed five ways to write a file that do not
    // spell "write".
    // A SLICE, not a fixed-size array: the count is not a fact
    // worth maintaining, and getting it wrong is a compile error at
    // exactly the moment someone is trying to make the gate
    // stricter.
    const MUTATORS: &[&str] = &[
        "remove_file",
        "remove_dir",
        "::rename",
        "create_dir",
        "set_len",
        "set_permissions",
        "File::create",
        "File::options",
        "fs::write",
        "fs::copy",
        "fs::hard_link",
        "fs::soft_link",
        // `fs::symlink(` and NOT `symlink(`: the bare form matches
        // `is_symlink()`, which is a READ and is used by this
        // module's own refusal guards. The widened list caught that
        // on its first run — a detector that fires on the guards it
        // exists to protect is one somebody deletes.
        "fs::symlink(",
        "OpenOptions",
        // THE WRITE-CAPABLE `fsguard` HELPERS, and the sharpest
        // thing this list has to name: they were introduced in the
        // same commit that wrote this gate and imported into this
        // very module, so without them
        // `fsguard::open_regular_append(p)?.write_all(..)` in the
        // production half passes clean — the DIRECT form the gate
        // exists to catch, written through the crate's own helper.
        // `open_regular_read` is deliberately absent: reading is
        // what this verb does.
        "open_regular_append",
        "create_regular_lock",
    ];

    /// Comments say the words too ("performs no rename"), so the
    /// scan is over CODE only — a detector that trips on its own
    /// documentation would be turned off within a week.
    fn offenders(src: &str) -> Vec<String> {
        src.lines()
            .enumerate()
            .filter_map(|(i, line)| {
                let code = line.split("//").next().unwrap_or("");
                MUTATORS
                    .iter()
                    .find(|m| code.contains(**m))
                    .map(|m| format!("line {}: {m} in `{}`", i + 1, line.trim()))
            })
            .collect()
    }

    // POSITIVE CONTROL. A gate with no proof it can fire cannot
    // tell "clean" from "blind", and this project has now recorded
    // nine gates that failed open. If this assertion ever stops
    // holding, the scan below is meaningless and must not be read
    // as a pass.
    assert_eq!(
        offenders("    fs::remove_file(&path);").len(),
        1,
        "the detector itself is broken — it no longer recognises a mutating call, so its \
         verdict on the real source below means nothing"
    );
    assert!(
        offenders("//! performs no rename, no remove_file, no create_dir").is_empty(),
        "the detector must not trip on prose, or it will be disabled rather than obeyed"
    );
    // The write-capable helpers must be caught, and the read one
    // must NOT be — a gate that forbids reading would forbid the
    // verb.
    assert_eq!(
        offenders("    let f = fsguard::open_regular_append(&p)?;").len(),
        1,
        "the gate must catch the helpers this very change introduced"
    );
    assert!(
        offenders("    let f = fsguard::open_regular_read(&p)?;").is_empty(),
        "reading is the whole job; the gate must not forbid it"
    );
    // NEGATIVE control, and it is here because this exact false
    // positive happened: `is_symlink()` is a READ that the refusal
    // guards depend on, and a needle of `symlink(` flagged every
    // one of them. A gate that cries wolf on correct code gets
    // switched off, which is a slower way of having no gate.
    assert!(
        offenders("        Ok(m) if m.file_type().is_symlink() => Err(refuse()),").is_empty(),
        "reading whether something IS a symlink is not creating one"
    );
    assert!(
        offenders("    let meta = fs::symlink_metadata(&path).ok()?;").is_empty(),
        "lstat is a read, not a mutation"
    );

    // A needle of `"\nmod tests {"` alone, WITH the brace, behind
    // `.split(..).next().unwrap_or(SRC)` goes missing in a PARENT whose
    // tests are out of line (it ends with `mod tests;`), and the fallback
    // would silently widen the ceiling to the whole parent file.
    //
    // Why that is a FAIL-OPEN even though it looks harmless TODAY: the
    // parent is now entirely production, so a widened ceiling happens to
    // scan the right text. The guard does not rest on that. It rests on
    // the narrowing being CHECKED rather than incidentally correct — the
    // moment the parent regains any `#[cfg(test)]` text, a missing needle
    // silently puts it inside the scanned span and the verdict below
    // becomes a verdict about this suite's own fixtures.
    //
    // So: accept either spelling, and if NEITHER is found, fail loudly
    // rather than scan everything.
    let ceiling = SRC
        .find("\nmod tests {")
        .or_else(|| SRC.find("\nmod tests;"))
        .unwrap_or_else(|| {
            panic!(
                "this test's production/test ceiling marker is GONE from verify.rs ({} bytes \
                 read). It looks for `mod tests {{` (inline) or `mod tests;` (out-of-line). \
                 Without one, the scan below would cover this file's own test text \
                 and the mutation-scan's verdict would be about nothing. Re-point the needle; \
                 do NOT restore a fallback that widens the ceiling instead of failing",
                SRC.len()
            )
        });
    let production = SRC.get(..ceiling).unwrap_or("");
    assert!(
        production.contains("fn run_verify"),
        "sanity: the scanned span must actually be this module's production half"
    );
    let found = offenders(production);
    assert!(
        found.is_empty(),
        "gran verify is DIAGNOSTIC-ONLY: it must perform no \
         unlink, rename, truncation, directory creation or write under the root it is \
         given. Repair by RECONSTRUCTED path is the defect class this verb removed rather \
         than guarded for the eighth time; bringing one back needs the descriptor-relative \
         primitive anchored to held directory descriptors, not a new call here. Found:\n{}",
        found.join("\n")
    );
}

// ------------------------------------------- accumulator bookkeeping

/// C2, and it is exactly the kind of defect that appears when a
/// side effect is deleted without noticing what rode along with
/// it. The `seen_ids` insert for an oversized object has to be
/// explicit, or an INDEXED oversized object is reported `oversized`
/// by the walk and `dropped` again by `find_dropped` — two findings
/// for one file that is sitting right there.
///
/// Mutation probe: delete the `seen_ids.insert(claimed)` in the
/// `Oversized` arm and this test fails with two findings.
#[test]
fn an_indexed_oversized_object_is_reported_once_and_never_also_dropped() {
    let id = GrainId::of(b"indexed, and far too large");
    let mut index_map = BTreeMap::new();
    index_map.insert(id, 64u32);

    let hex = id.digest_hex();
    let mut rel = b"objects/".to_vec();
    rel.extend_from_slice(&hex.as_bytes()[..2]);
    rel.push(b'/');
    rel.extend_from_slice(hex.as_bytes());

    let mut acc = AuditAccumulator::default();
    acc.handle_entry(
        ScanEntry {
            rel_path: rel,
            outcome: ScanOutcome::Oversized {
                claimed: id,
                actual_size: META_MAX_BYTES + 1,
            },
        },
        &index_map,
    );
    acc.find_dropped(Path::new("/unused"), &index_map);

    assert_eq!(
        acc.findings.len(),
        1,
        "one file, one finding — the oversized object is ON DISK, so it is not also \
         dropped: {:?}",
        acc.findings
    );
    assert_eq!(acc.findings[0].kind, FindingKind::Oversized);
}

/// C6's top-level decision, tested where it can be: a FAILING
/// `DirEntry::file_type()` is not constructible portably (APFS and
/// ext4 answer from `readdir`'s `d_type` and never stat), so the
/// DECISION is what a test can pin and the call site is verified by
/// reading.
///
/// Mutation probe: return `Foreign { claimed: None }` for the
/// `Some` case and the first assertion fails — which is the whole
/// defect, because `find_dropped` would then conclude `dropped` for
/// every indexed id under a fanout this run never enumerated.
#[test]
fn an_undeterminable_top_level_entry_keeps_its_doubt_scoped_to_its_fanout() {
    assert!(
        matches!(
            unknown_type_top_level_outcome(Some("ab")),
            ScanOutcome::FanoutUnreadable { ref dir_hex } if dir_hex == "ab"
        ),
        "a valid two-hex name might BE that fanout, so the doubt must be scoped to it"
    );
    assert!(
        matches!(
            unknown_type_top_level_outcome(None),
            ScanOutcome::Foreign { claimed: None }
        ),
        "a non-fanout name can hold no indexed id, so plain foreign is honest"
    );
}

// ------------------------------------------------ hostile object leaves

/// C22, exercised where it can actually be exercised. A FIFO
/// planted at a valid object name is caught at ENUMERATION by
/// `DirEntry::file_type()` and never reaches `classify_object_file`
/// through the walk, so the walk cannot test the new flags. Called
/// DIRECTLY, it can: this is the state the walk reaches when the
/// leaf is replaced AFTER `file_type()` said "regular file", which
/// is not constructible as a race but is exactly one function call.
///
/// Behind a bounded join, because without `O_NONBLOCK` this open
/// never returns and the whole suite wedges rather than failing.
#[test]
fn classify_object_file_refuses_a_fifo_promptly_instead_of_blocking() {
    let dir = ScratchDir::new();
    let id = GrainId::of(b"whatever this name claims");
    let hex = id.digest_hex();
    let fanout = dir.0.join("objects").join(&hex[..2]);
    fs::create_dir_all(&fanout).unwrap_or_else(|e| panic!("{e}"));
    let path = fanout.join(&hex);
    crate::fsguard::testutil::mkfifo(&path);

    let outcome =
        crate::fsguard::testutil::within_deadline("classify_object_file on a FIFO", move || {
            let mut err = Vec::new();
            classify_object_file(&path, id, &mut err, b"objects/x")
        });
    match outcome {
        ScanOutcome::Foreign { claimed } => assert_eq!(
            claimed,
            Some(id),
            "a FIFO at a determinable object name must still count the id SEEN, or \
             find_dropped reports it dropped for a path that is occupied"
        ),
        other => panic!("a FIFO must be foreign, never opened or hashed: {other:?}"),
    }
}

/// The other half of C22: a SYMLINK at the leaf. Without
/// `O_NOFOLLOW` this open follows the link and verify hashes — and
/// PRINTS — a file from outside the root.
#[test]
fn classify_object_file_refuses_a_symlinked_leaf_instead_of_hashing_its_target() {
    let dir = ScratchDir::new();
    let victim = dir.0.join("victim-outside-the-objects-tree");
    fs::write(&victim, b"bytes that must never be hashed or printed")
        .unwrap_or_else(|e| panic!("{e}"));

    let id = GrainId::of(b"a name pointing somewhere else");
    let hex = id.digest_hex();
    let fanout = dir.0.join("objects").join(&hex[..2]);
    fs::create_dir_all(&fanout).unwrap_or_else(|e| panic!("{e}"));
    let path = fanout.join(&hex);
    std::os::unix::fs::symlink(&victim, &path).unwrap_or_else(|e| panic!("{e}"));

    let mut err = Vec::new();
    match classify_object_file(&path, id, &mut err, b"objects/x") {
        ScanOutcome::Foreign { claimed } => assert_eq!(claimed, Some(id)),
        other => {
            panic!("a symlinked leaf must be refused, never followed and hashed: {other:?}")
        }
    }
}

/// End to end, and its real job is proving the run TERMINATES: a
/// FIFO under `objects/` must not hang `gran verify` mid-walk. The
/// enumeration-time classification is asserted as it actually is —
/// `foreign`, plus `dropped` because a non-regular entry that
/// `file_type()` can SEE means the indexed object is genuinely not
/// there. Both statements are true and an operator needs both.
#[test]
fn a_fifo_under_objects_is_reported_and_the_run_terminates() {
    let dir = ScratchDir::new();
    let mut cache =
        Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}"));
    let (id, bytes) = (
        GrainId::of(b"replaced by a pipe"),
        b"replaced by a pipe".to_vec(),
    );
    cache.insert(&id, &bytes);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let hex = id.digest_hex();
    let path = dir.0.join("objects").join(&hex[..2]).join(&hex);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap_or_else(|e| panic!("{e}"));
    fs::remove_file(&path).unwrap_or_else(|e| panic!("{e}"));
    crate::fsguard::testutil::mkfifo(&path);

    let root = dir.0.clone();
    let (code, out, _err) = crate::fsguard::testutil::within_deadline(
        "gran verify over a FIFO under objects/",
        move || run_capture(&root),
    );
    assert_eq!(code, 1, "got {out:?}");
    assert!(
        out.lines().any(|l| l.starts_with("foreign\t")),
        "the FIFO must be reported foreign: {out:?}"
    );
    assert!(
        out.lines().any(|l| l.starts_with("dropped\t")),
        "and the indexed object it replaced is genuinely gone, so dropped is also true: \
         {out:?}"
    );
    // Cleanup: a FIFO left behind can wedge the scratch-dir remove.
    let _ = fs::remove_file(&path);
}

// ------------------------------------------- symlink-refusal exhaustiveness

/// The exhaustive `lstat` match in [`refuse_symlinked_objects_dir`]
/// must REFUSE on any unexpected error, not just on a symlink — a
/// fail-open `is_ok_and` rewrite would instead treat any error
/// (including this one) as "not a symlink" and let the walk
/// proceed. A path component past `NAME_MAX` makes `lstat` fail
/// with a non-`NotFound` error regardless of whether anything
/// actually exists on disk at this path, so no fixture needs to be
/// created to exercise it.
#[test]
fn refuse_symlinked_objects_dir_refuses_on_a_non_notfound_lstat_error() {
    let dir = ScratchDir::new();
    let huge_component = "x".repeat(300);
    let root = dir.0.join(huge_component);
    let result = refuse_symlinked_objects_dir(&root);
    assert!(
        result.is_err(),
        "a non-NotFound lstat error on objects/ must be refused, never treated as \"not a \
         symlink\": {result:?}"
    );
}

// ------------------------------------- symlinked structural directories

/// An attacker plants `objects -> <victim dir>` in an otherwise
/// legitimate cache root (real marker, real lock, real `index/` —
/// only `objects/` is swapped for a symlink) plus a file inside the
/// victim directory that is well-formed BY NAME (64-hex under its
/// fanout) but whose content does not hash to that name.
///
/// This test was written when that content was DELETED through the
/// link, and it is kept now that nothing is deleted, because the
/// refusal is what stops the remaining harm: reading through the
/// link would let a planted directory choose which of an
/// operator's files verify hashes and prints. Refusal must be
/// cannot-open (exit 2), never a reported finding, and the
/// victim's file must be untouched and unmentioned.
#[test]
fn a_symlinked_objects_dir_is_refused_and_the_walk_cannot_reach_the_victim() {
    let dir = ScratchDir::new();
    drop(Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}")));

    let victim = ScratchDir::new();
    let claimed_hex = GrainId::of(b"the name this file claims").digest_hex();
    let fanout = &claimed_hex[..2];
    fs::create_dir_all(victim.0.join(fanout)).unwrap_or_else(|e| panic!("{e}"));
    let victim_file = victim.0.join(fanout).join(&claimed_hex);
    fs::write(
        &victim_file,
        b"different bytes; will not hash to the claimed name",
    )
    .unwrap_or_else(|e| panic!("{e}"));

    fs::remove_dir_all(dir.0.join("objects")).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&victim.0, dir.0.join("objects")).unwrap_or_else(|e| panic!("{e}"));

    let (code, _out, _err) = run_capture(&dir.0);
    assert!(
        victim_file.exists(),
        "a symlinked objects/ must never let gran verify delete the victim's file through it"
    );
    assert_eq!(
        code, 2,
        "a symlinked objects/ must be a refusal (cannot-open), never a finding"
    );
}

/// An attacker swaps `index/` for a symlink to a victim directory
/// holding its own files at the names verify reads (`snapshot`,
/// `journal`).
///
/// Written when those files were OVERWRITTEN through the link, and
/// kept now that nothing is written, because refusal still carries
/// weight: reading an index through a planted link would let the
/// attacker choose the set of ids verify compares against, and so
/// choose which of the operator's real objects get reported
/// `adopted` or `dropped`. Refusal must be cannot-open (exit 2),
/// never a reported finding, and the victim's files must be
/// byte-identical afterwards.
#[test]
fn a_symlinked_index_dir_is_refused_and_the_walk_cannot_read_the_victim() {
    let dir = ScratchDir::new();
    let mut cache =
        Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}"));
    let (id, bytes) = (
        GrainId::of(b"legit indexed object"),
        b"legit indexed object".to_vec(),
    );
    cache.insert(&id, &bytes);
    cache.close().unwrap_or_else(|e| panic!("{e}"));

    let victim = ScratchDir::new();
    let victim_snapshot = victim.0.join("snapshot");
    let victim_journal = victim.0.join("journal");
    fs::write(&victim_snapshot, b"victim snapshot must not be overwritten")
        .unwrap_or_else(|e| panic!("{e}"));
    fs::write(&victim_journal, b"victim journal must not be overwritten")
        .unwrap_or_else(|e| panic!("{e}"));

    // An orphan on disk (objects/ is untouched here — only index/ is
    // swapped) forces an ADOPTED finding, which is what drives the
    // full-snapshot rewrite path.
    write_object(&dir.0, b"an orphan forcing a snapshot rewrite");

    fs::remove_dir_all(dir.0.join("index")).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&victim.0, dir.0.join("index")).unwrap_or_else(|e| panic!("{e}"));

    let (code, _out, _err) = run_capture(&dir.0);

    assert_eq!(
        fs::read(&victim_snapshot).unwrap_or_else(|e| panic!("{e}")),
        b"victim snapshot must not be overwritten",
        "a symlinked index/ must never let gran verify overwrite the victim's snapshot"
    );
    assert_eq!(
        fs::read(&victim_journal).unwrap_or_else(|e| panic!("{e}")),
        b"victim journal must not be overwritten",
        "a symlinked index/ must never let gran verify overwrite the victim's journal"
    );
    assert_eq!(
        code, 2,
        "a symlinked index/ must be a refusal (cannot-open), never a finding"
    );
}

/// The independent guard, exercised directly: `scan_objects()` called
/// on its own, bypassing `Cache::open_for_verify()`/
/// `Store::open_for_verify()`'s open-time check entirely (no marker,
/// no lock — a bare directory with only a symlinked `objects/`),
/// must refuse rather than walk through it. Proves the guard does
/// not merely rely on running after the open-time check.
#[test]
fn scan_objects_refuses_a_symlinked_objects_dir_independently_of_the_open_time_check() {
    let dir = ScratchDir::new();
    let victim = ScratchDir::new();
    let id = GrainId::of(b"victim's own real object");
    let hex = id.digest_hex();
    fs::create_dir_all(victim.0.join(&hex[..2])).unwrap_or_else(|e| panic!("{e}"));
    fs::write(
        victim.0.join(&hex[..2]).join(&hex),
        b"victim's own real object",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&victim.0, dir.0.join("objects")).unwrap_or_else(|e| panic!("{e}"));

    let mut err = Vec::new();
    let result = scan_objects(&dir.0, &mut err);
    match result {
        Err(_) => {}
        Ok(entries) => panic!(
            "scan_objects, called directly with no open-time check in front of it, must \
             refuse a symlinked objects/ on its own: got {} entries instead",
            entries.len()
        ),
    }
}

// ---------------------------------------------------- root-type detection

#[test]
fn a_store_marker_alone_selects_store_mode() {
    let dir = ScratchDir::new();
    crate::store::Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let mut err = Vec::new();
    assert!(matches!(
        detect_root_kind(&dir.0, &mut err),
        Some(RootKind::Store)
    ));
}

#[test]
fn a_cache_marker_alone_selects_cache_mode() {
    let dir = ScratchDir::new();
    drop(Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}")));
    let mut err = Vec::new();
    assert!(matches!(
        detect_root_kind(&dir.0, &mut err),
        Some(RootKind::Cache)
    ));
}

#[test]
fn both_markers_present_is_cannot_open() {
    let dir = ScratchDir::new();
    crate::store::Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    // Plant a cache marker file directly (a fully-fledged Cache::open
    // in the SAME dir would collide with the store's own txn/lock
    // shapes in ways unrelated to this test) — root-type detection
    // only reads the marker's first line.
    fs::write(
        dir.0.join("granary-cache"),
        b"granary-cache-version 1\nchunker x\nhash blake3\norigin y z\n",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let mut err = Vec::new();
    assert!(detect_root_kind(&dir.0, &mut err).is_none());
    assert!(err.iter().any(|_| true)); // some diagnostic was written
    let (code, _out, _err2) = run_capture(&dir.0);
    assert_eq!(code, 2);
}

#[test]
fn neither_marker_is_cannot_open() {
    let dir = ScratchDir::new();
    let (code, out, err) = run_capture(&dir.0);
    assert_eq!(code, 2);
    assert!(out.is_empty());
    assert!(!err.is_empty());
}

/// C7's negative, and the reason the boolean predicate had to
/// become a tri-state. Read as a boolean, an OVER-CAP cache marker
/// beside a valid store marker is `(true, false)` — "a store, no
/// cache" — and would silently run STORE-mode verification against a
/// directory whose type this process could not determine. The
/// honest answer is cannot-open. Note the existing
/// `is_store_marker_refuses_an_oversized_file` covers the
/// PREDICATE; nothing covered the DISPATCH, which is where the
/// conflation actually did harm.
#[test]
fn an_unreadable_cache_marker_beside_a_store_marker_is_cannot_open() {
    let dir = ScratchDir::new();
    crate::store::Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let mut oversized = b"granary-cache-version 1\n".to_vec();
    oversized.resize(128 * 1024, b'x');
    fs::write(dir.0.join("granary-cache"), &oversized).unwrap_or_else(|e| panic!("{e}"));

    let (code, out, err) = run_capture(&dir.0);
    assert_eq!(
        code, 2,
        "an unreadable marker of EITHER kind leaves the root's type undetermined: \
         out={out:?} err={err:?}"
    );
    assert!(
        err.contains("cache marker"),
        "the diagnostic must name WHICH marker could not be read: {err:?}"
    );
    assert!(out.is_empty(), "no findings may be reported: {out:?}");
}

/// The same conflation from the other side, and behind a bounded
/// join because a FIFO is the input that HANGS rather than fails
/// when the `O_NONBLOCK` half of the discipline regresses.
#[test]
fn a_fifo_cache_marker_is_cannot_open_and_does_not_hang() {
    let dir = ScratchDir::new();
    crate::store::Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let marker = dir.0.join("granary-cache");
    crate::fsguard::testutil::mkfifo(&marker);

    let root = dir.0.clone();
    let (code, _out, err) = crate::fsguard::testutil::within_deadline(
        "gran verify against a FIFO cache marker",
        move || run_capture(&root),
    );
    assert_eq!(code, 2, "got {err:?}");
    assert!(err.contains("cache marker"), "got {err:?}");
    let _ = fs::remove_file(&marker);
}

// ------------------------------------------------ index trustworthiness

/// C8/C16's headline negative: a cache whose snapshot cannot be
/// decoded and whose `objects/` is EMPTY must not verify clean —
/// exit 0, no output — which is what collapsing an untrustworthy
/// index to "an empty index" gives, since an empty index compared
/// against an empty tree finds nothing. The index file is itself
/// the finding.
#[test]
fn an_undecodable_snapshot_is_reported_never_reported_clean() {
    let dir = ScratchDir::new();
    drop(Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}")));
    fs::write(
        dir.0.join("index").join("snapshot"),
        b"not a snapshot at all",
    )
    .unwrap_or_else(|e| panic!("{e}"));

    let (code, out, err) = run_capture(&dir.0);
    assert_eq!(
        code, 1,
        "a damaged index is a finding, never a clean run: {out:?}"
    );
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        vec!["foreign\tindex/snapshot\t-\t-"],
        "exactly the index file, and nothing invented around it: {out:?}"
    );
    assert!(
        err.contains("cannot be trusted"),
        "the reason belongs on stderr, not in a machine-parsed column: {err:?}"
    );
}

/// And the comparison is SKIPPED rather than run against the
/// damage. Comparing a healthy object tree against an index that
/// decoded to "empty" would report every object `adopted` — a
/// flood of findings that describe the corruption rather than the
/// objects, burying the one line that is real.
#[test]
fn an_undecodable_snapshot_suppresses_the_index_comparison() {
    let dir = ScratchDir::new();
    let mut cache =
        Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}"));
    let (id, bytes) = (
        GrainId::of(b"a healthy object"),
        b"a healthy object".to_vec(),
    );
    cache.insert(&id, &bytes);
    cache.close().unwrap_or_else(|e| panic!("{e}"));
    fs::write(
        dir.0.join("index").join("snapshot"),
        b"not a snapshot at all",
    )
    .unwrap_or_else(|e| panic!("{e}"));

    let (code, out, _err) = run_capture(&dir.0);
    assert_eq!(code, 1, "got {out:?}");
    assert!(
        !out.contains("adopted"),
        "a healthy object must not be reported adopted just because the index is \
         unreadable — that describes the damage, not the object: {out:?}"
    );
    assert_eq!(out.lines().count(), 1, "exactly the index finding: {out:?}");
}

/// C16: the trust decision is PAIRWISE. An ABSENT snapshot beside a
/// PRESENT journal is `load_index`'s own tamper class, and a
/// snapshot-first decision (`Absent` -> trusted-empty) would audit
/// it as a clean empty cache.
#[test]
fn an_absent_snapshot_beside_a_present_journal_is_untrusted_not_empty() {
    let dir = ScratchDir::new();
    drop(Cache::open(&dir.0, 1_000_000, &cache_origin()).unwrap_or_else(|e| panic!("{e}")));
    fs::remove_file(dir.0.join("index").join("snapshot")).unwrap_or_else(|e| panic!("{e}"));

    let (code, out, err) = run_capture(&dir.0);
    assert_eq!(
        code, 1,
        "snapshot gone, journal present: incoherent, and never a clean run: {out:?} {err:?}"
    );
    assert!(
        out.contains("foreign\tindex/snapshot"),
        "the snapshot is the half that is missing, so it is the half reported: {out:?}"
    );
}
