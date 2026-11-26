// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::wire_snapshot` — the client's wire-byte
//! snapshot writer: the clean-exit record that seals `WireByteHandle`'s
//! process-wide response-byte total.
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

fn totals() -> ClientTotals {
    ClientTotals {
        response_bytes: Some(8_192),
        endpoint: Some("https://granary.example:9443".to_owned()),
        pinned_seq: Some(41),
        publish: None,
    }
}

/// **Row (m), the golden**: fixed inputs, rendered,
/// must be byte-identical to the committed fixture.
/// The propagation harness's own parser is tested
/// against BOTH this file and the server's own golden.
#[test]
fn the_render_is_byte_identical_to_the_committed_golden() {
    let golden = include_str!("../../tests/fixtures/wire_snapshot_client_golden.json");
    let fixed = ClientTotals {
        response_bytes: Some(654_321),
        endpoint: Some("https://granary.example:9443".to_owned()),
        pinned_seq: Some(41),
        publish: Some(PublishFields {
            seq: 42,
            novel_objects: Some(9),
            novel_bytes: Some(987_654),
            bins_uploaded: Some(2),
            bin_bytes_uploaded: Some(500_000),
            manifest_root: Some("blake3:0123456789abcdef".to_owned()),
        }),
    };
    let rendered = render("golden-run-0001", "publisher", &fixed);
    assert_eq!(
        rendered, golden,
        "the client snapshot format drifted from the committed golden"
    );
}

/// **Row (m), the render half, non-publish**: fixed inputs render
/// byte-identical every time.
#[test]
fn render_is_deterministic_for_fixed_inputs() {
    let a = render("run-abc", "client-1", &totals());
    let b = render("run-abc", "client-1", &totals());
    assert_eq!(a, b);
    assert!(a.contains("\"writer_kind\": \"granary-client\""));
    assert!(a.contains("\"response_bytes\": 8192"));
    assert!(a.contains("\"publish\": null"));
}

/// **Row (m), a writer run as `gran publish`**: the `publish` object
/// is present, with `seq` and `novel_bytes` equal to the
/// `PublishSummary` the run produced.
#[test]
fn a_publish_writer_embeds_the_publish_summary_fields() {
    let with_publish = ClientTotals {
        publish: Some(PublishFields {
            seq: 7,
            novel_objects: Some(3),
            novel_bytes: Some(12_345),
            bins_uploaded: Some(1),
            bin_bytes_uploaded: Some(6_000),
            manifest_root: Some("blake3:deadbeef".to_owned()),
        }),
        ..totals()
    };
    let text = render("run-abc", "publisher", &with_publish);
    assert!(text.contains("\"publish\": {"));
    assert!(text.contains("\"seq\": 7"));
    assert!(text.contains("\"novel_bytes\": 12345"));
    assert!(text.contains("\"manifest_root\": \"blake3:deadbeef\""));
}

/// A poisoned total renders `null`, never a number, and `endpoint`/
/// `pinned_seq` render `null` on their own `None`.
#[test]
fn poisoned_and_absent_fields_render_null() {
    let none = ClientTotals {
        response_bytes: None,
        endpoint: None,
        pinned_seq: None,
        publish: None,
    };
    let text = render("run-abc", "client-1", &none);
    assert!(text.contains("\"response_bytes\": null"));
    assert!(text.contains("\"poisoned\": true"));
    assert!(text.contains("\"endpoint\": null"));
    assert!(text.contains("\"pinned_seq\": null"));
}

/// **Row (n): the client writer's own refusal rows, the twins of
/// (f) and (g).**
#[test]
fn the_writer_refuses_empty_run_id_empty_role_and_an_unknown_role() {
    let dir = tempdir();
    let dest = dir.join("client.json");
    assert_eq!(
        write_client_snapshot(&dest, "", "client-1", &totals()),
        Err(SnapshotError::EmptyRunId)
    );
    assert_eq!(
        write_client_snapshot(&dest, "run-1", "", &totals()),
        Err(SnapshotError::EmptyRole)
    );
    assert_eq!(
        write_client_snapshot(&dest, "run-1", "not-a-role", &totals()),
        Err(SnapshotError::UnknownRole)
    );
    assert!(!dest.exists(), "a refused write must create nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

/// **The client's `validate` must refuse an empty path.**
/// Without that check, `--wire-snapshot ""` —
/// an unexpanded shell variable's shape — writes the snapshot
/// body into a bare `.tmp` in the process's CURRENT WORKING
/// DIRECTORY ( [`temp_path_for`] builds `.tmp` alone from an
/// empty `dest`) and only THEN fails to publish, matching the
/// symptom `granary-server`'s own `SnapshotError::EmptyPath`
/// closes. This is the client-side twin of that refusal.
#[test]
fn the_writer_refuses_an_empty_destination_path() {
    let empty = PathBuf::from("");
    assert_eq!(
        write_client_snapshot(&empty, "run-1", "client-1", &totals()),
        Err(SnapshotError::EmptyPath)
    );
    assert_eq!(
        wire_snapshot_trio_is_valid(&empty, "run-1", "client-1"),
        Err(SnapshotError::EmptyPath.to_string())
    );
}

/// **Only the empty string is refused**,
/// not every relative path. A bare relative filename
/// (`"snapshot.json"`, no directory component) has a real parent —
/// the process's own current working directory — so the
/// write-then-rename hygiene still holds; refusing it would be
/// second-guessing an operator's choice this function has no basis
/// for. Driven directly against `validate`, the pure decision,
/// rather than through a real write into this test process's own
/// cwd.
#[test]
fn validate_refuses_only_the_empty_string_not_a_bare_relative_name() {
    assert_eq!(
        validate(Path::new("snapshot.json"), "run-1", "client-1"),
        Ok(()),
        "a bare relative filename has a real parent and must not be \
         refused the same way the truly-empty string is"
    );
    assert_eq!(
        validate(Path::new(""), "run-1", "client-1"),
        Err(SnapshotError::EmptyPath)
    );
}

/// **Row (n): a pre-existing destination is refused.**
#[test]
fn a_pre_existing_destination_is_refused() {
    let dir = tempdir();
    let dest = dir.join("client.json");
    std::fs::write(&dest, b"leftover from a previous run").expect("plant");
    let before = std::fs::read(&dest).expect("read");
    assert_eq!(
        write_client_snapshot(&dest, "run-1", "client-1", &totals()),
        Err(SnapshotError::AlreadyExists)
    );
    let after = std::fs::read(&dest).expect("read");
    assert_eq!(before, after, "a refused write must not touch the file");
    let _ = std::fs::remove_dir_all(&dir);
}

/// [`confirmed_absent`]'s three branches, driven
/// directly over a SYNTHETIC `io::Result` — the same reasoning
/// and the same shape as the server's own row (see that crate's
/// own test for why an end-to-end filesystem fixture cannot
/// discriminate this: the condition that breaks
/// `symlink_metadata` almost always breaks the write that follows
/// it too, so it cannot tell a refusing check apart from a
/// fail-open one). The third branch pins the rule: an ambiguous stat
/// error must refuse as `Io`, never be treated as "absent".
#[test]
fn confirmed_absent_refuses_on_anything_but_a_definite_not_found() {
    let dest = PathBuf::from("/wire-snapshot-test/does-not-matter.json");

    assert_eq!(
        confirmed_absent(&dest, Ok(std::fs::metadata(".").expect("cwd exists"))),
        Err(SnapshotError::AlreadyExists),
        "something IS there: refuse as AlreadyExists"
    );
    assert_eq!(
        confirmed_absent(
            &dest,
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        ),
        Ok(()),
        "a DEFINITE NotFound is the only stat answer confirmed absent"
    );
    let ambiguous = confirmed_absent(
        &dest,
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
    );
    assert!(
        matches!(ambiguous, Err(SnapshotError::Io(_))),
        "an ambiguous stat error (here: PermissionDenied) must refuse \
         as Io — treating it as confirmed absent is the fail-open \
         direction this row exists to close: {ambiguous:?}"
    );
}

/// A legitimate write lands atomically and leaves no temp file.
#[test]
fn a_legitimate_write_lands_atomically_with_no_temp_file_left_behind() {
    let dir = tempdir();
    let dest = dir.join("client.json");
    write_client_snapshot(&dest, "run-1", "client-1", &totals())
        .expect("a valid write must succeed");
    let written = std::fs::read_to_string(&dest).expect("read");
    assert_eq!(written, render("run-1", "client-1", &totals()));
    assert!(
        !temp_path_for(&dest).exists(),
        "the temp file must be gone after the rename"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed publish must not
/// leave the temp behind — a stale temp at the DETERMINISTIC
/// `<dest>.tmp` name would otherwise wedge every later attempt
/// at the SAME destination behind `create_regular_exclusive`'s
/// own `EEXIST`, reported as an opaque `Io` naming the TEMP
/// path rather than the failure that actually caused it.
///
/// Drives [`write_body_and_publish`] directly (see its own doc for
/// why a row through the public [`write_client_snapshot`] cannot
/// reach this deterministically) with a `dest` planted BEFORE the
/// call, so `publish_regular`'s `hard_link` fails with a REAL
/// `AlreadyExists` — the identical error class an actual
/// `confirmed_absent`-to-publish race would also produce.
#[test]
fn a_failed_publish_does_not_leave_the_temp_behind() {
    let dir = tempdir();
    let dest = dir.join("client.json");
    let tmp = temp_path_for(&dest);
    std::fs::write(&dest, b"a concurrent writer got here first").expect("plant dest");

    let result = write_body_and_publish(&dest, "run-1", "client-1", &totals());
    assert_eq!(result, Err(SnapshotError::AlreadyExists));
    assert!(
        !tmp.exists(),
        "the temp must not survive a failed publish — a stale temp at this \
         deterministic name would wedge every later attempt at the same destination"
    );

    // Not wedged: with `dest` now gone (as it would be once a real
    // race resolves, or a stale destination is cleared), a FULL
    // `write_client_snapshot` at the SAME destination must succeed
    // — proving the deterministic temp NAME is free again, not
    // merely that this one file object is gone.
    std::fs::remove_file(&dest).expect("remove the planted dest");
    write_client_snapshot(&dest, "run-1", "client-1", &totals())
        .expect("a retry at the same destination must not be wedged by a leftover temp");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A fresh, process-unique scratch directory — the same shape
/// `granary-server`'s own writer test uses.
fn tempdir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    #[expect(
        clippy::disallowed_methods,
        reason = "the lint bans `std::process::id` as AMBIENT INPUT because the preimage of a hashed or signed \
                  value must take a WriterIdentity instead. Here it is a SCRATCH-DIRECTORY NAME and nothing \
                  else, load-bearing only for not colliding with a concurrently-running test binary's own \
                  scratch directory of the same counter value — it reaches no hashed or signed value and \
                  nothing under test reads it"
    )]
    let pid = std::process::id();
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "granary-wire-snapshot-test-{pid}-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

#[test]
fn authority_completion_has_nullable_historical_counters_and_absent_publish_is_null() {
    let totals = ClientTotals {
        publish: Some(PublishFields {
            seq: 9,
            novel_objects: None,
            novel_bytes: None,
            bins_uploaded: None,
            bin_bytes_uploaded: None,
            manifest_root: Some("blake3:test".into()),
        }),
        ..totals()
    };
    let text = render("run", "publisher", &totals);
    for name in [
        "novel_objects",
        "novel_bytes",
        "bins_uploaded",
        "bin_bytes_uploaded",
    ] {
        assert!(text.contains(&format!("\"{name}\": null")));
    }
    assert!(text.contains("\"seq\": 9"));
    assert!(
        render(
            "run",
            "client-1",
            &ClientTotals {
                publish: None,
                ..totals
            }
        )
        .contains("\"publish\": null")
    );
}
