// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `crate::wire_snapshot` — the shutdown-time wire-byte
//! snapshot writer.
//!
//! Out-of-line: `granary-server`'s non-test artifact has
//! its own `[[bin]]` (`granary-server`) and its own
//! `tests/` directory (`crates/granary-server/tests/`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::*;

fn totals() -> ServerTotals {
    ServerTotals {
        request_bytes: Some(4_242),
        requests_with_body: 3,
        response_bytes_produced: 9_000,
    }
}

/// **Row (e), the render half**: fixed inputs render byte-identical
/// output every time — the property the golden-fixture test in
/// `adapter.rs` pins against a committed file.
#[test]
fn render_is_deterministic_for_fixed_inputs() {
    let a = render("run-abc", "server", "127.0.0.1:4242", totals());
    let b = render("run-abc", "server", "127.0.0.1:4242", totals());
    assert_eq!(a, b);
    assert!(a.contains("\"writer_kind\": \"granary-server\""));
    assert!(a.contains("\"drain_outcome\": \"drained\""));
    assert!(a.contains("\"request_bytes\": 4242"));
    assert!(a.contains("\"poisoned\": false"));
}

/// **Row (e), the golden**: fixed inputs, rendered, must be
/// byte-identical to the committed fixture. A change to the format
/// is then a visible diff in a golden, not silent drift — and the
/// ingest parser is tested against this same file.
#[test]
fn the_render_is_byte_identical_to_the_committed_golden() {
    let golden = include_str!("../../tests/fixtures/wire_snapshot_server_golden.json");
    let fixed = ServerTotals {
        request_bytes: Some(123_456),
        requests_with_body: 7,
        response_bytes_produced: 654_321,
    };
    let rendered = render("golden-run-0001", "server", "127.0.0.1:4242", fixed);
    assert_eq!(
        rendered, golden,
        "the server snapshot format drifted from the committed golden"
    );
}

/// The poison row's OWN render, at the JSON layer: a `None` total
/// writes `null`, never a number.
#[test]
fn a_poisoned_total_renders_null_and_poisoned_true() {
    let poisoned = ServerTotals {
        request_bytes: None,
        requests_with_body: 1,
        response_bytes_produced: 0,
    };
    let text = render("run-abc", "server", "127.0.0.1:4242", poisoned);
    assert!(text.contains("\"request_bytes\": null"));
    assert!(text.contains("\"poisoned\": true"));
}

/// **Row (g), the server writer's own refusal rows**: an empty run
/// id, an empty role, and a role outside the vocabulary are each
/// refused — by variant, so a caller can tell which.
#[test]
fn the_writer_refuses_empty_run_id_empty_role_and_an_unknown_role() {
    let dir = tempdir();
    let dest = dir.join("server.json");
    assert_eq!(
        write_server_snapshot(&dest, "", "server", "a", totals()),
        Err(SnapshotError::EmptyRunId)
    );
    assert_eq!(
        write_server_snapshot(&dest, "run-1", "", "a", totals()),
        Err(SnapshotError::EmptyRole)
    );
    assert_eq!(
        write_server_snapshot(&dest, "run-1", "not-a-role", "a", totals()),
        Err(SnapshotError::UnknownRole)
    );
    assert!(!dest.exists(), "a refused write must create nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

/// **Row (f): a pre-existing destination is refused.**
#[test]
fn a_pre_existing_destination_is_refused() {
    let dir = tempdir();
    let dest = dir.join("server.json");
    std::fs::write(&dest, b"leftover from a previous run").expect("plant");
    let before = std::fs::read(&dest).expect("read");
    assert_eq!(
        write_server_snapshot(&dest, "run-1", "server", "a", totals()),
        Err(SnapshotError::AlreadyExists)
    );
    let after = std::fs::read(&dest).expect("read");
    assert_eq!(before, after, "a refused write must not touch the file");
    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty destination path is refused —
/// `wire_snapshot_trio_is_valid`'s own name promises a TRIO, so it
/// validates `dest` as well as `run_id`/`role`. `dest = ""`
/// stats `NotFound` (so `confirmed_absent` alone would have read it
/// as merely absent) and `temp_path_for` would build a bare `.tmp`
/// that resolves in the process's CURRENT WORKING DIRECTORY.
#[test]
fn the_writer_refuses_an_empty_destination_path() {
    let empty = PathBuf::from("");
    assert_eq!(
        write_server_snapshot(&empty, "run-1", "server", "a", totals()),
        Err(SnapshotError::EmptyPath)
    );
    assert_eq!(
        wire_snapshot_trio_is_valid(&empty, "run-1", "server"),
        Err(SnapshotError::EmptyPath.to_string())
    );
}

/// **A symlink planted at `<dest>.tmp` is refused,
/// not followed.** A plain `std::fs::File::create` would
/// have followed it and written the snapshot body through to
/// `victim`, with this process's own privileges.
#[test]
fn create_temp_exclusive_refuses_a_symlink_at_the_temp_name() {
    let dir = tempdir();
    let victim = dir.join("victim");
    std::fs::write(&victim, b"outside").expect("plant victim");
    let tmp = dir.join("server.json.tmp");
    std::os::unix::fs::symlink(&victim, &tmp).expect("plant symlink");
    let before = std::fs::read(&victim).expect("read");
    assert!(
        create_temp_exclusive(&tmp).is_err(),
        "a symlink at the temp name must be refused, not followed"
    );
    let after = std::fs::read(&victim).expect("read");
    assert_eq!(before, after, "the symlink's target must be untouched");
    let _ = std::fs::remove_dir_all(&dir);
}

/// **A pre-existing REGULAR file at `<dest>.tmp` is
/// refused, not truncated.** A plain `std::fs::File::create`
/// would have truncated it and overwritten it with the new body —
/// a stale `.tmp` from a previous run is exactly this shape.
#[test]
fn create_temp_exclusive_refuses_a_pre_existing_temp_file_rather_than_truncating_it() {
    let dir = tempdir();
    let tmp = dir.join("server.json.tmp");
    std::fs::write(&tmp, b"a stray temp file from a previous run").expect("plant");
    let before = std::fs::read(&tmp).expect("read");
    assert!(
        create_temp_exclusive(&tmp).is_err(),
        "a pre-existing temp file must be refused, not truncated"
    );
    let after = std::fs::read(&tmp).expect("read");
    assert_eq!(before, after, "a refused create must not touch the file");
    let _ = std::fs::remove_dir_all(&dir);
}

/// **A destination that appeared AFTER the caller's own
/// `confirmed_absent` check — that check is not atomic with the
/// publish — is refused at publish time, not silently overwritten.**
/// A plain `std::fs::rename` would not refuse it — `rename`
/// on Unix REPLACES an existing destination rather than refusing.
#[test]
fn publish_no_replace_refuses_a_destination_that_appeared_after_the_check() {
    let dir = tempdir();
    let tmp = dir.join("server.json.tmp");
    let dest = dir.join("server.json");
    std::fs::write(&tmp, b"the real snapshot body").expect("plant tmp");
    // Simulates a destination a concurrent writer (or a stale run)
    // created in the window between `confirmed_absent`'s check and
    // this publish — a window that check and this call do not
    // share a lock across.
    std::fs::write(&dest, b"a concurrent writer got here first").expect("plant dest");
    let before = std::fs::read(&dest).expect("read");
    assert_eq!(
        publish_no_replace(&tmp, &dest, b"the real snapshot body"),
        Err(SnapshotError::AlreadyExists)
    );
    let after = std::fs::read(&dest).expect("read");
    assert_eq!(
        before, after,
        "a refused publish must not overwrite the file that beat it there"
    );
    assert!(
        tmp.exists(),
        "a refused publish must leave the temp file alone"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **A symlink swapped in at the temp pathname between the body
/// write and the link must be refused, not published through.** This
/// is the exact attack shape exercised here: a local writer in the
/// snapshot directory replaces `<dest>.tmp` during that interval.
/// A `publish_no_replace` that took only the PATH `tmp` and never
/// re-verified it would link whatever sits at that name at
/// `hard_link` time to `dest`: `link(2)`'s
/// treatment of a symlink source is platform-defined, and on a
/// platform that follows it this would publish the victim's
/// CONTENT, unauthenticated, as this server's own snapshot.
#[test]
fn publish_no_replace_refuses_a_symlink_swapped_in_at_the_temp_name() {
    let dir = tempdir();
    let tmp = dir.join("server.json.tmp");
    let dest = dir.join("server.json");
    let victim = dir.join("victim");
    std::fs::write(&victim, b"not this server's snapshot").expect("plant victim");
    // The real write happens first, exactly as `write_body_and_publish`
    // does it ...
    std::fs::write(&tmp, b"the real snapshot body").expect("plant tmp");
    // ... then a concurrent writer in the SAME directory replaces the
    // temp name with a symlink to a file this process never wrote,
    // BEFORE `publish_no_replace` re-opens it: the replacement its
    // re-verification refuses. What it cannot close is the interval
    // between its final pathname check and the `hard_link`.
    std::fs::remove_file(&tmp).expect("remove the real temp");
    std::os::unix::fs::symlink(&victim, &tmp).expect("plant symlink");
    // The symlink open must be refused (`O_NOFOLLOW`) before the
    // content anchor is ever compared, so any bytes do for this row.
    let result = publish_no_replace(&tmp, &dest, b"the real snapshot body");
    assert!(
        result.is_err(),
        "a symlink at the temp name must be refused, not published: {result:?}"
    );
    assert!(!dest.exists(), "a refused publish must create nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

/// **A hard link to a file this process never wrote, planted at the
/// temp pathname, must be refused too** — the
/// symlink row above is refused by `O_NOFOLLOW` at the re-open; this
/// row is refused by the nlink check, because linking `victim` a
/// second time (once at its own name, once at `tmp`) leaves it with
/// two links, and a write-then-publish temporary this process
/// created itself always has exactly one.
#[test]
fn publish_no_replace_refuses_a_hard_link_to_another_file_planted_at_the_temp_name() {
    let dir = tempdir();
    let tmp = dir.join("server.json.tmp");
    let dest = dir.join("server.json");
    let victim = dir.join("victim");
    std::fs::write(&victim, b"not this server's snapshot").expect("plant victim");
    std::fs::write(&tmp, b"the real snapshot body").expect("plant tmp");
    std::fs::remove_file(&tmp).expect("remove the real temp");
    std::fs::hard_link(&victim, &tmp).expect("plant hard link");
    // The nlink check must refuse this before the content anchor is
    // ever compared, so any bytes do for this row.
    let result = publish_no_replace(&tmp, &dest, b"the real snapshot body");
    assert!(
        result.is_err(),
        "a hard-linked-elsewhere file at the temp name must be refused: {result:?}"
    );
    assert!(!dest.exists(), "a refused publish must create nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

/// **A fresh, solitary-linked regular file replanted at the temp
/// pathname with different content must be refused.** The symlink row
/// above is refused by `O_NOFOLLOW` at the re-open; the hard-link row
/// by the nlink check. Neither catches a co-tenant that watches for the exclusive
/// create, `unlink`s `tmp`, and `creat`s a FRESH, solitary-linked
/// regular file at the same name — never hard-linked from elsewhere
/// (so `refuse_non_sole_regular`'s nlink check passes), not a
/// symlink (so `O_NOFOLLOW` passes).
///
/// **A create-time `(dev, ino)` check cannot see this, and is
/// UNSOUND on Linux**: ext4/tmpfs recycle a freed inode number for
/// the very next create in the same directory, so the fresh replant
/// below regularly gets handed back the SAME inode this process
/// just released, comparing equal and publishing the forgery —
/// reproduced by Linux CI even though this exact row was green on
/// macOS/APFS, which does not recycle that way. **This row is now
/// content-independent of inode semantics**: the replant below uses
/// DIFFERENT bytes than this process wrote, so
/// [`verify_published_body`] refuses it on every platform,
/// regardless of what the inode number happens to be. See the row
/// below this one for the companion case — an IDENTICAL-content
/// replant, which this check does not and need not refuse.
#[test]
fn publish_no_replace_refuses_a_fresh_regular_file_replanted_at_the_temp_name() {
    let dir = tempdir();
    let tmp = dir.join("server.json.tmp");
    let dest = dir.join("server.json");
    // Exactly `write_body_and_publish`'s own sequence: exclusive
    // create, then write the body.
    let mut file = create_temp_exclusive(&tmp).expect("create tmp");
    file.write_all(b"the real snapshot body")
        .expect("write body");
    file.flush().expect("flush");
    drop(file);
    // A co-tenant unlinks the real temp and replants a FRESH regular
    // file, with DIFFERENT content, at the same name, in the window
    // between this process's own write finishing and the publish
    // below.
    std::fs::remove_file(&tmp).expect("attacker unlinks the real temp");
    std::fs::write(&tmp, b"forged snapshot, never written by this process")
        .expect("attacker replants a fresh regular file");
    let result = publish_no_replace(&tmp, &dest, b"the real snapshot body");
    assert!(
        result.is_err(),
        "a fresh regular file replanted at the temp name, with content \
         different from what this process wrote, must be refused: {result:?}"
    );
    assert!(!dest.exists(), "a refused publish must create nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

/// **An identical-content replant must be accepted.** The same
/// replant as the row above, except the co-tenant's fresh file
/// happens to hold the EXACT SAME bytes this process wrote — the
/// one case a content anchor cannot distinguish from "no replant
/// happened at all" (and neither could a sound inode-identity
/// anchor: a dev/ino comparison speaks to WHICH inode, not to what
/// bytes it holds).
///
/// **This publish is expected to SUCCEED, not be refused, and that
/// is the correct, documented behaviour — not a gap.** The attacker
/// gains nothing from this substitution: the bytes that land at
/// `dest` are, byte for byte, the bytes this process itself
/// rendered and would have published anyway. A "replant" whose
/// entire effect is "swap the file for a bit-identical copy of
/// itself" has no observable outcome for this snapshot to defend
/// against — there is no forged content, no different author, and
/// no information the attacker could not already read from the
/// original write.
#[test]
fn publish_no_replace_allows_a_fresh_regular_file_replanted_at_the_temp_name_with_identical_content()
 {
    let dir = tempdir();
    let tmp = dir.join("server.json.tmp");
    let dest = dir.join("server.json");
    let mut file = create_temp_exclusive(&tmp).expect("create tmp");
    file.write_all(b"the real snapshot body")
        .expect("write body");
    file.flush().expect("flush");
    drop(file);
    // A co-tenant unlinks the real temp and replants a FRESH regular
    // file at the same name — a genuinely different inode — holding
    // the IDENTICAL bytes this process wrote.
    std::fs::remove_file(&tmp).expect("attacker unlinks the real temp");
    std::fs::write(&tmp, b"the real snapshot body")
        .expect("attacker replants a fresh regular file");
    let result = publish_no_replace(&tmp, &dest, b"the real snapshot body");
    assert!(
        result.is_ok(),
        "a replant with content identical to what this process wrote is \
         indistinguishable from no replant at all, and must publish: {result:?}"
    );
    assert_eq!(
        std::fs::read(&dest).expect("read dest"),
        b"the real snapshot body"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **The reopen must include `O_NONBLOCK`.** A FIFO planted at the
/// temp name must not wedge the shutdown-time snapshot write. The
/// nonblocking reopen lets the regular-file check refuse it;
/// `within_deadline` turns a blocking regression into a failed test.
#[test]
fn publish_no_replace_does_not_block_on_a_fifo_swapped_in_at_the_temp_name() {
    let dir = tempdir();
    let tmp = dir.join("server.json.tmp");
    let dest = dir.join("server.json");
    // The FIFO plant must be refused (`O_NONBLOCK` at the reopen)
    // before the content anchor is ever compared, so any bytes do
    // for this row.
    testutil::mkfifo(&tmp);
    let dest_check = dest.clone();
    let result = testutil::within_deadline(
        "publish_no_replace reopening a FIFO swapped in at the temp name",
        move || publish_no_replace(&tmp, &dest, b"the real snapshot body"),
    );
    assert!(
        result.is_err(),
        "a FIFO swapped in at the temp name must be refused, not linked: {result:?}"
    );
    assert!(
        !dest_check.exists(),
        "a refused publish must create nothing"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// **The pure identity decision `publish_no_replace` makes** (the
/// actual race cannot be landed between two statements of one
/// synchronous call, the same reason `granary-client`'s own
/// `same_identity` test gives): two REAL but unrelated files never
/// compare equal, and a file compared against its OWN re-stat does.
#[test]
fn same_identity_is_false_for_two_different_real_files_and_true_for_a_re_stat() {
    let dir = tempdir();
    let a = dir.join("a");
    let b = dir.join("b");
    std::fs::write(&a, b"a").expect("write a");
    std::fs::write(&b, b"b").expect("write b");
    let meta_a = std::fs::symlink_metadata(&a).expect("stat a");
    let meta_b = std::fs::symlink_metadata(&b).expect("stat b");
    assert!(
        !same_identity(&meta_a, &meta_b),
        "two different real files must not compare equal"
    );
    let meta_a_again = std::fs::symlink_metadata(&a).expect("restat a");
    assert!(
        same_identity(&meta_a, &meta_a_again),
        "the same file, re-stat, must compare equal"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// [`publish_outcome`]'s three branches are tested directly over
/// synthetic `io::Result` values because a real fixture cannot
/// discriminate the cleanup-failure branch, as that function documents.
/// The middle row pins the rule: `hard_link` landing but `remove_file`
/// failing must resolve `Clean`-adjacent (`LeftoverTemp`, still a
/// SUCCESS from `publish_no_replace`'s point of view), never
/// `Failed`.
#[test]
fn publish_outcome_reports_success_once_hard_link_lands_even_if_cleanup_fails() {
    assert!(matches!(
        publish_outcome(Ok(()), Ok(())),
        PublishOutcome::Clean
    ));
    assert!(matches!(
        publish_outcome(
            Ok(()),
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        ),
        PublishOutcome::LeftoverTemp(_)
    ));
    // `remove_temp` is irrelevant once `hard_link` itself failed —
    // the real caller never even attempts the remove in that case
    // (see `publish_no_replace`'s own `if hard_link_result.is_ok()`
    // guard), but the decision function must not depend on that
    // discipline to get this branch right.
    assert!(matches!(
        publish_outcome(
            Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists)),
            Ok(())
        ),
        PublishOutcome::Failed(_)
    ));
}

/// **The wiring test must cover `PublishOutcome::into_result` as well
/// as `publish_outcome`:** the test above proves the DECISION is
/// right, but `publish_no_replace` only reports what
/// [`PublishOutcome::into_result`] says — a mutation to THAT mapping
/// (swapping `LeftoverTemp`'s arm back to `Err`, misreporting a
/// successful publish) would not move the other rows: not
/// `publish_outcome`'s own test, which never calls `into_result`,
/// and not `publish_no_replace`'s end-to-end tests, none of which
/// reach the `LeftoverTemp` branch
/// (`a_legitimate_write_lands_atomically_with_no_temp_file_left_behind`
/// hits `Clean`, `publish_no_replace_refuses_a_destination_that_appeared_after_the_check`
/// hits `Failed`). This row closes that gap directly, over the pure
/// mapping alone.
#[test]
fn publish_outcome_into_result_is_ok_for_leftover_temp_and_err_only_for_failed() {
    assert!(PublishOutcome::Clean.into_result().is_ok());
    assert!(
        PublishOutcome::LeftoverTemp(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            .into_result()
            .is_ok(),
        "a leftover temp is cleanup debt, not a reported failure"
    );
    assert!(
        PublishOutcome::Failed(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
            .into_result()
            .is_err(),
        "hard_link itself failing must still be reported"
    );
}

/// A calibration row, not a discriminating one: confirms
/// `PublishOutcome::LeftoverTemp`'s synthetic row above is reachable
/// with a REAL `io::Error` of the SAME shape `remove_file` would
/// produce in practice (EACCES/EROFS are not portably constructible
/// here, but "the name now holds a directory" is, and `remove_file`
/// — unlike `remove_dir` — always refuses that) — so the branch is
/// pinned against a real error value, not only a hand-built one.
#[test]
fn publish_outcome_leftover_temp_is_reachable_with_a_real_remove_file_error() {
    let dir = tempdir();
    let occupied = dir.join("occupied");
    std::fs::create_dir(&occupied).expect("create dir");
    let real_remove_err = std::fs::remove_file(&occupied)
        .expect_err("remove_file on a directory must fail on every platform this ships for");
    assert!(matches!(
        publish_outcome(Ok(()), Err(real_remove_err)),
        PublishOutcome::LeftoverTemp(_)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed publish must remove its temp before returning — a stale
/// temp at the DETERMINISTIC
/// `<dest>.tmp` name would otherwise wedge every later attempt at
/// the SAME destination behind `create_temp_exclusive`'s own
/// `EEXIST`, reported as an opaque `Io` naming the TEMP path rather
/// than the failure that actually caused it.
///
/// Drives [`write_body_and_publish`] directly (see its own doc for
/// why a row through the public [`write_server_snapshot`] cannot
/// reach this deterministically) with a `dest` planted BEFORE the
/// call, so `publish_no_replace`'s `hard_link` fails with a REAL
/// `AlreadyExists` — the identical error class an actual
/// `confirmed_absent`-to-publish race would also produce.
#[test]
fn a_failed_publish_does_not_leave_the_temp_behind() {
    let dir = tempdir();
    let dest = dir.join("server.json");
    let tmp = temp_path_for(&dest);
    std::fs::write(&dest, b"a concurrent writer got here first").expect("plant dest");

    let result = write_body_and_publish(&dest, "run-1", "server", "127.0.0.1:4242", totals());
    assert_eq!(result, Err(SnapshotError::AlreadyExists));
    assert!(
        !tmp.exists(),
        "the temp must not survive a failed publish — a stale temp at this \
         deterministic name would wedge every later attempt at the same destination"
    );

    // Not wedged: with `dest` now gone (as it would be once a real
    // race resolves, or a stale destination is cleared), a FULL
    // `write_server_snapshot` at the SAME destination must succeed
    // — proving the deterministic temp NAME is free again, not
    // merely that this one file object is gone.
    std::fs::remove_file(&dest).expect("remove the planted dest");
    write_server_snapshot(&dest, "run-1", "server", "127.0.0.1:4242", totals())
        .expect("a retry at the same destination must not be wedged by a leftover temp");
    let _ = std::fs::remove_dir_all(&dir);
}

/// [`confirmed_absent`]'s three branches are driven
/// directly over a SYNTHETIC `io::Result` rather than a real
/// filesystem race — `Ok`, a definite `NotFound`, and every other
/// stat error must land in three different outcomes, and the third
/// one pins the rule: a `PermissionDenied` (or any other ambiguous
/// error) must refuse as `Io`, never be treated as "absent".
///
/// Drive the metadata decision directly with a `PermissionDenied`
/// result, so a later write failure cannot substitute for the
/// guard's own refusal.
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

/// **Row (e), the write half**: a legitimate write lands atomically
/// at `dest`, leaves no temp file behind, and its bytes are exactly
/// [`render`]'s own output.
#[test]
fn a_legitimate_write_lands_atomically_with_no_temp_file_left_behind() {
    let dir = tempdir();
    let dest = dir.join("server.json");
    write_server_snapshot(&dest, "run-1", "server", "127.0.0.1:4242", totals())
        .expect("a valid write must succeed");
    let written = std::fs::read_to_string(&dest).expect("read");
    assert_eq!(
        written,
        render("run-1", "server", "127.0.0.1:4242", totals())
    );
    assert!(
        !temp_path_for(&dest).exists(),
        "the temp file must be gone after the rename"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A fresh, process-unique scratch directory — this module's tests
/// touch the real filesystem (the atomicity and pre-existence
/// properties are only real when a real rename is exercised) and
/// must not collide with a parallel test's own directory of the
/// same name.
///
/// `granary-wire-snapshot-test-<pid>-<counter>`, the same shape
/// `harvest.rs`'s own `ScratchDir` uses and for the same reason: the
/// counter alone is per-process, so two concurrent test binaries
/// need the pid too or they collide on the same directory name.
fn tempdir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    #[expect(
        clippy::disallowed_methods,
        reason = "`std::process::id` is banned as AMBIENT INPUT because the preimage of a hashed or signed \
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

mod testutil;
