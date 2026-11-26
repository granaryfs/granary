// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::fsguard` — opening a file under a root this
//! process does not control, and the FIFO/hard-link/symlink hardening
//! that makes such an open safe.
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.
//!
//! This module also carries `fsguard`'s shared FIFO fixture as a second
//! conforming body, nested at `tests::testutil` so the parent keeps one
//! test-module declaration, and re-exported for its 20 outside call sites:
//! `#[cfg(test)] pub(crate) use
//! tests::testutil;`, imported here as `self::testutil` rather than
//! `super::testutil` so the last outside consumer's disappearance turns
//! the re-export into a denied `unused_imports` rather than a silent
//! survivor.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

pub(crate) mod testutil;

use self::testutil::{mkfifo, within_deadline};
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// Matches `cache.rs`'s and `store.rs`'s own test fixture — pid plus
/// a per-process counter, so two tests in one binary never collide.
struct ScratchDir(std::path::PathBuf);
impl ScratchDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "the lint row this licenses bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
            hashed or signed value must take a `WriterIdentity` instead. Here it is a SCRATCH-DIRECTORY NAME \
            and nothing else (`granary-fsguard-test-<pid>-<counter>` under the temp dir, created and removed by \
            this fixture), and it is load-bearing for correctness there: the counter beside it is \
            per-process, and every test binary runs in its own process, so without the pid two concurrent \
            runs generate the same name and share one directory. It reaches no hashed or signed value, and \
            nothing this module asserts is derived from it: every row here checks a syscall's own outcome \
            — the error a guarded primitive returns, the shape it refuses — against a directory this \
            fixture made and will delete, and the directory NAME is an input to none of those checks"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-fsguard-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }
}
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_regular_file_opens_and_reads_normally() {
    let dir = ScratchDir::new();
    let p = dir.0.join("plain");
    std::fs::write(&p, b"hello").unwrap_or_else(|e| panic!("{e}"));
    let f = open_regular_read(&p).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(f.metadata().unwrap_or_else(|e| panic!("{e}")).len(), 5);
}

#[test]
fn an_absent_file_still_reports_not_found() {
    let dir = ScratchDir::new();
    let err = open_regular_read(&dir.0.join("nope"))
        .err()
        .unwrap_or_else(|| panic!("an absent path must not open"));
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn a_symlink_is_refused_rather_than_followed() {
    let dir = ScratchDir::new();
    let victim = dir.0.join("victim");
    std::fs::write(&victim, b"outside").unwrap_or_else(|e| panic!("{e}"));
    let link = dir.0.join("link");
    std::os::unix::fs::symlink(&victim, &link).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        open_regular_read(&link).is_err(),
        "O_NOFOLLOW must refuse a symlink, not read its target"
    );
}

#[test]
fn a_directory_is_refused_as_not_regular() {
    let dir = ScratchDir::new();
    let sub = dir.0.join("sub");
    std::fs::create_dir(&sub).unwrap_or_else(|e| panic!("{e}"));
    assert!(open_regular_read(&sub).is_err());
}

/// The one that matters: WITHOUT `O_NONBLOCK` this open never
/// returns, and the process that called it hangs holding no lock,
/// having reported nothing.
#[test]
fn a_fifo_is_refused_promptly_rather_than_blocking_the_reader() {
    let dir = ScratchDir::new();
    let p = dir.0.join("pipe");
    mkfifo(&p);
    let err = within_deadline("open_regular_read on a FIFO", move || open_regular_read(&p))
        .err()
        .unwrap_or_else(|| panic!("a FIFO must not open as a regular file"));
    assert!(
        matches!(err.kind(), io::ErrorKind::InvalidData),
        "expected InvalidData, got {err:?}"
    );
}

/// The write side blocks on the OTHER condition — an `O_WRONLY`
/// open of a FIFO waits for a reader — so the lock path needs its
/// own proof, not an argument by analogy with the read path.
///
/// **With NO reader this passes on `ENXIO` alone**, which means it
/// would stay green with the post-open `fstat` refusal deleted. So
/// this row does not pin the refusal at all — it pins only that the
/// open does not hang. The row below it is the one that pins the
/// refusal, and the two are not interchangeable.
#[test]
fn a_fifo_with_no_reader_is_refused_promptly_rather_than_blocking() {
    let dir = ScratchDir::new();
    let p = dir.0.join("lock");
    mkfifo(&p);
    assert!(
        within_deadline("create_regular_lock on a reader-less FIFO", move || {
            create_regular_lock(&p, false)
        })
        .is_err(),
        "a FIFO must never be accepted as a lock file"
    );
}

/// The case the reader-less test CANNOT reach. With a reader
/// holding the FIFO open, `O_WRONLY|O_NONBLOCK` SUCCEEDS — no
/// `ENXIO` — so the only thing standing between the caller and a
/// "lock file" that is really a pipe is the post-open `fstat`.
/// Delete `refuse_non_regular` and this test fails while the
/// reader-less one above stays green: that asymmetry is the whole
/// reason it exists.
#[test]
fn a_fifo_with_a_live_reader_is_refused_by_the_fstat_not_by_enxio() {
    let dir = ScratchDir::new();
    let p = dir.0.join("lock");
    mkfifo(&p);

    // Hold the read end open for the duration, so the write open
    // cannot fail with ENXIO and must be refused on its own merits.
    let reader_path = p.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        // O_NONBLOCK so the READER does not block waiting for a
        // writer either — this fixture must not be able to hang.
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&reader_path);
        let _ = ready_tx.send(held.is_ok());
        let _ = done_rx.recv(); // keep the fd alive until released
    });
    let reader_open = ready_rx
        .recv_timeout(Duration::from_secs(20))
        .unwrap_or_else(|_| panic!("the fixture's own reader could not open the FIFO"));
    assert!(
        reader_open,
        "fixture precondition: the read end must be open"
    );

    let probe = p.clone();
    let result = within_deadline("create_regular_lock on a peer-connected FIFO", move || {
        create_regular_lock(&probe, false)
    });
    let _ = done_tx.send(());
    let err = result
        .err()
        .unwrap_or_else(|| panic!("a FIFO with a live reader must still be refused"));
    assert_eq!(
        err.kind(),
        io::ErrorKind::InvalidData,
        "and refused by the fstat (InvalidData), not incidentally by ENXIO: {err:?}"
    );
}

/// `open_regular_append` had no test of its own at all — it was
/// added last, for the journal, and inherited its coverage by
/// resemblance to the other primitives. Resemblance is not
/// coverage: this is its own row.
#[test]
fn open_regular_append_refuses_a_fifo_and_never_creates() {
    let dir = ScratchDir::new();
    let fifo = dir.0.join("journal-fifo");
    mkfifo(&fifo);

    // A LIVE READER, for the same reason the lock test needs one:
    // without a peer, `O_WRONLY|O_NONBLOCK` fails `ENXIO` before
    // the fstat refusal is ever reached, and the test stays green
    // with `refuse_non_regular` deleted from this function — the
    // test would then pass on the errno rather than on the guard it
    // names. `create_regular_lock`'s own row carries the identical
    // peer for the identical reason; one function away, the same
    // class.
    let reader_path = fifo.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&reader_path);
        let _ = ready_tx.send(held.is_ok());
        let _ = done_rx.recv();
    });
    assert!(
        ready_rx
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| panic!("the fixture's own reader could not open the FIFO")),
        "fixture precondition: the read end must be open, or ENXIO masks the guard"
    );

    let probe = fifo.clone();
    let result = within_deadline("open_regular_append on a peer-connected FIFO", move || {
        open_regular_append(&probe)
    });
    let _ = done_tx.send(());
    let err = result
        .err()
        .unwrap_or_else(|| panic!("the journal append must refuse a FIFO"));
    assert_eq!(
        err.kind(),
        io::ErrorKind::InvalidData,
        "refused by the fstat, not incidentally by ENXIO — otherwise journal records go \
         into a pipe: {err:?}"
    );

    // NEVER creates: a caller that needs the file must have written
    // it, so an absent path stays a real `NotFound` rather than
    // silently becoming an empty journal with no envelope.
    let absent = dir.0.join("not-there");
    let err = open_regular_append(&absent)
        .err()
        .unwrap_or_else(|| panic!("append must not create"));
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    assert!(
        !absent.exists(),
        "and must not have created it as a side effect"
    );
}

#[test]
fn create_regular_lock_still_creates_an_ordinary_lock() {
    let dir = ScratchDir::new();
    let p = dir.0.join("lock");
    let f = create_regular_lock(&p, false).unwrap_or_else(|e| panic!("{e}"));
    assert!(f.metadata().unwrap_or_else(|e| panic!("{e}")).is_file());
    // Re-opening an existing lock must keep working — the flock
    // protocol depends on it.
    drop(create_regular_lock(&p, false).unwrap_or_else(|e| panic!("{e}")));
}
/// A HARD LINK planted at the lock path must be REFUSED, and — the
/// half that is the actual defect — its target must still hold its
/// bytes afterwards. An open carrying `O_TRUNC` acts at open: the
/// victim would be emptied before any check ran, so a test that only
/// asserted the refusal would pass on such an open.
///
/// The CONTROL is the same call on an ordinary path in the same test:
/// it must SUCCEED. Without it a refusal that rejected everything
/// would look like a fix.
#[test]
fn a_hard_linked_lock_is_refused_without_truncating_its_target() {
    let dir = ScratchDir::new();
    let victim = dir.0.join("victim");
    std::fs::write(&victim, b"the target's bytes").unwrap_or_else(|e| panic!("{e}"));
    let planted = dir.0.join("lock");
    std::fs::hard_link(&victim, &planted).unwrap_or_else(|e| panic!("{e}"));

    let refused = create_regular_lock(&planted, false);
    assert!(
        refused.is_err(),
        "a hard link at the lock path must be refused: O_NOFOLLOW does not \
         see it, O_NONBLOCK does not see it, and it IS a regular file"
    );
    assert_eq!(
        std::fs::read(&victim).unwrap_or_else(|e| panic!("{e}")),
        b"the target's bytes",
        "THE DEFECT: the target must still hold its bytes — the refusal is \
         worthless if the open truncated it on the way to being refused"
    );

    // CONTROL: an ordinary, sole-linked path still works.
    let ordinary = dir.0.join("ordinary-lock");
    drop(create_regular_lock(&ordinary, false).unwrap_or_else(|e| panic!("{e}")));
}

/// The append open has the same gap with a different sink: records
/// would be appended INTO the victim. Same shape, same control.
#[test]
fn a_hard_linked_append_target_is_refused_and_never_written() {
    let dir = ScratchDir::new();
    let victim = dir.0.join("victim");
    std::fs::write(&victim, b"original").unwrap_or_else(|e| panic!("{e}"));
    let planted = dir.0.join("journal");
    std::fs::hard_link(&victim, &planted).unwrap_or_else(|e| panic!("{e}"));

    assert!(
        open_regular_append(&planted).is_err(),
        "a hard link at an append target must be refused"
    );
    assert_eq!(
        std::fs::read(&victim).unwrap_or_else(|e| panic!("{e}")),
        b"original"
    );

    // CONTROL: an ordinary existing file still opens for append.
    let ordinary = dir.0.join("ordinary-journal");
    std::fs::write(&ordinary, b"x").unwrap_or_else(|e| panic!("{e}"));
    drop(open_regular_append(&ordinary).unwrap_or_else(|e| panic!("{e}")));
}

/// A lock that already exists is TRUNCATED, not appended to — by
/// `set_len` after the check, not by `O_TRUNC` at open. Without this
/// row the open could silently drop truncation and nothing would
/// notice.
#[test]
fn re_creating_an_existing_lock_still_truncates_it() {
    let dir = ScratchDir::new();
    let p = dir.0.join("lock");
    std::fs::write(&p, b"stale contents from a previous run").unwrap_or_else(|e| panic!("{e}"));
    drop(create_regular_lock(&p, false).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(
        std::fs::metadata(&p)
            .unwrap_or_else(|e| panic!("{e}"))
            .len(),
        0,
        "create_regular_lock must still leave the lock file empty"
    );
}

// -- create_regular_exclusive / publish_regular ----------------------

#[test]
fn create_regular_exclusive_creates_a_fresh_file_and_refuses_a_second_call() {
    let dir = ScratchDir::new();
    let p = dir.0.join("snapshot.tmp");
    let f = create_regular_exclusive(&p).unwrap_or_else(|e| panic!("{e}"));
    assert!(f.metadata().unwrap_or_else(|e| panic!("{e}")).is_file());
    drop(f);
    assert!(
        create_regular_exclusive(&p).is_err(),
        "O_EXCL must refuse a name that already exists"
    );
}

/// A symlink planted at the target name must be refused, not
/// followed — `O_EXCL` alone refuses any pre-existing name, symlink
/// included, before `O_NOFOLLOW`'s own check would ever run.
#[test]
fn create_regular_exclusive_refuses_a_symlink_at_the_target_name() {
    let dir = ScratchDir::new();
    let victim = dir.0.join("victim");
    std::fs::write(&victim, b"outside").unwrap_or_else(|e| panic!("{e}"));
    let link = dir.0.join("link");
    std::os::unix::fs::symlink(&victim, &link).unwrap_or_else(|e| panic!("{e}"));
    assert!(create_regular_exclusive(&link).is_err());
}

#[test]
fn publish_regular_renames_the_temp_file_onto_the_final_name() {
    let dir = ScratchDir::new();
    let tmp = dir.0.join("snapshot.json.tmp");
    let dest = dir.0.join("snapshot.json");
    let mut f = create_regular_exclusive(&tmp).unwrap_or_else(|e| panic!("{e}"));
    std::io::Write::write_all(&mut f, b"the snapshot body").unwrap_or_else(|e| panic!("{e}"));
    drop(f);
    publish_regular(&tmp, &dest, b"the snapshot body").unwrap_or_else(|e| panic!("{e}"));
    assert!(!tmp.exists(), "the temp name must be gone after the rename");
    assert_eq!(
        std::fs::read(&dest).unwrap_or_else(|e| panic!("{e}")),
        b"the snapshot body"
    );
}

/// A symlink at the SOURCE name must be refused, not published —
/// `publish_regular` re-opens `from` with `O_NOFOLLOW` immediately
/// before the rename for exactly this reason.
#[test]
fn publish_regular_refuses_a_symlink_at_the_source_name() {
    let dir = ScratchDir::new();
    let victim = dir.0.join("victim");
    std::fs::write(&victim, b"outside").unwrap_or_else(|e| panic!("{e}"));
    let link = dir.0.join("link");
    std::os::unix::fs::symlink(&victim, &link).unwrap_or_else(|e| panic!("{e}"));
    let dest = dir.0.join("dest");
    // The symlink open must be refused (`O_NOFOLLOW`) before this
    // value is ever compared, so any bytes do for this row.
    assert!(publish_regular(&link, &dest, b"irrelevant").is_err());
    assert!(!dest.exists(), "a refused publish must create nothing");
}

/// A destination that appeared AFTER the caller's own
/// existence check is refused, not overwritten. `publish_regular`
/// publishes with `hard_link`, which refuses an existing destination
/// (`AlreadyExists`), where `std::fs::rename` on Unix would REPLACE it.
#[test]
fn publish_regular_refuses_a_destination_that_appeared_after_the_check() {
    let dir = ScratchDir::new();
    let tmp = dir.0.join("snapshot.json.tmp");
    let dest = dir.0.join("snapshot.json");
    let mut f = create_regular_exclusive(&tmp).unwrap_or_else(|e| panic!("{e}"));
    std::io::Write::write_all(&mut f, b"the real snapshot body").unwrap_or_else(|e| panic!("{e}"));
    drop(f);
    // Simulates a destination a concurrent writer (or a stale run)
    // planted in the window between the caller's own
    // `confirmed_absent`-shaped check and this publish — a window
    // the check and the publish do not share a lock across.
    std::fs::write(&dest, b"a concurrent writer got here first").unwrap_or_else(|e| panic!("{e}"));
    let before = std::fs::read(&dest).unwrap_or_else(|e| panic!("{e}"));
    let result = publish_regular(&tmp, &dest, b"the real snapshot body");
    assert!(
        matches!(&result, Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists),
        "a destination that appeared after the check must be refused as \
         AlreadyExists, not overwritten: {result:?}"
    );
    let after = std::fs::read(&dest).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        before, after,
        "a refused publish must not overwrite the file that beat it there"
    );
    assert!(
        tmp.exists(),
        "a refused publish must leave the temp file alone"
    );
}

/// **A fresh regular file at the source name.** The symlink row above is
/// refused by `O_NOFOLLOW` at the re-open. Neither that nor the
/// nlink check catches THIS plant: a co-tenant in the snapshot
/// directory watches for the exclusive create, `unlink`s `from`,
/// and `creat`s a FRESH, solitary-linked regular file at the same
/// name — never hard-linked from elsewhere (so
/// `refuse_non_sole_regular`'s nlink check passes), not a symlink
/// (so `O_NOFOLLOW` passes).
///
/// **A check based on `(dev, ino)` alone
/// is UNSOUND on Linux**: ext4/tmpfs recycle a freed inode number
/// for the very next create in the same directory, so the fresh
/// replant below regularly gets handed back the SAME inode this
/// process just released, comparing equal and publishing the
/// forgery — reproduced by Linux CI even though this exact row was
/// green on macOS/APFS, which does not recycle that way. **This row
/// is now content-independent of inode semantics**: the replant
/// below uses DIFFERENT bytes than this process wrote, so
/// [`verify_published_body`] refuses it on every platform,
/// regardless of what the inode number happens to be. See the row
/// below this one for the companion case — an IDENTICAL-content
/// replant, which this check does not and need not refuse.
#[test]
fn publish_regular_refuses_a_fresh_regular_file_replanted_at_the_source_name() {
    let dir = ScratchDir::new();
    let tmp = dir.0.join("snapshot.json.tmp");
    let dest = dir.0.join("snapshot.json");
    // Exactly the caller's own sequence: exclusive create, then
    // write the body.
    let mut f = create_regular_exclusive(&tmp).unwrap_or_else(|e| panic!("{e}"));
    std::io::Write::write_all(&mut f, b"the real snapshot body").unwrap_or_else(|e| panic!("{e}"));
    drop(f);
    // A co-tenant unlinks the real temp and replants a FRESH
    // regular file, with DIFFERENT content, at the same name, in
    // the window between this process's own write finishing and
    // the publish below.
    std::fs::remove_file(&tmp).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&tmp, b"forged snapshot, never written by this process")
        .unwrap_or_else(|e| panic!("{e}"));
    let result = publish_regular(&tmp, &dest, b"the real snapshot body");
    assert!(
        result.is_err(),
        "a fresh regular file replanted at the source name, with content \
         different from what this process wrote, must be refused: {result:?}"
    );
    assert!(!dest.exists(), "a refused publish must create nothing");
}

/// **The companion row with identical content.** The same
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
fn publish_regular_allows_a_fresh_regular_file_replanted_at_the_source_name_with_identical_content()
{
    let dir = ScratchDir::new();
    let tmp = dir.0.join("snapshot.json.tmp");
    let dest = dir.0.join("snapshot.json");
    let mut f = create_regular_exclusive(&tmp).unwrap_or_else(|e| panic!("{e}"));
    std::io::Write::write_all(&mut f, b"the real snapshot body").unwrap_or_else(|e| panic!("{e}"));
    drop(f);
    // A co-tenant unlinks the real temp and replants a FRESH
    // regular file at the same name — a genuinely different inode
    // — holding the IDENTICAL bytes this process wrote.
    std::fs::remove_file(&tmp).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&tmp, b"the real snapshot body").unwrap_or_else(|e| panic!("{e}"));
    let result = publish_regular(&tmp, &dest, b"the real snapshot body");
    assert!(
        result.is_ok(),
        "a replant with content identical to what this process wrote is \
         indistinguishable from no replant at all, and must publish: {result:?}"
    );
    assert_eq!(
        std::fs::read(&dest).unwrap_or_else(|e| panic!("{e}")),
        b"the real snapshot body"
    );
}

/// **The pure decision `publish_regular` makes** (see
/// `same_identity`'s own doc for why this is driven directly rather
/// than through an actual race): two REAL but unrelated files never
/// compare equal, and a file compared against its OWN re-stat does.
#[test]
fn same_identity_is_false_for_two_different_real_files_and_true_for_a_re_stat() {
    let dir = ScratchDir::new();
    let a = dir.0.join("a");
    let b = dir.0.join("b");
    std::fs::write(&a, b"a").unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&b, b"b").unwrap_or_else(|e| panic!("{e}"));
    let meta_a = std::fs::symlink_metadata(&a).unwrap_or_else(|e| panic!("{e}"));
    let meta_b = std::fs::symlink_metadata(&b).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !same_identity(&meta_a, &meta_b),
        "two different real files must not compare equal"
    );
    let meta_a_again = std::fs::symlink_metadata(&a).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        same_identity(&meta_a, &meta_a_again),
        "the same file, re-stat, must compare equal"
    );
}

/// [`publish_outcome`]'s own three
/// branches, driven directly over SYNTHETIC `io::Result`s — see that
/// function's doc for why a real fixture cannot discriminate this.
/// The middle row pins the rule: `hard_link` landing but `remove_file`
/// failing must resolve `Clean`-adjacent (`LeftoverTemp`, still a
/// SUCCESS from `publish_regular`'s point of view), never `Failed`.
#[test]
fn publish_outcome_reports_success_once_hard_link_lands_even_if_cleanup_fails() {
    assert!(matches!(
        publish_outcome(Ok(()), &Ok(())),
        PublishOutcome::Clean
    ));
    assert!(matches!(
        publish_outcome(
            Ok(()),
            &Err(io::Error::from(io::ErrorKind::PermissionDenied))
        ),
        PublishOutcome::LeftoverTemp
    ));
    // `remove_temp` is irrelevant once `hard_link` itself failed —
    // the real caller never even attempts the remove in that case
    // (see `publish_regular`'s own `if hard_link_result.is_ok()`
    // guard), but the decision function must not depend on that
    // discipline to get this branch right.
    assert!(matches!(
        publish_outcome(Err(io::Error::from(io::ErrorKind::AlreadyExists)), &Ok(())),
        PublishOutcome::Failed(_)
    ));
}

/// **The outcome decision and its result mapping need separate
/// tests**: `publish_outcome`'s own test above proves the DECISION is
/// right, but `publish_regular` only reports what
/// [`PublishOutcome::into_result`] says — a mutation to THAT mapping
/// (swapping `LeftoverTemp`'s arm back to `Err`, reintroducing the
/// cleanup-failure reporting bug) would not move ANY existing row: not
/// `publish_outcome`'s own test, which never calls `into_result`, and
/// not `publish_regular`'s end-to-end tests, none of which reach the
/// `LeftoverTemp` branch (`publish_regular_renames_the_temp_file_onto_the_final_name`
/// hits `Clean`, `publish_regular_refuses_a_destination_that_appeared_after_the_check`
/// hits `Failed`). This row closes that gap directly, over the pure
/// mapping alone.
#[test]
fn publish_outcome_into_result_is_ok_for_leftover_temp_and_err_only_for_failed() {
    assert!(PublishOutcome::Clean.into_result().is_ok());
    assert!(
        PublishOutcome::LeftoverTemp.into_result().is_ok(),
        "a leftover temp is cleanup debt, not a reported failure"
    );
    assert!(
        PublishOutcome::Failed(io::Error::from(io::ErrorKind::AlreadyExists))
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
    let dir = ScratchDir::new();
    let occupied = dir.0.join("occupied");
    std::fs::create_dir(&occupied).unwrap_or_else(|e| panic!("{e}"));
    let real_remove_err = std::fs::remove_file(&occupied)
        .expect_err("remove_file on a directory must fail on every platform this ships for");
    assert!(matches!(
        publish_outcome(Ok(()), &Err(real_remove_err)),
        PublishOutcome::LeftoverTemp
    ));
}
