// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A writable mount's endings through the kernel: a signal's shutdown while
//! the mount serves, a lazy unmount that flushes at the last close, and an
//! expiry that cuts a stalled shutdown at once.

use super::*;
use crate::sync::{Cause, Cut, Outcome, ShutdownReport, Trigger};
use std::os::unix::fs::OpenOptionsExt as _;

/// How long a row waits for another thread before it names the hang.
const HANG: std::time::Duration = std::time::Duration::from_secs(20);

/// Begin the mount's shutdown on its own thread, as a signal's would.
fn begin_on_thread(fixture: &SyncMount, trigger: Trigger) -> mpsc::Receiver<ShutdownReport> {
    let (send, receive) = mpsc::channel();
    let shutdown = fixture.shutdown.clone();
    std::thread::spawn(move || {
        let _ = send.send(shutdown.begin(trigger));
    });
    receive
}

/// Wait until `name`/`phase` has fired, or name the hang.
fn wait_fired(faults: &crate::FaultControl, name: &str, phase: &str) {
    let started = std::time::Instant::now();
    while !faults
        .sync_fired()
        .iter()
        .any(|event| event.name == name && event.phase == phase)
    {
        assert!(started.elapsed() < HANG, "{name}/{phase} never fired");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Wait until the mount's session has ended, or name the hang.
fn wait_ended(fixture: &SyncMount) {
    let started = std::time::Instant::now();
    while fixture.mount.daemon_alive() {
        assert!(started.elapsed() < HANG, "the session never ended");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// The root-level file `name` in the last root the mount registered, read
/// from the mount's own store past its phase, which a released mount's
/// content source refuses; `None` when a grain is not held locally.
fn last_registered_file(fixture: &SyncMount, name: &[u8]) -> Option<Vec<u8>> {
    let sends = fixture.state.lock().unwrap().sends.clone();
    let manifest = sends
        .iter()
        .rev()
        .find_map(|bytes| intent::decode_register(bytes, &fixture.tree.volume, |_, _| true).ok())
        .and_then(|request| granary_core::root::decode_root(request.root).ok())?
        .manifest_root;
    let stored = |id: GrainId| {
        fixture
            .mediator
            .with(|store| Ok(store.stored_for_test(&id)))
            .ok()
            .flatten()
    };
    let node = stored(manifest)?;
    let (_, cursor) = granary_core::encoding::open_envelope(&node).ok()?;
    let entry = granary_core::manifest::decode_dir_leaf(cursor)
        .ok()?
        .into_iter()
        .find(|entry| entry.name.as_bytes() == name)?;
    let granary_core::manifest::EntryKind::File {
        grains: granary_core::manifest::FileGrains::Inline(refs),
        ..
    } = entry.kind
    else {
        return None;
    };
    refs.iter()
        .map(|grain| stored(grain.id))
        .collect::<Option<Vec<_>>>()
        .map(|grains| grains.concat())
}

fn errno(error: &std::io::Error) -> Option<i32> {
    error.raw_os_error()
}

/// A signal's shutdown runs while the mount is still mounted: held at its
/// first registration, the latch already answers a write, a synchronous
/// write and an fsync through the kernel with `EROFS`, while a read is
/// served. Resumed, it commits the three dirty files in one publication;
/// the unmount after it runs `destroy`, whose shutdown answers the same
/// report and registers nothing more. The same store then restarts and
/// serves the committed bytes.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the mounted shutdown report, teardown and restart byte checks share one fixture"
)]
fn writable_linux_signal_shutdown_commits_while_mounted() {
    let name = "writable_linux_signal_shutdown_commits_while_mounted";
    if !venue(name) {
        return;
    }
    let deadline = sync_deadline();
    let mut cases = 0;
    for profile in [
        crate::SyncProfile::DurablePrepared,
        crate::SyncProfile::Published,
    ] {
        let mut fixture = SyncMount::with_profile(deadline, Hook::Bound, profile);
        for file in ["a", "b", "c"] {
            std::fs::write(fixture.paths.mountpoint.join(file), file.repeat(64)).unwrap();
        }
        let held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(fixture.paths.mountpoint.join("a"))
            .unwrap();
        let seq_before = fixture.remote_seq();
        let faults = fixture.faults();
        faults.arm(
            "sync.registration",
            "before_dispatch",
            1,
            crate::FaultAction::Block,
        );
        let report = begin_on_thread(&fixture, Trigger::Signal);
        wait_fired(&faults, "sync.registration", "before_dispatch");
        let file = fixture.paths.mountpoint.join("f.txt");
        let latched = (
            held.write_at(b"x", 0).map_err(|error| errno(&error)),
            std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_SYNC)
                .open(&file)
                .and_then(|synced| synced.write_at(b"y", 0))
                .map_err(|error| errno(&error)),
            held.sync_all().map_err(|error| errno(&error)),
            std::fs::read(&file)
                .map(|bytes| !bytes.is_empty())
                .map_err(|error| errno(&error)),
        );
        faults.resume();
        let report = report.recv_timeout(HANG).ok().map(|report| report.outcome);
        drop(held);
        let registered = fixture.registrations();
        let cleaned = fixture.mount.finish().map_err(|error| error.to_string());
        assert_eq!(
            (
                latched,
                report.is_some_and(|outcome| matches!(outcome, Outcome::Committed(_))),
                fixture.registrations() - registered,
                fixture.remote_seq() - seq_before,
                cleaned,
            ),
            (
                (
                    Err(Some(libc::EROFS)),
                    Err(Some(libc::EROFS)),
                    Err(Some(libc::EROFS)),
                    Ok(true)
                ),
                true,
                0,
                1,
                Ok(())
            ),
            "profile={profile:?}, report={report:?}: ((write, O_SYNC write, fsync, read), \
             committed, registrations after the unmount, head moved, cleanup)"
        );
        let authority_state = {
            let state = fixture.state.lock().unwrap();
            AuthorityState {
                cursor: state.cursor,
                row: state.row,
                root: state.root.clone(),
                head_seq: state.head_seq,
                ..AuthorityState::default()
            }
        };
        let (paths, tree) = fixture.finish_shared_cache();
        let restarted = SyncMount::shared_cache_with_authority(
            sync_deadline(),
            profile,
            authority_state,
            paths,
            tree,
        )
        .unwrap();
        for file in ["a", "b", "c"] {
            assert_eq!(
                std::fs::read(restarted.paths.mountpoint.join(file))
                    .map_err(|error| error.to_string()),
                Ok(file.repeat(64).into_bytes()),
                "profile={profile:?}, file={file}"
            );
        }
        restarted.finish();
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A lazy unmount with a descriptor held takes the mount out of the table
/// at once, but the session serves the descriptor on, writes included, and
/// no shutdown has run. At its last close the kernel ends the session, and
/// `destroy`'s shutdown commits that write: the root it registers holds it,
/// and the end classifies clean.
#[test]
fn writable_linux_lazy_unmount_flushes_at_the_last_close() {
    let name = "writable_linux_lazy_unmount_flushes_at_the_last_close";
    if !venue(name) {
        return;
    }
    let mut fixture = SyncMount::new(sync_deadline());
    let held = fixture.file();
    let seq_before = fixture.remote_seq();
    granary_fuse::detach_unmount(&fixture.paths.mountpoint).unwrap();
    let identity_gone = granary_fuse::MountIdentity::capture(&fixture.paths.mountpoint)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
    let written = held
        .write_at(b"lazy-written", 0)
        .map_err(|error| errno(&error));
    std::thread::sleep(std::time::Duration::from_millis(200));
    let before_close = (fixture.shutdown.report(), fixture.mount.daemon_alive());
    drop(held);
    wait_ended(&fixture);
    let report = fixture.shutdown.report().map(|report| report.outcome);
    let cleaned = fixture.mount.finish().map_err(|error| error.to_string());
    let bytes = last_registered_file(&fixture, b"f.txt").unwrap_or_default();
    assert_eq!(
        (
            identity_gone,
            written,
            before_close,
            report.is_some_and(|outcome| matches!(outcome, Outcome::Committed(_))),
            fixture.remote_seq() - seq_before,
            bytes.starts_with(b"lazy-written"),
            cleaned,
        ),
        (true, Ok(12), (None, true), true, 1, true, Ok(())),
        "report={report:?}: (the row gone, a write through the held descriptor, (report \
         and session before the close), committed, head moved, the root holds the write, \
         cleanup)"
    );
}

/// A further signal's expiry cuts a shutdown stalled at a registration at
/// once, far inside its thirty-second bound: the outcome names the deadline
/// and the cut the signal, and the journal and the intent are kept.
#[test]
fn writable_linux_expire_while_mounted_stops_at_once() {
    let name = "writable_linux_expire_while_mounted_stops_at_once";
    if !venue(name) {
        return;
    }
    let mut fixture = SyncMount::new(sync_deadline());
    std::fs::write(fixture.paths.mountpoint.join("a"), b"stalled").unwrap();
    fixture.wait("the write's stage hold to be released", || {
        fixture
            .mediator
            .with(|store| Ok(!store.has_open_write_handles()))
            .unwrap()
    });
    let records = fixture.journal_records();
    let faults = fixture.faults();
    faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let report = begin_on_thread(&fixture, Trigger::Signal);
    wait_fired(&faults, "sync.registration", "before_dispatch");
    let expired = std::time::Instant::now();
    fixture.shutdown.expire();
    let report = report.recv_timeout(HANG).ok();
    let took = expired.elapsed();
    // The supervised registration can still finish once the fixture unblocks
    // it. Observe the state left by expiry while registration is still stalled.
    let phase = fixture
        .mediator
        .with(|store| Ok(store.snapshot().phase))
        .unwrap();
    let kept = fixture.journal_records() == records;
    faults.resume();
    let cleaned = fixture.mount.finish().map_err(|error| error.to_string());
    assert_eq!(
        (
            report.map(|report| (report.outcome, report.cut)),
            took < std::time::Duration::from_secs(1),
            kept,
            phase,
            cleaned,
        ),
        (
            Some((Outcome::Incomplete(Cause::Deadline), Some(Cut::Signal))),
            true,
            true,
            granary_core::overlay_ownership::Phase::Serving,
            Ok(())
        ),
        "took={took:?}: ((outcome, cut), within a second, journal kept, phase, cleanup)"
    );
}
