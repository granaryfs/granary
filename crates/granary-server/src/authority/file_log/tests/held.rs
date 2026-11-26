// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The held state directory: its mode rule, its lock, the re-check of its
//! name before each call, the `*at` calls on the held descriptors, and the
//! rule every opened file is held to (created `0o600`; group or other
//! write refused, read accepted; a FIFO neither blocks an open nor passes
//! it; the marker's read bounded).

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use granary_core::authlog::encode_envelope;
use granary_core::decisionlog::{DecisionLog as _, IoErrorKind, LogIoError, MarkerRead};
use granary_core::runmarker::{RunMarker, encode_marker};

use super::super::{FileLog, FileLogConfigError, FileLogOn, FileOps as _, StdFileOps};
use super::{envelope, now, scratch, state_dir, vol};
use crate::protected_dir::{ProtectionError, RuleBroken};

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

fn adapter(state: &Path) -> FileLogOn<StdFileOps> {
    FileLogOn::with_ops(StdFileOps::open(state, true).unwrap())
}

/// `mkfifo` at `path`, mode `0o600`.
fn fifo(path: &Path) {
    nix::unistd::mkfifo(
        path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
}

/// Run `f` on a thread of its own and require it to return within a
/// bound: an open that blocks fails the test instead of hanging it.
fn bounded<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (send, recv) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = send.send(f());
    });
    recv.recv_timeout(Duration::from_secs(10))
        .expect("the call blocked: an open without O_NONBLOCK waits on a FIFO")
}

// --------------------------------------------------------- the directory

/// The state directory takes no group or other access of any kind, read
/// and search included (the enrollment directory's rule): whoever could
/// open it could hold its lock and refuse the authority's start.
#[test]
fn the_state_directory_refuses_any_group_or_other_access() {
    let state = state_dir();
    for mode in [
        0o750, 0o705, 0o755, 0o711, 0o701, 0o710, 0o720, 0o702, 0o777,
    ] {
        chmod(&state, mode);
        match FileLog::new(&state, true) {
            Err(FileLogConfigError::Directory(ProtectionError::Rule {
                component,
                rule: RuleBroken::DirectoryAccessible { mode: got },
            })) => assert_eq!((component, got), (state.clone(), mode), "{mode:o}"),
            other => panic!("{mode:o}: {other:?}"),
        }
    }
    for mode in [0o700, 0o500] {
        chmod(&state, mode);
        let log = FileLog::new(&state, true).unwrap_or_else(|e| panic!("{mode:o}: {e}"));
        drop(log);
    }
    chmod(&state, 0o700);
}

/// A second adapter on the same state directory, in this process or
/// another, is refused by the lock on the held descriptor while the first
/// lives, and takes it once the first is gone. No lock file is created.
#[test]
fn a_second_adapter_on_the_same_directory_is_refused_by_the_lock() {
    let state = state_dir();
    let first = FileLog::new(&state, true).unwrap();
    match FileLog::new(&state, true) {
        Err(FileLogConfigError::Locked { path }) => assert_eq!(path, state),
        other => panic!("{other:?}"),
    }
    drop(first);
    let second = FileLog::new(&state, true).unwrap();
    assert_eq!(
        std::fs::read_dir(&state).unwrap().count(),
        0,
        "the lock left a file"
    );
    drop(second);
}

/// Before each call's I/O the configured name is re-checked against the
/// held directory: another directory moved in at the name, or nothing at
/// it, refuses the call, and the moved-away held directory is not written.
#[test]
fn another_directory_or_nothing_at_the_state_name_refuses_every_call() {
    for replace in [true, false] {
        let state = state_dir();
        let log = adapter(&state);
        let v = vol("vol-a");
        now(log.initialise(&encode_envelope(&envelope(&v, 7)))).unwrap();
        let held = state.parent().unwrap().join("held");
        std::fs::rename(&state, &held).unwrap();
        if replace {
            std::fs::create_dir(&state).unwrap();
            chmod(&state, 0o700);
        }
        let refused = Err(LogIoError::Io(IoErrorKind::Other));
        assert_eq!(now(log.read_marker()).map(|_| ()), refused, "{replace}");
        assert_eq!(
            now(log.write_marker(&encode_marker(&RunMarker::Clean))),
            refused,
            "replace {replace}"
        );
        assert_eq!(now(log.resync(&v)), refused, "replace {replace}");
        assert_eq!(
            now(log.remove_temporary(&v)).map(|_| ()),
            refused,
            "{replace}"
        );
        assert!(!held.join("MARKER").exists(), "replace {replace}");
        if replace {
            assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
        }
    }
}

/// The calls are made on the held descriptors, not by path: an ancestor
/// swapped for a link to a look-alike tree after the walk moves nothing,
/// and every file lands in the directory the walk resolved.
#[test]
fn an_ancestor_swapped_after_the_walk_does_not_move_the_calls() {
    let state = state_dir();
    let log = adapter(&state);
    let anchor = state.parent().unwrap().to_path_buf();
    let moved = anchor.with_file_name(format!(
        "{}-moved",
        anchor.file_name().unwrap().to_string_lossy()
    ));
    std::fs::rename(&anchor, &moved).unwrap();
    let decoy = anchor.with_file_name(format!(
        "{}-decoy",
        anchor.file_name().unwrap().to_string_lossy()
    ));
    std::fs::create_dir_all(decoy.join("state")).unwrap();
    std::os::unix::fs::symlink(&decoy, &anchor).unwrap();
    now(log.write_marker(&encode_marker(&RunMarker::Clean))).unwrap();
    let v = vol("vol-a");
    now(log.initialise(&encode_envelope(&envelope(&v, 7)))).unwrap();
    assert!(moved.join("state").join("MARKER").exists());
    assert!(moved.join("state").join("vol-a.log").exists());
    assert_eq!(
        std::fs::read_dir(decoy.join("state")).unwrap().count(),
        0,
        "a path call reached the decoy"
    );
}

// ------------------------------------------------------------- the files

/// The marker, its temporary, a log and its temporary are created `0o600`
/// by their create modes.
#[test]
fn every_file_is_created_0600() {
    let state = state_dir();
    let log = adapter(&state);
    now(log.write_marker(&encode_marker(&RunMarker::Clean))).unwrap();
    let v = vol("vol-a");
    now(log.initialise(&encode_envelope(&envelope(&v, 7)))).unwrap();
    assert_eq!(mode_of(&state.join("MARKER")), 0o600);
    assert_eq!(mode_of(&state.join("vol-a.log")), 0o600);
}

/// An existing marker or log that grants group or other write is refused;
/// one that grants group or other read is taken (behind a `0o700`
/// directory its read bits reach no one).
#[test]
fn an_existing_file_with_group_or_other_write_is_refused_and_read_is_taken() {
    let state = state_dir();
    let log = adapter(&state);
    let marker = encode_marker(&RunMarker::Clean);
    std::fs::write(state.join("MARKER"), marker.as_bytes()).unwrap();
    let v = vol("vol-a");
    std::fs::write(
        state.join("vol-a.log"),
        encode_envelope(&envelope(&v, 7)).as_bytes(),
    )
    .unwrap();
    for mode in [0o620, 0o602, 0o666] {
        chmod(&state.join("MARKER"), mode);
        assert_eq!(
            now(log.read_marker()),
            Err(LogIoError::Io(IoErrorKind::Other)),
            "marker {mode:o}"
        );
        chmod(&state.join("vol-a.log"), mode);
        log.forget_open_logs();
        assert_eq!(
            now(log.read(&v)),
            Err(LogIoError::Io(IoErrorKind::Other)),
            "log {mode:o}"
        );
    }
    for mode in [0o600, 0o640, 0o644] {
        chmod(&state.join("MARKER"), mode);
        assert_eq!(
            now(log.read_marker()),
            Ok(MarkerRead::Present(marker.as_bytes().to_vec())),
            "marker {mode:o}"
        );
        chmod(&state.join("vol-a.log"), mode);
        log.forget_open_logs();
        assert!(now(log.read(&v)).unwrap().is_some(), "log {mode:o}");
    }
}

/// A FIFO at the marker's or a log's name neither blocks the open
/// (`O_NONBLOCK`) nor passes it (the `fstat` type check).
#[test]
fn a_fifo_neither_blocks_an_open_nor_passes_it() {
    let state = state_dir();
    fifo(&state.join("MARKER"));
    fifo(&state.join("vol-a.log"));
    let ops = StdFileOps::open(&state, true).unwrap();
    let (marker, log) = bounded(move || (ops.read_marker("MARKER"), ops.open_rw("vol-a.log")));
    assert!(marker.is_err(), "{marker:?}");
    assert!(log.is_err(), "{:?}", log.map(|_| ()));
}

/// The marker's read takes at most the largest marker plus one byte, so a
/// longer file reads as a wrong-length marker.
#[test]
fn the_marker_read_is_bounded() {
    let state = state_dir();
    std::fs::write(state.join("MARKER"), vec![0x5A; 4096]).unwrap();
    let log = adapter(&state);
    match now(log.read_marker()) {
        Ok(MarkerRead::Present(bytes)) => {
            assert_eq!(bytes.len(), super::super::ops::MARKER_READ_LIMIT);
            assert_eq!(
                super::super::ops::MARKER_READ_LIMIT,
                granary_core::runmarker::RUNNING_LEN + 1
            );
        }
        other => panic!("{other:?}"),
    }
}

/// A scratch path that is not a provisioned directory: a regular file at
/// the state directory's name refuses the adapter.
#[test]
fn a_file_at_the_state_name_is_refused() {
    let state = scratch().join("state");
    std::fs::write(&state, b"not a directory").unwrap();
    assert!(
        matches!(
            FileLog::new(&state, true),
            Err(FileLogConfigError::Directory(
                ProtectionError::LinkOrNotDirectory { .. }
            ))
        ),
        "a file at the name"
    );
}

#[test]
fn enrollment_separation_uses_held_directories_and_allows_children() {
    let state = super::state_dir();
    let log = crate::FileLog::new(&state, true).unwrap();
    for path in [
        state.clone(),
        std::path::PathBuf::from(format!("{}/", state.display())),
    ] {
        let reader = crate::EnrollmentReader::open(&path, true).unwrap();
        let reason = log.require_separate_enrollment(&reader).unwrap_err();
        assert!(reason.contains("GRANARY_AUTHORITY_STATE_DIR"));
        assert!(reason.contains("GRANARY_AUTHORITY_ENROLLMENT_DIR"));
    }
    let child = state.join("enrollment");
    std::fs::create_dir(&child).unwrap();
    crate::protected_dir::tests::chmod(&child, 0o700);
    let reader = crate::EnrollmentReader::open(&child, true).unwrap();
    assert_eq!(log.require_separate_enrollment(&reader), Ok(()));
    // Replacing the path cannot change the identity of the reader's held
    // directory. No detached stat of its spelling belongs in this check.
    let moved = state.join("moved");
    std::fs::rename(&child, &moved).unwrap();
    std::fs::create_dir(&child).unwrap();
    assert_eq!(log.require_separate_enrollment(&reader), Ok(()));
    std::fs::remove_dir_all(state).unwrap();
}
