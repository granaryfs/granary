// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Test-only connection pinning and supervision, with a portable directory seam.

use crate::overlay_test_support::arm_fuse_abort;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let cwd = std::env::current_dir().unwrap();
        let workspace = cwd
            .ancestors()
            .find(|path| path.join("Cargo.lock").is_file() && path.join("crates").is_dir())
            .expect("test must run inside the workspace");
        let root = workspace.join("target/test-scratch");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(format!(
            "abort-{}-{}",
            super::test_process_id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(super) fn supervise(
    commands: &mpsc::Receiver<()>,
    deadline: Duration,
    mut abort: Option<File>,
    recover: impl FnOnce(),
    cleanup: impl FnOnce(Option<File>, &mpsc::Receiver<()>) -> io::Result<()>,
) -> io::Result<()> {
    let timed_out = commands.recv_timeout(deadline).is_err();
    let aborted = if timed_out {
        use std::io::Write as _;

        let result = abort.as_mut().map_or_else(
            || {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "test FUSE connection abort unavailable",
                ))
            },
            |abort| {
                abort.write_all(b"1").map_err(|error| {
                    io::Error::other(format!("test FUSE connection abort failed: {error}"))
                })
            },
        );
        recover();
        result
    } else {
        Ok(())
    };
    let cleaned = cleanup(abort, commands);
    aborted?;
    cleaned.and_then(|()| {
        if timed_out {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "mounted test exceeded its deadline",
            ))
        } else {
            Ok(())
        }
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn require_available(available: bool, case: &str) -> bool {
    if !available {
        eprintln!("SKIPPED-NO-FUSE-CONTROL {case}: connection abort unavailable; NOT EXECUTED");
    }
    available
}

#[test]
fn missing_connections_directory_degrades_arm() {
    let missing = Path::new("target/missing-fuse-connections");
    assert!(!missing.exists(), "connections seam must be absent");
    let (connection, abort) = arm_fuse_abort(Ok(Some(42)), missing);
    assert_eq!(connection, Some(42));
    assert!(abort.is_none(), "cleanup must arm without connection abort");
    for identity in [Ok(None), Err(io::Error::from(io::ErrorKind::NotFound))] {
        let (connection, abort) = arm_fuse_abort(identity, missing);
        assert_eq!(connection, None);
        assert!(abort.is_none());
    }
}

#[test]
fn available_connections_directory_pins_only_own_abort() {
    use std::io::Write as _;

    let scratch = Scratch::new();
    let connections = scratch
        .0
        .join(concat!("fuse-connections-", env!("CARGO_PKG_NAME")));
    std::fs::create_dir(&connections).unwrap();
    for name in ["42", "43"] {
        std::fs::create_dir(connections.join(name)).unwrap();
        std::fs::write(connections.join(name).join("abort"), b"0").unwrap();
    }
    let (connection, abort) = arm_fuse_abort(Ok(Some(42)), &connections);
    assert_eq!(connection, Some(42));
    let mut abort = abort.expect("own connection abort must be pinned");
    // Reusing the device number must not redirect the retained descriptor.
    std::fs::rename(connections.join("42"), connections.join("retired")).unwrap();
    std::fs::create_dir(connections.join("42")).unwrap();
    std::fs::write(connections.join("42/abort"), b"0").unwrap();
    abort.write_all(b"1").unwrap();
    drop(abort);
    assert_eq!(
        std::fs::read(connections.join("retired/abort")).unwrap(),
        b"1"
    );
    for name in ["42", "43"] {
        assert_eq!(
            std::fs::read(connections.join(name).join("abort")).unwrap(),
            b"0"
        );
    }
}

#[test]
fn watchdog_aborts_own_connection_before_recovery_and_cleanup() {
    let mut cases = 0;
    for finish in [true, false] {
        let scratch = Scratch::new();
        let connections = scratch.0.join("connections");
        for name in ["42", "43"] {
            std::fs::create_dir_all(connections.join(name)).unwrap();
            std::fs::write(connections.join(name).join("abort"), b"0").unwrap();
        }
        let (_, abort) = arm_fuse_abort(Ok(Some(42)), &connections);
        std::fs::rename(connections.join("42"), connections.join("retired")).unwrap();
        std::fs::create_dir(connections.join("42")).unwrap();
        std::fs::write(connections.join("42/abort"), b"0").unwrap();
        let (stop, commands) = mpsc::channel();
        if finish {
            stop.send(()).unwrap();
        }
        let recovered = std::cell::Cell::new(false);
        let result = supervise(
            &commands,
            Duration::from_millis(10),
            abort,
            || {
                assert_eq!(
                    std::fs::read(connections.join("retired/abort")).unwrap(),
                    b"1",
                    "own connection must be aborted before fault recovery"
                );
                recovered.set(true);
            },
            |_, _| {
                assert_eq!(
                    (
                        std::fs::read(connections.join("retired/abort")).unwrap(),
                        std::fs::read(connections.join("42/abort")).unwrap(),
                        std::fs::read(connections.join("43/abort")).unwrap(),
                        recovered.get(),
                    ),
                    (
                        if finish { b"0".to_vec() } else { b"1".to_vec() },
                        b"0".to_vec(),
                        b"0".to_vec(),
                        !finish,
                    ),
                    "watchdog must abort only its pinned connection before cleanup"
                );
                Ok(())
            },
        );
        assert_eq!(
            result.map_err(|error| (error.kind(), error.to_string())),
            if finish {
                Ok(())
            } else {
                Err((
                    io::ErrorKind::TimedOut,
                    "mounted test exceeded its deadline".into(),
                ))
            }
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn watchdog_reports_missing_or_failed_abort_and_still_cleans_up() {
    let scratch = Scratch::new();
    let path = scratch.0.join("abort");
    std::fs::write(&path, b"0").unwrap();
    let mut cases = 0;
    for abort in [None, Some(File::open(&path).unwrap())] {
        let missing = abort.is_none();
        let (_stop, commands) = mpsc::channel();
        let cleaned = std::cell::Cell::new(false);
        let recovered = std::cell::Cell::new(false);
        let result = supervise(
            &commands,
            Duration::from_millis(10),
            abort,
            || recovered.set(true),
            |_, _| {
                assert!(
                    recovered.get(),
                    "fault recovery must precede cleanup: recovered={}",
                    recovered.get()
                );
                cleaned.set(true);
                Ok(())
            },
        );
        let error = result.unwrap_err().to_string();
        assert!(
            cleaned.get()
                && error.starts_with(if missing {
                    "test FUSE connection abort unavailable"
                } else {
                    "test FUSE connection abort failed:"
                }),
            "missing={missing}, cleaned={}, error={error}",
            cleaned.get()
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}
