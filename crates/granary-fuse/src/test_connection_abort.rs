// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Test-only connection pinning, with a portable connections-directory seam.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

struct Scratch(PathBuf);

impl Scratch {
    #[expect(
        clippy::disallowed_methods,
        reason = "test scratch name uses the process id to avoid cross-process collisions"
    )]
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
            std::process::id(),
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

#[cfg(target_os = "linux")]
pub(crate) use crate::test_cleanup_wait as cleanup_wait;

pub(crate) fn arm(
    connection: io::Result<Option<u64>>,
    connections: &Path,
) -> (Option<u64>, Option<File>) {
    let connection = match connection {
        Ok(Some(connection)) => connection,
        other => {
            eprintln!("mount test cleanup: connection abort unavailable: {other:?}");
            return (None, None);
        }
    };
    let abort = match OpenOptions::new()
        .write(true)
        .open(connections.join(connection.to_string()).join("abort"))
    {
        Ok(abort) => Some(abort),
        Err(error) => {
            eprintln!("mount test cleanup: connection abort unavailable: {error}");
            None
        }
    };
    (Some(connection), abort)
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
    let scratch = Scratch::new();
    let missing = scratch.0.join("missing-fuse-connections");
    assert!(!missing.exists(), "connections seam must be absent");
    let (connection, abort) = arm(Ok(Some(42)), &missing);
    assert_eq!(connection, Some(42));
    assert!(abort.is_none(), "cleanup must arm without connection abort");
    for identity in [Ok(None), Err(io::Error::from(io::ErrorKind::NotFound))] {
        let (connection, abort) = arm(identity, &missing);
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
    let (connection, abort) = arm(Ok(Some(42)), &connections);
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
