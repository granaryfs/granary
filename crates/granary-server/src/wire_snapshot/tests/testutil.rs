// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixture helpers for `crate::wire_snapshot`'s own tests: a bounded-join
//! helper and a private `mkfifo` wrapper.
//!
//! Out-of-line, because this module carries a second
//! conforming test body alongside `tests` (`testutil`, the
//! "second, differently-named inline block"), so it becomes a
//! leaf under `tests`, declared by `wire_snapshot/tests.rs`'s
//! `mod testutil;` rather than a second sibling declaration
//! in the parent (`wire_snapshot.rs`).
//!
//! A bounded join is required so
//! a FIFO plant that regresses the `O_NONBLOCK` guard fails the test
//! promptly instead of hanging the whole `nextest` process at 0% CPU —
//! the identical shape `granary-client`'s own `fsguard::testutil`
//! carries, kept as a private copy here rather than imported: this
//! crate has no dependency on that one (AGPL does not import Apache
//! test code either), and this is the first FIFO fixture this crate has
//! needed.

use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

/// Run `f` on a worker and FAIL, rather than hang, if it does not
/// return within the deadline. The blocked worker is leaked
/// deliberately: `nextest` gives each test its own process, and
/// process exit does not wait on non-main threads.
pub(crate) fn within_deadline<T: Send + 'static>(
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(20))
        .unwrap_or_else(|_| {
            panic!("{what} did not return within 20s — the O_NONBLOCK guard has regressed")
        })
}

/// `mkfifo(1)`, not `libc::mkfifo` — this crate inherits the
/// workspace's `unsafe_code = "forbid"` and a test fixture does not
/// earn an exception to it. POSIX, present on every platform this
/// builds for.
pub(crate) fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap_or_else(|e| panic!("mkfifo: {e}"));
    assert!(status.success(), "mkfifo {} failed", path.display());
}
