// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The FIFO fixtures, shared. `cache.rs` and `verify.rs` harden their
//! own opens and need the SAME bounded-join discipline to test them;
//! three private copies of a deadline helper is how three copies
//! drift, and a drifted one here would silently stop catching the
//! regression it exists for.
//!
//! **Two inner attributes, and both are load-bearing rather than tidy.**
//! Nesting this fixture under `tests` put it
//! INSIDE `tests.rs`'s file-scoped `#![expect(clippy::disallowed_methods)]`,
//! which it was never under while it was an inline sibling in `fsguard.rs` —
//! a lint level set by an inner attribute is inherited down the module tree.
//! That is a SILENT WIDENING of the licence, and it was proved with a control:
//! a planted `std::fs::metadata` here is clippy-silent on the migrated layout
//! and `error: use of a disallowed method` on the inline one. `deny` restores
//! the ban for this file without moving `EXPECTED_LICENSED_SITES` — a `deny`
//! is not a licence, so the scanner does not count it.
//!
//! The file's own `cfg(test)` is an independent production-build shield: a file
//! carrying it cannot reach a production build whatever declares it. It is
//! redundant with the ancestor's gate TODAY and is written anyway, so that a
//! future declaration of this fixture from somewhere ungated cannot compile
//! it into the binary with the fs bans relaxed.
#![cfg(test)]
#![deny(clippy::disallowed_methods)]

use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

/// Run `f` on a worker and FAIL, rather than hang, if it does not
/// return. Every caller plants a FIFO — precisely the input that
/// blocks forever if the `O_NONBLOCK` guard regresses — so
/// asserting on a bounded receive is what turns that regression
/// into a red test instead of a wedged `nextest` run sitting at 0%
/// CPU (a failure mode this project has already paid an hour to
/// diagnose once). The blocked worker is leaked deliberately:
/// nextest gives each test its own process, and process exit does
/// not wait on non-main threads.
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

/// `mkfifo(1)`, not `libc::mkfifo` — this crate denies `unsafe_code`
/// with a fixed inventory of sanctioned sites; a test fixture does not
/// earn another. POSIX, present on every platform this builds for.
pub(crate) fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap_or_else(|e| panic!("mkfifo: {e}"));
    assert!(status.success(), "mkfifo {} failed", path.display());
}
