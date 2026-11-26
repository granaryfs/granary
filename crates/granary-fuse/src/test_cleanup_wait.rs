// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Shared, test-only polling for asynchronous kernel teardown.

use std::sync::mpsc;
use std::time::{Duration, Instant};

const CLEANUP_BOUND: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(10);

/// Cleanup has already released the mount and joined the daemon. Allow kernel
/// reference/connection disposal to catch up; a surviving resource still fails.
#[expect(
    clippy::disallowed_methods,
    reason = "test-only monotonic deadline for real kernel teardown, outside simulated logic"
)]
pub(crate) fn assert_gone(connection: Option<u64>, resource: &str, gone: impl FnMut() -> bool) {
    let start = Instant::now();
    // Keep the sender alive: recv_timeout supplies the same short waits used by
    // the session guards, rather than a disconnected receiver's immediate return.
    let (_send, receive) = mpsc::channel::<()>();
    assert_gone_with(
        connection,
        resource,
        CLEANUP_BOUND,
        gone,
        || start.elapsed(),
        |delay| {
            let _ = receive.recv_timeout(delay);
        },
    );
}

fn assert_gone_with(
    connection: Option<u64>,
    resource: &str,
    bound: Duration,
    mut gone: impl FnMut() -> bool,
    elapsed: impl Fn() -> Duration,
    mut wait: impl FnMut(Duration),
) {
    loop {
        if gone() {
            return;
        }
        let elapsed = elapsed();
        assert!(
            elapsed < bound,
            "FUSE connection {connection}: {resource} still present after {bound:?} teardown bound (elapsed {elapsed:?})",
            connection =
                connection.map_or_else(|| "unknown".to_owned(), |number| number.to_string())
        );
        wait(POLL.min(bound.checked_sub(elapsed).unwrap()));
    }
}

#[test]
fn gone_immediately_needs_no_wait() {
    assert_gone(Some(42), "connection directory", || true);
    assert_gone_with(
        Some(42),
        "connection directory",
        CLEANUP_BOUND,
        || true,
        || panic!("an absent resource needs no clock read"),
        |_| panic!("an absent resource needs no wait"),
    );
}

#[test]
fn gone_after_delay_is_polled_until_absent() {
    let elapsed = std::cell::Cell::new(Duration::ZERO);
    let checks = std::cell::Cell::new(0);
    assert_gone_with(
        Some(42),
        "connection directory",
        CLEANUP_BOUND,
        || {
            checks.set(checks.get() + 1);
            elapsed.get() >= POLL * 3
        },
        || elapsed.get(),
        |delay| elapsed.set(elapsed.get() + delay),
    );
    assert_eq!(elapsed.get(), POLL * 3);
    assert_eq!(checks.get(), 4);
}

#[test]
fn never_gone_fails_with_connection_and_bound() {
    let elapsed = std::cell::Cell::new(Duration::ZERO);
    let bound = Duration::from_millis(25);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_gone_with(
            Some(42),
            "connection directory",
            bound,
            || false,
            || elapsed.get(),
            |delay| elapsed.set(elapsed.get() + delay),
        );
    }));
    let panic = result.expect_err("a surviving connection must fail");
    let message = panic.downcast_ref::<String>().unwrap();
    assert!(message.contains("FUSE connection 42"), "{message}");
    assert!(
        message.contains("connection directory still present after 25ms teardown bound"),
        "{message}"
    );
    assert!(message.contains("elapsed 25ms"), "{message}");
    assert_eq!(elapsed.get(), bound, "the last sleep must be capped");
}
