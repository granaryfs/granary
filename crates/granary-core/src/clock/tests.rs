// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::clock` — the clock seam trait.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::sheaf::Timestamp;

/// A clock the caller pins. Nothing ambient: `now` answers with the
/// value it was constructed from, which is what makes a replay a
/// replay.
struct Pinned(Timestamp);

impl Clock for Pinned {
    fn now(&self) -> Timestamp {
        self.0
    }
}

/// The replay property, stated as an assertion: two reads of a
/// pinned clock agree, so a publish driven by one has no ambient
/// input left on this axis.
#[test]
fn a_pinned_clock_answers_the_same_timestamp_every_time() {
    let clock = Pinned(Timestamp {
        secs: 1_760_000_000,
        nanos: 42,
    });
    assert_eq!(clock.now(), clock.now());
    assert_eq!(
        clock.now(),
        Timestamp {
            secs: 1_760_000_000,
            nanos: 42
        }
    );
}

/// One method and no `async` means the trait is DYN-COMPATIBLE —
/// unlike `RootStore`/`BinStore`, whose desugared futures are not.
/// This is asserted because it is
/// the mechanical consequence of the shape this module fixes: add a
/// `sleep`/`timeout` returning a future, or a generic parameter, and
/// this stops compiling.
#[test]
fn clock_is_dyn_compatible_and_send_and_sync() {
    fn assert_send_sync<T: Send + Sync + ?Sized>() {}
    assert_send_sync::<dyn Clock>();
    let clock: Box<dyn Clock> = Box::new(Pinned(Timestamp {
        secs: -1,
        nanos: 999_999_999,
    }));
    assert_eq!(
        clock.now(),
        Timestamp {
            secs: -1,
            nanos: 999_999_999
        }
    );
}
