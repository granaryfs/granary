// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::direct_deadline` — the per-call
//! deadline for the direct-S3 remote route.
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use granary_store::backend::GranaryStore;
use object_store::memory::InMemory;

use super::*;

/// The `Busy` walk stops counting once it has been polled this many
/// times. The row below only needs to know the walk was polled at
/// all; a spin that keeps writing a shared atomic for the whole
/// deadline buys nothing and adds contention to a real-clock test.
const BUSY_POLL_CAP: u64 = 4;

/// The one `RootStore` + `BinStore` fixture the deadline rows drive:
/// every method's behaviour follows `mode`, so one type covers a
/// store that never answers at all, one that wedges a single
/// `max_seq` and then answers, and one whose `max_seq` is a
/// genuinely cooperative loop.
///
/// It is not the module's only fixture — [`PassThrough`] is the
/// pass-the-result-through one, and its methods answer with
/// distinctive values this decorator must not alter. `Walk`
/// consolidates the DEADLINE rows: everything that has to fail to
/// resolve.
struct Walk {
    mode: WalkMode,
    /// How many times a [`WalkMode::Busy`] `max_seq` was polled,
    /// saturating at [`BUSY_POLL_CAP`].
    polls: AtomicU64,
}

impl Walk {
    fn new(mode: WalkMode) -> Self {
        Self {
            mode,
            polls: AtomicU64::new(0),
        }
    }
}

/// How [`Walk`]'s methods behave.
enum WalkMode {
    /// NO method resolves — every one of the ten pends forever.
    Wedged,
    /// `max_seq` never resolves the FIRST call; answers immediately
    /// after — the shape that tells a fresh per-call clock apart
    /// from a shared budget left consumed by the call that elapsed
    /// before it. The other nine answer inertly.
    WedgeOnce(AtomicBool),
    /// `max_seq` never resolves on its own: a genuinely
    /// cooperative, self-waking loop that counts how many times it
    /// was polled. The other nine answer inertly.
    Busy,
}

impl Walk {
    /// Whether this mode wedges every method rather than just
    /// `max_seq`.
    fn wedges_everything(&self) -> bool {
        matches!(self.mode, WalkMode::Wedged)
    }
}

impl RootStore for Walk {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        if self.wedges_everything() {
            std::future::pending().await
        } else {
            Ok(())
        }
    }
    async fn get_root(&self, _volume: &str, _seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        if self.wedges_everything() {
            std::future::pending().await
        } else {
            Ok(None)
        }
    }
    async fn read_hint(
        &self,
        _volume: &str,
        _cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        if self.wedges_everything() {
            std::future::pending().await
        } else {
            Ok(HintRead::Missing)
        }
    }
    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        if self.wedges_everything() {
            std::future::pending().await
        } else {
            Ok(())
        }
    }
    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        match &self.mode {
            WalkMode::Wedged => std::future::pending().await,
            WalkMode::WedgeOnce(wedged) => {
                if wedged.swap(false, Ordering::Relaxed) {
                    std::future::pending().await
                } else {
                    // `tokio::time::Timeout` polls the wrapped future
                    // BEFORE it checks its own timer, so a future
                    // that is `Ready` on the very first poll never
                    // gives a consumed-budget bug the chance to
                    // matter. One real yield forces the timeout to
                    // actually consult its clock.
                    tokio::task::yield_now().await;
                    Ok(Some(9))
                }
            }
            WalkMode::Busy => loop {
                if self.polls.load(Ordering::Relaxed) < BUSY_POLL_CAP {
                    self.polls.fetch_add(1, Ordering::Relaxed);
                }
                tokio::task::yield_now().await;
            },
        }
    }
    async fn max_seq_above(
        &self,
        _volume: &str,
        _floor: u64,
    ) -> Result<Option<u64>, RootStoreError> {
        if self.wedges_everything() {
            std::future::pending().await
        } else {
            Ok(None)
        }
    }
}

impl BinStore for Walk {
    async fn put_bin(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        if self.wedges_everything() {
            std::future::pending().await
        } else {
            Ok(true)
        }
    }
    async fn put_meta(
        &self,
        _volume: &str,
        _id: &GrainId,
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        if self.wedges_everything() {
            std::future::pending().await
        } else {
            Ok(true)
        }
    }
    async fn get_meta(&self, _volume: &str, _id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        if self.wedges_everything() {
            std::future::pending().await
        } else {
            Ok(Vec::new())
        }
    }
    async fn get_bin_range(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _offset: u64,
        _len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        if self.wedges_everything() {
            std::future::pending().await
        } else {
            Ok(Vec::new())
        }
    }
}

/// The OUTER safety timeout for a row whose inner deadline is
/// `expected_after`: twice that, floored at ten seconds.
///
/// The floor is REAL WALL TIME, and it exists for the one UNPAUSED
/// caller ([`a_cooperative_walk_that_never_terminates_is_cut`],
/// whose inner deadline is 10 ms, so the floor IS its whole guard).
/// A one-second floor sits close enough to a loaded runner's
/// scheduling noise to print "was not cut" for a walk that was
/// about to be cut; ten seconds does not, and costs nothing on a
/// green run because the guard only elapses when the row is already
/// failing. For the paused rows the floor never binds — twice
/// `DIRECT_STORE_CALL_DEADLINE` is half an hour of VIRTUAL time,
/// which auto-advance crosses instantly.
fn outer_guard(expected_after: Duration) -> Duration {
    (expected_after * 2).max(Duration::from_secs(10))
}

/// Await `call` under an outer safety timeout `outer`; panic naming
/// `what` if the OUTER fires first, rather than let the runtime park
/// forever. Under `start_paused`, a dropped `under_deadline`
/// wrap leaves an awaited `std::future::pending()` with no timer at
/// all — auto-advance has nothing to jump to, and the runtime parks
/// until this crate's nextest slow-timeout (`.config/nextest.toml`)
/// terminates the process, which is a killed job, not a failing
/// assertion. Wrapping every such await in a second, outer timeout
/// gives auto-advance exactly one timer to jump to in that case,
/// turning a hang-until-killed into a named assertion failure.
async fn cut_or_panic<T>(outer: Duration, call: impl Future<Output = T>, what: &str) -> T {
    tokio::time::timeout(outer, call)
        .await
        .unwrap_or_else(|_| panic!("`{what}` was not cut by the decorator"))
}

/// [`assert_elapsed_after`] at the production deadline — the form
/// the ten label rows use, so each needs only one call.
async fn assert_elapsed<T: std::fmt::Debug>(
    call: impl Future<Output = Result<T, RootStoreError>>,
    expected_label: &str,
) {
    assert_elapsed_after(call, expected_label, DIRECT_STORE_CALL_DEADLINE).await;
}

/// Await `call` under [`outer_guard`], then assert it resolved to
/// `Err(Elapsed { operation, after })` naming EXACTLY
/// `expected_label` at EXACTLY `expected_after`.
///
/// A plain function rather than a macro: `macro_rules!` is banned
/// anywhere under this crate (`scripts/check-fsguard-sites.sh`'s
/// source-closure check), so the repeated call sites below stay
/// separate statements sharing this one body instead.
async fn assert_elapsed_after<T: std::fmt::Debug>(
    call: impl Future<Output = Result<T, RootStoreError>>,
    expected_label: &str,
    expected_after: Duration,
) {
    match cut_or_panic(outer_guard(expected_after), call, expected_label).await {
        Err(RootStoreError::Elapsed { operation, after }) => {
            assert_eq!(operation, expected_label, "wrong seam label");
            assert_eq!(after, expected_after, "wrong deadline for {expected_label}");
        }
        other => panic!("expected Elapsed({expected_label:?}, ..), got {other:?}"),
    }
}

/// A `RootStore` + `BinStore` whose every method answers at once
/// with either a distinctive `Ok` or a distinctive `Backend` error —
/// nothing this decorator should ever alter on a call that neither
/// hangs nor elapses.
struct PassThrough {
    fail: bool,
}

impl RootStore for PassThrough {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        if self.fail {
            Err(RootStoreError::Backend(
                "INJECTED put_root failure".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
    async fn get_root(&self, _volume: &str, _seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        if self.fail {
            Err(RootStoreError::Backend(
                "INJECTED get_root failure".to_owned(),
            ))
        } else {
            Ok(Some(b"distinctive get_root bytes".to_vec()))
        }
    }
    async fn read_hint(
        &self,
        _volume: &str,
        _cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        if self.fail {
            Err(RootStoreError::Backend(
                "INJECTED read_hint failure".to_owned(),
            ))
        } else {
            Ok(HintRead::Current {
                seq: 42,
                token: HintToken("distinctive-token".to_owned()),
            })
        }
    }
    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        if self.fail {
            Err(RootStoreError::Backend(
                "INJECTED write_hint failure".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        if self.fail {
            Err(RootStoreError::Backend(
                "INJECTED max_seq failure".to_owned(),
            ))
        } else {
            Ok(Some(7))
        }
    }
    async fn max_seq_above(
        &self,
        _volume: &str,
        _floor: u64,
    ) -> Result<Option<u64>, RootStoreError> {
        if self.fail {
            Err(RootStoreError::Backend(
                "INJECTED max_seq_above failure".to_owned(),
            ))
        } else {
            Ok(Some(11))
        }
    }
}

impl BinStore for PassThrough {
    async fn put_bin(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        if self.fail {
            Err(RootStoreError::Backend(
                "INJECTED put_bin failure".to_owned(),
            ))
        } else {
            Ok(true)
        }
    }
    async fn put_meta(
        &self,
        _volume: &str,
        _id: &GrainId,
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        if self.fail {
            Err(RootStoreError::Backend(
                "INJECTED put_meta failure".to_owned(),
            ))
        } else {
            Ok(true)
        }
    }
    async fn get_meta(&self, _volume: &str, _id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        if self.fail {
            Err(RootStoreError::Backend(
                "INJECTED get_meta failure".to_owned(),
            ))
        } else {
            Ok(b"distinctive get_meta bytes".to_vec())
        }
    }
    async fn get_bin_range(
        &self,
        _digest: &[u8; DIGEST_LEN],
        _offset: u64,
        _len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        if self.fail {
            Err(RootStoreError::Backend(
                "INJECTED get_bin_range failure".to_owned(),
            ))
        } else {
            Ok(b"distinctive get_bin_range bytes".to_vec())
        }
    }
}

/// Every one of the ten wrapped methods, in both a success and a
/// `Backend`-error mode: the decorator must deliver the inner result
/// UNCHANGED — no wrapping of a non-elapsed error, no alteration of
/// a successful value.
#[tokio::test(start_paused = true)]
async fn every_method_passes_success_and_error_through_unchanged() {
    let digest = [7u8; DIGEST_LEN];
    let id = GrainId::of(b"direct-deadline-test-grain");

    let ok = DirectStoreDeadline::new(PassThrough { fail: false });
    assert_eq!(ok.put_root("vol", 1, b"bytes".to_vec()).await, Ok(()));
    assert_eq!(
        ok.get_root("vol", 1).await,
        Ok(Some(b"distinctive get_root bytes".to_vec()))
    );
    assert_eq!(
        ok.read_hint("vol", None).await,
        Ok(HintRead::Current {
            seq: 42,
            token: HintToken("distinctive-token".to_owned()),
        })
    );
    assert_eq!(ok.write_hint("vol", 1).await, Ok(()));
    assert_eq!(ok.max_seq("vol").await, Ok(Some(7)));
    assert_eq!(ok.max_seq_above("vol", 7).await, Ok(Some(11)));
    assert_eq!(ok.put_bin(&digest, b"bin".to_vec()).await, Ok(true));
    assert_eq!(ok.put_meta("vol", &id, b"meta".to_vec()).await, Ok(true));
    assert_eq!(
        ok.get_meta("vol", &id).await,
        Ok(b"distinctive get_meta bytes".to_vec())
    );
    assert_eq!(
        ok.get_bin_range(&digest, 0, 3).await,
        Ok(b"distinctive get_bin_range bytes".to_vec())
    );

    let failing = DirectStoreDeadline::new(PassThrough { fail: true });
    assert_eq!(
        failing.put_root("vol", 1, b"bytes".to_vec()).await,
        Err(RootStoreError::Backend(
            "INJECTED put_root failure".to_owned()
        ))
    );
    assert_eq!(
        failing.get_root("vol", 1).await,
        Err(RootStoreError::Backend(
            "INJECTED get_root failure".to_owned()
        ))
    );
    assert_eq!(
        failing.read_hint("vol", None).await,
        Err(RootStoreError::Backend(
            "INJECTED read_hint failure".to_owned()
        ))
    );
    assert_eq!(
        failing.write_hint("vol", 1).await,
        Err(RootStoreError::Backend(
            "INJECTED write_hint failure".to_owned()
        ))
    );
    assert_eq!(
        failing.max_seq("vol").await,
        Err(RootStoreError::Backend(
            "INJECTED max_seq failure".to_owned()
        ))
    );
    assert_eq!(
        failing.max_seq_above("vol", 7).await,
        Err(RootStoreError::Backend(
            "INJECTED max_seq_above failure".to_owned()
        ))
    );
    assert_eq!(
        failing.put_bin(&digest, b"bin".to_vec()).await,
        Err(RootStoreError::Backend(
            "INJECTED put_bin failure".to_owned()
        ))
    );
    assert_eq!(
        failing.put_meta("vol", &id, b"meta".to_vec()).await,
        Err(RootStoreError::Backend(
            "INJECTED put_meta failure".to_owned()
        ))
    );
    assert_eq!(
        failing.get_meta("vol", &id).await,
        Err(RootStoreError::Backend(
            "INJECTED get_meta failure".to_owned()
        ))
    );
    assert_eq!(
        failing.get_bin_range(&digest, 0, 3).await,
        Err(RootStoreError::Backend(
            "INJECTED get_bin_range failure".to_owned()
        ))
    );
}

/// No `Instant::now` of any flavour — the assertion is on the
/// OUTCOME of the second call, not on any timestamp.
#[tokio::test(start_paused = true)]
async fn each_call_gets_its_own_clock_not_a_shared_budget() {
    let decorated = DirectStoreDeadline::new(Walk::new(WalkMode::WedgeOnce(AtomicBool::new(true))));

    assert_elapsed(decorated.max_seq("vol"), "GET max-seq").await;

    // The SECOND call must resolve, so it is guarded rather than
    // asserted elapsed: a bug that left it pending would park the
    // paused runtime with no timer to advance to, and the row would
    // be killed by nextest's slow-timeout instead of failing.
    let second = cut_or_panic(
        outer_guard(DIRECT_STORE_CALL_DEADLINE),
        decorated.max_seq("vol"),
        "GET max-seq (second call)",
    )
    .await;
    assert_eq!(
        second,
        Ok(Some(9)),
        "a shared/consumed budget would refuse this call too; a fresh \
         per-call clock lets it through once the inner future is ready"
    );
}

/// Every one of the ten wrapped methods is cut at its OWN deadline
/// under its OWN label. Dropping any one method's `under_deadline`
/// wrap, or swapping two labels, fails one of the ten rows below —
/// the former by [`cut_or_panic`]'s outer-timeout panic, never by
/// hanging until nextest's slow-timeout kills it.
///
/// Built through [`DirectStoreDeadline::new`], not a lower-level
/// constructor, so a wrong deadline placed in `new` ITSELF is
/// caught — not merely a wrong deadline `under_deadline` was handed
/// directly.
#[tokio::test(start_paused = true)]
async fn every_wrapped_method_elapses_under_its_own_label() {
    let decorated = DirectStoreDeadline::new(Walk::new(WalkMode::Wedged));
    let digest = [3u8; DIGEST_LEN];
    let id = GrainId::of(b"every-label-grain");

    assert_elapsed(decorated.put_root("vol", 1, b"bytes".to_vec()), "PUT root").await;
    assert_elapsed(decorated.get_root("vol", 1), "GET root").await;
    assert_elapsed(decorated.read_hint("vol", None), "GET hint").await;
    assert_elapsed(decorated.write_hint("vol", 1), "PUT hint").await;
    assert_elapsed(decorated.max_seq("vol"), "GET max-seq").await;
    assert_elapsed(decorated.max_seq_above("vol", 7), "GET max-seq-above").await;
    assert_elapsed(decorated.put_bin(&digest, b"bin".to_vec()), "PUT bin").await;
    assert_elapsed(decorated.put_meta("vol", &id, b"meta".to_vec()), "PUT meta").await;
    assert_elapsed(decorated.get_meta("vol", &id), "GET meta").await;
    assert_elapsed(decorated.get_bin_range(&digest, 0, 3), "GET bin").await;
}

/// The seven figures, restated locally as an independent oracle so
/// an edit to any one constant is a deliberate, reviewed red rather
/// than a silent drift. (`from_mins` rather than `from_secs`: the
/// constants' own doc states why.)
#[test]
fn the_direct_store_constants_are_pinned() {
    assert_eq!(DIRECT_STORE_CALL_DEADLINE, Duration::from_mins(15));
    assert_eq!(DIRECT_STORE_REQUEST_TIMEOUT, Duration::from_secs(30));
    assert_eq!(DIRECT_STORE_RETRY_BUDGET, Duration::from_mins(3));
    assert_eq!(DIRECT_STORE_MAX_RETRIES, 10);
    assert_eq!(DIRECT_STORE_MAX_BACKOFF, Duration::from_secs(15));
    assert_eq!(DIRECT_STORE_INIT_BACKOFF, Duration::from_millis(100));
    assert!(
        (DIRECT_STORE_BACKOFF_BASE - 2.0).abs() < f64::EPSILON,
        "the backoff base must be 2.0, got {DIRECT_STORE_BACKOFF_BASE}"
    );
}

/// The load-bearing case, actually executed: every other fixture
/// parks on its first poll, which a paused clock fast-forwards
/// through trivially — none of them exercises the listing case this
/// decorator's figure is actually for, a cooperative listing walk
/// that never completes on its own.
///
/// UNPAUSED (a real, current-thread `#[tokio::test]`) because
/// `tokio::time::pause`'s auto-advance fires only once the runtime
/// has nothing left to poll; this walk always has something to poll
/// — it self-wakes every iteration via `yield_now`, exactly like
/// `max_seq`'s own 128-entry cooperative yield — so it never idles
/// and auto-advance never fires. A REAL 10 ms deadline is what makes
/// this fast without a paused clock.
///
/// `Ordering::Relaxed`: single-threaded runtime, and the counter is
/// read only after the call completes. Read directly off the
/// fixture through the decorator's own field — `mod tests` is a
/// child module of this one, so the field is visible to it — rather
/// than an `Arc`, since nothing outside this test needs the count.
#[tokio::test]
async fn a_cooperative_walk_that_never_terminates_is_cut() {
    let decorated =
        DirectStoreDeadline::with_deadline(Walk::new(WalkMode::Busy), Duration::from_millis(10));

    assert_elapsed_after(
        decorated.max_seq("vol"),
        "GET max-seq",
        Duration::from_millis(10),
    )
    .await;

    // ONE poll, not two. The deadline is fixed when the timeout is
    // constructed, so a deschedule of at least 10 ms before the
    // FIRST poll leaves the timer already expired on that poll —
    // `tokio::time::Timeout` polls the inner future first, so the
    // walk runs exactly one iteration and the timer then fires.
    // Zero is what is impossible, and zero is what a fixture parked
    // outside the loop (or a wrap that never polled the call) would
    // give.
    assert!(
        decorated.inner.polls.load(Ordering::Relaxed) >= 1,
        "the cooperative walk must have been polled at least once — zero means the \
         call never reached the loop at all"
    );
}

/// **The decorator is a `RootStore`/`BinStore` IMPLEMENTATION SITE,
/// so it runs the shared conformance body like every other one.**
///
/// Everything above drives the decorator through fixtures that bind
/// `_volume`/`_seq`/`_bytes` and ignore them, which is exactly the
/// shape that cannot see a forwarding bug: `self.inner.write_hint(volume, 0)`
/// in place of `(volume, seq)` passes every deadline row in this
/// file. The conformance suite reads back what it wrote, so a
/// dropped or scrambled argument fails it.
///
/// The store underneath is `GranaryStore<Arc<InMemory>>` — the same
/// pairing `granary-store`'s own
/// `adapter_satisfies_the_shared_rootstore_conformance_suite` runs,
/// and the same one `tests/publish_inmemory.rs` already drives here.
/// No filesystem, no network, no new dependency: `object_store` and
/// `granary-store` are both already this crate's, and `InMemory`
/// carries no feature of its own.
///
/// UNPAUSED and undecorated in time: every call resolves on its
/// first poll against an in-memory bucket, so nothing here ever
/// approaches `DIRECT_STORE_CALL_DEADLINE`. What is under test is
/// the pass-through, not the clock.
#[tokio::test]
async fn the_decorator_satisfies_the_shared_rootstore_conformance_suite() {
    let store = DirectStoreDeadline::new(GranaryStore::new(Arc::new(InMemory::new())));
    granary_core::testkit::rootstore_conformance(&store).await;
}

/// The `BinStore` half of the same closure, for the same reason —
/// `put_bin`'s digest and `get_bin_range`'s offset/len are
/// arguments no fixture in this file inspects either.
#[tokio::test]
async fn the_decorator_satisfies_the_shared_binstore_conformance_suite() {
    let store = DirectStoreDeadline::new(GranaryStore::new(Arc::new(InMemory::new())));
    granary_core::testkit::binstore_conformance(&store).await;
}
