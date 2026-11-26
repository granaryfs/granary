// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::head` — hint-first head discovery
//! (fresh-hint reuse, wire revalidation and forward probing, `max_seq`
//! fallback, and the per-volume freshness anchor).
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use granary_core::rng::SeededRng;
use granary_core::rootstore::filter_above;

use crate::cache::{Cache, CacheOrigin, HintUpdate, PersistedHint};

use super::*;

// ------------------------------------------------------------ fixtures

/// A fixed reading — every test that needs "now" pins it explicitly
/// rather than reading the wall clock.
struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

fn at(secs: i64) -> Box<dyn Clock> {
    Box::new(FixedClock(Timestamp { secs, nanos: 0 }))
}

fn seeded(seed: u64) -> Box<dyn Rng + Send> {
    Box::new(SeededRng::new(seed))
}

/// A minimal `RootStore` fake with wire-call counters — std only,
/// no `object_store` — instrumented so a test can assert HOW MANY
/// times the wire was actually touched, not just what it answered.
/// `get_root`/`read_hint`/`max_seq` each `yield_now` once before
/// answering: a genuine poll point that lets the concurrency test
/// force real interleaving on a single-threaded runtime instead of
/// one future running to completion before a second is ever polled.
#[derive(Default)]
struct FakeRoots {
    existing: Mutex<BTreeSet<u64>>,
    hint: Mutex<Option<(u64, String)>>,
    max: Mutex<Option<u64>>,
    get_root_calls: AtomicU64,
    read_hint_calls: AtomicU64,
    max_seq_calls: AtomicU64,
}

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeRoots {
    fn with_max(seq: u64) -> Self {
        let store = Self::default();
        *locked(&store.max) = Some(seq);
        locked(&store.existing).insert(seq);
        store
    }

    fn set_hint(&self, seq: u64, token: &str) {
        *locked(&self.hint) = Some((seq, token.to_owned()));
    }

    fn plant_root(&self, seq: u64) {
        locked(&self.existing).insert(seq);
    }
}

impl RootStore for FakeRoots {
    async fn put_root(
        &self,
        _volume: &str,
        seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        locked(&self.existing).insert(seq);
        Ok(())
    }

    async fn get_root(&self, _volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        tokio::task::yield_now().await;
        self.get_root_calls.fetch_add(1, Ordering::SeqCst);
        let exists = locked(&self.existing).contains(&seq);
        Ok(exists.then(|| vec![0xAA]))
    }

    async fn read_hint(
        &self,
        _volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        tokio::task::yield_now().await;
        self.read_hint_calls.fetch_add(1, Ordering::SeqCst);
        let hint = locked(&self.hint).clone();
        Ok(match hint {
            None => HintRead::Missing,
            Some((seq, token)) => {
                if cached.map(|t| &t.0) == Some(&token) {
                    HintRead::NotModified
                } else {
                    HintRead::Current {
                        seq,
                        token: HintToken(token),
                    }
                }
            }
        })
    }

    async fn write_hint(&self, _volume: &str, seq: u64) -> Result<(), RootStoreError> {
        let next = locked(&self.hint)
            .as_ref()
            .map_or(1, |(_, t)| t.parse::<u64>().unwrap_or(0) + 1);
        *locked(&self.hint) = Some((seq, next.to_string()));
        Ok(())
    }

    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        tokio::task::yield_now().await;
        self.max_seq_calls.fetch_add(1, Ordering::SeqCst);
        Ok(*locked(&self.max))
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    #[expect(
        clippy::disallowed_methods,
        reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
    )]
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "granary-head-test-{}-{}",
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

fn fresh_cache(dir: &ScratchDir) -> Cache {
    let origin = CacheOrigin {
        endpoint_url: "https://example.invalid/".to_owned(),
        pin_set_digest: [0x11; 32],
        root_key_id: None,
    };
    Cache::open(&dir.0, 1024 * 1024 * 1024, &origin).unwrap_or_else(|e| panic!("{e}"))
}

fn vol() -> VolumeName {
    VolumeName::new("head-test-vol".to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

// ----------------------------------------------------------- the tests

/// Freshness-floor test: a store that rolls back to an earlier, still
/// validly-signed-looking seq is refused once the anchor exists.
/// Discovery only ever sees seq NUMBERS (signature checking is
/// `resolve_at_verified`'s job, downstream of this refusal), so the
/// fake plants no real signature at all — the refusal fires before
/// one would ever be checked.
#[tokio::test]
async fn an_older_signed_head_is_refused_once_the_anchor_exists() {
    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);
    cache.raise_anchor(&vol(), Some(2), HintUpdate::Unchanged);

    let store = FakeRoots::with_max(1); // the "rollback": only seq 1 exists now
    let ctx = HeadContext::new(at(0), seeded(1));

    let err = discover_head(&ctx, &store, vol().as_str(), Some(&mut cache))
        .await
        .expect_err("a candidate below the anchor must be refused");
    assert!(
        matches!(
            err,
            ResolveError::StaleHead {
                candidate: 1,
                anchor: 2
            }
        ),
        "expected StaleHead naming both seqs, got {err:?}"
    );
}

/// The anchor only ever rises: a lower raise is a no-op, and a
/// higher one replaces it — the max, never a lowering.
#[tokio::test]
async fn the_anchor_only_ever_rises() {
    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);

    cache.raise_anchor(&vol(), Some(5), HintUpdate::Unchanged);
    assert_eq!(cache.read_anchor(&vol()).map(|a| a.seq), Some(5));

    cache.raise_anchor(&vol(), Some(3), HintUpdate::Unchanged);
    assert_eq!(
        cache.read_anchor(&vol()).map(|a| a.seq),
        Some(5),
        "a lower candidate must never lower the floor"
    );

    cache.raise_anchor(&vol(), Some(10), HintUpdate::Unchanged);
    assert_eq!(cache.read_anchor(&vol()).map(|a| a.seq), Some(10));

    cache.raise_anchor(&vol(), None, HintUpdate::Unchanged);
    assert_eq!(
        cache.read_anchor(&vol()).map(|a| a.seq),
        Some(10),
        "no candidate at all must never touch the floor"
    );
}

/// Inside the TTL, the persisted hint answers with zero wire calls.
#[tokio::test]
async fn a_fresh_hint_answers_without_the_wire() {
    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);
    cache.raise_anchor(
        &vol(),
        Some(7),
        HintUpdate::Replace(PersistedHint {
            seq: 7,
            token: "t1".to_owned(),
            stamp_secs: 1_000,
        }),
    );

    let store = FakeRoots::with_max(7);
    // now = stamp + 1s, well inside even the shortest jittered TTL
    // (48s floor).
    let ctx = HeadContext::new(at(1_001), seeded(1));

    let discovered = discover_head(&ctx, &store, vol().as_str(), Some(&mut cache))
        .await
        .unwrap_or_else(|e| panic!("a fresh hint must answer: {e}"));
    assert_eq!(discovered.seq, 7);
    assert_eq!(store.get_root_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.read_hint_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.max_seq_calls.load(Ordering::SeqCst), 0);
}

/// The token round-trips through `read_hint`'s own seam: a `304`
/// keeps seq+token and only refreshes the persisted stamp; a `200`
/// replaces seq+token+stamp outright.
#[tokio::test]
async fn a_304_refreshes_and_a_200_replaces() {
    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);
    cache.raise_anchor(
        &vol(),
        Some(3),
        HintUpdate::Replace(PersistedHint {
            seq: 3,
            token: "t1".to_owned(),
            stamp_secs: 0,
        }),
    );
    let store = FakeRoots::with_max(3);
    store.set_hint(3, "t1");

    // now is far past the TTL, so this call revalidates over the
    // wire rather than taking the fresh shortcut.
    let ctx = HeadContext::new(at(1_000_000), seeded(1));
    let discovered = discover_head(&ctx, &store, vol().as_str(), Some(&mut cache))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(discovered.seq, 3);
    assert_eq!(
        store.read_hint_calls.load(Ordering::SeqCst),
        1,
        "a stale hint must revalidate exactly once"
    );

    // The write-side of discovery lives in resolve_head_verified,
    // not in discover_head alone — simulate it here the same way
    // that caller does, so this test proves the CACHE round-trip
    // (the discovery contract) rather than merely the discovery
    // answer. The persisted stamp is the WIRE-confirmation reading
    // `discovered` already carries, never a fresh `now()`.
    if let Some(confirmation) = discovered.wire_confirmation.clone() {
        cache.raise_anchor(
            &vol(),
            None,
            HintUpdate::Replace(PersistedHint {
                seq: discovered.seq,
                token: confirmation.token.0,
                stamp_secs: confirmation.stamp_secs,
            }),
        );
    }
    let after_304 = cache
        .read_anchor(&vol())
        .and_then(|a| a.hint)
        .unwrap_or_else(|| panic!("a hint must still be persisted"));
    assert_eq!(after_304.token, "t1", "a 304 must keep the same token");
    assert_eq!(
        after_304.stamp_secs, 1_000_000,
        "a 304 must refresh the stamp"
    );

    // Now a genuine new publish: max_seq/hint move to 4, a fresh
    // token — the wire answers Current, not NotModified.
    store.plant_root(4);
    *locked(&store.max) = Some(4);
    store.set_hint(4, "t2");
    let ctx2 = HeadContext::new(at(2_000_000), seeded(2));
    let discovered2 = discover_head(&ctx2, &store, vol().as_str(), Some(&mut cache))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(discovered2.seq, 4);
    if let Some(confirmation) = discovered2.wire_confirmation.clone() {
        cache.raise_anchor(
            &vol(),
            Some(discovered2.seq),
            HintUpdate::Replace(PersistedHint {
                seq: discovered2.seq,
                token: confirmation.token.0,
                stamp_secs: confirmation.stamp_secs,
            }),
        );
    }
    let after_200 = cache
        .read_anchor(&vol())
        .and_then(|a| a.hint)
        .unwrap_or_else(|| panic!("a hint must still be persisted"));
    assert_eq!(after_200.seq, 4, "a 200 must replace the seq");
    assert_eq!(after_200.token, "t2", "a 200 must replace the token");
    assert_eq!(after_200.stamp_secs, 2_000_000);
}

/// A stale (but ordinary) hint forward-probes to the true head, and
/// a hint of `u64::MAX` cannot even attempt the next probe — the
/// checked-add guard falls back to `max_seq` instead of panicking
/// under overflow-checks or wrapping to the never-valid seq 0.
#[tokio::test]
async fn a_stale_hint_forward_probes_and_a_umax_hint_does_not_wrap() {
    // Ordinary stale hint: the wire's hint still says 2, but 3 and 4
    // have since landed.
    let store = FakeRoots::with_max(4);
    store.set_hint(2, "old");
    store.plant_root(2);
    store.plant_root(3);
    let ctx = HeadContext::new(at(0), seeded(1));
    let discovered = discover_head(&ctx, &store, "v", None)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        discovered.seq, 4,
        "forward-probing must reach the true head"
    );
    assert!(
        store.get_root_calls.load(Ordering::SeqCst) >= 2,
        "the walk must have actually probed forward from the stale hint"
    );

    // u64::MAX: a hostile wire hint that must not wrap or panic.
    let store2 = FakeRoots::with_max(1);
    store2.set_hint(u64::MAX, "hostile");
    let ctx2 = HeadContext::new(at(0), seeded(1));
    let discovered2 = discover_head(&ctx2, &store2, "v", None)
        .await
        .unwrap_or_else(|e| panic!("a u64::MAX hint must fall back to max_seq: {e}"));
    assert_eq!(
        discovered2.seq, 1,
        "must fall back to max_seq, never wrap or panic"
    );
    assert_eq!(
        store2.get_root_calls.load(Ordering::SeqCst),
        0,
        "checked_add must refuse the probe before any wire call for it"
    );
}

/// N concurrent head questions for one volume coalesce onto one
/// wire poll — the leader does the work, every follower gets the
/// same answer without touching the wire itself.
///
/// **Driven by hand, never `tokio::join!`/`tokio::spawn`.** Both are
/// this crate's own concurrency bans (`clippy.toml`):
/// `join!` degenerates on a current-thread runtime — the first
/// branch would run to completion before a second is ever polled,
/// proving nothing about coalescing — and `spawn` hands ordering to
/// a runtime the sim cannot sequence. A hand-rolled round-robin poll
/// loop is what actually exercises genuine interleaving: each of the
/// four futures is polled in turn, every round, until all four are
/// `Ready` — the same "poll what is runnable" shape the sim's own
/// scheduler uses, borrowed for one test.
#[tokio::test]
async fn concurrent_head_questions_coalesce() {
    use std::future::Future as _;
    use std::task::{Context, Poll, Waker};

    let store = FakeRoots::with_max(9);
    let ctx = HeadContext::new(at(0), seeded(1));

    let mut futs: [_; 4] =
        std::array::from_fn(|_| Box::pin(discover_head(&ctx, &store, "v", None)));
    let mut results: [Option<Result<Discovered, ResolveError>>; 4] = [None, None, None, None];
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    while results.iter().any(Option::is_none) {
        for (fut, slot) in futs.iter_mut().zip(results.iter_mut()) {
            if slot.is_none()
                && let Poll::Ready(v) = fut.as_mut().poll(&mut cx)
            {
                *slot = Some(v);
            }
        }
    }
    for r in &results {
        let seq = match r {
            Some(Ok(d)) => Some(d.seq),
            _ => None,
        };
        assert_eq!(seq, Some(9), "every caller must see the same answer");
    }
    assert_eq!(
        store.max_seq_calls.load(Ordering::SeqCst),
        1,
        "four concurrent callers for one volume must coalesce onto ONE wire poll"
    );
}

/// A coalesced answer must not bypass a FOLLOWER's own freshness
/// floor. Two callers share one `HeadContext`/store but have
/// DIFFERENT cache dirs; the leader's own floor is low enough to let
/// the real head stand, but the follower's is higher — the follower
/// must see its OWN `StaleHead`, never silently inherit the leader's
/// (lower-floor) answer.
#[tokio::test]
async fn a_follower_applies_its_own_floor() {
    use std::future::Future as _;
    use std::task::{Context, Poll, Waker};

    let store = FakeRoots::with_max(9);
    let ctx = HeadContext::new(at(0), seeded(1));
    let v = vol();

    let leader_dir = ScratchDir::new();
    let mut leader_cache = fresh_cache(&leader_dir); // no floor at all
    let follower_dir = ScratchDir::new();
    let mut follower_cache = fresh_cache(&follower_dir);
    follower_cache.raise_anchor(&v, Some(20), HintUpdate::Unchanged); // above the real head

    let mut leader_fut = Box::pin(discover_head(
        &ctx,
        &store,
        v.as_str(),
        Some(&mut leader_cache),
    ));
    let mut follower_fut = Box::pin(discover_head(
        &ctx,
        &store,
        v.as_str(),
        Some(&mut follower_cache),
    ));

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut leader_result = None;
    let mut follower_result = None;
    while leader_result.is_none() || follower_result.is_none() {
        if leader_result.is_none()
            && let Poll::Ready(v) = leader_fut.as_mut().poll(&mut cx)
        {
            leader_result = Some(v);
        }
        if follower_result.is_none()
            && let Poll::Ready(v) = follower_fut.as_mut().poll(&mut cx)
        {
            follower_result = Some(v);
        }
    }

    match leader_result.unwrap_or_else(|| panic!("the leader future must complete")) {
        Ok(d) => assert_eq!(
            d.seq, 9,
            "the leader's own (low) floor must let the real head stand"
        ),
        other => panic!("expected the leader to see the real head, got {other:?}"),
    }
    match follower_result.unwrap_or_else(|| panic!("the follower future must complete")) {
        Err(ResolveError::StaleHead { candidate, anchor }) => {
            assert_eq!(candidate, 9);
            assert_eq!(anchor, 20);
        }
        other => {
            panic!("the follower must apply its OWN floor and see StaleHead, got {other:?}")
        }
    }
    assert_eq!(
        store.max_seq_calls.load(Ordering::SeqCst),
        1,
        "the two callers must still coalesce onto ONE wire poll — the per-caller floor \
         gate is a post-coalescing check, not a reason to duplicate the poll"
    );
}

/// Seeded sweep: every draw lands inside `[48_000, 72_000)`, and the
/// same seed reproduces the same sequence.
#[tokio::test]
async fn jitter_stays_inside_twenty_percent() {
    for seed in [0_u64, 1, 42, 0xDEAD_BEEF, u64::MAX] {
        let ctx = HeadContext::new(at(0), seeded(seed));
        let draws: Vec<u64> = (0..64).map(|_| ctx.jitter_ttl_ms()).collect();
        for &d in &draws {
            assert!(
                (48_000..72_000).contains(&d),
                "draw {d} outside the ±20% band for seed {seed}"
            );
        }
        let ctx_replay = HeadContext::new(at(0), seeded(seed));
        let replay: Vec<u64> = (0..64).map(|_| ctx_replay.jitter_ttl_ms()).collect();
        assert_eq!(
            draws, replay,
            "the same seed must reproduce the same TTL sequence"
        );
    }
}

/// Hostile bytes in `anchors/<volume>` degrade to "no anchor",
/// warned, never a hard failure.
#[tokio::test]
async fn a_garbage_anchor_is_absent_not_fatal() {
    let dir = ScratchDir::new();
    // Open once to lay out the cache dir, then close so the file
    // write below lands on a clean, closed cache.
    {
        let cache = fresh_cache(&dir);
        cache.close().unwrap_or_else(|e| panic!("{e}"));
    }
    let anchor_dir = dir.0.join("anchors");
    std::fs::create_dir_all(&anchor_dir).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(
        anchor_dir.join(vol().as_str()),
        b"not an anchor at all\xff\xfe",
    )
    .unwrap_or_else(|e| panic!("{e}"));

    let mut cache = fresh_cache(&dir);
    assert_eq!(
        cache.read_anchor(&vol()),
        None,
        "garbage bytes must read back as absent, not an error"
    );

    // And discovery must proceed normally with no floor at all.
    let store = FakeRoots::with_max(5);
    let ctx = HeadContext::new(at(0), seeded(1));
    let discovered = discover_head(&ctx, &store, vol().as_str(), Some(&mut cache))
        .await
        .unwrap_or_else(|e| panic!("a garbage anchor must not be fatal: {e}"));
    assert_eq!(discovered.seq, 5);
}

/// A reader with no cache dir at all: no anchor, no persisted hint —
/// full discovery still works.
#[tokio::test]
async fn no_cache_dir_falls_back_to_full_discovery() {
    let store = FakeRoots::with_max(3);
    let ctx = HeadContext::new(at(0), seeded(1));
    let discovered = discover_head(&ctx, &store, "v", None)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(discovered.seq, 3);
}

// ------------------------------------------- quality-lane additions

/// The IN-LOOP overflow guard, not the entry one: a hostile store
/// that answers `get_root(u64::MAX)` with bytes must make the walk
/// BREAK to the one `max_seq` call — never wrap past `u64::MAX` to
/// probe seq 0, and never answer the reserved seq as a
/// head.
#[tokio::test]
async fn a_probe_reaching_the_reserved_seq_breaks_to_max_seq_and_never_wraps() {
    let store = FakeRoots::with_max(3);
    store.set_hint(u64::MAX - 1, "hostile");
    store.plant_root(u64::MAX);
    let ctx = HeadContext::new(at(0), seeded(1));
    let discovered = discover_head(&ctx, &store, "v", None)
        .await
        .unwrap_or_else(|e| panic!("the reserved-seq boundary must not error: {e}"));
    assert_eq!(
        discovered.seq, 3,
        "the walk must break to max_seq at u64::MAX, never accept the reserved seq"
    );
    assert_eq!(
        store.max_seq_calls.load(Ordering::SeqCst),
        1,
        "the boundary must be answered by the one max_seq fallback"
    );
}

/// The cap-hit fallback (every one of `FORWARD_PROBE_MAX` probes
/// confirmed a real root, never a boundary) must never answer BELOW
/// what the walk itself just confirmed — a `max_seq` that lags or
/// lies must not win over 32 roots the walk directly observed.
#[tokio::test]
async fn a_capped_probe_never_answers_below_a_confirmed_seq() {
    let store = FakeRoots::default();
    let hint_seq = 100u64;
    for i in 1..=u64::from(FORWARD_PROBE_MAX) {
        store.plant_root(hint_seq + i);
    }
    let last_seen = hint_seq + u64::from(FORWARD_PROBE_MAX);
    // The store's own max_seq LAGS — far below what the walk just
    // confirmed exists.
    *locked(&store.max) = Some(hint_seq);

    let candidate = forward_probe_or_fallback(&store, "v", hint_seq)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        candidate, last_seen,
        "the cap-hit fallback must floor at the walk-confirmed seq when max_seq lags"
    );
}

/// A confirmed LEGAL seq must survive the walk reaching the reserved
/// `u64::MAX` boundary — never be discarded for a lagging/lying
/// `max_seq`. Distinct from the reserved-boundary test above, whose
/// hint sits AT `u64::MAX - 1` so nothing is confirmed before the
/// boundary: here the walk confirms `u64::MAX - 1` FIRST, then would
/// reach reserved `u64::MAX`, and a hostile `max_seq` reports 5. The
/// answer must be the confirmed `u64::MAX - 1`, never 5 — the walk
/// stops before probing the reserved seq, so its `Some` there can
/// never overwrite the highest legal confirmed value.
#[tokio::test]
async fn the_probe_never_discards_a_confirmed_seq_at_the_reserved_boundary() {
    let store = FakeRoots::default();
    store.set_hint(u64::MAX - 2, "hostile");
    store.plant_root(u64::MAX - 1); // legal, confirmed by the walk
    store.plant_root(u64::MAX); // a hostile plant at the reserved seq
    *locked(&store.max) = Some(5); // max_seq lies far below the confirmed seq

    let ctx = HeadContext::new(at(0), seeded(1));
    let discovered = discover_head(&ctx, &store, vol().as_str(), None)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        discovered.seq,
        u64::MAX - 1,
        "a confirmed legal seq must never be discarded for a lying max_seq at the reserved \
         boundary"
    );
}

/// Clock-skew rule: a stamp in the FUTURE (now < stamp)
/// is STALE, never infinitely fresh — the call must revalidate over
/// the wire instead of answering zero-wire.
#[tokio::test]
async fn a_future_stamped_hint_is_stale_and_revalidates() {
    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);
    cache.raise_anchor(
        &vol(),
        Some(5),
        HintUpdate::Replace(PersistedHint {
            seq: 5,
            token: "tf".to_owned(),
            stamp_secs: 10_000,
        }),
    );
    let store = FakeRoots::with_max(5);
    store.set_hint(5, "tf");

    // now sits BEFORE the stamp — a skewed clock, not a fresh hint.
    let ctx = HeadContext::new(at(1_000), seeded(1));
    let discovered = discover_head(&ctx, &store, vol().as_str(), Some(&mut cache))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(discovered.seq, 5);
    assert_eq!(
        store.read_hint_calls.load(Ordering::SeqCst),
        1,
        "a future-stamped hint must revalidate over the wire, never answer zero-wire"
    );
}

/// The strict 20-digit seq width: a 19- or 21-digit line (even one
/// whose VALUE parses fine) degrades the whole file to absent.
#[tokio::test]
async fn an_anchor_seq_of_the_wrong_width_is_absent() {
    let dir = ScratchDir::new();
    let cache = fresh_cache(&dir);
    let path = dir.0.join("anchors").join(vol().as_str());

    // 19 digits, value 5.
    std::fs::write(&path, b"seq 0000000000000000005\n").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cache.read_anchor(&vol()),
        None,
        "a 19-digit seq line must degrade the file to absent"
    );

    // 21 digits, value 5 — parses as u64, refused by width alone.
    std::fs::write(&path, b"seq 000000000000000000005\n").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cache.read_anchor(&vol()),
        None,
        "a 21-digit seq line must degrade the file to absent"
    );
}

/// The two absent-class seq VALUES (0 and the
/// reserved `u64::MAX`) at exactly the right width are still absent.
#[tokio::test]
async fn an_absent_class_seq_value_in_the_file_is_absent() {
    let dir = ScratchDir::new();
    let cache = fresh_cache(&dir);
    let path = dir.0.join("anchors").join(vol().as_str());

    std::fs::write(&path, b"seq 00000000000000000000\n").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(cache.read_anchor(&vol()), None, "seq 0 is absent-class");

    std::fs::write(&path, b"seq 18446744073709551615\n").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cache.read_anchor(&vol()),
        None,
        "the reserved u64::MAX is absent-class"
    );
}

/// The bounded anchor read: a file past `ANCHOR_FILE_MAX_BYTES` is
/// absent (warned), never a hard failure — and discovery proceeds
/// with no floor, exactly like the garbage-bytes case.
#[tokio::test]
async fn an_oversized_anchor_file_is_absent_not_fatal() {
    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);
    let path = dir.0.join("anchors").join(vol().as_str());
    let mut big = Vec::from(&b"seq 00000000000000000007\n"[..]);
    big.resize(5000, b'x'); // past the 4096 bound
    std::fs::write(&path, &big).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        cache.read_anchor(&vol()),
        None,
        "an over-cap anchor file must read back as absent"
    );

    let store = FakeRoots::with_max(9);
    let ctx = HeadContext::new(at(0), seeded(1));
    let discovered = discover_head(&ctx, &store, vol().as_str(), Some(&mut cache))
        .await
        .unwrap_or_else(|e| panic!("an oversized anchor must not be fatal: {e}"));
    assert_eq!(discovered.seq, 9);
}

/// Hint-write validation: an unpersistable token (space, over-length,
/// empty — and the worst case, one carrying a newline plus a forged
/// `seq` line) omits the hint LINE; the floor line still writes, and
/// no token can corrupt the file grammar into naming another seq.
#[tokio::test]
async fn an_unpersistable_token_omits_the_hint_line_but_still_writes_the_floor() {
    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);
    let bad_tokens = [
        "with space".to_owned(),
        "x".repeat(600),
        String::new(),
        // Grammar injection: a newline plus a line that would parse
        // as a far-higher floor if it ever reached the file.
        "x\nseq 00000000000009999999".to_owned(),
    ];
    for (i, token) in bad_tokens.into_iter().enumerate() {
        let floor = 10 + i as u64;
        cache.raise_anchor(
            &vol(),
            Some(floor),
            HintUpdate::Replace(PersistedHint {
                seq: floor,
                token,
                stamp_secs: 1,
            }),
        );
        let anchor = cache.read_anchor(&vol()).unwrap_or_else(|| {
            panic!("the floor line must still write when the token is unpersistable")
        });
        assert_eq!(
            anchor.seq, floor,
            "the floor must be the caller's, not forged"
        );
        assert_eq!(
            anchor.hint, None,
            "an unpersistable token must omit the hint line entirely"
        );
    }
}

/// Write-read symmetry for the OTHER two hint fields (the token is
/// guarded; these were not): a negative stamp or an absent-class
/// hint seq must degrade to hint-omitted — never render a hint line
/// the module's own strict reader refuses, which would erase the
/// just-written FLOOR on the next read (silently disabling the
/// rollback defence).
#[tokio::test]
async fn an_unpersistable_stamp_or_hint_seq_never_erases_the_floor() {
    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);
    let bad_hints = [
        PersistedHint {
            seq: 5,
            token: "t".to_owned(),
            stamp_secs: -1, // renders signed; the parser demands unsigned
        },
        PersistedHint {
            seq: 0, // absent-class
            token: "t".to_owned(),
            stamp_secs: 1,
        },
        PersistedHint {
            seq: u64::MAX, // absent-class
            token: "t".to_owned(),
            stamp_secs: 1,
        },
    ];
    for (i, hint) in bad_hints.into_iter().enumerate() {
        let floor = 20 + i as u64;
        cache.raise_anchor(&vol(), Some(floor), HintUpdate::Replace(hint));
        let anchor = cache.read_anchor(&vol()).unwrap_or_else(|| {
            panic!("an unpersistable hint must never erase the floor (case {i})")
        });
        assert_eq!(anchor.seq, floor);
        assert_eq!(
            anchor.hint, None,
            "the unpersistable hint line must be omitted"
        );
    }
}

/// An absent-class FLOOR candidate (0, `u64::MAX`) is refused, not
/// written: rendering it would produce a `seq` line the strict
/// reader refuses, erasing whatever floor the file already held.
#[tokio::test]
async fn an_absent_class_floor_candidate_is_refused_not_written() {
    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);

    cache.raise_anchor(&vol(), Some(5), HintUpdate::Unchanged);
    assert_eq!(cache.read_anchor(&vol()).map(|a| a.seq), Some(5));

    // A hostile resolve claiming the reserved seq must not clobber
    // the real floor with a self-erasing line.
    cache.raise_anchor(&vol(), Some(u64::MAX), HintUpdate::Unchanged);
    assert_eq!(
        cache.read_anchor(&vol()).map(|a| a.seq),
        Some(5),
        "a u64::MAX candidate must never erase the existing floor"
    );

    cache.raise_anchor(&vol(), Some(0), HintUpdate::Unchanged);
    assert_eq!(cache.read_anchor(&vol()).map(|a| a.seq), Some(5));

    // And on a fresh volume, an absent-class candidate establishes
    // nothing — absent, not a self-erasing file, not a panic.
    let other = VolumeName::new("head-test-vol-b".to_owned()).unwrap_or_else(|e| panic!("{e}"));
    cache.raise_anchor(&other, Some(0), HintUpdate::Unchanged);
    assert_eq!(cache.read_anchor(&other), None);
}

/// A hint below the floor is ignored, not refused, from the FILE side: a fresh
/// hint sitting strictly below the floor (a foreign or crash-window
/// file) falls through to the wire — revalidate + probe — and lands
/// on the true head; it must never zero-wire answer the low seq.
#[tokio::test]
async fn a_fresh_hint_below_the_floor_falls_through_to_the_wire() {
    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);
    cache.raise_anchor(&vol(), Some(10), HintUpdate::Unchanged);
    cache.raise_anchor(
        &vol(),
        None,
        HintUpdate::Replace(PersistedHint {
            seq: 8, // strictly below the floor
            token: "t8".to_owned(),
            stamp_secs: 1_000,
        }),
    );
    let store = FakeRoots::with_max(10);
    store.plant_root(9);
    store.set_hint(8, "t8");

    // Inside the TTL — the hint is FRESH, and still must not answer.
    let ctx = HeadContext::new(at(1_001), seeded(1));
    let discovered = discover_head(&ctx, &store, vol().as_str(), Some(&mut cache))
        .await
        .unwrap_or_else(|e| panic!("a below-floor hint is ignored, not refused: {e}"));
    assert_eq!(
        discovered.seq, 10,
        "discovery must walk to the true head, never answer the below-floor hint"
    );
    assert_eq!(
        store.read_hint_calls.load(Ordering::SeqCst),
        1,
        "the below-floor hint must force a wire revalidation"
    );
}

/// Single-flight ERROR propagation: a leader whose discovery fails
/// hands every follower the error — no hang, no panic — and clears
/// the slot so the next call leads a fresh poll.
#[tokio::test]
async fn a_failing_leader_hands_every_follower_the_error_and_clears_the_slot() {
    use std::future::Future as _;
    use std::task::{Context, Poll, Waker};

    let store = FakeRoots::default(); // no roots at all -> NoHead
    let ctx = HeadContext::new(at(0), seeded(1));

    let mut futs: [_; 4] =
        std::array::from_fn(|_| Box::pin(discover_head(&ctx, &store, "v", None)));
    let mut results: [Option<Result<Discovered, ResolveError>>; 4] = [None, None, None, None];
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    while results.iter().any(Option::is_none) {
        for (fut, slot) in futs.iter_mut().zip(results.iter_mut()) {
            if slot.is_none()
                && let Poll::Ready(v) = fut.as_mut().poll(&mut cx)
            {
                *slot = Some(v);
            }
        }
    }
    for (i, r) in results.iter().enumerate() {
        assert!(
            matches!(r, Some(Err(ResolveError::NoHead))),
            "caller {i} must see the leader's own error, got {r:?}"
        );
    }
    assert_eq!(
        store.max_seq_calls.load(Ordering::SeqCst),
        1,
        "the error round must still have coalesced onto one wire poll"
    );

    // The slot must be CLEARED on the error path too: after the
    // volume gains a head, a fresh call leads a fresh poll.
    *locked(&store.max) = Some(5);
    locked(&store.existing).insert(5);
    let discovered = discover_head(&ctx, &store, "v", None)
        .await
        .unwrap_or_else(|e| panic!("the slot must be cleared after an error: {e}"));
    assert_eq!(discovered.seq, 5);
}

/// A leader FUTURE dropped mid-flight (caller cancellation) must not
/// wedge the volume: the next call for it must lead a fresh poll and
/// succeed, not join a dead channel forever.
#[tokio::test]
async fn a_dropped_leader_does_not_wedge_the_volume() {
    use std::future::Future as _;
    use std::task::{Context, Waker};

    let store = FakeRoots::with_max(4);
    let ctx = HeadContext::new(at(0), seeded(1));
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    {
        let mut fut = Box::pin(discover_head(&ctx, &store, "v", None));
        // One poll: the map entry is inserted synchronously and the
        // leader parks at the store's first yield point.
        assert!(fut.as_mut().poll(&mut cx).is_pending());
    } // dropped here — the cancellation

    let discovered = discover_head(&ctx, &store, "v", None)
        .await
        .unwrap_or_else(|e| panic!("a cancelled leader must not wedge the volume: {e}"));
    assert_eq!(discovered.seq, 4);
}

/// Degraded mode (lock contention): `raise_anchor` is a silent
/// no-op — a degraded reader never mutates the cache dir — while
/// `read_anchor` still serves both modes.
#[tokio::test]
async fn a_degraded_reader_never_writes_an_anchor() {
    let dir = ScratchDir::new();
    let mut writer = fresh_cache(&dir);
    writer.raise_anchor(&vol(), Some(3), HintUpdate::Unchanged);

    let mut degraded = fresh_cache(&dir); // second open: lock contention
    assert_eq!(
        degraded.read_anchor(&vol()).map(|a| a.seq),
        Some(3),
        "read_anchor must serve the degraded mode too"
    );
    degraded.raise_anchor(&vol(), Some(99), HintUpdate::Unchanged);
    assert_eq!(
        writer.read_anchor(&vol()).map(|a| a.seq),
        Some(3),
        "a degraded raise must be a silent no-op"
    );
}

/// Writer-mode anchor I/O failure (unwritable anchors/): warn +
/// no-op, never a panic or an error surfaced to the operation — and
/// the old floor stays readable.
#[tokio::test]
async fn an_unwritable_anchors_dir_warns_and_never_fails_the_operation() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);
    cache.raise_anchor(&vol(), Some(3), HintUpdate::Unchanged);
    assert_eq!(cache.read_anchor(&vol()).map(|a| a.seq), Some(3));

    let anchors_dir = dir.0.join("anchors");
    std::fs::set_permissions(&anchors_dir, std::fs::Permissions::from_mode(0o555))
        .unwrap_or_else(|e| panic!("{e}"));
    // Must neither panic nor error — raise_anchor is infallible by
    // contract; the floor simply stays at its old value.
    cache.raise_anchor(&vol(), Some(9), HintUpdate::Unchanged);
    std::fs::set_permissions(&anchors_dir, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cache.read_anchor(&vol()).map(|a| a.seq),
        Some(3),
        "after a refused write the floor stays at its old, lower value"
    );
}

/// A hostile store answering `304 NotModified` when the caller sent
/// NO `If-None-Match` token at all: discovery has no hint seq to
/// probe from, so it falls back to `max_seq` — panic-free — and the
/// floor still binds that candidate.
struct NotModifiedAlways;

impl RootStore for NotModifiedAlways {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        Ok(())
    }

    async fn get_root(&self, _volume: &str, _seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        Ok(None)
    }

    async fn read_hint(
        &self,
        _volume: &str,
        _cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        Ok(HintRead::NotModified)
    }

    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        Ok(())
    }

    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        Ok(Some(2))
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

#[tokio::test]
async fn not_modified_without_a_sent_token_falls_back_to_max_seq() {
    let store = NotModifiedAlways;

    // Cacheless: no token was sent, the off-protocol 304 answers
    // nothing — max_seq must answer instead, panic-free.
    let ctx = HeadContext::new(at(0), seeded(1));
    let discovered = discover_head(&ctx, &store, "v", None)
        .await
        .unwrap_or_else(|e| panic!("an off-protocol 304 must not break discovery: {e}"));
    assert_eq!(discovered.seq, 2);

    // Floor-only anchor (no hint, so still no token sent): the same
    // fallback — and the floor still binds the candidate.
    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);
    cache.raise_anchor(&vol(), Some(3), HintUpdate::Unchanged);
    let ctx2 = HeadContext::new(at(0), seeded(1));
    let err = discover_head(&ctx2, &store, vol().as_str(), Some(&mut cache))
        .await
        .expect_err("max_seq 2 sits below the floor 3 and must be refused");
    assert!(
        matches!(
            err,
            ResolveError::StaleHead {
                candidate: 2,
                anchor: 3
            }
        ),
        "the floor must bind the fallback candidate too, got {err:?}"
    );
}

/// A `read_hint` TRANSPORT/STATUS error degrades to the
/// `max_seq` fallback — the hint route is ADVISORY, so an error on
/// it must never abort a discovery `max_seq` alone would answer.
struct ErringHintRoute;

impl RootStore for ErringHintRoute {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        Ok(())
    }

    async fn get_root(&self, _volume: &str, _seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        Ok(None)
    }

    async fn read_hint(
        &self,
        _volume: &str,
        _cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        Err(RootStoreError::Backend(
            "simulated hint route failure (403/5xx)".to_owned(),
        ))
    }

    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        Ok(())
    }

    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        Ok(Some(7))
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

#[tokio::test]
async fn a_hint_route_error_degrades_to_max_seq() {
    let store = ErringHintRoute;
    let ctx = HeadContext::new(at(0), seeded(1));
    let discovered = discover_head(&ctx, &store, "v", None)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "a hint route error must degrade to the max_seq fallback, not abort discovery: {e}"
            )
        });
    assert_eq!(discovered.seq, 7);
}

/// The freshness-floor refusal through the REAL verified entry point: the
/// floor fires inside discovery, BEFORE `resolve_at_verified` (the
/// signature path) fetches a single root or bin — so no signature,
/// valid or not, ever gets a chance to bless a rolled-back head.
/// (The bins erroring and the zero `get_root` count are the order
/// proof: had discovery answered instead of refusing, the resolve
/// would have read roots and died on the bins with `Remote`.)
impl granary_core::binstore::BinStore for FakeRoots {
    async fn put_bin(&self, _digest: &[u8; 32], _bytes: Vec<u8>) -> Result<bool, RootStoreError> {
        Err(RootStoreError::Backend(
            "bins must never be touched".to_owned(),
        ))
    }

    async fn put_meta(
        &self,
        _volume: &str,
        _id: &granary_core::hash::GrainId,
        _bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        Err(RootStoreError::Backend(
            "meta must never be touched".to_owned(),
        ))
    }

    async fn get_meta(
        &self,
        _volume: &str,
        _id: &granary_core::hash::GrainId,
    ) -> Result<Vec<u8>, RootStoreError> {
        Err(RootStoreError::Backend(
            "meta must never be touched".to_owned(),
        ))
    }

    async fn get_bin_range(
        &self,
        _digest: &[u8; 32],
        _offset: u64,
        _len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        Err(RootStoreError::Backend(
            "bins must never be touched".to_owned(),
        ))
    }
}

#[tokio::test]
async fn the_stale_head_refusal_precedes_any_root_or_bin_fetch() {
    use crate::resolve::{ResolveTarget, RootVerifier, resolve_head_verified};

    let dir = ScratchDir::new();
    let mut cache = fresh_cache(&dir);
    cache.raise_anchor(&vol(), Some(2), HintUpdate::Unchanged);

    let store = FakeRoots::with_max(1); // the rollback
    let ctx = HeadContext::new(at(0), seeded(1));
    let mut sink =
        |_id: granary_core::hash::GrainId, _bytes: &[u8]| -> Result<(), String> { Ok(()) };
    let err = resolve_head_verified(
        &store,
        vol().as_str(),
        &RootVerifier::unverified(),
        &ctx,
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut sink,
    )
    .await
    .expect_err("the floor must refuse the rolled-back head through the full entry point");
    assert!(
        matches!(
            err,
            ResolveError::StaleHead {
                candidate: 1,
                anchor: 2
            }
        ),
        "expected StaleHead through resolve_head_verified, got {err:?}"
    );
    assert_eq!(
        store.get_root_calls.load(Ordering::SeqCst),
        0,
        "the refusal must fire before a single root is fetched — a fortiori before \
         any signature over one could be checked"
    );
}
