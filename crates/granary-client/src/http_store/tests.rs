// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::http_store` — `RootStore + BinStore`
//! over the grain protocol.
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::task::Poll;

use hyper::body::Frame;

struct FramedBody {
    frames: VecDeque<Result<Frame<Bytes>, Infallible>>,
}

impl hyper::body::Body for FramedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front())
    }
}

fn framed_body(frames: Vec<Frame<Bytes>>) -> FramedBody {
    FramedBody {
        frames: frames.into_iter().map(Ok).collect(),
    }
}

/// A body that hands over `good` as ONE data frame, then a
/// TRANSPORT error — the shape a connection resetting mid-response
/// produces, and `FramedBody`'s `Error = Infallible` cannot make.
struct BrokenAfter {
    good: Option<Bytes>,
    broke: bool,
}

impl BrokenAfter {
    fn new(good: Vec<u8>) -> Self {
        Self {
            good: Some(Bytes::from(good)),
            broke: false,
        }
    }
}

impl hyper::body::Body for BrokenAfter {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(data) = this.good.take() {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if !this.broke {
            this.broke = true;
            return Poll::Ready(Some(Err(std::io::Error::other(
                "connection reset mid-body",
            ))));
        }
        Poll::Ready(None)
    }
}

// -- The client's process-wide response-byte counter ----------------

/// **Row (i): a response of known length leaves the client's own
/// counter holding exactly that many RECEIVED bytes.**
#[tokio::test]
async fn a_known_length_response_leaves_the_counter_holding_exactly_its_length() {
    let counter = ResponseByteCounter::new();
    let body = framed_body(vec![Frame::data(Bytes::from(vec![0x11_u8; 4096]))]);
    let got = read_capped(body, 8192, &counter, None).await;
    assert_eq!(got, Ok(Some(vec![0x11_u8; 4096])));
    assert_eq!(counter.total(), Some(4096));
}

/// THREE separate frames arrive in one call, of DIFFERENT sizes —
/// rows (i)/(j)/(k) above each feed exactly one non-empty data
/// frame, so `record_frame(arrived)` (this frame's own delta) and
/// `record_frame(out.len() + data.len())` (the running total after
/// extending) agree on all of them: a call's first frame always
/// has `out.len() == 0` beforehand. They diverge only across many
/// frames — the delta sums to exactly 100 + 200 + 300 = 600, while
/// re-adding the running total sums to 100 + 300 + 600 = 1000.
#[tokio::test]
async fn three_frames_of_different_sizes_in_one_call_sum_to_their_total() {
    let counter = ResponseByteCounter::new();
    let body = framed_body(vec![
        Frame::data(Bytes::from(vec![0xAA_u8; 100])),
        Frame::data(Bytes::from(vec![0xBB_u8; 200])),
        Frame::data(Bytes::from(vec![0xCC_u8; 300])),
    ]);
    let got = read_capped(body, 1_000, &counter, None).await;
    assert_eq!(
        got.map(|content| content.map(|c| c.len())),
        Ok(Some(600)),
        "the three frames must all land"
    );
    assert_eq!(
        counter.total(),
        Some(600),
        "three frames of 100/200/300 bytes in ONE call must add exactly \
         600 to the counter — a running-total re-add would add far more \
         than the bytes that actually arrived"
    );
}

/// **Row (j): `k` bytes then a broken frame leaves `k` counted.**
///
/// Counting only completed responses loses bytes: a counter
/// that records only at `Ok(Some(out))` never runs at all here,
/// because the broken frame returns an `Err` first — so a naive
/// implementation leaves the counter at ZERO, not `k`. Counting at
/// the frame is what makes `k` survive a broken tail.
#[tokio::test]
async fn k_bytes_then_a_broken_frame_leaves_k_counted() {
    let counter = ResponseByteCounter::new();
    let k = 777_usize;
    let body = BrokenAfter::new(vec![0x22_u8; k]);
    let got = read_capped(body, 10_000, &counter, None).await;
    assert!(matches!(got, Err(RootStoreError::Backend(_))), "{got:?}");
    assert_eq!(
        counter.total(),
        Some(k as u64),
        "the broken frame must not erase what already arrived"
    );
}

/// **Row (k): a final frame that crosses `cap` is counted in full
/// although `read_capped` returns `Ok(None)`.**
#[tokio::test]
async fn a_final_frame_crossing_the_cap_is_counted_in_full() {
    let counter = ResponseByteCounter::new();
    let cap = 10_usize;
    // One frame of `cap + 5` bytes — arrives whole, and the cap
    // check cuts the READ, not the count.
    let body = framed_body(vec![Frame::data(Bytes::from(vec![0x33_u8; cap + 5]))]);
    let got = read_capped(body, cap, &counter, None).await;
    assert_eq!(got, Ok(None), "the cap must still cut the read");
    assert_eq!(
        counter.total(),
        Some((cap + 5) as u64),
        "the over-cap frame DID arrive, and must be counted in full"
    );
}

/// **Row (l): the client poison row, same shape as the server's row
/// (d).**
#[tokio::test]
async fn the_response_byte_counter_poisons_rather_than_wraps_on_overflow() {
    let counter = ResponseByteCounter::new_at(u64::MAX - 1);
    counter.record_frame(2);
    assert_eq!(
        counter.total(),
        None,
        "an overflowing add must poison, not wrap"
    );
}

#[tokio::test]
async fn read_capped_bounds_frames_that_carry_no_payload() {
    let mut control = (0..1_024)
        .map(|_| Frame::data(Bytes::new()))
        .collect::<Vec<_>>();
    control.push(Frame::data(Bytes::from_static(b"x")));
    control.push(Frame::trailers(hyper::HeaderMap::new()));
    let counter = ResponseByteCounter::new();
    assert_eq!(
        read_capped(framed_body(control), 1, &counter, None).await,
        Ok(Some(b"x".to_vec())),
        "the full allowance, real payload, and a legitimate trailing frame must pass"
    );

    let attack = (0..=1_024).map(|_| Frame::data(Bytes::new())).collect();
    let got = read_capped(framed_body(attack), 1, &ResponseByteCounter::new(), None).await;
    let Err(RootStoreError::RefusedResponse { reason, kind }) = got else {
        panic!("excess non-payload frames must be refused, got {got:?}");
    };
    assert!(reason.contains("empty DATA frames"), "got {reason:?}");
    assert_eq!(
        kind,
        RefusalKind::NoProgress,
        "a zero-progress flood is NoProgress, never a size-cap kind"
    );

    let duplicate_trailers = vec![
        Frame::trailers(hyper::HeaderMap::new()),
        Frame::trailers(hyper::HeaderMap::new()),
    ];
    let got = read_capped(
        framed_body(duplicate_trailers),
        1,
        &ResponseByteCounter::new(),
        None,
    )
    .await;
    let Err(RootStoreError::RefusedResponse { reason, kind }) = got else {
        panic!("a second trailer frame must be refused, got {got:?}");
    };
    assert!(reason.contains("more than one trailer"), "got {reason:?}");
    assert_eq!(
        kind,
        RefusalKind::Framing,
        "a second trailer frame is a framing fault, never a size-cap kind"
    );
}

/// EXTENT-GATE CHECK 3, reached the only way it can be.
///
/// §7.2 states outright that check 0 makes this check unreachable over
/// the wire and that both are required anyway — an implementation of
/// this seam that obtains its extent from something other than a parsed
/// `Content-Range` (`granary-store`'s adapter reads an `object_store`
/// range struct) has no check 0 to have passed, and one that computes
/// the width by saturating subtraction, as that adapter does, converts
/// a reversed extent into a zero-width one.
///
/// So NO stub server can pin this guard: over the wire, deleting it
/// leaves check 0 to refuse the same input, and deleting BOTH is what
/// the integration row `bytes 10-9/*` is for. This is the direct call
/// that isolates it — the gate handed a `served_last` one below the
/// requested `first-pos`, which is exactly what a saturating width
/// computation yields.
#[test]
fn extent_gate_refuses_a_zero_width_extent() {
    let extent = RequestedExtent::new(10, 10).expect("a legal ten-byte extent at offset 10");

    // The positive control FIRST: without it, a gate that refused
    // every extent would satisfy the assertion below.
    assert_eq!(extent_gate(&extent, 10, 19), Ok(10));

    let got = extent_gate(&extent, 10, 9);
    let Err(RootStoreError::RefusedResponse { reason, kind }) = got else {
        panic!("a zero-width extent is never a success on this seam, got {got:?}");
    };
    assert!(reason.contains("zero-width extent"), "got {reason:?}");
    assert_eq!(kind, RefusalKind::Extent);
}

#[test]
fn all_seam_429_answers_are_unavailable() {
    for operation in [
        "GET bin",
        "PUT bin",
        "GET meta",
        "PUT meta",
        "GET root",
        "PUT root",
        "GET hint",
        "PUT hint",
        "GET max-seq",
    ] {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let error = unmapped(operation, status);
            assert_eq!(
                error,
                RootStoreError::Unavailable {
                    operation,
                    status: status.as_u16()
                },
                "{operation}: status classification is independent of an intermediary's token"
            );
            assert!(error.to_string().contains(&status.as_u16().to_string()));
        }
        assert_eq!(
            unmapped(operation, StatusCode::PRECONDITION_FAILED),
            RootStoreError::Precondition
        );
    }
}

#[tokio::test]
async fn metrics_response_frames_count_partial_and_over_cap_bytes_per_session() {
    let a = crate::metrics::tests::metrics();
    let b = crate::metrics::tests::metrics();
    a.set_available(crate::MetricsGroup::Transport, true);
    b.set_available(crate::MetricsGroup::Transport, true);
    let wire = ResponseByteCounter::new();
    let over = read_capped(
        framed_body(vec![Frame::data(Bytes::from_static(b"12345"))]),
        4,
        &wire,
        Some(&a),
    )
    .await;
    assert!(matches!(over, Ok(None)), "{over:?}");
    let partial = read_capped(BrokenAfter::new(b"abc".to_vec()), 9, &wire, Some(&b)).await;
    assert!(
        matches!(partial, Err(RootStoreError::Backend(_))),
        "{partial:?}"
    );
    let success = read_capped(
        framed_body(vec![Frame::data(Bytes::from_static(b"xx"))]),
        2,
        &wire,
        Some(&a),
    )
    .await;
    assert_eq!(success.unwrap(), Some(b"xx".to_vec()));
    let a_text = a.snapshot().unwrap().render_prometheus().unwrap();
    let b_text = b.snapshot().unwrap().render_prometheus().unwrap();
    assert!(a_text.contains("direction=\"down\"} 7\n"), "{a_text}");
    assert!(b_text.contains("direction=\"down\"} 3\n"), "{b_text}");
    assert_eq!(wire.total(), Some(10));
}

#[tokio::test]
async fn metrics_offered_bytes_count_failed_attempts_on_independent_pooled_facades() {
    let store =
        HttpStore::new("https://127.0.0.1:1", vec![[1; 32]], &crate::AmbientNetwork).unwrap();
    let a = crate::metrics::tests::metrics();
    let b = crate::metrics::tests::metrics();
    let first = store.with_metrics(a.clone());
    let second = store.with_metrics(b.clone());
    assert!(Arc::ptr_eq(&first.wire, &second.wire));
    let req = || {
        Request::builder()
            .uri("https://127.0.0.1:1/metrics-fixture")
            .body(Full::new(Bytes::from_static(b"12345")))
            .unwrap()
    };
    let got = first.send(req(), "fixture", RetryPolicy::Idempotent).await;
    assert!(got.is_err(), "expected failed connect, got {got:?}");
    let got = second.send(req(), "fixture", RetryPolicy::Never).await;
    assert!(got.is_err(), "expected failed connect, got {got:?}");
    let a_text = a.snapshot().unwrap().render_prometheus().unwrap();
    let b_text = b.snapshot().unwrap().render_prometheus().unwrap();
    assert!(a_text.contains("direction=\"up\"} 10\n"), "{a_text}");
    assert!(
        b_text.contains("direction=\"up\"} 10\n"),
        "a Never policy still resends once when connect proves the first request was unsent: {b_text}"
    );
}

#[test]
fn http_facade_supplies_the_same_handle_to_cache_and_transport() {
    use crate::MountMetrics as _;
    let store =
        HttpStore::new("https://127.0.0.1:1", vec![[1; 32]], &crate::AmbientNetwork).unwrap();
    let a = crate::metrics::tests::metrics();
    let b = crate::metrics::tests::metrics();
    let first = store.with_metrics(a.clone());
    let second = store.with_metrics(b.clone());
    let mut cache = crate::fetcher::FetchState::new().unwrap();
    cache.set_metrics(first.client_metrics().cloned());
    cache
        .metrics()
        .expect("facade's recorder")
        .record_cache(crate::CachePhase::Read, crate::CacheResult::Hit);
    let req = Request::builder()
        .uri("https://127.0.0.1:1/fixture")
        .body(Full::new(Bytes::from_static(b"12345")))
        .unwrap();
    // Offering the known body is counted synchronously; polling would connect.
    drop(first.request_attempt(req));
    let text = a.snapshot().unwrap().render_prometheus().unwrap();
    assert!(text.contains("direction=\"up\"} 5\n"), "{text}");
    assert!(
        text.contains("phase=\"read\",result=\"hit\"} 1\n"),
        "{text}"
    );
    let other = second
        .client_metrics()
        .unwrap()
        .snapshot()
        .unwrap()
        .render_prometheus()
        .unwrap();
    assert!(
        other.contains("direction=\"up\"} 0\n")
            && !other.contains("# HELP granary_client_cache_lookups"),
        "{other}"
    );
    assert!(store.client_metrics().is_none());
    assert!(Arc::ptr_eq(&first.wire, &second.wire));
}

#[test]
fn intent_scope_accepts_unsorted_duplicate_configured_pins() {
    let store = HttpStore::new(
        "https://fixture.invalid",
        vec![[2; 32], [1; 32], [2; 32]],
        &crate::AmbientNetwork,
    )
    .unwrap();
    let mut scope = granary_core::retained_submission::Scope {
        authority_base: b"https://fixture.invalid".to_vec(),
        pins: vec![[1; 32], [2; 32]],
        credential_context: b"test".to_vec(),
    };
    assert!(
        store.intent_scope_matches(&scope),
        "unordered configured pins match canonical scope"
    );
    scope.pins = vec![[1; 32], [3; 32]];
    assert!(
        !store.intent_scope_matches(&scope),
        "different pin set remains refused"
    );
}
