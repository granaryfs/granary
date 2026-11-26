// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request-attempt and landed-root observers at the server's outer seams.

use super::*;
use http_body_util::Full;
use hyper::{Request, Response, body::Bytes, service::Service};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize};

#[derive(Clone, Debug)]
pub(super) struct Attempt {
    pub arrival_seq: u64,
    pub method: String,
    pub route: String,
    pub outcome: AttemptOutcome,
    pub elapsed: Duration,
    pub request_id: Option<String>,
    pub request_id_refusal: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AttemptOutcome {
    Response(u16),
    ServiceError,
    Cancelled,
}

#[derive(Clone, Debug)]
pub(super) struct Attempts {
    samples: Arc<Mutex<Vec<Attempt>>>,
    lost: Arc<AtomicUsize>,
    next_arrival: Arc<AtomicU64>,
}

impl Attempts {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            samples: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
            lost: Arc::new(AtomicUsize::new(0)),
            next_arrival: Arc::new(AtomicU64::new(1)),
        }
    }

    fn record(&self, sample: Attempt) {
        let mut samples = self
            .samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if samples.len() < samples.capacity() {
            samples.push(sample);
        } else {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn take(&self) -> (Vec<Attempt>, usize) {
        let samples = self
            .samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect();
        (samples, self.lost.swap(0, Ordering::Relaxed))
    }
}

#[derive(Clone)]
pub(super) struct ObservedService<S> {
    inner: S,
    attempts: Attempts,
}

impl<S> ObservedService<S> {
    pub(super) fn new(inner: S, attempts: Attempts) -> Self {
        Self { inner, attempts }
    }
}

impl<S, B> Service<Request<B>> for ObservedService<S>
where
    S: Service<Request<B>, Response = Response<Full<Bytes>>> + Send + Sync + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<Full<Bytes>>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<B>) -> Self::Future {
        let arrival_seq = self.attempts.next_arrival.fetch_add(1, Ordering::Relaxed);
        let at = stopwatch();
        let method = request.method().to_string();
        let route = normalized_route(request.uri().path());
        let (request_id, request_id_refusal) = match request_id(request.headers()) {
            Ok(value) => (value, None),
            Err(refusal) => (None, Some(refusal)),
        };
        let future = self.inner.call(request);
        let mut pending = PendingAttempt {
            attempts: self.attempts.clone(),
            at,
            sample: Some(Attempt {
                arrival_seq,
                method,
                route,
                outcome: AttemptOutcome::Cancelled,
                elapsed: Duration::ZERO,
                request_id,
                request_id_refusal,
            }),
        };
        Box::pin(async move {
            match future.await {
                Ok(response) => {
                    pending.finish(AttemptOutcome::Response(response.status().as_u16()));
                    Ok(response)
                }
                Err(error) => {
                    pending.finish(AttemptOutcome::ServiceError);
                    Err(error)
                }
            }
        })
    }
}

struct PendingAttempt {
    attempts: Attempts,
    at: Instant,
    sample: Option<Attempt>,
}

impl PendingAttempt {
    fn finish(&mut self, outcome: AttemptOutcome) {
        if let Some(mut sample) = self.sample.take() {
            sample.outcome = outcome;
            sample.elapsed = self.at.elapsed();
            self.attempts.record(sample);
        }
    }
}

impl Drop for PendingAttempt {
    fn drop(&mut self) {
        self.finish(AttemptOutcome::Cancelled);
    }
}

fn request_id(headers: &hyper::HeaderMap) -> Result<Option<String>, &'static str> {
    let mut values = headers.get_all("granary-request-id").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| "request id is malformed")?;
    if values.next().is_some()
        || !(1..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("request id is malformed");
    }
    Ok(Some(value.to_owned()))
}

fn normalized_route(path: &str) -> String {
    let parts: Vec<_> = path.split('/').collect();
    match parts.as_slice() {
        ["", "volume", _, "publish"] => "/volume/:volume/publish".to_owned(),
        ["", "volume", _, "intent"] => "/volume/:volume/intent".to_owned(),
        ["", "volume", _, "intent", "release"] => "/volume/:volume/intent/release".to_owned(),
        ["", "volume", _, "intent", "ownership"] => "/volume/:volume/intent/ownership".to_owned(),
        _ => "/other".to_owned(),
    }
}

pub(super) async fn landed_growth<S: RootStore>(
    store: &S,
    volume: &VolumeName,
    before: u64,
) -> Result<(u64, u64), &'static str> {
    let after = store
        .max_seq(volume.as_str())
        .await
        .map_err(|_| "landed max sequence is unreadable")?
        .unwrap_or(0);
    let growth = after
        .checked_sub(before)
        .ok_or("landed sequence moved backwards")?;
    if growth > 0 {
        for seq in before.saturating_add(1)..=after {
            match store.get_root(volume.as_str(), seq).await {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return Err("landed sequence is unreadable"),
            }
        }
    }
    Ok((after, growth))
}

#[derive(Clone)]
struct Immediate {
    calls: Arc<AtomicUsize>,
}

impl Service<Request<Full<Bytes>>> for Immediate {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    #[expect(
        clippy::disallowed_methods,
        reason = "the fake's synchronous delay distinguishes an outer timer from a handler timer"
    )]
    fn call(&self, _: Request<Full<Bytes>>) -> Self::Future {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(20));
        let status = if call == 0 { 409 } else { 429 };
        std::future::ready(Ok(Response::builder()
            .status(status)
            .body(Full::new(Bytes::new()))
            .unwrap()))
    }
}

#[test]
fn authority_measurement_outer_attempt_observer_controls() {
    let attempts = Attempts::new(4);
    let service = ObservedService::new(
        Immediate {
            calls: Arc::new(AtomicUsize::new(0)),
        },
        attempts.clone(),
    );
    for path in ["/volume/v/intent", "/volume/v/publish"] {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("granary-request-id", "fsync-7")
            .body(Full::new(Bytes::new()))
            .unwrap();
        block(service.call(request)).unwrap();
    }
    let (samples, lost) = attempts.take();
    assert_eq!(lost, 0);
    assert_eq!(samples.len(), 2, "both outer attempts must be retained");
    assert_eq!(
        samples
            .iter()
            .map(|sample| (
                sample.method.as_str(),
                sample.route.as_str(),
                sample.outcome,
                sample.request_id.as_deref(),
                sample.request_id_refusal,
            ))
            .collect::<Vec<_>>(),
        [
            (
                "POST",
                "/volume/:volume/intent",
                AttemptOutcome::Response(409),
                Some("fsync-7"),
                None
            ),
            (
                "POST",
                "/volume/:volume/publish",
                AttemptOutcome::Response(429),
                Some("fsync-7"),
                None
            ),
        ]
    );
    assert!(
        samples
            .iter()
            .all(|sample| sample.elapsed >= Duration::from_millis(20)),
        "the outer timer must include synchronous Service::call work: {samples:?}"
    );
    let distinct = samples
        .iter()
        .filter_map(|sample| sample.request_id.as_deref())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert_eq!(
        (
            samples
                .iter()
                .filter(|sample| sample.outcome == AttemptOutcome::Response(409))
                .count(),
            samples
                .iter()
                .filter(|sample| sample.outcome == AttemptOutcome::Response(429))
                .count(),
            samples.len().saturating_sub(distinct),
        ),
        (1, 1, 1),
        "conflict, rate limiting and a repeated-id retry must stay distinguishable"
    );
}

#[tokio::test]
async fn authority_measurement_arrival_sequence_is_drawn_before_completion() {
    #[derive(Clone)]
    struct Reordered {
        first: Arc<tokio::sync::Notify>,
        calls: Arc<AtomicUsize>,
    }
    impl Service<Request<Full<Bytes>>> for Reordered {
        type Response = Response<Full<Bytes>>;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn call(&self, _: Request<Full<Bytes>>) -> Self::Future {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            let first = self.first.clone();
            Box::pin(async move {
                if call == 0 {
                    first.notified().await;
                } else {
                    first.notify_one();
                }
                Ok(Response::new(Full::new(Bytes::new())))
            })
        }
    }

    let attempts = Attempts::new(2);
    let service = ObservedService::new(
        Reordered {
            first: Arc::new(tokio::sync::Notify::new()),
            calls: Arc::new(AtomicUsize::new(0)),
        },
        attempts.clone(),
    );
    let first = service.call(
        Request::builder()
            .uri("/first")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    );
    let second = service.call(
        Request::builder()
            .uri("/second")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    );
    let mut first = first;
    let mut second = second;
    let mut first_result = None;
    let mut second_result = None;
    let (first, second) = std::future::poll_fn(|cx| {
        if first_result.is_none()
            && let std::task::Poll::Ready(result) = first.as_mut().poll(cx)
        {
            first_result = Some(result);
        }
        if second_result.is_none()
            && let std::task::Poll::Ready(result) = second.as_mut().poll(cx)
        {
            second_result = Some(result);
        }
        match (first_result.take(), second_result.take()) {
            (Some(first), Some(second)) => std::task::Poll::Ready((first, second)),
            (first, second) => {
                first_result = first;
                second_result = second;
                std::task::Poll::Pending
            }
        }
    })
    .await;
    assert!(
        first.is_ok() && second.is_ok(),
        "both reordered requests must complete successfully"
    );
    let (samples, lost) = attempts.take();
    assert_eq!(lost, 0);
    assert_eq!(
        samples
            .iter()
            .map(|sample| (sample.route.as_str(), sample.arrival_seq))
            .collect::<Vec<_>>(),
        [("/other", 2), ("/other", 1)],
        "completion order must not allocate the server arrival sequence"
    );
}

#[test]
fn authority_measurement_request_id_valid_and_malformed_controls() {
    let mut valid = hyper::HeaderMap::new();
    valid.insert("granary-request-id", "a.B_9-7".parse().unwrap());
    assert_eq!(request_id(&valid), Ok(Some("a.B_9-7".to_owned())));
    let mut duplicate = valid.clone();
    duplicate.append("granary-request-id", "second".parse().unwrap());
    let cases = [
        hyper::HeaderMap::from_iter([(
            hyper::header::HeaderName::from_static("granary-request-id"),
            hyper::header::HeaderValue::from_static("bad/id"),
        )]),
        duplicate,
        hyper::HeaderMap::from_iter([(
            hyper::header::HeaderName::from_static("granary-request-id"),
            hyper::header::HeaderValue::from_str(&"x".repeat(65)).unwrap(),
        )]),
    ];
    assert!(!cases.is_empty());
    for headers in cases {
        assert_eq!(request_id(&headers), Err("request id is malformed"));
    }
}

#[tokio::test]
async fn authority_measurement_landed_growth_is_not_put_attempts() {
    let inner = TestStore::new(Sim::new().node(1, Faults::none()));
    let timings = super::io::Timings::new(16);
    let store = super::io::TimedStore {
        inner,
        timings: timings.clone(),
    };
    let volume = a();
    let bytes = good_root(&volume, 1, None, 1);
    store
        .put_root(volume.as_str(), 1, bytes.clone())
        .await
        .unwrap();
    assert_eq!(
        store.put_root(volume.as_str(), 1, bytes).await,
        Err(RootStoreError::AlreadyExists)
    );
    let (after, growth) = landed_growth(&store, &volume, 0).await.unwrap();
    assert_eq!(
        (
            after,
            growth,
            timings.counts()[super::io::Call::Put as usize]
        ),
        (1, 1, 2),
        "one landed root must not become two roots because the PUT was retried"
    );
}

#[tokio::test]
async fn authority_measurement_landed_growth_requires_intervening_roots() {
    let store = TestStore::new(Sim::new().node(1, Faults::none()));
    let volume = a();
    let parent = GrainId::of(&good_root(&volume, 1, None, 1));
    store
        .put_root(volume.as_str(), 3, good_root(&volume, 3, Some(parent), 1))
        .await
        .unwrap();
    let cases = [
        (0, "landed sequence is unreadable"),
        (4, "landed sequence moved backwards"),
    ];
    assert!(!cases.is_empty());
    for (before, refusal) in cases {
        assert_eq!(landed_growth(&store, &volume, before).await, Err(refusal));
    }
}

#[tokio::test]
async fn authority_measurement_cancelled_attempt_is_counted() {
    #[derive(Clone)]
    struct Pending;
    impl Service<Request<Full<Bytes>>> for Pending {
        type Response = Response<Full<Bytes>>;
        type Error = Infallible;
        type Future = std::future::Pending<Result<Self::Response, Self::Error>>;
        fn call(&self, _: Request<Full<Bytes>>) -> Self::Future {
            std::future::pending()
        }
    }

    let attempts = Attempts::new(2);
    let service = ObservedService::new(Pending, attempts.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/volume/v/publish")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), service.call(request))
            .await
            .is_err()
    );
    let (samples, lost) = attempts.take();
    assert_eq!(
        (samples.len(), lost),
        (1, 0),
        "a timed-out request must be counted as a cancelled attempt"
    );
    assert_eq!(
        samples.first().map(|sample| sample.outcome),
        Some(AttemptOutcome::Cancelled)
    );
}
