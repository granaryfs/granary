// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::{Mutex, atomic::AtomicU64};

use object_store::client::{HttpError, HttpErrorKind, HttpRequest, HttpResponse, HttpService};

use crate::authority::content::intake::{Outcome, run};
use crate::authority::content::store::tests::s3_fixture;
use crate::authority::join::{Raced, race};

use super::*;

#[derive(Debug, Clone)]
struct Wire {
    backend: Arc<InMemory>,
    pages: u64,
    state: Arc<Mutex<WireState>>,
}

#[derive(Debug, Default)]
struct WireState {
    calls: Vec<String>,
    // A timeout stalls the request, a transport fault fails immediately.
    faults: VecDeque<(String, bool)>,
}

impl Wire {
    fn new(backend: Arc<InMemory>, pages: u64) -> Self {
        Self {
            backend,
            pages,
            state: Arc::default(),
        }
    }
}

impl HttpService for Wire {
    fn call<'a, 'future>(
        &'a self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send + 'future>>
    where
        'a: 'future,
        Self: 'future,
    {
        Box::pin(async move {
            let key = request.uri().path().trim_start_matches('/');
            let query = request.uri().query().unwrap_or_default();
            let list = query.contains("list-type=");
            let page = if query.contains("continuation-token=") {
                2
            } else {
                1
            };
            let scope = if query.contains("start-after=") {
                "recheck"
            } else {
                "list"
            };
            let route = if list {
                format!("{scope}:{page}")
            } else {
                key.to_owned()
            };
            let fault = {
                let mut state = self.state.lock().unwrap();
                state.calls.push(route.clone());
                if state.faults.front().is_some_and(|(at, _)| &route == at) {
                    state.faults.pop_front()
                } else {
                    None
                }
            };
            if let Some((_, stall)) = fault {
                if stall {
                    return pending().await;
                }
                return Err(HttpError::new(
                    HttpErrorKind::Connect,
                    std::io::Error::other("fixture transport failure"),
                ));
            }
            if list {
                let next = if page < self.pages {
                    "<IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken>"
                } else {
                    "<IsTruncated>false</IsTruncated>"
                };
                return Ok(HttpResponse::new(
                    Bytes::from(format!(
                        "<ListBucketResult>{next}<Contents><Key>root/{}/{page:020}</Key>\
                     <LastModified>2026-01-01T00:00:00Z</LastModified><ETag>fixture</ETag>\
                     <Size>128</Size></Contents></ListBucketResult>",
                        a().as_str()
                    ))
                    .into(),
                ));
            }
            let Ok(body) = self.backend.get(&Path::from(key)).await else {
                return Ok(Response::builder()
                    .status(404)
                    .body(Bytes::new().into())
                    .unwrap());
            };
            let bytes = body.bytes().await.unwrap();
            let mut response = Response::builder()
                .header("etag", "fixture")
                .header("last-modified", "Thu, 01 Jan 2026 00:00:00 GMT");
            let bytes = if let Some(range) = request.headers().get("range") {
                let range = range.to_str().unwrap().strip_prefix("bytes=").unwrap();
                let (start, end) = range.split_once('-').unwrap();
                let (start, end): (usize, usize) = (start.parse().unwrap(), end.parse().unwrap());
                response = response.status(206).header(
                    "content-range",
                    format!("bytes {start}-{end}/{}", bytes.len()),
                );
                bytes.slice(start..=end)
            } else {
                bytes
            };
            Ok(response
                .header("content-length", bytes.len())
                .body(bytes.into())
                .unwrap())
        })
    }
}

#[tokio::test]
async fn root_transport_failures_and_definitive_damage_have_distinct_http_answers() {
    let backend = Arc::new(InMemory::new());
    let (mut fx, initial) = Fx::with_content(backend.clone(), ValidationLimits::default()).await;
    let wire = Wire::new(backend.clone(), 1);
    let driver = restart(&mut fx, initial, s3_fixture(wire.clone()), &[a()]).await;
    let mut run = spawn_driver(driver);
    let candidate = good_root(&a(), 1, None, 1);
    let key = "root/vol-a/00000000000000000001";
    wire.state.lock().unwrap().faults =
        VecDeque::from([("list:1".to_owned(), false), (key.to_owned(), false)]);
    for op in 1..=2 {
        fx.refill(i128::from(op) * 10);
        refused(
            &fx,
            true,
            op,
            &candidate,
            ValidationError::Unavailable,
            503,
            "unavailable",
        )
        .await;
    }
    assert!(wire.state.lock().unwrap().faults.is_empty());
    let before = fx.bytes().await;
    let appends = fx.log.append_calls();
    for op in 3..=4 {
        fx.refill(i128::from(op) * 10);
        check(
            &fx.send(publish(op, candidate.clone())).await,
            409,
            Some("volume-damaged"),
        );
        backend
            .put(&Path::from(key), Bytes::from_static(b"bad root").into())
            .await
            .unwrap();
    }
    assert_eq!(fx.bytes().await, before);
    assert_eq!(fx.log.append_calls(), appends);
    assert_eq!(fx.store.root_puts.load(Ordering::Relaxed), 0);
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn intake_retries_at_the_current_page_root_and_final_recheck() {
    let backend = Arc::new(InMemory::new());
    let store = granary_store::backend::GranaryStore::new(backend.clone());
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    for seq in 1..=2 {
        let bytes = prepare(&store, &objects, tree).await;
        store.put_root(a().as_str(), seq, bytes).await.unwrap();
    }
    let wire = Wire::new(backend, 2);
    let anchor = "root/vol-a/00000000000000000001";
    let head = "root/vol-a/00000000000000000002";
    // The stalled ancestry read needs a hard timeout to make any progress.
    wire.state.lock().unwrap().faults = VecDeque::from([
        ("list:2".to_owned(), false),
        (anchor.to_owned(), true),
        ("recheck:2".to_owned(), false),
    ]);
    let source = s3_fixture(wire.clone()).with_limits(
        ValidationLimits {
            wall_time: Duration::from_millis(50),
            ..ValidationLimits::default()
        },
        2,
    );
    let keys = TrustedKeys::new([*publisher().public_key()]).unwrap();
    let outcome = run(&source, Arc::new(FixedClock), a(), keys).await;
    assert!(matches!(outcome, Outcome::Verified(_)), "{outcome:?}");
    let state = wire.state.lock().unwrap();
    assert!(state.faults.is_empty());
    let at = |route: &str| state.calls.iter().filter(|call| *call == route).count();
    assert_eq!((at("list:1"), at("list:2")), (1, 2));
    assert_eq!((at(anchor), at(head)), (2, 2));
    assert_eq!((at("recheck:1"), at("recheck:2")), (1, 2));
}

#[tokio::test(start_paused = true)]
async fn intake_total_deadline_includes_request_timeouts_and_backoff() {
    let wire = Wire::new(Arc::new(InMemory::new()), 1);
    wire.state.lock().unwrap().faults = VecDeque::from(vec![("list:1".to_owned(), true); 400]);
    let source = s3_fixture(wire.clone());
    let keys = TrustedKeys::new([*publisher().public_key()]).unwrap();
    let outcome = tokio::time::timeout(
        Duration::from_secs(1_801),
        run(&source, Arc::new(FixedClock), a(), keys),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, Outcome::Retry));
    let state = wire.state.lock().unwrap();
    assert!(state.calls.len() > 250 && !state.faults.is_empty());
}

/// A real single-page listing of `vol-a` roots 1..=head, with the same
/// fault queue as `Wire`, and a trip that moves the head when a route
/// is first requested.
#[derive(Debug, Clone)]
struct Moving {
    wire: Wire,
    head: Arc<AtomicU64>,
    trip: Arc<Mutex<Option<(String, u64)>>>,
}

impl Moving {
    fn new(backend: Arc<InMemory>, head: u64) -> Self {
        Self {
            wire: Wire::new(backend, 1),
            head: Arc::new(AtomicU64::new(head)),
            trip: Arc::default(),
        }
    }
    fn calls(&self, route: &str) -> usize {
        let state = self.wire.state.lock().unwrap();
        state.calls.iter().filter(|call| *call == route).count()
    }
}

impl HttpService for Moving {
    fn call<'a, 'future>(
        &'a self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send + 'future>>
    where
        'a: 'future,
        Self: 'future,
    {
        Box::pin(async move {
            let key = request.uri().path().trim_start_matches('/').to_owned();
            let query = request.uri().query().unwrap_or_default().to_owned();
            let list = query.contains("list-type=");
            let route = if !list {
                key
            } else if query.contains("start-after=") {
                "recheck:1".to_owned()
            } else {
                "list:1".to_owned()
            };
            {
                let mut trip = self.trip.lock().unwrap();
                if trip.as_ref().is_some_and(|(at, _)| *at == route) {
                    let (_, head) = trip.take().unwrap();
                    self.head.store(head, Ordering::Relaxed);
                }
            }
            if !list {
                return self.wire.call(request).await;
            }
            let fault = {
                let mut state = self.wire.state.lock().unwrap();
                state.calls.push(route.clone());
                if state.faults.front().is_some_and(|(at, _)| &route == at) {
                    state.faults.pop_front()
                } else {
                    None
                }
            };
            if let Some((_, stall)) = fault {
                if stall {
                    return pending().await;
                }
                return Err(HttpError::new(
                    HttpErrorKind::Connect,
                    std::io::Error::other("fixture transport failure"),
                ));
            }
            let mut body = String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
            for seq in 1..=self.head.load(Ordering::Relaxed) {
                write!(
                    body,
                    "<Contents><Key>root/{}/{seq:020}</Key>\
                     <LastModified>2026-01-01T00:00:00Z</LastModified><ETag>fixture</ETag>\
                     <Size>128</Size></Contents>",
                    a().as_str()
                )
                .unwrap();
            }
            body.push_str("</ListBucketResult>");
            Ok(HttpResponse::new(Bytes::from(body).into()))
        })
    }
}

fn keys() -> TrustedKeys {
    TrustedKeys::new([*publisher().public_key()]).unwrap()
}

const ROOT1: &str = "root/vol-a/00000000000000000001";

async fn verified_at(backend: &InMemory, outcome: &Outcome, seq: u64) -> bool {
    let key = Path::from(format!("root/vol-a/{seq:020}"));
    let bytes = backend.get(&key).await.unwrap().bytes().await.unwrap();
    matches!(outcome, Outcome::Verified(v) if v.matches(&a(), GrainId::of(&bytes)))
}

/// Roots 1..=3 are stored; the listing shows only 1..=2 until tripped.
async fn three_roots() -> (Arc<InMemory>, Moving) {
    let backend = Arc::new(InMemory::new());
    let store = granary_store::backend::GranaryStore::new(backend.clone());
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    for seq in 1..=3 {
        let bytes = prepare(&store, &objects, tree).await;
        store.put_root(a().as_str(), seq, bytes).await.unwrap();
    }
    let wire = Moving::new(backend.clone(), 2);
    (backend, wire)
}

#[tokio::test]
async fn intake_control_transient_faults_without_a_head_move_verify() {
    let (backend, wire) = three_roots().await;
    wire.wire.state.lock().unwrap().faults =
        VecDeque::from([(ROOT1.to_owned(), false), ("recheck:1".to_owned(), false)]);
    let outcome = run(&s3_fixture(wire.clone()), Arc::new(FixedClock), a(), keys()).await;
    assert!(verified_at(&backend, &outcome, 2).await, "{outcome:?}");
    assert!(wire.wire.state.lock().unwrap().faults.is_empty());
    assert_eq!(
        (
            wire.calls("list:1"),
            wire.calls(ROOT1),
            wire.calls("recheck:1")
        ),
        (1, 2, 2)
    );
}

#[tokio::test]
async fn intake_progress_kept_across_a_transient_error_does_not_install_a_moved_head() {
    // The head moves while a mid-walk ancestry read fails transiently.
    let (_backend, wire) = three_roots().await;
    wire.wire.state.lock().unwrap().faults = VecDeque::from([(ROOT1.to_owned(), false)]);
    *wire.trip.lock().unwrap() = Some((ROOT1.to_owned(), 3));
    let outcome = run(&s3_fixture(wire.clone()), Arc::new(FixedClock), a(), keys()).await;
    assert!(matches!(outcome, Outcome::Retry), "mid-walk: {outcome:?}");
    // Progress was kept: one listing, the failed read retried in place.
    assert_eq!((wire.calls("list:1"), wire.calls(ROOT1)), (1, 2));

    // The head moves while the final recheck listing fails transiently.
    let (backend, wire) = three_roots().await;
    wire.wire.state.lock().unwrap().faults = VecDeque::from([("recheck:1".to_owned(), false)]);
    *wire.trip.lock().unwrap() = Some(("recheck:1".to_owned(), 3));
    let outcome = run(&s3_fixture(wire.clone()), Arc::new(FixedClock), a(), keys()).await;
    assert!(matches!(outcome, Outcome::Retry), "recheck: {outcome:?}");
    assert_eq!((wire.calls("list:1"), wire.calls("recheck:1")), (1, 2));

    // The next attempt verifies the new head.
    let outcome = run(&s3_fixture(wire.clone()), Arc::new(FixedClock), a(), keys()).await;
    assert!(verified_at(&backend, &outcome, 3).await, "{outcome:?}");
}

#[tokio::test]
async fn intake_head_root_swapped_in_place_during_a_transient_recheck_is_not_installed() {
    // Same seq, different bytes at the recheck (a store that lost and
    // regained the key with other content): the exact root id decides.
    let (backend, wire) = three_roots().await;
    let head = "root/vol-a/00000000000000000002";
    let other = backend
        .get(&Path::from("root/vol-a/00000000000000000003"))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let source = {
        let mut source = s3_fixture(wire.clone());
        source.intake_gate = Some(Arc::new(crate::authority::content::intake::Gate::default()));
        source
    };
    let gate = source.intake_gate.clone().unwrap();
    let mut job = std::pin::pin!(run(&source, Arc::new(FixedClock), a(), keys()));
    let swap = async {
        gate.entered.notified().await;
        backend.put(&Path::from(head), other.into()).await.unwrap();
        wire.wire.state.lock().unwrap().faults = VecDeque::from([(head.to_owned(), false)]);
        gate.release.notify_one();
    };
    assert!(matches!(
        race(job.as_mut(), std::pin::pin!(swap)).await,
        Raced::Second(())
    ));
    let outcome = job.await;
    assert!(matches!(outcome, Outcome::Retry), "{outcome:?}");
    assert!(wire.wire.state.lock().unwrap().faults.is_empty());
}

async fn wire_authority(
    limits: ValidationLimits,
    gate: Option<Arc<crate::authority::content::intake::Gate>>,
) -> (Fx, Moving, tokio::task::JoinSet<RunEnd>, Objects, Vec<u8>) {
    let backend = Arc::new(InMemory::new());
    let (mut fx, initial) = Fx::with_content(backend.clone(), limits).await;
    let mut run = spawn_driver(initial);
    let mut objects = Objects::default();
    let base = objects.file(b"base", b"base content");
    let tree = objects.tree(&[base]);
    let genesis = prepare(&fx.store, &objects, tree).await;
    land(&fx, false, 1, &genesis).await;
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
    let wire = Moving::new(backend, 1);
    let mut parts = fx.parts();
    parts.admission = s3_fixture(wire.clone()).with_limits(limits, 2);
    parts.admission.intake_gate = gate;
    let (handle, driver) = start(parts, boot(2), configs(&[a()])).await.unwrap();
    fx.handle = handle;
    (fx, wire, spawn_driver(driver), objects, genesis)
}

async fn rule6_deadline(stall: bool) -> (Answer, Answer) {
    use crate::authority::content::intake::Gate;
    let limits = ValidationLimits {
        wall_time: Duration::from_millis(400),
        ..ValidationLimits::default()
    };
    let gate = Arc::new(Gate::default());
    let (fx, wire, mut run, mut objects, genesis) =
        wire_authority(limits, Some(gate.clone())).await;
    let base = objects.file(b"base", b"base content");
    let more = objects.file(b"more", b"one new small file");
    let tree = objects.tree(&[base, more]);
    let next = prepare(&fx.store, &objects, tree).await;

    // Cold start: the first eligible submission requests intake.
    assert_eq!(
        submit(&fx, 2, &next).await,
        Answer::Validation(ValidationError::Unavailable)
    );
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    gate.release.notify_one();
    // A stale probe says when intake has finished; it decides nothing.
    let probe = retry_intake(&fx, 9, &genesis).await;
    assert!(matches!(probe, Answer::StaleBase { .. }), "{probe:?}");

    // The landed proof is installed. One head listing now stalls.
    if stall {
        wire.wire.state.lock().unwrap().faults = VecDeque::from([("recheck:1".to_owned(), true)]);
    }
    let first = submit(&fx, 3, &next).await;
    assert!(wire.wire.state.lock().unwrap().faults.is_empty());
    let second = if matches!(first, Answer::Accepted { .. }) {
        first.clone()
    } else {
        submit(&fx, 3, &next).await
    };
    gate.release.notify_one();
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
    (first, second)
}

#[tokio::test]
async fn one_stalled_head_listing_does_not_force_reintake_over_a_landed_proof() {
    let (first, _) = rule6_deadline(false).await;
    assert!(
        matches!(first, Answer::Accepted { .. }),
        "control {first:?}"
    );
    let (first, second) = rule6_deadline(true).await;
    assert_eq!(first, Answer::Validation(ValidationError::Unavailable));
    assert!(
        matches!(second, Answer::Accepted { .. }),
        "the exact retry after one stalled listing: {second:?}"
    );
}

#[tokio::test]
async fn admission_content_read_transient_is_503_and_missing_is_400() {
    let backend = Arc::new(InMemory::new());
    let (mut fx, initial) = Fx::with_content(backend.clone(), ValidationLimits::default()).await;
    let wire = Moving::new(backend.clone(), 0);
    let driver = restart(&mut fx, initial, s3_fixture(wire.clone()), &[a()]).await;
    let mut run = spawn_driver(driver);
    let mut objects = Objects::default();
    let file = objects.file(b"f", b"some content");
    let tree = objects.tree(&[file]);
    let candidate = prepare(&fx.store, &objects, tree).await;
    let root = root::decode_root(&candidate).unwrap();
    let index = granary_core::binmap::decode_binmap_index(
        &fx.store
            .get_meta(a().as_str(), &root.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    let digest = first_bin(&fx.store, &a(), &candidate).await;
    let bin = object_path(
        "bins",
        GrainId::from_parts(granary_core::hash::HashAlgorithm::Blake3, digest),
    );
    let points = [
        meta_path(root.sheaf_head),
        meta_path(root.binmap_index),
        meta_path(index.bin_table),
        meta_path(index.shards[0]),
        bin,
    ];
    let before = fx.bytes().await;
    for (op, object) in points.iter().enumerate() {
        let op = u8::try_from(op + 1).unwrap();
        // Transport failure is retryable; a missing key is definitive.
        wire.wire.state.lock().unwrap().faults = VecDeque::from([(object.to_string(), false)]);
        assert_eq!(
            submit(&fx, op, &candidate).await,
            Answer::Validation(ValidationError::Unavailable),
            "transient {object}"
        );
        assert!(
            wire.wire.state.lock().unwrap().faults.is_empty(),
            "{object}"
        );
        // Definitive absence is the candidate's fault.
        let saved = backend.get(object).await.unwrap().bytes().await.unwrap();
        backend.delete(object).await.unwrap();
        assert_eq!(
            submit(&fx, op, &candidate).await,
            Answer::Validation(ValidationError::MissingReference),
            "missing {object}"
        );
        backend.put(object, saved.into()).await.unwrap();
    }
    assert_eq!(fx.bytes().await, before);
    // A transient head listing is 503; then the exact retry is accepted.
    wire.wire.state.lock().unwrap().faults = VecDeque::from([("list:1".to_owned(), false)]);
    assert_eq!(
        submit(&fx, 9, &candidate).await,
        Answer::Validation(ValidationError::Unavailable)
    );
    let answer = submit(&fx, 9, &candidate).await;
    assert!(matches!(answer, Answer::Accepted { .. }), "{answer:?}");
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "the test owns and joins the gated submitters"
)]
async fn queued_submission_whose_base_went_stale_is_not_validated_or_decided() {
    use crate::authority::content::store::BinGate;
    use tokio::sync::Semaphore;

    let volumes = [a(), b(), c()];
    let [va, vb, vc] = &volumes;
    let backend = Arc::new(InMemory::new());
    let (mut fx, initial) = Fx::with_backend(
        false,
        &volumes,
        &[],
        &volumes,
        Some((backend.clone(), ValidationLimits::default())),
    )
    .await;
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    let first_a = prepare_for(va, &fx.store, &objects, tree).await;
    let first_b = prepare_for(vb, &fx.store, &objects, tree).await;
    let digest = first_bin(&fx.store, va, &first_a).await;
    let mine = objects.file(b"mine", b"valid distinct content");
    let tree = objects.tree(&[mine]);
    let queued = prepare_for(vc, &fx.store, &objects, tree).await;
    let theirs = objects.file(b"theirs", b"a foreign writer");
    let tree = objects.tree(&[theirs]);
    let foreign = prepare_for(vc, &fx.store, &objects, tree).await;

    let gate = Arc::new(BinGate {
        digest,
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let mut admission = crate::Admission::memory(backend);
    admission.bin_gate = Some(gate.clone());
    let driver = restart(&mut fx, initial, admission, &volumes).await;
    let mut run = spawn_driver(driver);

    let mut holders = tokio::task::JoinSet::new();
    for (volume, bytes) in [(va, &first_a), (vb, &first_b)] {
        let (handle, request) = (fx.handle.clone(), submission(volume, 1, bytes));
        holders.spawn(async move { handle.submit(request).await });
    }
    tokio::time::timeout(Duration::from_secs(5), gate.entered.acquire_many(2))
        .await
        .unwrap()
        .unwrap()
        .forget();
    // Both slots are held. The third volume resolves its (empty) head
    // and waits in the queue.
    let request = submission(vc, 1, &queued);
    let (handle, waiting) = (fx.handle.clone(), request.clone());
    let mut victim = tokio::spawn(async move { handle.submit(waiting).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut victim)
            .await
            .is_err(),
        "the third volume must be queued"
    );
    let log_before = fx.log.read(vc).await.unwrap();
    // Its base goes stale while it waits: a foreign root lands at seq 1.
    fx.store.put_root(vc.as_str(), 1, foreign).await.unwrap();
    gate.release.add_permits(8);
    let answer = tokio::time::timeout(Duration::from_secs(5), victim)
        .await
        .unwrap()
        .unwrap();
    let decided = fx.log.read(vc).await.unwrap() != log_before;
    let settled = if matches!(answer, Answer::Accepted { .. }) {
        Some(settle(&fx.handle, &request).await)
    } else {
        None
    };
    while holders.join_next().await.is_some() {}
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
    assert!(
        matches!(answer, Answer::StaleBase { .. }) && !decided,
        "queued past a head move: {answer:?}, decision appended {decided}, then {settled:?}"
    );
}
