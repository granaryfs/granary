// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::controls::tests::TestClock;
use crate::controls::{ControlsConfig, PrincipalControls, WritePermit};
use crate::enrollment::{EnrollmentReader, VerbOptions, attach, mint, revoke};
use crate::loopback::{RequestIdShape, ResponseTuple, request_id_shapes};
use crate::protected_dir::tests::{chmod, scratch};
use granary_core::enrollment::{ClientSpkiDigest, PrincipalId, TenantName};
use granary_core::secure_random::{EntropyUnavailable, SecureRandom};
use granary_net::identity::ConnectionIdentity;
use std::path::PathBuf;

pub(super) const A: PrincipalId = PrincipalId::from_bytes([1; 16]);
pub(super) const B: PrincipalId = PrincipalId::from_bytes([2; 16]);
pub(super) const DA: ClientSpkiDigest = ClientSpkiDigest::from_bytes([1; 32]);
pub(super) const DA2: ClientSpkiDigest = ClientSpkiDigest::from_bytes([3; 32]);
pub(super) const DB: ClientSpkiDigest = ClientSpkiDigest::from_bytes([2; 32]);
const OPTS: VerbOptions = VerbOptions {
    accept_unsupported_filesystem: true,
};
const ROOT: &str = "/volume/v/root/00000000000000000001";
const HINT: &str = "/volume/v/hint";

struct Door(u8);
impl SecureRandom for Door {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), EntropyUnavailable> {
        bytes.fill(self.0);
        Ok(())
    }
}

pub(super) struct Fx {
    dir: PathBuf,
    clock: Arc<TestClock>,
    controls: Arc<PrincipalControls>,
    reader: EnrollmentReader,
    pub(super) service: GrainService<FakeSeam>,
}

impl Fx {
    pub(super) fn new(tag: &str) -> Self {
        let dir = scratch(tag).join("enroll");
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o700);
        let tenant = TenantName::parse("test").unwrap();
        assert_eq!(mint(&dir, OPTS, &tenant, DA, &mut Door(1)).unwrap().0, A);
        assert_eq!(mint(&dir, OPTS, &tenant, DB, &mut Door(2)).unwrap().0, B);
        attach(&dir, OPTS, A, DA2).unwrap();
        let reader = EnrollmentReader::open(&dir, true).unwrap();
        let clock = Arc::new(TestClock::default());
        let controls = Arc::new(PrincipalControls::new(
            ControlsConfig::default(),
            clock.clone(),
        ));
        let service = GrainService::for_test(
            Arc::new(FakeSeam::default()),
            "",
            VerifyPolicy::seam_only(),
            Some(DECLARED_MAX_EXTENT),
            WRITE_BODY_BUDGET_BYTES,
            READ_BODY_BUDGET_BYTES,
            VERIFY_PERMIT_MAX_WAIT,
            None,
        )
        .with_test_write_controls(reader.clone(), controls.clone());
        Self {
            dir,
            clock,
            controls,
            reader,
            service,
        }
    }

    fn fill_cap(&self) -> Vec<WritePermit> {
        (0..4)
            .map(|_| self.controls.admit(A, false).unwrap())
            .collect()
    }
}

pub(super) fn request<B>(
    method: Method,
    target: &str,
    identity: Option<ClientSpkiDigest>,
    body: B,
) -> Request<B> {
    let mut request = Request::builder()
        .method(method)
        .uri(target)
        .body(body)
        .unwrap();
    request
        .extensions_mut()
        .insert(identity.map_or(ConnectionIdentity::Anonymous, ConnectionIdentity::Verified));
    request
}

async fn through<R, B>(service: &GrainService<R>, request: Request<B>) -> Response<Full<Bytes>>
where
    R: RootStore + BinStore,
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let bounds = Bounds {
        capture: service.capture.as_ref(),
        debug_grants: service.debug_grants.as_ref(),
        authority: service.authority.as_deref(),
        budget: &service.write_budget,
        read_budget: &service.read_budget,
        permits: &service.verify_permits,
        read_permits: &service.read_permits,
        permit_wait: service.permit_wait,
        dispatch_deadline: service.dispatch_deadline,
        #[cfg(feature = "crash-points")]
        test_reply_deadline: service.test_reply_deadline,
        draining: service.draining.subscribe(),
    };
    respond(
        &*service.store,
        "",
        service.policy,
        service.max_extent,
        bounds,
        request,
    )
    .await
}

pub(super) fn empty() -> Full<Bytes> {
    Full::new(Bytes::new())
}

#[tokio::test]
async fn reads_never_touch_controls() {
    let fx = Fx::new("controls-reads");
    let held = fx.fill_cap();
    fx.controls
        .admit(B, true)
        .unwrap()
        .charge_bytes(BIN_MAX_BYTES)
        .unwrap();
    let id = GrainId::of(b"meta");
    let paths = [
        ROOT.to_owned(),
        HINT.to_owned(),
        "/volume/v/max-seq".to_owned(),
        format!("/volume/v/meta/{id}"),
        format!("/bin/{}", hex64(&[1; 32])),
    ];
    for state in ["enrolled", "revoked", "unavailable"] {
        if state == "revoked" {
            revoke(&fx.dir, OPTS, DA).unwrap();
        }
        if state == "unavailable" {
            std::fs::rename(fx.dir.join("ENROLLMENT"), fx.dir.join("aside")).unwrap();
        }
        for identity in [None, Some(DA), Some(DB)] {
            let before = fx.reader.snapshot().sequence;
            let states = fx.controls.state_count();
            for path in &paths {
                let mut req = request(Method::GET, path, identity, empty());
                if path.starts_with("/bin/") {
                    req.headers_mut()
                        .insert(RANGE, HeaderValue::from_static("bytes=0-0"));
                }
                let response = through(&fx.service, req).await;
                assert_eq!(
                    response.status(),
                    StatusCode::NOT_FOUND,
                    "{state}: {path} must reach the store"
                );
            }
            assert_eq!(
                fx.reader.snapshot().sequence,
                before,
                "reads never consult enrollment"
            );
            assert_eq!(
                fx.controls.state_count(),
                states,
                "reads never create rate state"
            );
            assert_eq!(fx.controls.in_flight(A), 4, "reads consume no write slots");
        }
    }
    drop(held);
}

#[tokio::test]
async fn principal_rates_and_cap_are_independent() {
    let fx = Fx::new("controls-independent");
    let held = fx.fill_cap();
    for credential in [DA, DA2] {
        let connection = fx.service.clone();
        let response = through(
            &connection,
            request(Method::PUT, ROOT, Some(credential), empty()),
        )
        .await;
        assert_eq!(
            response.status(),
            429,
            "credentials and connections share A's cap"
        );
    }
    let response = through(
        &fx.service.clone(),
        request(Method::PUT, ROOT, Some(DB), empty()),
    )
    .await;
    assert_eq!(response.status(), 201, "B writes while A is capped");
    let response = through(&fx.service, request(Method::GET, ROOT, None, empty())).await;
    assert_eq!(
        response.status(),
        200,
        "anonymous reads complete within shared bounds"
    );
    drop(held);
    fx.controls
        .admit(A, false)
        .unwrap()
        .charge_bytes(BIN_MAX_BYTES)
        .unwrap();
    for credential in [DA, DA2] {
        let response = through(
            &fx.service.clone(),
            request(
                Method::PUT,
                HINT,
                Some(credential),
                Full::new(Bytes::from_static(b"00000000000000000001")),
            ),
        )
        .await;
        assert_eq!(response.status(), 429, "credentials share A's byte debt");
    }
    assert_eq!(
        through(
            &fx.service,
            request(
                Method::PUT,
                HINT,
                Some(DB),
                Full::new(Bytes::from_static(b"00000000000000000001"))
            )
        )
        .await
        .status(),
        204
    );
}

#[tokio::test]
async fn admission_refusals_follow_contract_order() {
    let fx = Fx::new("controls-order");
    let held = fx.fill_cap();
    let id = GrainId::of(b"meta");
    for path in [
        ROOT.to_owned(),
        HINT.to_owned(),
        format!("/volume/v/meta/{id}"),
        format!("/bin/{}", hex64(&[1; 32])),
    ] {
        let response = through(
            &fx.service,
            request(
                Method::PUT,
                &path,
                None,
                NeverPolled(Some(BIN_MAX_BYTES + 1)),
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            403,
            "principal before controls on {path}"
        );
        assert_eq!(token(&response).as_deref(), Some("no-principal"));
        let response = through(
            &fx.service,
            request(
                Method::PUT,
                &path,
                Some(DA),
                NeverPolled(Some(BIN_MAX_BYTES + 1)),
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            429,
            "cap before declared length on {path}"
        );
    }
    drop(held);
    let response = through(
        &fx.service,
        request(
            Method::PUT,
            ROOT,
            Some(DA),
            NeverPolled(Some(BIN_MAX_BYTES + 1)),
        ),
    )
    .await;
    assert_eq!(response.status(), 413, "declared bound before polling");
    assert_eq!(fx.service.store.objects(), 0, "no early store calls");
    // Cross all three upload limits. The frame is counted but not retained.
    fx.controls
        .admit(A, false)
        .unwrap()
        .charge_bytes(BIN_MAX_BYTES)
        .unwrap();
    let mut service = fx.service.clone();
    service.write_budget = Arc::new(WriteBudget::new(0));
    let response = through(
        &service,
        request(
            Method::PUT,
            ROOT,
            Some(DA),
            Frames::one(vec![0; usize::try_from(ROOT_MAX_BYTES).unwrap() + 1]),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        413,
        "body bound before byte rate before shared budget"
    );
    let response = through(
        &service,
        request(Method::PUT, ROOT, Some(DA), Frames::one(vec![0])),
    )
    .await;
    assert_eq!(response.status(), 429, "byte rate before shared budget");
    fx.clock.set(8_000_000_000);
    let response = through(
        &service,
        request(Method::PUT, ROOT, Some(DA), Frames::one(vec![0])),
    )
    .await;
    assert_eq!(response.status(), 503, "shared budget is the final bound");
    let response = through(
        &service,
        request(Method::PUT, HINT, Some(DA), Frames::one(vec![0; 21])),
    )
    .await;
    assert_eq!(
        response.status(),
        400,
        "hint keeps its body-bound exception"
    );
}

#[tokio::test]
async fn admission_refusal_keeps_only_known_empty_bodies_reusable() {
    let fx = Fx::new("controls-refusal-reuse");
    revoke(&fx.dir, OPTS, DA).unwrap();
    for declared_len in [Some(0), Some(10), None] {
        let response = through(
            &fx.service,
            request(Method::PUT, ROOT, Some(DA), NeverPolled(declared_len)),
        )
        .await;
        assert_eq!(response.status(), 403);
        assert_eq!(token(&response).as_deref(), Some("not-enrolled"));
        assert_eq!(
            field(&response, &CONNECTION).as_deref(),
            if declared_len == Some(0) {
                None
            } else {
                Some("close")
            },
            "declared length {declared_len:?}"
        );
    }
}

struct NeverPolled(Option<u64>);
impl Body for NeverPolled {
    type Data = Bytes;
    type Error = Infallible;
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.0.map_or_else(
            hyper::body::SizeHint::default,
            hyper::body::SizeHint::with_exact,
        )
    }
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        panic!("an early refusal must not poll content")
    }
}

struct Frames(std::collections::VecDeque<Bytes>);
impl Frames {
    fn one(body: Vec<u8>) -> Self {
        Self([Bytes::from(body)].into())
    }
}
impl Body for Frames {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.0.pop_front().map(|bytes| Ok(Frame::data(bytes))))
    }
}

struct FramesWithoutTail<'a>(Frames, &'a mut usize);
impl Body for FramesWithoutTail<'_> {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        *self.1 += 1;
        let frame = Pin::new(&mut self.0).poll_frame(cx);
        assert!(
            matches!(frame, Poll::Ready(Some(_))),
            "an oversized intent body must stop at the frame that crosses the limit"
        );
        frame
    }
}

#[tokio::test]
async fn intent_release_and_ownership_stop_at_their_own_body_limits() {
    for (operation, limit) in [("release", 58), ("ownership", 94)] {
        let fx = Fx::new("intent-body-limits");
        let target = format!("/volume/v/intent/{operation}");
        let at_limit = through(
            &fx.service,
            request(Method::POST, &target, Some(DA), Frames::one(vec![0; limit])),
        )
        .await;
        // With no authority handle, this response witnesses that body
        // acceptance finished and the request reached dispatch.
        assert_eq!(
            (at_limit.status().as_u16(), token(&at_limit).as_deref()),
            (404, Some("unknown-target")),
            "{operation} at the limit"
        );

        let above = u64::try_from(limit + 1).unwrap();
        let declared = through(
            &fx.service,
            request(Method::POST, &target, Some(DA), NeverPolled(Some(above))),
        )
        .await;
        assert_eq!(
            (declared.status().as_u16(), token(&declared).as_deref()),
            (413, Some("too-large")),
            "{operation} with a declared length one above the limit"
        );

        let mut polls = 0;
        let frames = Frames([Bytes::from(vec![0; limit]), Bytes::from_static(&[0])].into());
        let streamed = through(
            &fx.service,
            request(
                Method::POST,
                &target,
                Some(DA),
                FramesWithoutTail(frames, &mut polls),
            ),
        )
        .await;
        assert_eq!(
            (
                streamed.status().as_u16(),
                token(&streamed).as_deref(),
                polls
            ),
            (413, Some("too-large"), 2),
            "{operation} with a streamed length one above the limit"
        );
    }
}

#[tokio::test]
async fn refusals_and_resets_never_refund_rates() {
    let fx = Fx::new("controls-no-refunds");
    for _ in 0..5 {
        drop(fx.controls.admit(A, true).unwrap());
    }
    assert!(
        fx.controls.admit(A, true).is_err(),
        "submissions remain spent on a subsequent refusal"
    );
    for kind in ["reset", "bound", "store", "shared"] {
        fx.clock.set(match kind {
            "reset" => 0,
            "bound" => 8_000_000_000,
            "store" => 16_000_000_000,
            _ => 24_000_000_000,
        });
        let permit = fx.controls.admit(A, false).unwrap();
        permit.charge_bytes(BIN_MAX_BYTES - 21).unwrap();
        drop(permit);
        let mut service = fx.service.clone();
        let response = match kind {
            "reset" => {
                through(
                    &service,
                    request(Method::PUT, ROOT, Some(DA), BrokenAfter::new(vec![0; 21])),
                )
                .await
            }
            "bound" => {
                through(
                    &service,
                    request(Method::PUT, HINT, Some(DA), Frames::one(vec![0; 22])),
                )
                .await
            }
            "store" => {
                through(
                    &service,
                    request(Method::PUT, HINT, Some(DA), Frames::one(vec![0; 20])),
                )
                .await
            }
            _ => {
                service.write_budget = Arc::new(WriteBudget::new(0));
                through(
                    &service,
                    request(Method::PUT, ROOT, Some(DA), Frames::one(vec![0; 21])),
                )
                .await
            }
        };
        assert_eq!(
            response.status().as_u16(),
            if kind == "shared" { 503 } else { 400 },
            "{kind}"
        );
        let permit = fx.controls.admit(A, false).unwrap();
        assert!(
            permit
                .charge_bytes(if kind == "store" { 2 } else { 1 })
                .is_err(),
            "{kind}: received bytes must remain spent, including the refusing frame"
        );
    }
}

#[tokio::test]
async fn eviction_requires_fresh_state() {
    let fx = Fx::new("controls-replacement");
    fx.controls
        .admit(A, false)
        .unwrap()
        .charge_bytes(BIN_MAX_BYTES)
        .unwrap();
    let set = fx.dir.join("ENROLLMENT");
    let saved = fx.dir.join("saved");
    std::fs::rename(&set, &saved).unwrap();
    mint(
        &fx.dir,
        OPTS,
        &TenantName::parse("replacement").unwrap(),
        DB,
        &mut Door(2),
    )
    .unwrap();
    let response = through(&fx.service, request(Method::PUT, ROOT, Some(DA), empty())).await;
    assert_eq!(token(&response).as_deref(), Some("not-enrolled"));
    assert_eq!(
        fx.controls.state_count(),
        1,
        "removing a record must preserve its debt"
    );
    std::fs::rename(&saved, &set).unwrap();
    let response = through(
        &fx.service,
        request(Method::PUT, ROOT, Some(DA2), Frames::one(vec![0])),
    )
    .await;
    assert_eq!(
        response.status(),
        429,
        "restoring a removed principal before refill must meet its debt"
    );
    revoke(&fx.dir, OPTS, DA).unwrap();
    attach(&fx.dir, OPTS, A, DA).unwrap();
    assert_eq!(
        through(
            &fx.service,
            request(Method::PUT, ROOT, Some(DA), Frames::one(vec![0]))
        )
        .await
        .status(),
        429,
        "revocation and reattachment never forgive debt"
    );
    std::fs::rename(&set, &saved).unwrap();
    mint(
        &fx.dir,
        OPTS,
        &TenantName::parse("replacement").unwrap(),
        DB,
        &mut Door(2),
    )
    .unwrap();
    fx.clock.set(8_000_000_000);
    let response = through(&fx.service, request(Method::PUT, ROOT, Some(DB), empty())).await;
    assert_eq!(response.status(), 201);
    assert_eq!(
        fx.controls.state_count(),
        1,
        "one insertion after full refill sweeps removed state"
    );
}

#[test]
fn retry_after_is_429_only() {
    for (name, outcome, status, _) in outcome_rows() {
        let response = render(outcome, Drain::Drained);
        if status == 429 {
            assert!(
                field(&response, &RETRY_AFTER)
                    .unwrap()
                    .parse::<u32>()
                    .unwrap()
                    > 0,
                "{name}"
            );
        } else {
            assert_eq!(
                field(&response, &RETRY_AFTER),
                None,
                "{name}: Retry-After is 429 only"
            );
        }
    }
    let controls =
        PrincipalControls::new(ControlsConfig::default(), Arc::new(TestClock::default()));
    let permits: Vec<_> = (0..4).map(|_| controls.admit(A, true).unwrap()).collect();
    assert_eq!(controls.admit(A, true).unwrap_err().retry_after, 1);
    drop(permits);
    drop(controls.admit(A, true).unwrap());
    assert_eq!(controls.admit(A, true).unwrap_err().retry_after, 1);
    assert_eq!(
        controls
            .admit(A, false)
            .unwrap()
            .charge_bytes(BIN_MAX_BYTES + 1)
            .unwrap_err()
            .retry_after,
        8
    );
}

struct ParkedBody(Arc<AtomicBool>);
impl Body for ParkedBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        self.0.store(true, Ordering::SeqCst);
        Poll::Pending
    }
}

#[derive(Default)]
struct PanickingStore(FakeSeam);
impl RootStore for PanickingStore {
    async fn put_root(&self, _: &str, _: u64, _: Vec<u8>) -> Result<(), RootStoreError> {
        panic!("injected handler unwind")
    }
    async fn get_root(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.0.get_root(v, n).await
    }
    async fn read_hint(&self, v: &str, t: Option<&HintToken>) -> Result<HintRead, RootStoreError> {
        self.0.read_hint(v, t).await
    }
    async fn write_hint(&self, v: &str, n: u64) -> Result<(), RootStoreError> {
        self.0.write_hint(v, n).await
    }
    async fn max_seq(&self, v: &str) -> Result<Option<u64>, RootStoreError> {
        self.0.max_seq(v).await
    }

    async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.0.max_seq_above(v, floor).await
    }
}
impl BinStore for PanickingStore {
    async fn put_meta(&self, v: &str, id: &GrainId, b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.0.put_meta(v, id, b).await
    }
    async fn get_meta(&self, v: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.0.get_meta(v, id).await
    }
    async fn put_bin(&self, d: &[u8; 32], b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.0.put_bin(d, b).await
    }
    async fn get_bin_range(&self, d: &[u8; 32], o: u64, n: u32) -> Result<Vec<u8>, RootStoreError> {
        self.0.get_bin_range(d, o, n).await
    }
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one table checks exact release and replacement for every cancellation boundary"
)]
async fn write_permit_drops_on_every_exit() {
    let fx = Fx::new("controls-permit-exits");
    // Hold the other three slots so every exit must release exactly one.
    let held: Vec<_> = (0..3)
        .map(|_| fx.controls.admit(A, false).unwrap())
        .collect();
    for kind in [
        "completion",
        "reset",
        "mid-body",
        "timeout",
        "dropped-future",
        "unwind",
    ] {
        match kind {
            "completion" => {
                assert_eq!(
                    through(&fx.service, request(Method::PUT, ROOT, Some(DA), empty()))
                        .await
                        .status(),
                    201
                );
            }
            "reset" => {
                assert_eq!(
                    through(
                        &fx.service,
                        request(Method::PUT, ROOT, Some(DA), BrokenAfter::new(vec![0]))
                    )
                    .await
                    .status(),
                    400
                );
            }
            "mid-body" => {
                assert_eq!(
                    through(
                        &fx.service,
                        request(Method::PUT, HINT, Some(DA), Frames::one(vec![0; 21]))
                    )
                    .await
                    .status(),
                    400
                );
            }
            "timeout" => {
                assert_eq!(
                    through(
                        &fx.service,
                        request(
                            Method::PUT,
                            ROOT,
                            Some(DA),
                            ParkedBody(Arc::new(AtomicBool::new(false)))
                        )
                    )
                    .await
                    .status(),
                    503
                );
            }
            "dropped-future" => {
                let seen = Arc::new(AtomicBool::new(false));
                let mut future = Box::pin(through(
                    &fx.service,
                    request(Method::PUT, ROOT, Some(DA), ParkedBody(seen.clone())),
                ));
                std::future::poll_fn(|cx| {
                    assert!(future.as_mut().poll(cx).is_pending());
                    if seen.load(Ordering::SeqCst) {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                assert_eq!(fx.controls.in_flight(A), 4);
                assert!(fx.controls.admit(A, false).is_err());
                drop(future);
            }
            _ => {
                let service =
                    GrainService::new(Arc::new(PanickingStore::default()), "", TEST_WORKER_THREADS)
                        .with_test_write_controls(fx.reader.clone(), fx.controls.clone());
                let task = crate::loopback::spawn(async move {
                    through(&service, request(Method::PUT, ROOT, Some(DA), empty())).await
                });
                assert!(task.await.unwrap_err().is_panic());
            }
        }
        assert_eq!(
            fx.controls.in_flight(A),
            3,
            "{kind}: release exactly the request's one slot"
        );
        let replacement = fx
            .controls
            .admit(A, false)
            .expect("the released slot admits a replacement");
        assert!(fx.controls.admit(A, false).is_err(), "no double release");
        drop(replacement);
    }
    drop(held);
    assert_eq!(fx.controls.in_flight(A), 0);
}

// Raw zstd blocks make the fixture's exact wire size independent of the
// compressor's version. Every grain still decompresses and hashes normally.
fn raw_frame(len: usize, byte: u8) -> granary_core::binfmt::PackedFrame {
    let payload = vec![byte; len];
    let mut frame = granary_core::binfmt::encode_frame_header(u32::try_from(len).unwrap())
        .unwrap()
        .to_vec();
    frame.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0xa0]);
    frame.extend_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
    let count = payload.chunks(128 * 1024).len();
    for (i, chunk) in payload.chunks(128 * 1024).enumerate() {
        let header = (u32::try_from(chunk.len()).unwrap() << 3) | u32::from(i + 1 == count);
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.extend_from_slice(chunk);
    }
    granary_core::binfmt::PackedFrame {
        id: GrainId::of(&payload),
        frame,
    }
}

#[tokio::test]
async fn full_allowance_accepts_maximum_body() {
    use granary_core::binfmt::{BIN_FIXED_HEADER_LEN, BIN_INDEX_ENTRY_LEN, encode_bin};
    let fx = Fx::new("controls-max-body");
    let mut frames: Vec<_> = (1..32).map(|n| raw_frame(8 * 1024 * 1024, n)).collect();
    let last_len = usize::try_from(BIN_MAX_BYTES).unwrap()
        - BIN_FIXED_HEADER_LEN
        - 32 * BIN_INDEX_ENTRY_LEN
        - frames.iter().map(|f| f.frame.len()).sum::<usize>()
        - 210;
    frames.push(raw_frame(last_len, 32));
    let bin = encode_bin(&frames).unwrap();
    drop(frames);
    assert_eq!(bin.len() as u64, BIN_MAX_BYTES);
    granary_store::verify::verify_bin(&bin, crate::admission::INGEST_UNPACKED_SUM_MAX).unwrap();
    let target = format!("/bin/{}", GrainId::of(&bin).digest_hex());
    let bin = Bytes::from(bin);
    for frame_size in [bin.len(), 65537] {
        // A fresh principal allowance with the clock frozen, every time.
        let controls = Arc::new(PrincipalControls::new(
            ControlsConfig::default(),
            fx.clock.clone(),
        ));
        let service = GrainService::new(Arc::new(FakeSeam::default()), "", TEST_WORKER_THREADS)
            .with_test_write_controls(fx.reader.clone(), controls.clone());
        let chunks = (0..bin.len())
            .step_by(frame_size)
            .map(|start| bin.slice(start..(start + frame_size).min(bin.len())))
            .collect();
        let response = through(
            &service,
            request(Method::PUT, &target, Some(DA), Frames(chunks)),
        )
        .await;
        assert_eq!(
            response.status(),
            201,
            "a valid maximum body completes from full allowance"
        );
        assert_eq!(service.store.objects(), 1);
        assert!(
            controls.admit(A, false).unwrap().charge_bytes(1).is_err(),
            "frame partitioning charges exactly the body"
        );
    }
}

mod cold_resolve;

#[derive(Debug, Clone, Copy)]
enum ExhaustedAllowance {
    Submission,
    Bytes,
    Cap,
}

// A provisioned authority runs beside the HTTP adapter; GET must never reach
// principal accounting, even when only one allowance is unavailable.
#[expect(
    clippy::disallowed_methods,
    reason = "JoinSet owns the real authority driver for the HTTP control"
)]
#[expect(
    clippy::too_many_lines,
    reason = "One provisioned HTTP fixture observes independent allowances and persistence"
)]
async fn readback_independence(exhausted: ExhaustedAllowance) {
    use crate::authority::intent::tests as fixture;
    use crate::authority::tests::intents as venue;
    let path = venue::scratch();
    let rec = venue::recording(&path);
    let (handle, driver) = venue::start(rec.clone(), 1).await;
    let mut fx = Fx::new("readback");
    Arc::get_mut(fx.service.authority.as_mut().unwrap())
        .unwrap()
        .handle = Some(handle.clone());
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(driver);
    assert_eq!(
        venue::initialise_and_enroll(&handle)
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        handle
            .intent(
                &fixture::volume(),
                A,
                crate::authority::IntentOperation::Ownership,
                fixture::acquire(1, 2, 0)
            )
            .await
            .status()
            .as_u16(),
        200
    );
    let mut held = Vec::new();
    match exhausted {
        ExhaustedAllowance::Submission => {
            for _ in 0..5 {
                drop(fx.controls.admit(A, true).unwrap());
            }
        }
        ExhaustedAllowance::Bytes => {
            let permit = fx.controls.admit(A, false).unwrap();
            permit.charge_bytes(256 * 1024 * 1024).unwrap();
        }
        ExhaustedAllowance::Cap => held = fx.fill_cap(),
    }
    let before = fx.controls.accounting(A).unwrap();
    match exhausted {
        ExhaustedAllowance::Submission => {
            assert_eq!(before, (0, 256 * 1024 * 1024 * 1_000_000_000, 0));
        }
        ExhaustedAllowance::Bytes => assert_eq!(before, (5 * 1_000_000_000, 0, 0)),
        ExhaustedAllowance::Cap => assert_eq!(
            before,
            (5 * 1_000_000_000, 256 * 1024 * 1024 * 1_000_000_000, 4)
        ),
    }
    let durable = std::fs::read(path.join("intent-test.intent")).unwrap();
    rec.clear();
    for identity in [DA, DB] {
        let response = through(
            &fx.service,
            request(
                Method::GET,
                "/volume/intent-test/intent",
                Some(identity),
                empty(),
            ),
        )
        .await;
        assert_eq!(
            response.status().as_u16(),
            200,
            "GET independent of {exhausted:?}"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(response.headers().get("retry-after").is_none());
        assert!(response.headers().get("granary-error").is_none());
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), 20, "bounded empty readback");
        let read =
            granary_core::intent::decode_readback(&bytes, &fixture::volume(), |doc, signed| {
                granary_store::crypto::check_signatures(doc, signed, &fixture::keys()).is_ok()
            })
            .unwrap();
        assert_eq!(
            (read.cursor, read.rows.len()),
            (u64::from(identity == DA), 0),
            "principal scope"
        );
        assert_eq!(
            fx.controls.accounting(A),
            Some(before),
            "GET leaves all principal accounting unchanged"
        );
        assert_eq!(
            fx.controls.accounting(B),
            None,
            "GET does not create accounting state"
        );
        drop(bytes);
        assert_eq!(fx.service.read_budget.in_flight(), 0);
    }
    assert!(
        rec.calls().is_empty(),
        "readback performs no persistence I/O"
    );
    assert_eq!(
        std::fs::read(path.join("intent-test.intent")).unwrap(),
        durable
    );
    drop(held);
    let stopped = handle.stop().await;
    assert_eq!(tasks.join_next().await.unwrap().unwrap(), stopped);
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn readback_independent_of_submission_allowance() {
    readback_independence(ExhaustedAllowance::Submission).await;
}
#[tokio::test]
async fn readback_independent_of_byte_allowance() {
    readback_independence(ExhaustedAllowance::Bytes).await;
}
#[tokio::test]
async fn readback_independent_of_principal_cap() {
    readback_independence(ExhaustedAllowance::Cap).await;
}

#[tokio::test]
async fn readback_authentication_refusals_precede_controls() {
    let fx = Fx::new("readback-auth");
    let _held = fx.fill_cap();
    for (identity, status, token) in [
        (None, 403, "no-principal"),
        (
            Some(ClientSpkiDigest::from_bytes([9; 32])),
            403,
            "not-enrolled",
        ),
    ] {
        let response = through(
            &fx.service,
            request(Method::GET, "/volume/v/intent", identity, empty()),
        )
        .await;
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["granary-error"], token);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(response.headers().get("retry-after").is_none());
    }
    std::fs::write(
        fx.dir.join(crate::enrollment::SET_NAME),
        b"corrupt synthetic enrollment",
    )
    .unwrap();
    let response = through(
        &fx.service,
        request(Method::GET, "/volume/v/intent", Some(DA), empty()),
    )
    .await;
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(
        response.headers()["granary-error"],
        "enrollment-unavailable"
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(response.headers().get("retry-after").is_none());
    assert_eq!(fx.controls.in_flight(A), 4);
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "JoinSets own the authority and twelve HTTP flood clients"
)]
#[expect(
    clippy::too_many_lines,
    reason = "One composed flood schedule observes admission, principal scope and mutation accounting"
)]
async fn http_get_flood_allows_mutation_completion_while_active() {
    use crate::authority::intent::tests as fixture;
    use crate::authority::tests::intents as venue;
    use std::sync::atomic::{AtomicUsize, Ordering};
    // Allow each phase ample time under CI CPU saturation.
    const FLOOD_PHASE_TIMEOUT: Duration = Duration::from_mins(1);
    let path = venue::scratch();
    let (handle, driver) = venue::start(venue::recording(&path), 1).await;
    let mut fx = Fx::new("get-flood");
    Arc::get_mut(fx.service.authority.as_mut().unwrap())
        .unwrap()
        .handle = Some(handle.clone());
    let mut authority = tokio::task::JoinSet::new();
    authority.spawn(driver);
    assert_eq!(
        venue::initialise_and_enroll(&handle)
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        handle
            .intent(
                &fixture::volume(),
                A,
                crate::authority::IntentOperation::Ownership,
                fixture::acquire(1, 2, 0)
            )
            .await
            .status()
            .as_u16(),
        200
    );
    let (stop, _) = tokio::sync::watch::channel(false);
    let completed = Arc::new(AtomicUsize::new(0));
    let mut clients = tokio::task::JoinSet::new();
    for n in 0..12 {
        let service = fx.service.clone();
        let stop = stop.subscribe();
        let completed = completed.clone();
        clients.spawn(async move {
            let identity = if n % 2 == 0 { DA } else { DB };
            while !*stop.borrow() {
                let response = through(
                    &service,
                    request(
                        Method::GET,
                        "/volume/intent-test/intent",
                        Some(identity),
                        empty(),
                    ),
                )
                .await;
                assert_eq!(
                    response.status().as_u16(),
                    200,
                    "healthy shared read resources under declared load"
                );
                assert_eq!(response.headers()["cache-control"], "no-store");
                assert!(response.headers().get("retry-after").is_none());
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(bytes.len(), 20);
                let read = granary_core::intent::decode_readback(
                    &bytes,
                    &fixture::volume(),
                    |doc, signed| {
                        granary_store::crypto::check_signatures(doc, signed, &fixture::keys())
                            .is_ok()
                    },
                )
                .unwrap();
                assert!(read.rows.is_empty());
                if identity == DB {
                    assert_eq!(read.cursor, 0, "B never sees A's cursor");
                } else {
                    assert!([1, 2].contains(&read.cursor));
                }
                completed.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
            }
        });
    }
    tokio::time::timeout(FLOOD_PHASE_TIMEOUT, async {
        while completed.load(Ordering::SeqCst) < 24 {
            if let Some(result) = clients.try_join_next() {
                result.unwrap();
                panic!("flood client exited before stop");
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("flood must complete real HTTP GETs before the mutation");
    assert_eq!(
        fx.controls.accounting(A),
        None,
        "active flood does not charge a principal"
    );
    let body = fixture::acquire(2, 3, 1);
    let body_len = body.len() as u128;
    let response = tokio::time::timeout(
        FLOOD_PHASE_TIMEOUT,
        through(
            &fx.service,
            request(
                Method::POST,
                "/volume/intent-test/intent/ownership",
                Some(DA),
                Full::new(Bytes::from(body)),
            ),
        ),
    )
    .await
    .expect("mutation must finish while GET flood is active");
    assert_eq!(response.status().as_u16(), 200);
    let grant = granary_core::intent::decode_grant(
        &response.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    assert_eq!(grant.receipt.epoch, 2);
    assert!(
        !*stop.borrow(),
        "mutation completed before flood was stopped"
    );
    let after = completed.load(Ordering::SeqCst);
    tokio::time::timeout(FLOOD_PHASE_TIMEOUT, async {
        while completed.load(Ordering::SeqCst) < after + 24 {
            if let Some(result) = clients.try_join_next() {
                result.unwrap();
                panic!("flood client exited before stop");
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("flood must remain productive after the mutation completes");
    assert_eq!(
        fx.controls.accounting(A),
        Some((
            4 * 1_000_000_000,
            (256 * 1024 * 1024 - body_len) * 1_000_000_000,
            0
        )),
        "mutation spends exactly one token and its body bytes"
    );
    assert_eq!(fx.controls.accounting(B), None);
    assert_eq!(clients.len(), 12, "all flood clients are still active");
    stop.send(true).unwrap();
    while let Some(result) = clients.join_next().await {
        result.unwrap();
    }
    assert_eq!(fx.service.read_permits.available_permits(), 8);
    assert_eq!(fx.service.read_budget.in_flight(), 0);
    let stopped = handle.stop().await;
    assert_eq!(authority.join_next().await.unwrap().unwrap(), stopped);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "The grammar table enumerates valid and malformed identifier boundaries"
)]
fn request_id_grammar_table_pairs_valid_and_malformed_boundaries() {
    let max_valid = "a".repeat(64);
    let over_max = "a".repeat(65);

    let pairs: Vec<(RequestIdShape, String, RequestIdShape)> = vec![
        (
            RequestIdShape::Single(b"a"),
            "a".to_owned(),
            RequestIdShape::Single(b""),
        ),
        (
            RequestIdShape::Owned(max_valid.clone().into_bytes()),
            max_valid,
            RequestIdShape::Owned(over_max.into_bytes()),
        ),
        (
            RequestIdShape::Single(b"a"),
            "a".to_owned(),
            RequestIdShape::Repeated(b"a", b"a"),
        ),
        (
            RequestIdShape::Single(b"a"),
            "a".to_owned(),
            RequestIdShape::Repeated(b"a", b"b"),
        ),
        (
            RequestIdShape::Single(b"0"),
            "0".to_owned(),
            RequestIdShape::Single(b"/"),
        ),
        (
            RequestIdShape::Single(b"9"),
            "9".to_owned(),
            RequestIdShape::Single(b":"),
        ),
        (
            RequestIdShape::Single(b"A"),
            "A".to_owned(),
            RequestIdShape::Single(b"@"),
        ),
        (
            RequestIdShape::Single(b"Z"),
            "Z".to_owned(),
            RequestIdShape::Single(b"["),
        ),
        (
            RequestIdShape::Single(b"a"),
            "a".to_owned(),
            RequestIdShape::Single(b"`"),
        ),
        (
            RequestIdShape::Single(b"z"),
            "z".to_owned(),
            RequestIdShape::Single(b"{"),
        ),
        (
            RequestIdShape::Single(b"_"),
            "_".to_owned(),
            RequestIdShape::Single(b"^"),
        ),
        (
            RequestIdShape::Single(b"_"),
            "_".to_owned(),
            RequestIdShape::Single(b"`"),
        ),
        (
            RequestIdShape::Single(b"."),
            ".".to_owned(),
            RequestIdShape::Single(b"/"),
        ),
        (
            RequestIdShape::Single(b"-"),
            "-".to_owned(),
            RequestIdShape::Single(b","),
        ),
        (
            RequestIdShape::Single(b"a"),
            "a".to_owned(),
            RequestIdShape::Single(b"a b"),
        ),
        (
            RequestIdShape::Single(b"a"),
            "a".to_owned(),
            RequestIdShape::Single(b"a+b"),
        ),
        (
            RequestIdShape::Single(b"a"),
            "a".to_owned(),
            RequestIdShape::Single(b"a~b"),
        ),
        (
            RequestIdShape::Single(b"a"),
            "a".to_owned(),
            RequestIdShape::Single(b"a\tb"),
        ),
        (
            RequestIdShape::Single(b"a"),
            "a".to_owned(),
            RequestIdShape::Single(b"a\x80"),
        ),
        (
            RequestIdShape::Single(b"a"),
            "a".to_owned(),
            RequestIdShape::Single(b"a\xff"),
        ),
    ];

    let mut pair_count = 0;
    let mut case_count = 0;

    for (valid_entry, expected_str, malformed_entry) in &pairs {
        let valid_headers = valid_entry.to_headers();
        let malformed_headers = malformed_entry.to_headers();

        let valid_observed = super::super::request_id_field(&valid_headers);
        let malformed_observed = super::super::request_id_field(&malformed_headers);

        assert_eq!(
            (valid_observed, malformed_observed),
            (Some(expected_str.as_str()), None),
            "pair assertion failed for expected {expected_str}"
        );

        pair_count += 1;
        case_count += 2;
    }

    assert_eq!((pair_count, case_count), (20, 40));
}

pub(super) struct AuthorityVenue {
    pub(super) path: PathBuf,
    pub(super) handle: Option<crate::authority::AuthorityHandle>,
    pub(super) driving: Option<tokio::task::JoinHandle<crate::authority::RunEnd>>,
    pub(super) fx: Fx,
    pub(super) epoch_hex: String,
}

impl AuthorityVenue {
    #[expect(
        clippy::disallowed_methods,
        reason = "An independent driver services the composed HTTP mailbox against the real filesystem"
    )]
    pub(super) async fn new(tag: &str) -> Self {
        use crate::authority::intent::tests as fixture;
        use crate::authority::tests::intents as venue;
        use tracing::instrument::WithSubscriber as _;

        let path = venue::scratch();
        let (handle, driver) = venue::start(venue::recording(&path), 1).await;
        let mut fx = Fx::new(tag);
        Arc::get_mut(fx.service.authority.as_mut().unwrap())
            .unwrap()
            .handle = Some(handle.clone());
        let driving = tokio::spawn(driver.with_current_subscriber());

        assert_eq!(
            venue::initialise_and_enroll(&handle)
                .await
                .status()
                .as_u16(),
            200
        );

        let epoch = match handle.initialise(&fixture::volume()).await.unwrap() {
            crate::authority::Initialised::Created { epoch }
            | crate::authority::Initialised::Kept { epoch } => epoch,
        };
        let mut epoch_hex = String::with_capacity(64);
        for b in epoch.to_bytes() {
            use std::fmt::Write as _;
            let _ = write!(&mut epoch_hex, "{b:02x}");
        }

        Self {
            path,
            handle: Some(handle),
            driving: Some(driving),
            fx,
            epoch_hex,
        }
    }

    pub(super) async fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            let stopped = handle.stop().await;
            if let Some(driving) = self.driving.take() {
                assert_eq!(driving.await.unwrap(), stopped);
            }
        }
        if self.path.exists() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

impl Drop for AuthorityVenue {
    fn drop(&mut self) {
        if let Some(driving) = self.driving.take() {
            driving.abort();
        }
        if self.path.exists() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

async fn response_tuple_controls(response: Response<Full<Bytes>>) -> ResponseTuple {
    use http_body_util::BodyExt;
    let status = response.status().as_u16();
    let token = response
        .headers()
        .get("granary-error")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let cache_control = response
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let allow = response
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let content_range = response
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        token,
        content_type,
        cache_control,
        allow,
        etag,
        content_range,
        body,
    )
}

async fn run_publish(shape: Option<&RequestIdShape>) -> ResponseTuple {
    use crate::authority::intent::tests as fixture;

    let venue = AuthorityVenue::new("authority-publish-shape").await;
    let publish_target = format!("/volume/{}/publish", fixture::volume().as_str());
    let candidate = fixture::root(1, &fixture::volume());

    let mut req = request(
        Method::POST,
        &publish_target,
        Some(DA),
        Full::new(Bytes::from(candidate)),
    );
    req.headers_mut()
        .insert("granary-operation", HeaderValue::from_static("01"));
    req.headers_mut().insert(
        "granary-epoch",
        HeaderValue::from_str(&venue.epoch_hex).unwrap(),
    );
    if let Some(s) = shape {
        s.apply_headers(req.headers_mut());
    }
    let res = through(&venue.fx.service, req).await;
    let tuple = response_tuple_controls(res).await;
    venue.stop().await;
    tuple
}

async fn run_intent(shape: Option<&RequestIdShape>) -> ResponseTuple {
    use crate::authority::intent::tests as fixture;

    let venue = AuthorityVenue::new("authority-intent-shape").await;
    let target = format!("/volume/{}/intent/ownership", fixture::volume().as_str());
    let candidate = fixture::acquire(1, 2, 0);

    let mut req = request(
        Method::POST,
        &target,
        Some(DA),
        Full::new(Bytes::from(candidate)),
    );
    if let Some(s) = shape {
        s.apply_headers(req.headers_mut());
    }
    let res = through(&venue.fx.service, req).await;
    let tuple = response_tuple_controls(res).await;
    venue.stop().await;
    tuple
}

#[tokio::test]
async fn request_id_shapes_preserve_authority_endpoints_and_refusals() {
    use crate::authority::intent::tests as fixture;

    let shapes = request_id_shapes();
    let mut total_cases = 0;

    let control_publish = run_publish(None).await;
    assert_eq!(control_publish.0, 202);
    for shape in &shapes {
        let test_publish = run_publish(Some(shape)).await;
        assert_eq!(
            test_publish, control_publish,
            "mismatch on request 0 (POST publish 202)"
        );
        total_cases += 1;
    }

    let control_intent = run_intent(None).await;
    assert_eq!(control_intent.0, 200);
    for shape in &shapes {
        let test_intent = run_intent(Some(shape)).await;
        assert_eq!(
            test_intent, control_intent,
            "mismatch on request 3 (POST intent 200)"
        );
        total_cases += 1;
    }

    let venue = AuthorityVenue::new("authority-request-id-shared").await;
    let publish_target = format!("/volume/{}/publish", fixture::volume().as_str());
    let candidate = fixture::root(1, &fixture::volume());

    for req_idx in [1, 2, 4] {
        let build_req = |shape: Option<&RequestIdShape>| -> Request<Full<Bytes>> {
            let mut req = match req_idx {
                1 => {
                    let mut r = request(
                        Method::POST,
                        &publish_target,
                        Some(DA),
                        Full::new(Bytes::from(candidate.clone())),
                    );
                    r.headers_mut().insert(
                        "granary-epoch",
                        HeaderValue::from_str(&venue.epoch_hex).unwrap(),
                    );
                    r
                }
                2 => {
                    let mut r = request(
                        Method::POST,
                        &publish_target,
                        None,
                        Full::new(Bytes::from(candidate.clone())),
                    );
                    r.headers_mut()
                        .insert("granary-operation", HeaderValue::from_static("01"));
                    r.headers_mut().insert(
                        "granary-epoch",
                        HeaderValue::from_str(&venue.epoch_hex).unwrap(),
                    );
                    r
                }
                4 => request(
                    Method::GET,
                    &format!("/volume/{}/status", fixture::volume().as_str()),
                    Some(DA),
                    empty(),
                ),
                _ => unreachable!(),
            };
            if let Some(s) = shape {
                s.apply_headers(req.headers_mut());
            }
            req
        };

        venue.fx.clock.set(i128::from(req_idx) * 10_000_000_000);
        let control_send = build_req(None);
        let control_reply = through(&venue.fx.service, control_send).await;
        let control_tuple = response_tuple_controls(control_reply).await;

        let expected_status = match req_idx {
            1 => 400,
            2 => 403,
            4 => 200,
            _ => unreachable!(),
        };
        assert_eq!(control_tuple.0, expected_status);

        for (shape_idx, shape) in shapes.iter().enumerate() {
            let clock_tick = i128::from(req_idx) * 10_000_000_000
                + (i128::try_from(shape_idx).unwrap() + 1) * 1_000_000_000;
            venue.fx.clock.set(clock_tick);

            let test_send = build_req(Some(shape));
            let test_reply = through(&venue.fx.service, test_send).await;
            let test_tuple = response_tuple_controls(test_reply).await;

            assert_eq!(
                test_tuple, control_tuple,
                "mismatch on request {req_idx}, shape {shape_idx}"
            );
            total_cases += 1;
        }
    }

    assert_eq!(total_cases, 55);
    venue.stop().await;
}

#[tokio::test]
async fn request_id_shapes_preserve_intent_retry_after() {
    use crate::authority::intent::tests as fixture;

    let venue = AuthorityVenue::new("intent-retry-after-request-id").await;
    let target = format!("/volume/{}/intent/ownership", fixture::volume().as_str());
    let body = Bytes::from(fixture::acquire(1, 2, 0));
    let build_request = |shape: Option<&RequestIdShape>| {
        let mut req = request(Method::POST, &target, Some(DA), Full::new(body.clone()));
        if let Some(shape) = shape {
            shape.apply_headers(req.headers_mut());
        }
        req
    };

    let permits = venue.fx.fill_cap();
    let baseline = through(&venue.fx.service, build_request(None)).await;
    assert_eq!(field(&baseline, &RETRY_AFTER).as_deref(), Some("1"));
    let baseline = response_tuple_controls(baseline).await;
    assert_eq!(baseline.0, 429);
    assert_eq!(baseline.1.as_deref(), Some("rate-limited"));
    assert_eq!(baseline.3.as_deref(), Some("no-store"));

    for (index, shape) in request_id_shapes().iter().enumerate() {
        let response = through(&venue.fx.service, build_request(Some(shape))).await;
        assert_eq!(
            field(&response, &RETRY_AFTER).as_deref(),
            Some("1"),
            "Retry-After for shape {index}"
        );
        assert_eq!(
            response_tuple_controls(response).await,
            baseline,
            "intent 429 for shape {index}"
        );
    }

    drop(permits);
    let response = through(&venue.fx.service, build_request(None)).await;
    assert_eq!(response.status(), 200);
    assert_eq!(field(&response, &RETRY_AFTER), None);
    venue.stop().await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Publish and intent deduplication independent of request id"
)]
async fn request_id_does_not_affect_publish_or_intent_deduplication() {
    use crate::authority::intent::tests as fixture;

    let venue = AuthorityVenue::new("authority-request-id-dedup").await;
    let publish_target = format!("/volume/{}/publish", fixture::volume().as_str());
    let candidate = fixture::root(1, &fixture::volume());

    let mut tick = 10_000_000_000i128;
    venue.fx.clock.set(tick);

    let mut first_publish_req = request(
        Method::POST,
        &publish_target,
        Some(DA),
        Full::new(Bytes::from(candidate.clone())),
    );
    first_publish_req
        .headers_mut()
        .insert("granary-operation", HeaderValue::from_static("0a"));
    first_publish_req.headers_mut().insert(
        "granary-epoch",
        HeaderValue::from_str(&venue.epoch_hex).unwrap(),
    );
    first_publish_req.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_static("shared-request-id"),
    );
    let first_publish_reply = through(&venue.fx.service, first_publish_req).await;
    let (first_status, _, _, _, _, _, _, first_body) =
        response_tuple_controls(first_publish_reply).await;
    assert_eq!(first_status, 202);

    tick += 10_000_000_000;
    venue.fx.clock.set(tick);

    let mut second_publish_req = request(
        Method::POST,
        &publish_target,
        Some(DA),
        Full::new(Bytes::from(candidate.clone())),
    );
    second_publish_req
        .headers_mut()
        .insert("granary-operation", HeaderValue::from_static("0b"));
    second_publish_req.headers_mut().insert(
        "granary-epoch",
        HeaderValue::from_str(&venue.epoch_hex).unwrap(),
    );
    second_publish_req.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_static("shared-request-id"),
    );
    let second_publish_reply = through(&venue.fx.service, second_publish_req).await;
    let (second_status, _, _, _, _, _, _, second_body) =
        response_tuple_controls(second_publish_reply).await;
    assert_eq!(second_status, 409);
    assert_ne!(first_status, second_status);
    assert_ne!(first_body, second_body);

    tick += 10_000_000_000;
    venue.fx.clock.set(tick);

    let mut replay_initial_req = request(
        Method::POST,
        &publish_target,
        Some(DA),
        Full::new(Bytes::from(candidate.clone())),
    );
    replay_initial_req
        .headers_mut()
        .insert("granary-operation", HeaderValue::from_static("0a"));
    replay_initial_req.headers_mut().insert(
        "granary-epoch",
        HeaderValue::from_str(&venue.epoch_hex).unwrap(),
    );
    replay_initial_req
        .headers_mut()
        .insert("granary-request-id", HeaderValue::from_static("id-one"));
    let replay_initial_reply = through(&venue.fx.service, replay_initial_req).await;
    let (status_replay_one, _, _, _, _, _, _, body_replay_one) =
        response_tuple_controls(replay_initial_reply).await;
    assert_eq!(status_replay_one, 200);

    tick += 10_000_000_000;
    venue.fx.clock.set(tick);

    let mut replay_repeat_req = request(
        Method::POST,
        &publish_target,
        Some(DA),
        Full::new(Bytes::from(candidate.clone())),
    );
    replay_repeat_req
        .headers_mut()
        .insert("granary-operation", HeaderValue::from_static("0a"));
    replay_repeat_req.headers_mut().insert(
        "granary-epoch",
        HeaderValue::from_str(&venue.epoch_hex).unwrap(),
    );
    replay_repeat_req
        .headers_mut()
        .insert("granary-request-id", HeaderValue::from_static("id-two"));
    let replay_repeat_reply = through(&venue.fx.service, replay_repeat_req).await;
    let (status_replay_two, _, _, _, _, _, _, body_replay_two) =
        response_tuple_controls(replay_repeat_reply).await;
    assert_eq!(status_replay_two, 200);
    assert_eq!(body_replay_one, body_replay_two);

    let intent_ownership = format!("/volume/{}/intent/ownership", fixture::volume().as_str());
    let acquire_payload = fixture::acquire(1, 2, 0);

    tick += 10_000_000_000;
    venue.fx.clock.set(tick);

    let mut intent_initial_req = request(
        Method::POST,
        &intent_ownership,
        Some(DA),
        Full::new(Bytes::from(acquire_payload.clone())),
    );
    intent_initial_req.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_static("intent-id-first"),
    );
    let intent_initial_reply = through(&venue.fx.service, intent_initial_req).await;
    let (status_intent_first, _, _, _, _, _, _, grant_first) =
        response_tuple_controls(intent_initial_reply).await;
    assert_eq!(status_intent_first, 200);

    tick += 10_000_000_000;
    venue.fx.clock.set(tick);

    let mut intent_repeat_req = request(
        Method::POST,
        &intent_ownership,
        Some(DA),
        Full::new(Bytes::from(acquire_payload.clone())),
    );
    intent_repeat_req.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_static("intent-id-second"),
    );
    let intent_repeat_reply = through(&venue.fx.service, intent_repeat_req).await;
    let (status_intent_second, _, _, _, _, _, _, grant_second) =
        response_tuple_controls(intent_repeat_reply).await;
    assert_eq!(status_intent_second, 200);
    assert_eq!(grant_first, grant_second);

    tick += 10_000_000_000;
    venue.fx.clock.set(tick);

    let mut diff_first_req = request(
        Method::POST,
        &intent_ownership,
        Some(DA),
        Full::new(Bytes::from(acquire_payload)),
    );
    diff_first_req.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_static("constant-id"),
    );
    let diff_first_reply = through(&venue.fx.service, diff_first_req).await;
    let (status_diff_a, _, _, _, _, _, _, grant_diff_a) =
        response_tuple_controls(diff_first_reply).await;
    assert_eq!(status_diff_a, 200);
    assert_eq!(grant_first, grant_diff_a);

    tick += 10_000_000_000;
    venue.fx.clock.set(tick);

    let mut diff_second_req = request(
        Method::POST,
        &intent_ownership,
        Some(DA),
        Full::new(Bytes::from(fixture::acquire(1, 8, 0))),
    );
    diff_second_req.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_static("constant-id"),
    );
    let diff_second_reply = through(&venue.fx.service, diff_second_req).await;
    let (status_diff_b, _, _, _, _, _, _, _) = response_tuple_controls(diff_second_reply).await;
    assert_eq!(status_diff_b, 409);
    assert_ne!(status_diff_a, status_diff_b);

    venue.stop().await;
}

#[tokio::test]
#[expect(
    clippy::similar_names,
    reason = "da_hex and db_hex correspond to principal identifiers DA and DB"
)]
async fn request_id_does_not_affect_principal_resolution_or_refusal_counters() {
    let fx = Fx::new("principal-resolution-refusal-counters");

    let mut da_hex = String::with_capacity(64);
    for b in DA.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut da_hex, "{b:02x}");
    }
    assert_eq!(da_hex.len(), 64);

    let mut anonymous_req = request(
        Method::PUT,
        ROOT,
        None,
        Full::new(Bytes::from(b"candidate-bytes".as_slice())),
    );
    anonymous_req.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_str(&da_hex).unwrap(),
    );
    let anonymous_reply = through(&fx.service, anonymous_req).await;
    assert_eq!(
        (
            anonymous_reply.status().as_u16(),
            anonymous_reply
                .headers()
                .get("granary-error")
                .and_then(|v| v.to_str().ok()),
        ),
        (403, Some("no-principal"))
    );

    assert_eq!(fx.controls.accounting(A), None);
    assert_eq!(fx.controls.accounting(B), None);

    let mut db_hex = String::with_capacity(64);
    for b in DB.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut db_hex, "{b:02x}");
    }
    assert_eq!(db_hex.len(), 64);

    let mut authenticated_req = request(
        Method::PUT,
        ROOT,
        Some(DA),
        Full::new(Bytes::from(b"candidate-bytes".as_slice())),
    );
    authenticated_req.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_str(&db_hex).unwrap(),
    );
    let authenticated_reply = through(&fx.service, authenticated_req).await;
    assert_eq!(authenticated_reply.status().as_u16(), 201);
    assert!(fx.controls.accounting(A).is_some());
    assert_eq!(fx.controls.accounting(B), None);

    for i in 0..5 {
        let mut req = request(Method::PUT, ROOT, None, empty());
        req.headers_mut().insert(
            "granary-request-id",
            HeaderValue::from_str(&format!("test-distinct-id-{i}")).unwrap(),
        );
        let _ = through(&fx.service, req).await;
    }
    let snapshot = fx.service.refusal_counters().unwrap().snapshot();
    assert_eq!(
        snapshot.totals.get(&crate::wire::ErrorToken::NoPrincipal),
        Some(&6)
    );
    assert_eq!(snapshot.totals.len(), 1);
    assert_eq!(snapshot.principals.len(), 0);
}

#[tokio::test]
async fn request_id_is_never_echoed_in_authority_responses() {
    use crate::authority::intent::tests as fixture;

    let venue = AuthorityVenue::new("authority-never-echoes-id").await;

    let mut probe_pub_send = request(
        Method::POST,
        &format!("/volume/{}/publish", fixture::volume().as_str()),
        Some(DA),
        Full::new(Bytes::from(fixture::root(1, &fixture::volume()))),
    );
    probe_pub_send
        .headers_mut()
        .insert("granary-operation", HeaderValue::from_static("01"));
    probe_pub_send.headers_mut().insert(
        "granary-epoch",
        HeaderValue::from_str(&venue.epoch_hex).unwrap(),
    );
    probe_pub_send.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_static("echo-probe-publish"),
    );
    let probe_pub_reply = through(&venue.fx.service, probe_pub_send).await;
    assert_eq!(probe_pub_reply.status().as_u16(), 202);
    assert!(
        probe_pub_reply
            .headers()
            .get("granary-request-id")
            .is_none()
    );

    let mut probe_intent_send = request(
        Method::POST,
        &format!("/volume/{}/intent/ownership", fixture::volume().as_str()),
        Some(DA),
        Full::new(Bytes::from(fixture::acquire(1, 2, 0))),
    );
    probe_intent_send.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_static("echo-probe-intent"),
    );
    let probe_intent_reply = through(&venue.fx.service, probe_intent_send).await;
    assert_eq!(probe_intent_reply.status().as_u16(), 200);
    assert!(
        probe_intent_reply
            .headers()
            .get("granary-request-id")
            .is_none()
    );

    let mut probe_status_send = request(
        Method::GET,
        &format!("/volume/{}/status", fixture::volume().as_str()),
        Some(DA),
        empty(),
    );
    probe_status_send.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_static("echo-probe-status"),
    );
    let probe_status_reply = through(&venue.fx.service, probe_status_send).await;
    assert_eq!(probe_status_reply.status().as_u16(), 200);
    assert!(
        probe_status_reply
            .headers()
            .get("granary-request-id")
            .is_none()
    );

    let mut probe_refusal_send = request(
        Method::POST,
        &format!("/volume/{}/publish", fixture::volume().as_str()),
        None,
        empty(),
    );
    probe_refusal_send.headers_mut().insert(
        "granary-request-id",
        HeaderValue::from_static("echo-probe-refusal"),
    );
    let probe_refusal_reply = through(&venue.fx.service, probe_refusal_send).await;
    assert_eq!(probe_refusal_reply.status().as_u16(), 403);
    assert!(
        probe_refusal_reply
            .headers()
            .get("granary-request-id")
            .is_none()
    );

    venue.stop().await;
}

#[tokio::test]
async fn request_id_whitespace_logged_value_on_intent_request() {
    use crate::authority::intent::tests as fixture;
    use tracing_subscriber::prelude::*;

    let request_ids = Arc::new(std::sync::Mutex::new(Vec::new()));
    let _default = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(RequestIdLayer(Arc::clone(&request_ids))),
    );

    let venue = AuthorityVenue::new("whitespace-logged-intent").await;
    let target = format!("/volume/{}/intent/ownership", fixture::volume().as_str());

    // Hyper's HTTP/1.1 wire parser strips leading and trailing OWS (RFC 9110 §5.5).
    // An HTTP/1.1 header line `granary-request-id:  a ` is delivered by hyper as `HeaderValue` "a".
    // On the intent endpoint, the server records `wire_request_id` from hyper's delivered value.
    let mut req = request(
        Method::POST,
        &target,
        Some(DA),
        Full::new(Bytes::from(fixture::acquire(1, 2, 0))),
    );
    req.headers_mut()
        .insert("granary-request-id", HeaderValue::from_static("a"));
    let reply = through(&venue.fx.service, req).await;
    assert_eq!(reply.status().as_u16(), 200);

    assert_eq!(request_ids.lock().unwrap().as_slice(), ["a"]);
    venue.stop().await;
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "An independent driver services the composed HTTP mailbox against the real filesystem"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Five endpoint operations and scoped readbacks share one fixture"
)]
async fn intent_composed_five_operations_keep_control_read_scoped_and_refusals_no_store() {
    use crate::authority::intent::tests as fixture;
    use crate::authority::tests::intents as venue;
    use granary_core::intent as wire;
    use tracing_subscriber::prelude::*;
    let request_ids = Arc::new(std::sync::Mutex::new(Vec::new()));
    let _default = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(RequestIdLayer(Arc::clone(&request_ids))),
    );
    let path = venue::scratch();
    let (handle, driver) = venue::start(venue::recording(&path), 1).await;
    let mut fx = Fx::new("intent-composed");
    Arc::get_mut(fx.service.authority.as_mut().unwrap())
        .unwrap()
        .handle = Some(handle.clone());
    let sequence = async {
        assert_eq!(
            venue::initialise_and_enroll(&handle)
                .await
                .status()
                .as_u16(),
            200
        );
        let target = "/volume/intent-test/intent";
        let owned = fixture::owned(1);
        let register = fixture::register(&owned, 1, 1, 3);
        let live = crate::authority::intent::transition(
            Some(&owned),
            crate::authority::IntentOperation::Register,
            &register,
            &fixture::volume(),
            &fixture::keys(),
            fixture::now(),
        )
        .next
        .unwrap();
        let takeover = fixture::takeover(live.rows.values().next().unwrap(), 5);
        let taken = crate::authority::intent::transition(
            Some(&live),
            crate::authority::IntentOperation::Ownership,
            &takeover,
            &fixture::volume(),
            &fixture::keys(),
            fixture::now(),
        )
        .next
        .unwrap();
        drop(fx.controls.admit(A, false).unwrap());
        for (uri, body, response_media) in [
            (
                format!("{target}/ownership"),
                fixture::acquire(1, 2, 0),
                wire::MEDIA_GRANT,
            ),
            (
                format!("{target}/ownership"),
                fixture::acquire(1, 2, 0),
                wire::MEDIA_GRANT,
            ),
            (target.to_owned(), register, wire::MEDIA_RECEIPT),
            (format!("{target}/ownership"), takeover, wire::MEDIA_GRANT),
            (
                format!("{target}/release"),
                fixture::release(&taken, 1, 1),
                wire::MEDIA_RECEIPT,
            ),
        ] {
            let before = fx.controls.accounting(A).unwrap();
            let body_len = body.len() as u128;
            let mut req = request(Method::POST, &uri, Some(DA), Full::new(Bytes::from(body)));
            // The intent carrier is selected by the endpoint and bytes. The request media is advisory.
            req.headers_mut().insert(
                "content-type",
                HeaderValue::from_static("application/octet-stream"),
            );
            req.headers_mut().insert(
                "granary-request-id",
                HeaderValue::from_static("intent.test"),
            );
            let response = through(&fx.service, req).await;
            assert_eq!(
                fx.controls.accounting(A),
                Some((
                    before.0 - 1_000_000_000,
                    before.1 - body_len * 1_000_000_000,
                    0
                )),
                "each acquire/replay/register/takeover/release POST spends exactly one token and its bytes"
            );
            assert_eq!(
                (
                    response.status().as_u16(),
                    response.headers().get("granary-error"),
                    response
                        .headers()
                        .get("cache-control")
                        .and_then(|value| value.to_str().ok()),
                    response
                        .headers()
                        .get("content-type")
                        .and_then(|value| value.to_str().ok()),
                    response.headers().get("retry-after"),
                ),
                (200, None, Some("no-store"), Some(response_media), None),
                "intent response metadata for {uri}"
            );
        }
        for identity in [DA, DB] {
            let response = through(
                &fx.service,
                request(Method::GET, target, Some(identity), empty()),
            )
            .await;
            assert_eq!(
                (
                    response.status().as_u16(),
                    response.headers().get("granary-error"),
                    response
                        .headers()
                        .get("cache-control")
                        .and_then(|value| value.to_str().ok()),
                    response
                        .headers()
                        .get("content-type")
                        .and_then(|value| value.to_str().ok()),
                    response.headers().get("retry-after"),
                ),
                (
                    200,
                    None,
                    Some("no-store"),
                    Some(wire::MEDIA_READBACK),
                    None
                ),
                "intent readback metadata for {identity:?}"
            );
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let read = wire::decode_readback(&bytes, &fixture::volume(), |doc, signed| {
                granary_store::crypto::check_signatures(doc, signed, &fixture::keys()).is_ok()
            })
            .unwrap();
            assert_eq!(
                (read.cursor, read.rows.len()),
                (if identity == DA { 2 } else { 0 }, 0)
            );
        }
        let result = through(
            &fx.service,
            request(
                Method::POST,
                &format!("{target}/release"),
                Some(DB),
                Full::new(Bytes::from(fixture::release(&taken, 1, 1))),
            ),
        )
        .await;
        assert_eq!(
            (
                result.status().as_u16(),
                token(&result).as_deref(),
                field(&result, &CACHE_CONTROL).as_deref(),
                result.headers().get(CONTENT_TYPE),
                result.headers().get(RETRY_AFTER),
            ),
            (409, Some("intent-absent"), Some("no-store"), None, None),
            "absent release response metadata"
        );
        assert!(body_of(result).is_empty(), "absent release response body");
        let durable = std::fs::read(path.join("intent-test.intent")).unwrap();
        fx.clock.set(8_000_000_000);
        let response = through(
            &fx.service,
            request(
                Method::POST,
                &format!("{target}/ownership"),
                Some(DA),
                Full::new(Bytes::from(fixture::acquire(1, 6, 2))),
            ),
        )
        .await;
        assert_eq!(
            (
                response.status().as_u16(),
                token(&response).as_deref(),
                field(&response, &CACHE_CONTROL).as_deref(),
                field(&response, &CONTENT_TYPE).as_deref(),
                response.headers().get(RETRY_AFTER),
            ),
            (
                409,
                Some("intent-changed"),
                Some("no-store"),
                Some(wire::MEDIA_RECEIPT),
                None
            ),
            "existing-row acquire response metadata"
        );
        assert_eq!(
            wire::decode_receipt(&body_of(response)),
            Ok(wire::Receipt {
                writer: [1; 16],
                epoch: 2,
                instance: [5; 16],
                generation: 1,
                state: wire::ReceiptState::Released,
            }),
            "the conflict carries the previously released row"
        );
        assert_eq!(
            std::fs::read(path.join("intent-test.intent")).unwrap(),
            durable,
            "the existing-row acquire leaves durable bytes unchanged"
        );
        for (length, status, error) in [
            (65_594, 400, "invalid-candidate"),
            (65_595, 413, "too-large"),
        ] {
            let mut body = fixture::register(&taken, 1, 2, 3);
            body.truncate(58);
            body.resize(length, 0);
            let response = through(
                &fx.service,
                request(Method::POST, target, Some(DA), Full::new(Bytes::from(body))),
            )
            .await;
            assert_eq!(
                (
                    response.status().as_u16(),
                    token(&response).as_deref(),
                    field(&response, &CACHE_CONTROL).as_deref(),
                    response.headers().get(CONTENT_TYPE),
                    response.headers().get(RETRY_AFTER),
                ),
                (status, Some(error), Some("no-store"), None, None),
                "{error} register response metadata"
            );
            assert!(
                body_of(response).is_empty(),
                "{error} register response body"
            );
            assert_eq!(
                std::fs::read(path.join("intent-test.intent")).unwrap(),
                durable
            );
        }
        let held = fx.fill_cap();
        assert_eq!(held.len(), 4);
        drop(held);
        let counters = fx.service.refusal_counters().unwrap().snapshot();
        assert_eq!(
            (
                counters.totals.get(&crate::wire::ErrorToken::IntentAbsent),
                counters
                    .principals
                    .get(&B)
                    .and_then(|r| r.get(&crate::wire::ErrorToken::IntentAbsent))
            ),
            (Some(&1), Some(&1))
        );
        handle.stop().await
    };
    let driving = tokio::spawn(driver);
    let b = sequence.await;
    let a = driving.await.unwrap();
    assert_eq!(
        (a, b),
        (
            crate::authority::RunEnd::Stopped,
            crate::authority::RunEnd::Stopped
        )
    );
    assert_eq!(request_ids.lock().unwrap().as_slice(), ["intent.test"; 5]);
    drop(fx);
    drop(handle);
    std::fs::remove_dir_all(path).unwrap();
}

struct RequestIdLayer(Arc<std::sync::Mutex<Vec<String>>>);
struct RecordedId(String);
impl<S> tracing_subscriber::Layer<S> for RequestIdLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if attrs.metadata().name() == "grain_request" {
            struct Id(Option<String>);
            impl tracing::field::Visit for Id {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "wire_request_id" {
                        self.0 = Some(value.to_owned());
                    }
                }
                fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
            }
            let mut recorded = Id(None);
            attrs.record(&mut recorded);
            if let Some(value) = recorded.0 {
                ctx.span(id)
                    .unwrap()
                    .extensions_mut()
                    .insert(RecordedId(value));
            }
        }
    }
    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        struct Begin(bool);
        impl tracing::field::Visit for Begin {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "event" && value == "op.begin" {
                    self.0 = true;
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut begin = Begin(false);
        event.record(&mut begin);
        if begin.0
            && let Some(scope) = ctx.event_scope(event)
        {
            for span in scope {
                if span.name() == "grain_request"
                    && let Some(id) = span.extensions().get::<RecordedId>()
                {
                    self.0.lock().unwrap().push(id.0.clone());
                    break;
                }
            }
        }
    }
}

#[tokio::test]
async fn round1_maintenance_requires_authority_and_reports_unavailable_store() {
    let fx = Fx::new("round1-maintenance-disabled");
    assert_eq!(
        fx.service.maintain_intents().await,
        Err(crate::wire::ErrorToken::Unavailable)
    );
    let disabled = GrainService::new(Arc::new(FakeSeam::default()), "", TEST_WORKER_THREADS);
    assert_eq!(
        disabled.maintain_intents().await,
        Err(crate::wire::ErrorToken::Unavailable)
    );
}
