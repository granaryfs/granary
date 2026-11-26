// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `HttpStore` against stub TLS servers that answer the way a conforming
//! granary server never does.
//!
//! **A conforming peer cannot test this client.** §13.1 item 3 says so
//! outright: a real granary server sends `Granary-Error: not-found` on
//! every success-`404`, so a client driven only against one never executes
//! either refusal — and a client that mapped a bare `404` to `Ok(None)`
//! would pass every test in the document. The same holds for the over-long
//! hint (item 9: a server may bound its own read and answer `404`, so the
//! degrade path never runs), for the served `0` from `max-seq`, and for
//! every extent-gate row. So the stubs here are deliberately hostile.
//!
//! **The transport is REAL.** Every row goes over a TCP socket, a TLS 1.3
//! handshake against a minted certificate, and the shipped
//! `HttpsConnector` — because half of what is under test is the
//! connector's own behaviour (which ALPN tokens it offers, which HTTP
//! version it then speaks), and none of that exists in a fake.
//!
//! **`unwrap()` is a hard error in the helpers below.** `clippy.toml`'s
//! `allow-unwrap-in-tests` covers `#[test]` items, not the plain functions
//! in an integration-test target. The workspace idiom is
//! `.unwrap_or_else(|e| panic!("{e}"))`.

#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use granary_client::{
    AmbientNetwork, HttpStore, HttpStoreError, Policy, Prepared, PublishError, PublishRoute,
    ResolveError, ResolveTarget, RootVerifier, RouteError, SEAM_DEADLINE_BASE,
    SEAM_FLOOR_RATE_BYTES_PER_SEC, Store, WritableAuthority, open_publish_route,
    resolve_at_verified,
};
use granary_core::binfmt::BIN_MAX_BYTES;
use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::identity::WriterIdentity;
use granary_core::root::{self, RootDoc, RootSig, Timestamp, VolumeName};
use granary_core::rootstore::{HintRead, HintToken, RefusalKind, RootStore, RootStoreError};
use granary_core::thresh::CHUNKER_SPEC;
use granary_net::alpn::{ALPN_H2, ALPN_HTTP11};
use granary_net::pin::{SpkiPin, spki_digest};
use granary_net::tls::{ClientAuth, server_tls_config};
use granary_store::bounds::{META_MAX_BYTES, ROOT_MAX_BYTES};
use granary_store::crypto::SigningKey;
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::header::RANGE;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

mod support;
use support::base_url;

// ---------------------------------------------------------------- the spawn

/// The one spawn site in this file.
///
/// `tokio::spawn` is banned workspace-wide with no test exemption
/// because the simulator cannot sequence a runtime-ordered task.
/// Every use in this file is on the far side of that boundary — the
/// stub SERVER stands in for the layer `granary-sim` replaces rather
/// than drives, and the paused-clock rows spawn the CLIENT call under
/// test so this file's own body can interleave `tokio::time::advance`
/// with it (`tokio::join!`/`select!` are ALSO banned in this crate —
/// see `clippy.toml`'s `disallowed-macros` — so a second task is the
/// only sanctioned way to run the two concurrently); neither is code
/// the sim ever replays. Routing every task through one wrapper keeps
/// the exemption to a single reviewable site.
#[expect(
    clippy::disallowed_methods,
    reason = "the stub server stands in for the accept loop, the layer granary-sim replaces rather than drives; the paused-clock rows spawn the client call under test for the same reason — test harness concurrency the sim never drives"
)]
fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future)
}

/// The one `tokio::time::sleep` site in this file: a STUB SERVER's
/// own processing delay, running under `tokio::time::pause()`.
///
/// `tokio::time::sleep` is banned workspace-wide (`clippy.toml`'s
/// `disallowed-methods`): a production wall-clock read the sim
/// cannot replay. This is neither — it is test-only harness code
/// standing in for a slow-but-honest PEER's processing time, on the
/// far side of the same boundary the [`spawn`] wrapper's exemption
/// already draws, and it PARTICIPATES in the paused clock rather than
/// reading a real one: under `#[tokio::test(start_paused = true)]`,
/// `tokio::time::advance` moves this sleep and the client's own
/// per-call deadline forward together, on the same virtual clock.
#[expect(
    clippy::disallowed_methods,
    reason = "a stub server's own processing delay under tokio::time::pause, not a production clock read — the spawn() wrapper above draws the identical line"
)]
async fn park_for(delay: Duration) {
    tokio::time::sleep(delay).await;
}

// ------------------------------------------------------------- certificates

/// The certificate SAN. Clients dial the listener's numeric address;
/// pin verification ignores this name.
const HOST: &str = "localhost";

/// A minted certificate and its key.
struct Party {
    cert: CertificateDer<'static>,
    pkcs8: Vec<u8>,
}

impl Party {
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pkcs8.clone()))
    }

    fn pin(&self) -> SpkiPin {
        spki_digest(&self.cert).unwrap_or_else(|e| panic!("spki digest: {e}"))
    }
}

fn mint() -> Party {
    let key = rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("keypair: {e}"));
    let mut params = rcgen::CertificateParams::new(vec![HOST.to_owned()])
        .unwrap_or_else(|e| panic!("cert params: {e}"));
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    Party {
        cert: params
            .self_signed(&key)
            .unwrap_or_else(|e| panic!("self-sign: {e}"))
            .der()
            .clone(),
        pkcs8: key.serialize_der(),
    }
}

// ------------------------------------------------------------- the stub body

/// A response body produced LAZILY, counting the bytes it hands to hyper.
///
/// The count is what makes §13.1 item 9's second half observable: "assert
/// the read stopped at the bound rather than draining the body". A
/// `Full<Bytes>` cannot show that — it is one frame, produced whether or
/// not anyone reads it.
struct StubBody {
    chunks: VecDeque<Bytes>,
    repeat: Option<(Bytes, usize)>,
    sent: Arc<AtomicUsize>,
}

impl StubBody {
    fn of(bytes: impl Into<Bytes>) -> Self {
        Self {
            chunks: VecDeque::from(vec![bytes.into()]),
            repeat: None,
            sent: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn empty() -> Self {
        Self {
            chunks: VecDeque::new(),
            repeat: None,
            sent: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// `repeats` chunks of `chunk`, counted into `sent`.
    fn repeated(chunk: Bytes, repeats: usize, sent: &Arc<AtomicUsize>) -> Self {
        Self {
            chunks: VecDeque::new(),
            repeat: Some((chunk, repeats)),
            sent: Arc::clone(sent),
        }
    }
}

impl Body for StubBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = Pin::get_mut(self);
        if let Some(chunk) = this.chunks.pop_front() {
            this.sent.fetch_add(chunk.len(), Ordering::Relaxed);
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        if let Some((chunk, left)) = this.repeat.as_mut()
            && *left > 0
        {
            *left -= 1;
            let chunk = chunk.clone();
            this.sent.fetch_add(chunk.len(), Ordering::Relaxed);
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        Poll::Ready(None)
    }
}

// ----------------------------------------------------------- the stub server

/// What the stub saw. `version` is the load-bearing field: a defective
/// connector answers `200` over the wrong protocol, and a status-only
/// assertion cannot see it.
#[derive(Debug, Clone)]
struct Recorded {
    method: Method,
    path: String,
    version: Version,
    headers: HeaderMap,
    body: Vec<u8>,
}

type Answer = Arc<dyn Fn(&Recorded) -> Response<StubBody> + Send + Sync>;

type AcceptError = Arc<Mutex<Option<String>>>;

/// Keep accept failures observable by the owning test, including when a
/// spawned task panics. Check the recorded error when the fixture drops.
struct AcceptTask {
    task: JoinHandle<()>,
    error: AcceptError,
}

impl Drop for AcceptTask {
    fn drop(&mut self) {
        self.task.abort();
        if !std::thread::panicking() {
            let error = self
                .error
                .lock()
                .unwrap_or_else(|e| panic!("accept error lock poisoned: {e}"));
            assert!(error.is_none(), "stub accept failed: {error:?}");
        }
    }
}

fn spawn_accepting<F, Fut>(serve: F) -> AcceptTask
where
    F: FnOnce(AcceptError) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let error = Arc::new(Mutex::new(None));
    let task = spawn(serve(Arc::clone(&error)));
    AcceptTask { task, error }
}

async fn accept(listener: &TcpListener, error: &AcceptError) -> TcpStream {
    match listener.accept().await {
        Ok((socket, _)) => socket,
        Err(cause) => {
            let message = cause.to_string();
            *error
                .lock()
                .unwrap_or_else(|e| panic!("accept error lock poisoned: {e}")) =
                Some(message.clone());
            panic!("stub accept failed: {message}");
        }
    }
}

struct Stub {
    addr: SocketAddr,
    log: Arc<Mutex<Vec<Recorded>>>,
    pin: SpkiPin,
    connections: Arc<AtomicUsize>,
    _accepting: AcceptTask,
}

impl Stub {
    fn base(&self) -> String {
        base_url(self.addr)
    }

    fn seen(&self) -> Vec<Recorded> {
        self.log
            .lock()
            .unwrap_or_else(|e| panic!("stub log poisoned: {e}"))
            .clone()
    }

    fn store(&self) -> HttpStore {
        HttpStore::new(&self.base(), vec![self.pin], &AmbientNetwork)
            .unwrap_or_else(|e| panic!("http store: {e}"))
    }
}

/// Start a stub serving `alpn`, answering every request with `answer`.
async fn stub_with_alpn(alpn: &[&[u8]], answer: Answer) -> Stub {
    let party = mint();
    let pin = party.pin();
    let mut tls = server_tls_config(vec![party.cert.clone()], party.key(), ClientAuth::None)
        .unwrap_or_else(|e| panic!("server tls: {e}"));
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let log: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));

    let connections = Arc::new(AtomicUsize::new(0));
    let accept_connections = connections.clone();
    let accept_log = Arc::clone(&log);
    let accepting = spawn_accepting(move |accept_error| async move {
        loop {
            let sock = accept(&listener, &accept_error).await;
            accept_connections.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let answer = Arc::clone(&answer);
            let log = Arc::clone(&accept_log);
            let _served = spawn(async move {
                let Ok(tls) = acceptor.accept(sock).await else {
                    return;
                };
                let svc = service_fn(move |req: Request<Incoming>| {
                    let answer = Arc::clone(&answer);
                    let log = Arc::clone(&log);
                    async move {
                        let version = req.version();
                        let method = req.method().clone();
                        let path = req.uri().path().to_owned();
                        let headers = req.headers().clone();
                        let body = drain(req.into_body()).await;
                        let seen = Recorded {
                            method,
                            path,
                            version,
                            headers,
                            body,
                        };
                        if let Ok(mut guard) = log.lock() {
                            guard.push(seen.clone());
                        }
                        Ok::<_, Infallible>(answer(&seen))
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });

    Stub {
        addr,
        log,
        pin,
        connections,
        _accepting: accepting,
    }
}

/// Read a request body, bounded — the stub is a test peer, not a target.
async fn drain(body: Incoming) -> Vec<u8> {
    let mut body = body;
    let mut out = Vec::new();
    while let Some(Ok(frame)) = body.frame().await {
        if let Ok(data) = frame.into_data() {
            if out.len() + data.len() > 1 << 20 {
                break;
            }
            out.extend_from_slice(&data);
        }
    }
    out
}

use http_body_util::BodyExt as _;

/// A stub on both ALPN tokens — what the shipped server offers.
async fn stub(answer: Answer) -> Stub {
    stub_with_alpn(&[ALPN_H2, ALPN_HTTP11], answer).await
}

fn answering(f: impl Fn(&Recorded) -> Response<StubBody> + Send + Sync + 'static) -> Answer {
    Arc::new(f)
}

/// A response with a status, a `Granary-Error` token and no content.
fn refusal(status: StatusCode, token: Option<&str>) -> Response<StubBody> {
    let mut b = Response::builder().status(status);
    if let Some(token) = token {
        b = b.header("granary-error", token);
    }
    b.body(StubBody::empty())
        .unwrap_or_else(|e| panic!("response: {e}"))
}

fn ok_body(bytes: impl Into<Bytes>) -> Response<StubBody> {
    Response::builder()
        .status(StatusCode::OK)
        .body(StubBody::of(bytes))
        .unwrap_or_else(|e| panic!("response: {e}"))
}

// ------------------------------------------------------------------ fixtures

const VOLUME: &str = "http-store-vol";
const DIGEST: [u8; DIGEST_LEN] = [0x5a; DIGEST_LEN];

fn volume() -> VolumeName {
    VolumeName::new(VOLUME.to_owned()).unwrap_or_else(|e| panic!("volume: {e}"))
}

/// A root at seq 1, signed by `key`.
fn signed_root(key: &SigningKey) -> Vec<u8> {
    let doc = RootDoc {
        volume: volume(),
        seq: 1,
        parent: None,
        writer_uuid: [3_u8; 16],
        epoch: 1,
        timestamp: Timestamp {
            secs: 1_700_000_000,
            nanos: 0,
        },
        chunker_spec: CHUNKER_SPEC.to_string(),
        manifest_root: GrainId::of(b"t12 manifest"),
        binmap_index: GrainId::of(b"t12 binmap"),
        sheaf_head: GrainId::of(b"t12 sheaf"),
        sigs: vec![RootSig {
            key_id: key.key_id(),
            sig: [0_u8; 64],
        }],
    };
    let unsigned = root::encode_root(&doc).unwrap_or_else(|e| panic!("encode: {e}"));
    let prefix = root::signed_prefix(&unsigned).unwrap_or_else(|e| panic!("prefix: {e}"));
    let sig = key.sign(prefix);
    let doc = RootDoc {
        sigs: vec![RootSig {
            key_id: key.key_id(),
            sig,
        }],
        ..doc
    };
    root::encode_root(&doc).unwrap_or_else(|e| panic!("encode signed: {e}"))
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap_or_else(|e| panic!("signing key: {e}"))
}

/// A runtime facade owns its caller runtime's pool, not the original
/// runtime's live-but-idle h2 connection.
///
/// The second call on runtime A is the positive control: it proves the
/// warmed connection and peer still answer before runtime B asks. A facade
/// that merely clones `self.client` passes that control but stalls on B,
/// because the pooled connection's dispatcher remains on idle runtime A.
#[test]
fn a_runtime_facade_does_not_reuse_another_current_thread_runtimes_pool() {
    let server_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("server runtime: {e}"));
    let stub = server_runtime.block_on(stub(answering(|_| ok_body(&b"00000000000000000042"[..]))));
    let store = stub.store();
    let facade = store.read_facade();
    let runtime_a = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("runtime A: {e}"));
    let runtime_b = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("runtime B: {e}"));

    let warmed = runtime_a.block_on(store.max_seq(VOLUME));
    assert_eq!(warmed, Ok(Some(42)), "runtime A warm-up got {warmed:?}");
    let same_runtime = runtime_a.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), store.max_seq(VOLUME)).await
    });
    let connections = stub.connections.load(Ordering::SeqCst);
    assert!(
        matches!(same_runtime, Ok(Ok(Some(42)))) && connections == 1,
        "runtime A's warmed pool must remain responsive on one connection; got \
         {same_runtime:?} with {connections} connections"
    );

    let other_runtime = runtime_b.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), facade.max_seq(VOLUME)).await
    });
    let connections = stub.connections.load(Ordering::SeqCst);
    assert!(
        matches!(other_runtime, Ok(Ok(Some(42)))) && connections == 2,
        "runtime B's facade must answer through its own second connection; got \
         {other_runtime:?} with {connections} connections"
    );
}

// ------------------------------------------------------- construction (§4.1)

/// An `http://` base is refused at CONSTRUCTION, before a connector exists.
///
/// This is the fail-open question `https_only()` answers second: a
/// plaintext connection runs no certificate verifier at all, so the pin is
/// not "checked and passed" on one — it is never consulted. Two locks on
/// one door, and this is the outer one.
#[tokio::test]
async fn a_plaintext_base_is_refused_before_any_connector_exists() {
    let err = HttpStore::new("http://example.invalid", vec![[1_u8; 32]], &AmbientNetwork)
        .expect_err("an http:// base must never build a pinned store");
    assert!(matches!(err, HttpStoreError::BadBase { .. }), "got {err:?}");
}

/// A base that ends in `/` is refused: `{base}/` + `/bin/…` is `//bin/…`,
/// whose empty segment fails §4.3's grammar at every server — every
/// request would `404`, and on `GET root` that `404` is a SUCCESS shape.
#[tokio::test]
async fn a_base_with_a_trailing_slash_is_refused() {
    let err = HttpStore::new(
        "https://example.invalid/",
        vec![[1_u8; 32]],
        &AmbientNetwork,
    )
    .expect_err("a trailing slash must be refused");
    assert!(matches!(err, HttpStoreError::BadBase { .. }), "got {err:?}");
}

/// §4.1: a base carrying a FRAGMENT or a QUERY is refused, and neither
/// guard is cosmetic.
///
/// `{base}` is CONCATENATED, never re-rendered from a parsed URL (§4.3),
/// so `https://h#x` + `/bin/{digest}` is `https://h#x/bin/{digest}` —
/// whose path is `/` and whose fragment is `x/bin/{digest}`. The request
/// addresses the origin's root, and the digest never leaves the client.
/// `https://h/p?a=b` swallows the path into the QUERY the same way. Both
/// silently address the wrong target on every one of the nine seams, and
/// on `GET root`/`GET max-seq`/`GET hint` the wrong target's `404` is a
/// SUCCESS shape — so a mistyped base reports every volume as empty
/// rather than failing.
#[tokio::test]
async fn a_base_with_a_fragment_or_a_query_is_refused() {
    for base in ["https://example.invalid#x", "https://example.invalid/p?a=b"] {
        let err = HttpStore::new(base, vec![[1_u8; 32]], &AmbientNetwork)
            .expect_err("a base that truncates or swallows every target must be refused");
        assert!(
            matches!(err, HttpStoreError::BadBase { .. }),
            "{base}: got {err:?}"
        );
    }
}

/// The all-zero pin is refused, by the verifier this store installs. The
/// refusal lives in `granary_net::pin`, and this row is what proves the
/// production path goes through it rather than around it.
#[tokio::test]
async fn a_zero_pin_is_refused_at_construction() {
    let err = HttpStore::new("https://example.invalid", vec![[0_u8; 32]], &AmbientNetwork)
        .expect_err("the zero digest is a fail-open sentinel, not a pin");
    assert!(matches!(err, HttpStoreError::Pins(_)), "got {err:?}");
}

// ------------------------------------------------ the pin diagnosis

/// A WRONG pin names the pin in the message the operator reads.
///
/// **The failure is unchanged and must stay unchanged** — a pin miss
/// fails the handshake closed, as required — so this
/// row asserts the DIAGNOSIS and nothing about the outcome. The bare
/// hyper rendering of a wrong pin, `object store: transport: client
/// error (Connect)`, names no pin, no certificate and no store the
/// operator has.
#[tokio::test]
async fn a_wrong_pin_says_so_and_names_the_configured_pins() {
    let stub = stub(answering(|_| ok_body(&b"x"[..]))).await;
    let stranger = mint().pin();
    assert_ne!(stranger, stub.pin, "the stranger's pin must differ");
    let store = HttpStore::new(&stub.base(), vec![stranger], &AmbientNetwork)
        .unwrap_or_else(|e| panic!("http store: {e}"));
    let store = store.read_facade();

    let err = store
        .get_root(VOLUME, 1)
        .await
        .expect_err("a client pinned to a certificate the server does not hold gets nothing");
    let RootStoreError::Backend(text) = &err else {
        panic!("a failed handshake is a transport failure, got {err:?}");
    };
    // The WHOLE message, not a substring of it. Every clause is load
    // bearing: the outer hyper `Display` (what the operator sees in the
    // logs of anything else), the rustls variant the chain bottoms out
    // in, the sentence that reads it, and the configured operand in the
    // spelling `GRANARY_TLS_PINS` takes.
    assert_eq!(
        text.as_str(),
        &format!(
            "transport: client error (Connect): invalid peer certificate: \
             ApplicationVerificationFailure — pin mismatch: the server's certificate matches \
             none of this client's configured TLS pins: {}",
            granary_net::config::render_tls_pin(&stranger)
        ),
    );
    assert!(
        stub.seen().is_empty(),
        "no request may reach a peer the handshake refused"
    );
}

/// An EMPTY pin set gets its own sentence, because it is the
/// configuration mistake most likely to produce this failure.
///
/// `PinnedServerVerifier::new` accepts an empty set and refuses every
/// certificate — "not configured yet" must never mean "accept anything"
/// — so an unset `GRANARY_TLS_PINS` is a client that authenticates
/// nobody, and every connection it makes is a pin rejection. Rendering
/// that as an empty list would tell the operator their pins do not match
/// when they have none, which is a different problem with a different
/// fix.
#[tokio::test]
async fn an_empty_pin_set_says_it_is_empty_rather_than_listing_nothing() {
    let stub = stub(answering(|_| ok_body(&b"x"[..]))).await;
    let store = HttpStore::new(&stub.base(), Vec::new(), &AmbientNetwork)
        .unwrap_or_else(|e| panic!("an empty set is legal and refuses everything: {e}"));

    let err = store
        .get_root(VOLUME, 1)
        .await
        .expect_err("a client with no pins trusts no server");
    let RootStoreError::Backend(text) = &err else {
        panic!("a failed handshake is a transport failure, got {err:?}");
    };
    // The WHOLE message again, for the row above's reason and one more:
    // an exact match is the only assertion no ADDED sentence can pass,
    // and the sentence most likely to be added here is a guess at where
    // the empty set came from.
    assert_eq!(
        text.as_str(),
        "transport: client error (Connect): invalid peer certificate: \
         ApplicationVerificationFailure — pin mismatch: this client has no TLS pins \
         configured, and an empty set refuses every certificate",
    );
    assert!(
        stub.seen().is_empty(),
        "no request may reach a peer the handshake refused"
    );
}

/// **THE PIN VALUE IS A FACT THIS STORE HAS; ITS PROVENANCE IS NOT.**
///
/// A pin-mismatch message ending `GRANARY_TLS_PINS holds
/// …` would be false on the `gran cat` route: `gran cat`
/// does not read the variable at all — `parse_cat`'s own refusal says
/// so in terms ("`GRANARY_TLS_PINS` is NOT read on this path —
/// deliberately") — and on the publish route `--pin` overrides it. So an
/// operator who typed `--pin` would be sent to an environment variable
/// that is unset, or worse holds a stale value from an earlier session,
/// and told it was the source of the pin that had just failed. That is
/// the *misdirection* the pin diagnosis is meant
/// to remove.
///
/// [`HttpStore::new`] takes a `Vec<SpkiPin>` and is told nothing about
/// where the caller got them, so the honest message names the VALUE and
/// stops. Provenance belongs to `main.rs`, which knows it and already
/// hedges as `--pin (or GRANARY_TLS_PINS)` at every site that has the
/// standing to say so.
///
/// Both configurations are driven, because the empty-set sentence is
/// the one most tempting to write as "your `GRANARY_TLS_PINS` is empty".
#[tokio::test]
async fn the_pin_message_names_the_value_and_never_claims_a_provenance() {
    let stub = stub(answering(|_| ok_body(&b"x"[..]))).await;
    let stranger = mint().pin();

    for (pins, what) in [
        (vec![stranger], "a wrong pin"),
        (Vec::new(), "an empty pin set"),
    ] {
        let store = HttpStore::new(&stub.base(), pins, &AmbientNetwork)
            .unwrap_or_else(|e| panic!("http store: {e}"));
        let err = store
            .get_root(VOLUME, 1)
            .await
            .expect_err("neither configuration authenticates this server");
        let RootStoreError::Backend(text) = &err else {
            panic!("{what}: a failed handshake is a transport failure, got {err:?}");
        };
        for provenance in [granary_net::config::ENV_TLS_PINS, "--pin"] {
            assert!(
                !text.contains(provenance),
                "{what}: the message claims the pin came from {provenance:?}, which this \
                 store cannot know — it was handed a Vec<SpkiPin> and no source: {text:?}"
            );
        }
    }
}

/// **THE POSITIVE CONTROL for the row above**: a connect failure that is
/// NOT a pin miss must not claim one.
///
/// `is_connect()` has been observed true for seven distinct
/// classes — wrong pin, connection refused, DNS failure, TLS version
/// mismatch, a peer closing mid-handshake, a non-TLS peer, a
/// stock-verifier rejection — so a message that blamed the pin on a
/// `Connect` error would blame it for all seven, and a message that
/// always blames the pin is worse than a generic message. This row is
/// what makes the pin sentence a DISCRIMINATION rather than a decoration:
/// delete it and "name the pin" is satisfied by naming it every time.
///
/// A dead port is the cheapest member of the class: bind, take the
/// address, drop the listener.
#[tokio::test]
async fn a_dead_port_does_not_blame_the_pin() {
    let doomed = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = doomed
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    drop(doomed);

    let pin = mint().pin();
    let store = HttpStore::new(&base_url(addr), vec![pin], &AmbientNetwork)
        .unwrap_or_else(|e| panic!("http store: {e}"));

    let err = store
        .get_root(VOLUME, 1)
        .await
        .expect_err("nothing is listening on that port");
    let RootStoreError::Backend(text) = &err else {
        panic!("a refused connection is a transport failure, got {err:?}");
    };
    assert!(
        !text.contains(&granary_net::config::render_tls_pin(&pin)),
        "a refused CONNECTION is not a pin miss and must not name a pin: {text:?}"
    );
    assert!(
        !text.contains("pin mismatch"),
        "nor call itself one: {text:?}"
    );
    // What it must say INSTEAD. Not an exact match: the tail is the
    // platform's own `strerror` (errno 61 on macOS, 111 on Linux), so
    // the row pins the two clauses granary is responsible for and lets
    // the OS spell the last one.
    assert!(
        text.starts_with("transport: client error (Connect): "),
        "the outer hyper Display is still first: {text:?}"
    );
    assert_ne!(
        text.as_str(),
        "transport: client error (Connect)",
        "and the source chain BELOW it is rendered rather than discarded — this is the bare \
         generic string, and a message that only added a pin sentence would leave it here"
    );
    assert!(
        text.to_lowercase().contains("refused"),
        "the reason the OS gave must survive: {text:?}"
    );
}

// ----------------------------------------------------------- ALPN

/// BOTH ALPN tokens are offered, and the SERVED version is asserted
/// on both legs.
///
/// The status is not the assertion. A connector that offered only `h2`
/// answers `200` on the h2 stub and fails outright on the `http/1.1` one;
/// a connector that negotiated `h2` and then spoke HTTP/1.1 anyway would
/// answer `200` on both. Only `req.version()`, recorded by the peer, tells
/// those apart.
#[tokio::test]
async fn served_http_version_is_asserted_on_both_legs() {
    for (alpn, want) in [(ALPN_H2, Version::HTTP_2), (ALPN_HTTP11, Version::HTTP_11)] {
        let stub = stub_with_alpn(
            &[alpn],
            answering(|_| refusal(StatusCode::NOT_FOUND, Some("not-found"))),
        )
        .await;
        let store = stub.store();
        let got = store.get_root(VOLUME, 1).await;
        assert_eq!(got, Ok(None), "on {alpn:?}");
        let seen = stub.seen();
        let [only] = seen.as_slice() else {
            panic!(
                "expected exactly one request on {alpn:?}, got {}",
                seen.len()
            );
        };
        assert_eq!(only.version, want, "served version on {alpn:?}");
        assert_eq!(only.method, Method::GET);
    }
}

/// The offer is a SET, and a peer that shares neither token gets no
/// connection.
///
/// Without this row the test above is satisfied by a connector that offers
/// nothing at all and lets each server pick: rustls completes a handshake
/// with no ALPN negotiated whenever the client sends no extension, and
/// hyper would then speak HTTP/1.1 to the `http/1.1` stub and — because
/// the `h2` stub also answers over h1 once `auto` sniffs the preface —
/// possibly to both.
#[tokio::test]
async fn both_alpn_tokens_are_offered_by_the_production_connector() {
    let stub = stub_with_alpn(&[b"spdy/3"], answering(|_| ok_body(&b"x"[..]))).await;
    let store = stub.store();
    let err = store
        .get_root(VOLUME, 1)
        .await
        .expect_err("a peer sharing no ALPN token must not be served");
    assert!(
        matches!(err, RootStoreError::Backend(_)),
        "a failed handshake is a transport failure, got {err:?}"
    );
    assert!(
        stub.seen().is_empty(),
        "no request may reach a peer the handshake refused"
    );
}

// ---------------------------------------------------- the success-404 rows

/// §8.1: a `404` CARRYING `not-found` is `Ok(None)` on `GET root` — the
/// cheap negative a forward probe asks for constantly.
#[tokio::test]
async fn get_root_maps_a_404_with_not_found_to_none() {
    let stub = stub(answering(|_| {
        refusal(StatusCode::NOT_FOUND, Some("not-found"))
    }))
    .await;
    assert_eq!(stub.store().get_root(VOLUME, 7).await, Ok(None));
}

/// This pins the handle-to-counter LINKAGE, over a real connection
/// — `http_store.rs`'s own unit rows (i)-(l) each build a fresh,
/// LOCAL `ResponseByteCounter` and read it back directly, so none
/// of them can tell [`HttpStore::wire_bytes`] apart from one that
/// clones a fresh counter, or [`WireByteHandle::total`] apart from
/// a hardcoded result. This row drives one real `GET root` through a
/// runtime facade and a genuine TLS loopback connection, then reads the
/// total through the original store's PUBLIC handle a mount reads at
/// clean exit.
#[tokio::test]
async fn the_public_wire_bytes_handle_reads_what_the_store_actually_received() {
    let payload = vec![0x7a_u8; 4096];
    let stub = stub(answering({
        let payload = payload.clone();
        move |_| ok_body(payload.clone())
    }))
    .await;
    let store = stub.store();
    let facade = store.read_facade();
    assert_eq!(
        facade.get_root(VOLUME, 7).await,
        Ok(Some(payload.clone())),
        "the response must actually land for this row to state anything \
         about what got counted"
    );

    assert_eq!(
        store.wire_bytes().total(),
        Some(payload.len() as u64),
        "HttpStore::wire_bytes() — the same handle a mount reads at clean \
         exit — must report the bytes THIS response actually delivered, \
         read through WireByteHandle::total() and not through any \
         test-only local counter"
    );
}

/// §8.1: a `404` WITHOUT the field is a backend error, not `Ok(None)`.
/// This is the reverse proxy with a stale route, the captive portal, the
/// object store answering on that port — every one of which would
/// otherwise report a populated volume as empty.
#[tokio::test]
async fn get_root_refuses_a_404_without_not_found() {
    let stub = stub(answering(|_| refusal(StatusCode::NOT_FOUND, None))).await;
    let err = stub
        .store()
        .get_root(VOLUME, 7)
        .await
        .expect_err("a bare 404 is not an answer about this volume");
    assert!(
        matches!(
            err,
            RootStoreError::UnexpectedStatus {
                operation: "GET root",
                status: 404,
                token: None
            }
        ),
        "got {err:?}"
    );
}

/// §8.1: and a `404` carrying `unknown-target` — the token a REAL granary
/// server sends when the base URL's path is wrong — is refused too. This
/// is the live misconfiguration rather than a foreign peer, and a client
/// that special-cased only the absent field passes the row above and fails
/// in production.
#[tokio::test]
async fn get_root_refuses_a_404_carrying_unknown_target() {
    let stub = stub(answering(|_| {
        refusal(StatusCode::NOT_FOUND, Some("unknown-target"))
    }))
    .await;
    let err = stub
        .store()
        .get_root(VOLUME, 7)
        .await
        .expect_err("unknown-target is never a success mapping");
    assert!(
        matches!(err, RootStoreError::UnexpectedStatus { .. }),
        "got {err:?}"
    );
}

/// The same three-way on `max-seq` (§13.1 item 3).
#[tokio::test]
async fn max_seq_requires_the_not_found_token_on_a_404() {
    let with = stub(answering(|_| {
        refusal(StatusCode::NOT_FOUND, Some("not-found"))
    }))
    .await;
    assert_eq!(with.store().max_seq(VOLUME).await, Ok(None));

    let bare = stub(answering(|_| refusal(StatusCode::NOT_FOUND, None))).await;
    assert!(
        matches!(
            bare.store().max_seq(VOLUME).await,
            Err(RootStoreError::UnexpectedStatus { .. })
        ),
        "a bare 404 must not report an empty volume"
    );

    let wrong = stub(answering(|_| {
        refusal(StatusCode::NOT_FOUND, Some("unknown-target"))
    }))
    .await;
    assert!(
        matches!(
            wrong.store().max_seq(VOLUME).await,
            Err(RootStoreError::UnexpectedStatus { .. })
        ),
        "unknown-target must not report an empty volume"
    );
}

/// The same three-way on `GET hint`.
#[tokio::test]
async fn read_hint_requires_the_not_found_token_on_a_404() {
    let with = stub(answering(|_| {
        refusal(StatusCode::NOT_FOUND, Some("not-found"))
    }))
    .await;
    assert_eq!(
        with.store().read_hint(VOLUME, None).await,
        Ok(HintRead::Missing)
    );

    let bare = stub(answering(|_| refusal(StatusCode::NOT_FOUND, None))).await;
    assert!(
        matches!(
            bare.store().read_hint(VOLUME, None).await,
            Err(RootStoreError::UnexpectedStatus { .. })
        ),
        "a bare 404 must not report a missing hint"
    );

    // The third leg, which this test claimed to have and did not: the
    // token a REAL granary server sends when the base path is wrong. Absent
    // it, an implementation that accepted ANY token here passed the two
    // legs above — and would report every volume behind a mistyped base as
    // hintless, forever, silently.
    let wrong = stub(answering(|_| {
        refusal(StatusCode::NOT_FOUND, Some("unknown-target"))
    }))
    .await;
    assert!(
        matches!(
            wrong.store().read_hint(VOLUME, None).await,
            Err(RootStoreError::UnexpectedStatus { .. })
        ),
        "unknown-target must not report a missing hint"
    );
}

/// **TWO tokens is not ONE token**, and the difference is a fabricated
/// success.
///
/// §8.2's registry is closed and the field carries exactly one value, so
/// `error_token` refuses a response carrying more than one rather than
/// taking the first. Without that guard, a response carrying BOTH
/// `not-found` and `unknown-target` maps to `Ok(None)` on `get_root` and
/// `max_seq` — a success invented out of a header. Nothing in this
/// protocol stops a reverse proxy, a WAF, or an injection from ADDING a
/// field to a response; taking the first value would let any of them
/// convert "this volume has roots" into "this volume is empty", which is
/// the one answer that lets a publisher overwrite its own chain.
#[tokio::test]
async fn two_granary_error_fields_are_not_one_token() {
    let two = || {
        answering(|_| {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("granary-error", "not-found")
                .header("granary-error", "unknown-target")
                .body(StubBody::empty())
                .unwrap_or_else(|e| panic!("response: {e}"))
        })
    };

    let roots = stub(two()).await;
    let got = roots.store().get_root(VOLUME, 7).await;
    assert!(
        matches!(got, Err(RootStoreError::UnexpectedStatus { .. })),
        "get_root: two tokens must not complete a success-404, got {got:?}"
    );

    let heads = stub(two()).await;
    let got = heads.store().max_seq(VOLUME).await;
    assert!(
        matches!(got, Err(RootStoreError::UnexpectedStatus { .. })),
        "max_seq: two tokens must not report an empty volume, got {got:?}"
    );

    let hint = stub(two()).await;
    let got = hint.store().read_hint(VOLUME, None).await;
    assert!(
        matches!(got, Err(RootStoreError::UnexpectedStatus { .. })),
        "read_hint: two tokens must not report a missing hint, got {got:?}"
    );
}

// --------------------------------------------------------- max-seq (§5.7)

/// Seq 0 can hold no root, so a served `0` is `Ok(None)`
/// — never `Ok(Some(0))`, which would block the first publish to a fresh
/// volume forever.
#[tokio::test]
async fn max_seq_overrides_a_server_zero_to_none() {
    let stub = stub(answering(|_| ok_body(&b"00000000000000000000"[..]))).await;
    assert_eq!(stub.store().max_seq(VOLUME).await, Ok(None));
}

/// §5.7: `max-seq` is the ONE place a 20-digit body does not degrade. A
/// malformed body is a hard error rather than "the volume has no roots",
/// because guessing here loses a published volume.
#[tokio::test]
async fn a_malformed_max_seq_body_is_a_hard_error() {
    for body in [
        &b"1"[..],
        &b"0000000000000000000x"[..],
        &b"000000000000000000001"[..],
        &b""[..],
    ] {
        let stub = stub(answering(move |_| ok_body(body))).await;
        let got = stub.store().max_seq(VOLUME).await;
        assert!(
            matches!(got, Err(RootStoreError::Backend(_))),
            "body {body:?} must be a hard error, got {got:?}"
        );
    }
}

/// The well-formed case, so the refusals above are not the whole function.
#[tokio::test]
async fn max_seq_reads_a_well_formed_head() {
    let stub = stub(answering(|_| ok_body(&b"00000000000000000042"[..]))).await;
    assert_eq!(stub.store().max_seq(VOLUME).await, Ok(Some(42)));
}

/// At the OTHER end of the range, an additional §5.7 refusal: a body of
/// `18446744073709551615` is a PROTOCOL VIOLATION — a backend error, and
/// deliberately NOT a degrade to `Ok(None)`.
///
/// **The degrade was considered and rejected, and the reason must survive
/// a later "simplification".** Seq 0 can degrade safely because it MEANS
/// "no valid root". `u64::MAX` means nothing of the kind: a volume with
/// real roots at ordinary seqs would be reported EMPTY, which sends
/// `publish` down its new-volume branch to seq 1 — a spurious
/// `AlreadyExists` at best, and at worst the "let a publish overwrite its
/// own chain" hazard that `http_store.rs` names as the whole reason §5.7
/// is the one place a 20-digit body does not degrade.
///
/// Note this rule is NEW, not inherited: §5.7's existing MUST covers a
/// body that "is not exactly 20 ASCII digits, or does not fit a `u64`",
/// and `18446744073709551615` satisfies both limbs.
#[tokio::test]
async fn a_max_seq_body_of_the_reserved_top_of_the_range_is_a_hard_error() {
    let stub = stub(answering(|_| ok_body(&b"18446744073709551615"[..]))).await;
    let got = stub.store().max_seq(VOLUME).await;
    assert!(
        matches!(got, Err(RootStoreError::Backend(_))),
        "a max-seq body of u64::MAX must be a protocol violation, never Ok(None) and never \
         Ok(Some(u64::MAX)), got {got:?}"
    );
}

/// POSITIVE CONTROL for the row above: `u64::MAX - 1` is the top of the
/// USABLE range (`1 ..= u64::MAX - 1`) and reads back normally.
///
/// Without it the refusal above cannot be told from a client that refuses
/// the whole top of the range — exactly one value is reserved, not a band.
#[tokio::test]
async fn max_seq_reads_the_top_of_the_usable_range() {
    let stub = stub(answering(|_| ok_body(&b"18446744073709551614"[..]))).await;
    assert_eq!(stub.store().max_seq(VOLUME).await, Ok(Some(u64::MAX - 1)));
}

// ------------------------------------------------------------ hint (§5.8)

/// §13.1 item 9: an over-long hint body degrades to `Ok(Missing)`, and the
/// read STOPS at the bound rather than draining the body.
///
/// Both halves are asserted, and a 21-byte body is too small to tell them
/// apart — so the stub serves 16 MiB in 8 KiB pieces and counts what it
/// handed to hyper. A client that drained would consume all of it.
#[tokio::test]
async fn read_hint_degrades_an_over_long_body_to_missing() {
    const CHUNK: usize = 8 * 1024;
    const REPEATS: usize = 2048;
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&sent);
    let stub = stub(answering(move |_| {
        Response::builder()
            .status(StatusCode::OK)
            .header("etag", "\"v1\"")
            .body(StubBody::repeated(
                Bytes::from(vec![b'0'; CHUNK]),
                REPEATS,
                &counter,
            ))
            .unwrap_or_else(|e| panic!("response: {e}"))
    }))
    .await;
    assert_eq!(
        stub.store().read_hint(VOLUME, None).await,
        Ok(HintRead::Missing),
        "an over-long hint degrades; it never errors and never wedges a reader"
    );
    let handed = sent.load(Ordering::Relaxed);
    assert!(
        handed < CHUNK * REPEATS,
        "the read must stop at the bound: the peer handed all {handed} bytes over"
    );
}

/// §5.8: seq 0 cannot hold a root, so a body of `0` degrades to `Missing`, not
/// `Current { seq: 0 }`, which would send every reader through a doomed
/// `GET root/0` first.
#[tokio::test]
async fn read_hint_degrades_a_zero_body_to_missing() {
    let stub = stub(answering(|_| {
        Response::builder()
            .status(StatusCode::OK)
            .header("etag", "\"v1\"")
            .body(StubBody::of(&b"00000000000000000000"[..]))
            .unwrap_or_else(|e| panic!("response: {e}"))
    }))
    .await;
    assert_eq!(
        stub.store().read_hint(VOLUME, None).await,
        Ok(HintRead::Missing)
    );
}

/// A body that fails the strict 20-digit parse degrades too.
#[tokio::test]
async fn read_hint_degrades_an_unparsable_body_to_missing() {
    let stub = stub(answering(|_| {
        Response::builder()
            .status(StatusCode::OK)
            .header("etag", "\"v1\"")
            .body(StubBody::of(&b"0000000000000000000-"[..]))
            .unwrap_or_else(|e| panic!("response: {e}"))
    }))
    .await;
    assert_eq!(
        stub.store().read_hint(VOLUME, None).await,
        Ok(HintRead::Missing)
    );
}

/// §5.8: a `200` with NO `ETag` degrades to `Missing` — it does not
/// error, and it does not fabricate a validator.
///
/// The `ETag` is REQUIRED on this resource, so this response is
/// non-conforming; the body is still a perfectly good seq. Erroring would
/// let a merely sloppy server wedge every reader on the volume for the
/// sake of an ADVISORY read whose whole cost is one saved round trip.
/// Fabricating a token is worse: its only use is the next
/// `If-None-Match`, and an invented validator a server then matches pins
/// the reader to a dead seq — `304` after every poll, no error anywhere,
/// hint revalidation apparently healthy — which is the silent stall §5.8 spends a
/// paragraph forbidding.
///
/// The body here PARSES, so nothing but the missing validator decides the
/// answer, and `Current { seq: 9, .. }` is what a fabricating client
/// returns.
#[tokio::test]
async fn read_hint_degrades_a_200_without_an_etag_to_missing() {
    let stub = stub(answering(|_| ok_body(&b"00000000000000000009"[..]))).await;
    assert_eq!(
        stub.store().read_hint(VOLUME, None).await,
        Ok(HintRead::Missing),
        "a missing ETag degrades; it never errors and never invents a token"
    );
}

/// The `304` row: hint revalidation. The cached token is echoed VERBATIM
/// in `If-None-Match` and never derived, parsed or compared.
#[tokio::test]
async fn read_hint_revalidates_with_the_cached_token() {
    let stub = stub(answering(|seen| {
        if seen
            .headers
            .get("if-none-match")
            .map(hyper::header::HeaderValue::as_bytes)
            == Some(b"\"tok-1\"")
        {
            refusal(StatusCode::NOT_MODIFIED, None)
        } else {
            ok_body(&b"00000000000000000009"[..])
        }
    }))
    .await;
    let store = stub.store();
    assert_eq!(
        store
            .read_hint(VOLUME, Some(&HintToken("\"tok-1\"".to_owned())))
            .await,
        Ok(HintRead::NotModified)
    );
}

/// **An UNSOLICITED `304` is not believed.** §5.8's `304` row is
/// reachable only when the request carried the `If-None-Match` it answers
/// — "a conditional compares a validator against a representation, and
/// cannot conjure one" — so a `304` to a conditional-less `GET hint` is a
/// response to a request no conforming client sent, and §8.1's totality
/// rule makes that the unexpected-status error. `granary-server` guards
/// the mirror case (`HintRead::NotModified` with no cached token is
/// `internal()`, handlers.rs); this is the client half of the same rule.
///
/// Believing it would report "nothing changed" about a token the client
/// never held — and a poll that sent no validator has no cached seq to
/// carry forward, so `NotModified` names nothing.
#[tokio::test]
async fn an_unsolicited_304_on_the_hint_is_refused() {
    let stub = stub(answering(|_| refusal(StatusCode::NOT_MODIFIED, None))).await;
    let got = stub.store().read_hint(VOLUME, None).await;
    assert!(
        matches!(
            &got,
            Err(RootStoreError::UnexpectedStatus { status: 304, .. })
        ),
        "a 304 answering a request that carried no If-None-Match must not read as NotModified, \
         got {got:?}"
    );
}

/// The CONTROL for the guard above: `GET root` defines no conditional
/// request at all, so its `304` was already an unexpected status. Both
/// endpoints refuse, which is what says the new guard is about the absent
/// validator rather than about the status.
#[tokio::test]
async fn an_unsolicited_304_on_get_root_is_refused() {
    let stub = stub(answering(|_| refusal(StatusCode::NOT_MODIFIED, None))).await;
    let got = stub.store().get_root(VOLUME, 1).await;
    assert!(
        matches!(
            &got,
            Err(RootStoreError::UnexpectedStatus { status: 304, .. })
        ),
        "got {got:?}"
    );
}

/// The well-formed `200`, with the token handed back for the next poll.
#[tokio::test]
async fn read_hint_reads_a_well_formed_hint() {
    let stub = stub(answering(|_| {
        Response::builder()
            .status(StatusCode::OK)
            .header("etag", "\"tok-9\"")
            .body(StubBody::of(&b"00000000000000000009"[..]))
            .unwrap_or_else(|e| panic!("response: {e}"))
    }))
    .await;
    assert_eq!(
        stub.store().read_hint(VOLUME, None).await,
        Ok(HintRead::Current {
            seq: 9,
            token: HintToken("\"tok-9\"".to_owned()),
        })
    );
}

// ------------------------------------------------- the local-refusal set

/// §13.3's four pre-request rows. The stub is LIVE and would answer every
/// one of them successfully, so "no request was sent" is asserted directly
/// from its log rather than inferred from an error.
#[tokio::test]
async fn local_refusals_send_no_request() {
    let stub = stub(answering(|_| {
        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header("content-range", "bytes 0-0/*")
            .body(StubBody::of(&b"x"[..]))
            .unwrap_or_else(|e| panic!("response: {e}"))
    }))
    .await;
    let store = stub.store();

    // 1. the volume is not a DNS-1123 label
    let got = store.get_root("Not/A/Label", 1).await;
    assert!(
        matches!(got, Err(RootStoreError::InvalidVolume { .. })),
        "a name is KEY MATERIAL, checked before it becomes one: {got:?}"
    );

    // 2. len == 0 — a zero-length range has no wire form at all (§7.4)
    let got = store.get_bin_range(&DIGEST, 0, 0).await;
    assert!(
        matches!(got, Err(RootStoreError::Backend(_))),
        "len == 0 is the seam's range error: {got:?}"
    );

    // 3. offset + len overflows u64
    let got = store.get_bin_range(&DIGEST, u64::MAX, 2).await;
    assert_eq!(got, Err(RootStoreError::RangeOverflow), "got {got:?}");

    // 4. offset at or past BIN_MAX_BYTES — past the end of EVERY object
    //    that could be stored at that address, from a frozen constant
    let got = store.get_bin_range(&DIGEST, BIN_MAX_BYTES, 8).await;
    assert!(
        matches!(got, Err(RootStoreError::Backend(_))),
        "the ceiling is decided locally, not by the server: {got:?}"
    );

    assert!(
        stub.seen().is_empty(),
        "a local refusal must precede the request: the peer saw {:?}",
        stub.seen()
    );
}

/// The volume check binds EVERY volume-taking method, not just the one a
/// test happened to pick. Five methods, one invalid name, no requests.
#[tokio::test]
async fn every_volume_taking_method_refuses_an_invalid_name_locally() {
    let stub = stub(answering(|_| ok_body(&b"x"[..]))).await;
    let store = stub.store();
    let bad = "-leading-dash";

    let id = GrainId::of(b"m");
    assert!(matches!(
        store.get_root(bad, 1).await,
        Err(RootStoreError::InvalidVolume { .. })
    ));
    assert!(matches!(
        store.put_root(bad, 1, vec![1]).await,
        Err(RootStoreError::InvalidVolume { .. })
    ));
    assert!(matches!(
        store.max_seq(bad).await,
        Err(RootStoreError::InvalidVolume { .. })
    ));
    assert!(matches!(
        store.read_hint(bad, None).await,
        Err(RootStoreError::InvalidVolume { .. })
    ));
    assert!(matches!(
        store.write_hint(bad, 1).await,
        Err(RootStoreError::InvalidVolume { .. })
    ));
    assert!(matches!(
        store.get_meta(bad, &id).await,
        Err(RootStoreError::InvalidVolume { .. })
    ));
    assert!(matches!(
        store.put_meta(bad, &id, vec![1]).await,
        Err(RootStoreError::InvalidVolume { .. })
    ));
    assert!(stub.seen().is_empty(), "no request may be built from it");
}

// --------------------------------------------------------- the extent gate

/// Serve a `206` with a chosen `Content-Range` and a chosen body.
fn ranged(content_range: impl Into<String>, body: &'static [u8]) -> Answer {
    let content_range = content_range.into();
    answering(move |_| {
        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header("content-range", content_range.clone())
            .body(StubBody::of(body))
            .unwrap_or_else(|e| panic!("response: {e}"))
    })
}

/// The `Range` field value the client sent, from the peer's own log.
fn range_header(seen: &[Recorded]) -> String {
    let [only] = seen else {
        panic!("expected exactly one request, got {seen:?}");
    };
    String::from_utf8(
        only.headers
            .get("range")
            .unwrap_or_else(|| panic!("no Range field: {:?}", only.headers))
            .as_bytes()
            .to_vec(),
    )
    .unwrap_or_else(|e| panic!("Range is not UTF-8: {e}"))
}

/// CHECK 4 is the only bound on a ranged read's allocation, and this is
/// the input that reaches it.
///
/// `get_bin_range`'s local rows bound the OFFSET and not the length
/// (§13.3's table is four rows and closed), so `len == u32::MAX` is
/// accepted locally and the client asks for `bytes=0-4294967294` — asserted
/// here from the peer's log, because it is a surprising thing for this
/// client to send and the reason it is safe is check 4 rather than
/// restraint. A hostile pinned server that answers that extent verbatim
/// passes checks 1, 2 and 3; check 4 is what stands between it and a 4 GiB
/// `read_capped` cap, and NOTHING ELSE DOES.
#[tokio::test]
async fn an_extent_wider_than_the_ceiling_is_refused_and_never_capped_at_its_width() {
    let stub = stub(ranged("bytes 0-4294967294/*", b"tiny")).await;
    let got = stub.store().get_bin_range(&DIGEST, 0, u32::MAX).await;
    let reason = refusal_reason("check 4: over the ceiling", got);
    assert!(
        reason.contains("wider than BIN_MAX_BYTES"),
        "check 4 must be the refusal, not a later one: {reason:?}"
    );
    let seen = stub.seen();
    assert_eq!(seen.len(), 1, "exactly one request, got {seen:?}");
    assert_eq!(range_header(&seen), "bytes=0-4294967294");
}

/// The OTHER half of that decision, pinned so nobody closes it by
/// "symmetry": an extent that merely ENDS past the ceiling is sent, and
/// its short read is a SUCCESS.
///
/// `offset >= BIN_MAX_BYTES` is refused locally, and `offset + len >
/// BIN_MAX_BYTES` deliberately is not. The first exists for a DIVERGENCE
/// (§13.3): a server answers `416` for an over-ceiling `first-pos` whether
/// or not the bin exists, where the in-process implementations answer
/// `NotFound` for an absent one — so a client that asked would disagree
/// with them. The second has no such divergence. It starts INSIDE every
/// legal object, §7.2 check 2 declares "short is legal", and every
/// implementation of the seam short-reads it identically; refusing it
/// locally would refuse a request that is satisfiable in part.
#[tokio::test]
async fn an_extent_ending_past_the_ceiling_is_sent_and_short_reads() {
    let last = BIN_MAX_BYTES - 1;
    let stub = stub(ranged(format!("bytes {last}-{last}/*"), b"x")).await;
    assert_eq!(
        stub.store().get_bin_range(&DIGEST, last, 16).await,
        Ok(b"x".to_vec()),
        "the overhang short read is a success, not a local refusal"
    );
    assert_eq!(
        range_header(&stub.seen()),
        format!("bytes={last}-{}", last + 15)
    );
}

/// Pull the reason out of a refusal, or say what came back instead.
///
/// Every caller is a `get_bin_range` extent-gate row, so the kind is
/// asserted here once rather than at each call site: none of this
/// gate's refusals is ever the object-class `OverCap` kind — the cap
/// here is the extent the request itself declared.
fn refusal_reason(name: &str, got: Result<Vec<u8>, RootStoreError>) -> String {
    match got {
        Err(RootStoreError::RefusedResponse { reason, kind }) => {
            assert_eq!(
                kind,
                RefusalKind::Extent,
                "{name}: a get_bin_range refusal must be Extent, never a size-cap kind"
            );
            reason
        }
        other => panic!("{name}: expected RefusedResponse, got {other:?}"),
    }
}

/// §7.2's gate, row by row. Every failure is `RefusedResponse` and not
/// `Backend`: a transport failure invites a retry, while a response that
/// violates its own extent will violate it again.
///
/// **Each row asserts the REASON, not just the variant**, and that is what
/// makes it a row for its own check rather than for the gate in
/// aggregate. Asserting the variant alone, several of these are satisfied
/// by a LATER check catching the input after the one under test was
/// deleted — measured, not supposed: with check 0's `last < first` guard
/// removed, `bytes 19-10/*` is caught by check 1 and the whole file stayed
/// green.
#[tokio::test]
async fn get_bin_range_runs_the_extent_gate() {
    // The positive control FIRST — without it every row below is satisfied
    // by an implementation that refuses every 206.
    let good = stub(ranged("bytes 10-19/*", b"0123456789")).await;
    assert_eq!(
        good.store().get_bin_range(&DIGEST, 10, 10).await,
        Ok(b"0123456789".to_vec())
    );

    // A SHORT READ is a success, not an error: the range started inside
    // the object and overhung its end, and the server narrowed the extent
    // honestly.
    let short_read = stub(ranged("bytes 10-14/*", b"01234")).await;
    assert_eq!(
        short_read.store().get_bin_range(&DIGEST, 10, 10).await,
        Ok(b"01234".to_vec())
    );

    // check 0 — a reversed extent. A client computing the width with
    // saturating arithmetic would turn this into a zero-width one.
    let reversed = stub(ranged("bytes 19-10/*", b"0123456789")).await;
    // check 0 — a reversed extent that SHARES the requested first-pos,
    // which is the input check 1 cannot stand in for. Delete check 0's
    // `last < first` and this one walks straight through checks 1 and 2
    // and lands on check 3 — delete that too and `get_bin_range(_, 10, 10)`
    // answers `Ok([])`: a caller that asked for ten bytes is handed zero
    // bytes AND a success. `bytes 19-10/*` above cannot show that, because
    // check 1 refuses it on the way past.
    let reversed_at_offset = stub(ranged("bytes 10-9/*", b"")).await;
    // check 0 — a SIGNED first-pos. `str::parse::<u64>` accepts a leading
    // `+`, so without the digits-only rule `bytes +10-19/*` decodes as
    // `(10, 19)`: a second spelling of one extent, on a wire this document
    // keeps total.
    let signed = stub(ranged("bytes +10-19/*", b"0123456789")).await;
    // check 0 — a numeric complete-length, which §7.2 forbids: the seam
    // supplies no object length, so a server that filled one in invented
    // it.
    let numeric = stub(ranged("bytes 10-19/100", b"0123456789")).await;
    // check 0, the field half — TWO `Content-Range` fields, the first of
    // them impeccable. A gate that took the first value instead of
    // requiring exactly one accepts this and returns the bytes: the
    // response then declares two different extents and the client picked
    // one, which is not an answer to anything.
    let doubled = stub(answering(|_| {
        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header("content-range", "bytes 10-19/*")
            .header("content-range", "bytes 0-9/*")
            .body(StubBody::of(&b"0123456789"[..]))
            .unwrap_or_else(|e| panic!("response: {e}"))
    }))
    .await;
    // check 0 — no field at all
    let absent = stub(answering(|_| {
        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .body(StubBody::of(&b"0123456789"[..]))
            .unwrap_or_else(|e| panic!("response: {e}"))
    }))
    .await;
    // check 1 — a WRONG SLICE whose width is exactly right. A backend that
    // ignored the range answers 0-9 for a request at offset 10, and every
    // width-only test passes it.
    let wrong_slice = stub(ranged("bytes 0-9/*", b"0123456789")).await;
    // check 2 — one byte past the requested extent, the off-by-one an
    // inclusive/exclusive mix-up produces on every ranged read
    let too_long = stub(ranged("bytes 10-20/*", b"0123456789A")).await;
    // check 5 — a SHORT BODY under an honest-looking extent: checks 0-4
    // all pass, and the caller receives five bytes it believes are ten
    let short_body = stub(ranged("bytes 10-19/*", b"01234")).await;
    // check 5 — a body LONGER than the declared extent
    let long_body = stub(ranged("bytes 10-19/*", b"0123456789EXTRA")).await;
    // the `last-pos + 1` overflow guard, which sits between checks 1 and 2
    // and is the reason neither of them subtracts on an unchecked value
    let overflowing = stub(ranged("bytes 10-18446744073709551615/*", b"0123456789")).await;

    for (name, s, because) in [
        (
            "check 0: reversed, sharing the requested first-pos",
            &reversed_at_offset,
            "Content-Range is not `bytes first-last/*`",
        ),
        (
            "check 0: reversed",
            &reversed,
            "Content-Range is not `bytes first-last/*`",
        ),
        (
            "check 0: a signed position",
            &signed,
            "Content-Range is not `bytes first-last/*`",
        ),
        (
            "check 0: numeric complete-length",
            &numeric,
            "Content-Range is not `bytes first-last/*`",
        ),
        (
            "check 0: absent field",
            &absent,
            "must carry exactly one Content-Range field",
        ),
        (
            "check 0: two fields",
            &doubled,
            "must carry exactly one Content-Range field",
        ),
        (
            "check 1: wrong slice",
            &wrong_slice,
            "starts somewhere other than the requested offset",
        ),
        ("last-pos + 1 overflows", &overflowing, "last-pos overflows"),
        (
            "check 2: past the extent",
            &too_long,
            "reaches past the requested extent",
        ),
        ("check 5: short body", &short_body, "bytes under a"),
        (
            "check 5: long body",
            &long_body,
            "longer than its declared extent",
        ),
    ] {
        let got = s.store().get_bin_range(&DIGEST, 10, 10).await;
        let reason = refusal_reason(name, got);
        assert!(
            reason.contains(because),
            "{name}: expected a refusal naming {because:?}, got {reason:?}"
        );
    }
}

/// §5.2: a `404` on a bin is `Err(NotFound)`, and a `416`/`400`/`500` is a
/// backend error — the map is per endpoint, and here no `404` is a
/// success.
#[tokio::test]
async fn get_bin_range_maps_its_own_statuses() {
    let missing = stub(answering(|_| {
        refusal(StatusCode::NOT_FOUND, Some("not-found"))
    }))
    .await;
    assert_eq!(
        missing.store().get_bin_range(&DIGEST, 0, 8).await,
        Err(RootStoreError::NotFound)
    );

    let unsatisfiable = stub(answering(|_| {
        refusal(StatusCode::RANGE_NOT_SATISFIABLE, Some("bad-range"))
    }))
    .await;
    assert!(matches!(
        unsatisfiable.store().get_bin_range(&DIGEST, 0, 8).await,
        Err(RootStoreError::UnexpectedStatus { .. })
    ));

    // §7.2: a 200 in answer to a Range request on a bin is forbidden, and
    // falls to §8.1's totality rule.
    let whole = stub(answering(|_| ok_body(&b"01234567"[..]))).await;
    assert!(matches!(
        whole.store().get_bin_range(&DIGEST, 0, 8).await,
        Err(RootStoreError::UnexpectedStatus { .. })
    ));
}

// -------------------------------------------------------- put_root (§5.5)

/// §5a.4: `PUT root` is the one request this client must never retry. One
/// request, one `409`, one `AlreadyExists` — and the ONE-PROBE RULE is the
/// caller's, not this method's.
///
/// **WHAT THIS TEST DOES NOT PROVE.** It sends one request over a FRESH connection, and
/// hyper-util consults `retry_canceled_requests` only when
/// `connection_reused` is true (hyper-util-0.1.20
/// `src/client/legacy/client.rs:257`). So the store's flag is invisible
/// here: flipping it to `true` leaves this row — and every other row in
/// the crate — green, measured at 157/157. The docstring that said "the
/// store turns it off for exactly this reason" offered this test as the
/// evidence, and this test is not evidence for it.
///
/// **Nor is it reachable by tightening this test.** The retry needs a
/// connection that dies BETWEEN checkout and write. hyper-util's pool
/// filters closed connections at checkout, so a connection the peer closed
/// while idle is not chosen at all: measured with a hand-rolled HTTP/1.1
/// stub that serves two exchanges and closes, 12 consecutive runs, and the
/// third request reached the server on a fresh connection every time —
/// byte-for-byte identically with the flag on and with it off. Prising
/// that window open needs a timer or a `select!` to close the socket
/// mid-checkout, and the workspace bans both with no test exemption; a
/// scheduler race is not a row anyway.
///
/// So what holds §5a.4 is the constructor and the argument written beside
/// it, not a green test — and that is now written down instead of
/// implied.
#[tokio::test]
async fn put_root_issues_one_put_and_never_retries() {
    let stub = stub(answering(|_| {
        refusal(StatusCode::CONFLICT, Some("already-exists"))
    }))
    .await;
    let got = stub.store().put_root(VOLUME, 3, vec![7; 16]).await;
    assert_eq!(got, Err(RootStoreError::AlreadyExists));
    let seen = stub.seen();
    assert_eq!(seen.len(), 1, "exactly one PUT, got {seen:?}");
    let [only] = seen.as_slice() else {
        panic!("unreachable: length asserted above");
    };
    assert_eq!(only.method, Method::PUT);
    assert_eq!(
        only.path,
        format!("/volume/{VOLUME}/root/00000000000000000003")
    );
    assert_eq!(only.body, vec![7; 16]);
}

/// §5.10: **no granary server generates a `412`**, and the row exists so
/// the map is total for one an INTERMEDIARY supplies.
///
/// Without it a `412` falls through to §8.1's totality rule and becomes a
/// `Backend` error — the retryable class — for the one status that says a
/// precondition nobody sent was evaluated somewhere in the path. On `PUT
/// root` that matters most: retrying is the blind retry §5a.4 forbids,
/// and the caller cannot tell "the seq is taken" from "a proxy answered"
/// unless the two errors differ.
#[tokio::test]
async fn a_412_from_an_intermediary_is_its_own_error() {
    let stub = stub(answering(|_| {
        refusal(StatusCode::PRECONDITION_FAILED, None)
    }))
    .await;
    let store = stub.store();
    assert_eq!(
        store.put_root(VOLUME, 1, vec![1]).await,
        Err(RootStoreError::Precondition)
    );
    assert_eq!(
        store.get_root(VOLUME, 1).await,
        Err(RootStoreError::Precondition)
    );
    assert_eq!(
        store.read_hint(VOLUME, None).await,
        Err(RootStoreError::Precondition)
    );
}

/// On the client, a wire `503` must classify as
/// [`RootStoreError::Unavailable`], never fall through §8.1's totality
/// rule to [`RootStoreError::Backend`] — the fetcher's own backpressure
/// (window AIMD, bounded re-poll) needs a TYPED signal to act on, and a
/// rendered `Backend("… unexpected status 503")` string is exactly the
/// string-matching defect class that typed classification must avoid. All
/// NINE endpoints, because all nine route their unlisted statuses
/// through the one totality function this mapping lives in.
#[tokio::test]
async fn a_503_classifies_as_unavailable_never_backend() {
    let stub = stub(answering(|_| {
        refusal(StatusCode::SERVICE_UNAVAILABLE, None)
    }))
    .await;
    let store = stub.store();
    let id = GrainId::of(b"whatever");

    assert_eq!(
        store.get_root(VOLUME, 1).await,
        Err(RootStoreError::Unavailable {
            operation: "GET root",
            status: 503,
        })
    );
    assert_eq!(
        store.get_meta(VOLUME, &id).await,
        Err(RootStoreError::Unavailable {
            operation: "GET meta",
            status: 503,
        })
    );
    assert_eq!(
        store.get_bin_range(&DIGEST, 0, 8).await,
        Err(RootStoreError::Unavailable {
            operation: "GET bin",
            status: 503,
        })
    );
    assert_eq!(
        store.put_root(VOLUME, 1, vec![1]).await,
        Err(RootStoreError::Unavailable {
            operation: "PUT root",
            status: 503,
        })
    );
    assert_eq!(
        store.put_bin(&DIGEST, vec![1]).await,
        Err(RootStoreError::Unavailable {
            operation: "PUT bin",
            status: 503,
        })
    );
    assert_eq!(
        store.put_meta(VOLUME, &id, vec![1]).await,
        Err(RootStoreError::Unavailable {
            operation: "PUT meta",
            status: 503,
        })
    );
    assert_eq!(
        store.read_hint(VOLUME, None).await,
        Err(RootStoreError::Unavailable {
            operation: "GET hint",
            status: 503,
        })
    );
    assert_eq!(
        store.write_hint(VOLUME, 1).await,
        Err(RootStoreError::Unavailable {
            operation: "PUT hint",
            status: 503,
        })
    );
    assert_eq!(
        store.max_seq(VOLUME).await,
        Err(RootStoreError::Unavailable {
            operation: "GET max-seq",
            status: 503,
        })
    );
}

#[tokio::test]
async fn all_seam_429_answers_are_unavailable() {
    for token in [Some("rate-limited"), None] {
        let stub = stub(answering(move |_| {
            refusal(StatusCode::TOO_MANY_REQUESTS, token)
        }))
        .await;
        let store = stub.store();
        let id = GrainId::of(b"whatever");

        assert_eq!(
            store.get_root(VOLUME, 1).await,
            Err(RootStoreError::Unavailable {
                operation: "GET root",
                status: 429,
            })
        );
        assert_eq!(
            store.get_meta(VOLUME, &id).await,
            Err(RootStoreError::Unavailable {
                operation: "GET meta",
                status: 429,
            })
        );
        assert_eq!(
            store.get_bin_range(&DIGEST, 0, 8).await,
            Err(RootStoreError::Unavailable {
                operation: "GET bin",
                status: 429,
            })
        );
        assert_eq!(
            store.put_root(VOLUME, 1, vec![1]).await,
            Err(RootStoreError::Unavailable {
                operation: "PUT root",
                status: 429,
            })
        );
        assert_eq!(
            store.put_bin(&DIGEST, vec![1]).await,
            Err(RootStoreError::Unavailable {
                operation: "PUT bin",
                status: 429,
            })
        );
        assert_eq!(
            store.put_meta(VOLUME, &id, vec![1]).await,
            Err(RootStoreError::Unavailable {
                operation: "PUT meta",
                status: 429,
            })
        );
        assert_eq!(
            store.read_hint(VOLUME, None).await,
            Err(RootStoreError::Unavailable {
                operation: "GET hint",
                status: 429,
            })
        );
        assert_eq!(
            store.write_hint(VOLUME, 1).await,
            Err(RootStoreError::Unavailable {
                operation: "PUT hint",
                status: 429,
            })
        );
        assert_eq!(
            store.max_seq(VOLUME).await,
            Err(RootStoreError::Unavailable {
                operation: "GET max-seq",
                status: 429,
            })
        );
    }
}

/// The nine targets are §4.2's, spelled by concatenation onto the base and
/// never percent-encoded (§4.3).
#[tokio::test]
async fn the_urls_are_the_nine_resources() {
    let stub = stub(answering(|_| refusal(StatusCode::CREATED, None))).await;
    let store = stub.store();
    let id = GrainId::of(b"meta bytes");
    let _ = store.put_bin(&DIGEST, vec![1]).await;
    let _ = store.put_meta(VOLUME, &id, vec![1]).await;
    let _ = store.put_root(VOLUME, 1, vec![1]).await;
    let _ = store.write_hint(VOLUME, 1).await;
    let paths: Vec<String> = stub.seen().into_iter().map(|r| r.path).collect();
    assert_eq!(
        paths,
        vec![
            format!("/bin/{}", "5a".repeat(DIGEST_LEN)),
            format!("/volume/{VOLUME}/meta/{id}"),
            format!("/volume/{VOLUME}/root/00000000000000000001"),
            format!("/volume/{VOLUME}/hint"),
        ]
    );
}

/// The `201`/`200` split is the seam's novelty `bool` and nothing else.
#[tokio::test]
async fn put_bin_reports_novelty_from_the_status() {
    let novel = stub(answering(|_| refusal(StatusCode::CREATED, None))).await;
    assert_eq!(novel.store().put_bin(&DIGEST, vec![1, 2]).await, Ok(true));
    let present = stub(answering(|_| refusal(StatusCode::OK, None))).await;
    assert_eq!(
        present.store().put_bin(&DIGEST, vec![1, 2]).await,
        Ok(false)
    );
}

/// `write_hint` answers `204` on both the create and the replace path
/// (§5.9, deviation 9), and a failure is survivable by design.
#[tokio::test]
async fn write_hint_takes_the_204() {
    let stub = stub(answering(|_| refusal(StatusCode::NO_CONTENT, None))).await;
    assert_eq!(stub.store().write_hint(VOLUME, 5).await, Ok(()));
    let seen = stub.seen();
    let [only] = seen.as_slice() else {
        panic!("expected one PUT, got {seen:?}");
    };
    assert_eq!(only.body, b"00000000000000000005".to_vec());
}

/// §5a.2 applies to what a client READS BACK: a root over `ROOT_MAX_BYTES`
/// is refused rather than buffered. The server is authenticated; the
/// bucket behind it is not.
///
/// **This stub is not a conforming granary server, and that is what makes
/// it a distinct reachability row.** A conforming server applies its OWN
/// `within_cap` check to what its store hands back
/// (`granary-server`'s `handlers::get_root`) and answers `500` rather
/// than streaming an oversized body through — the client then sees
/// `Backend`, not `RefusedResponse`, and `commit` reports
/// `ProbeUnresolved`, not `LostRace` (a distinct, wire-visible server
/// answer for this case is a protocol change, not an adapter choice). So
/// `OverCap` reaching the settling probe over THIS wire needs a peer
/// that streams the oversized body anyway —
/// exactly what this stub does — never a real granary server; the other
/// route that reaches `OverCap` is the direct store route
/// (`granary-store`'s own adapter over `object_store`, exercised in that
/// crate's own suite).
#[tokio::test]
async fn an_over_cap_root_response_is_refused_not_buffered() {
    const CHUNK: usize = 8 * 1024;
    const REPEATS: usize = 32; // 256 KiB, four times ROOT_MAX_BYTES
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&sent);
    let stub = stub(answering(move |_| {
        Response::builder()
            .status(StatusCode::OK)
            .body(StubBody::repeated(
                Bytes::from(vec![b'r'; CHUNK]),
                REPEATS,
                &counter,
            ))
            .unwrap_or_else(|e| panic!("response: {e}"))
    }))
    .await;
    let got = stub.store().get_root(VOLUME, 1).await;
    assert!(
        matches!(
            got,
            Err(RootStoreError::RefusedResponse {
                kind: RefusalKind::OverCap,
                ..
            })
        ),
        "got {got:?}; also REACHABILITY evidence for the ONE-PROBE RULE's settling probe: a \
         peer that streams an oversized root body over a real h2/TLS connection can deliver \
         OverCap to it (a conforming granary server, unlike this stub, would not)"
    );
}

/// **Reachability, measured rather than assumed: `NoProgress` on the
/// settling probe's own read is NOT reachable through this workspace's
/// h2 client stack either, though for a DIFFERENT reason than
/// `Framing`'s.** A flood of empty DATA frames is ordinary, spec-legal
/// HTTP/2 that this very stub can send — the attempt below really does
/// reach the wire, unlike a second trailer frame — but `h2` 0.4.18's own
/// client-side flood defence (`proto::streams::counts::Counts::record_data_frame`,
/// budget `DEFAULT_DATA_FRAME_BUDGET` = `DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD`
/// (256) × 100 = 25,600, and every DATA frame under the 256-byte
/// threshold consumes `256 - len` of it) resets the connection with
/// `GOAWAY(ENHANCE_YOUR_CALM, "too_many_data_frames")` after roughly the
/// **100th** empty frame — an order of magnitude below granary's own
/// 1,024-frame `NoProgress` allowance. So `read_capped`'s own zero-progress
/// counter never gets the chance to run out on a real connection: the
/// transport layer it rides on refuses first, and the refusal surfaces
/// here as `RootStoreError::Backend`, not `RefusedResponse`. Measured by
/// running exactly this row with the granary-side threshold raised past
/// what `h2` tolerates and confirming the GOAWAY reason in the error's
/// source chain — a fact about the pinned `h2` dependency, not a gap in
/// this stub.
#[tokio::test]
async fn a_no_progress_flood_trips_the_transport_before_granarys_own_limit() {
    let mut flood: VecDeque<Bytes> = (0..=1024).map(|_| Bytes::new()).collect();
    flood.push_back(Bytes::from_static(b"never reached"));
    let stub = stub(answering(move |_| {
        Response::builder()
            .status(StatusCode::OK)
            .body(StubBody {
                chunks: flood.clone(),
                repeat: None,
                sent: Arc::new(AtomicUsize::new(0)),
            })
            .unwrap_or_else(|e| panic!("response: {e}"))
    }))
    .await;
    let got = stub.store().get_root(VOLUME, 1).await;
    assert!(
        matches!(got, Err(RootStoreError::Backend(_))),
        "expected the h2 client's OWN flood defence to reset the connection before granary's \
         1,024-frame NoProgress counter ever runs out — got {got:?}. If this now sees \
         RefusedResponse{{ kind: NoProgress, .. }}, `h2` changed its data-frame budget and this \
         row's REACHABILITY finding (recorded on this test's own doc) needs re-measuring, not \
         silently keeping the old comment."
    );
}

// **Reachability: `Framing` on the settling probe's own read is NOT
// reachable via any h2 peer this stub — or any conformant one — can
// build, unlike the `NoProgress` row above.** `h2` 0.4.18's
// `SendStream::send_trailers` closes the send side of the stream as
// part of sending the FIRST trailer HEADERS frame
// (`proto/streams/send.rs::send_trailers` calls `stream.state.send_close()`
// before queuing the frame), and a second call on a stream that is no
// longer send-streaming returns `Err(UserError::UnexpectedFrameType)`
// from inside the crate — never reaching the wire. Nothing in this
// stub, or in `granary-server`'s own h2-leg conformance client (a
// dev-dependency of a different crate, built for hand-crafting
// malformed CLIENT requests rather than server responses), exposes a
// lower-level way to place a second trailer HEADERS frame on a
// stream. So the only place this refusal is producible at all is a
// synthetic `hyper::body::Body` handed directly to `read_capped` —
// exactly `http_store::tests::read_capped_bounds_frames_that_carry_no_payload`,
// this crate's own unit test — which is deliberate defence-in-depth
// against a non-conformant peer, not a gap in this file's coverage of
// a case any real h2 connection here is expected to reach.

/// §5a.2's headline claim, and the one nothing tested: **no buffer is
/// ever sized from `Content-Length`.**
///
/// The stub declares 128 TiB and hands over ten bytes. A reader that sized
/// its buffer from the declaration would ask the allocator for
/// 140737488355328 bytes before reading one of them — and an allocation
/// failure in Rust is an ABORT, not a catchable error, so a peer-chosen
/// header becomes a process kill. Measured, by sizing `read_capped`'s
/// buffer from `size_hint().upper()`: `memory allocation of
/// 140737488355328 bytes failed`, SIGABRT, no assertion involved.
///
/// The shipped reader starts empty and grows only by bytes that actually
/// arrived, so the declaration costs nothing and the ten-byte body is
/// caught one layer down as the framing error it is.
#[tokio::test]
async fn a_response_body_is_never_sized_from_content_length() {
    const LIE: u64 = 1 << 47;
    let stub = stub(answering(|_| {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-length", LIE.to_string())
            .body(StubBody::of(&b"0123456789"[..]))
            .unwrap_or_else(|e| panic!("response: {e}"))
    }))
    .await;
    let got = stub.store().get_root(VOLUME, 1).await;
    assert!(
        matches!(got, Err(RootStoreError::Backend(_))),
        "ten bytes under a 128 TiB declaration is a framing error, got {got:?}"
    );
}

// ------------------------------------------------------------ independent TLS and signing anchors

/// Flip the PIN and TLS breaks, while root verification is
/// never reached.
///
/// The two halves of the pinned-key configuration are independent
/// consumers, and this is the direction that proves the TLS half is not
/// silently doing the signing half's work.
#[tokio::test]
async fn d5_flip_pin_breaks_tls_and_leaves_root_verification_unreached() {
    let key = signing_key(9);
    let root_bytes = signed_root(&key);
    let stub = stub(answering(move |_| ok_body(root_bytes.clone()))).await;

    // The control: with the RIGHT pin the bytes arrive and the signature
    // verifies — so the refusal below is the pin's doing.
    let verifier =
        RootVerifier::trusting(*key.public_key()).unwrap_or_else(|e| panic!("verifier: {e}"));
    let ok_store = stub.store();
    let control = resolve_at_verified(
        &ok_store,
        VOLUME,
        1,
        &verifier,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await;
    assert!(
        !matches!(
            control,
            Err(ResolveError::UnknownSigner { .. }
                | ResolveError::BadSignature { .. }
                | ResolveError::Remote(_))
        ),
        "the control must reach PAST both TLS and the signature, got {control:?}"
    );

    // Flip one bit of the pin. Nothing else changes.
    let mut wrong = stub.pin;
    wrong[0] ^= 1;
    let store = HttpStore::new(&stub.base(), vec![wrong], &AmbientNetwork)
        .unwrap_or_else(|e| panic!("http store: {e}"));
    let got = resolve_at_verified(
        &store,
        VOLUME,
        1,
        &verifier,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await;
    assert!(
        matches!(got, Err(ResolveError::Remote(RootStoreError::Backend(_)))),
        "a flipped pin is a transport refusal, got {got:?}"
    );
}

/// Flip the SIGNING KEY and root verification breaks, while
/// TLS is untouched.
#[tokio::test]
async fn d5_flip_signing_key_breaks_root_verification_and_leaves_tls_intact() {
    let key = signing_key(9);
    let root_bytes = signed_root(&key);
    let stub = stub(answering(move |_| ok_body(root_bytes.clone()))).await;
    let store = stub.store();

    let right =
        RootVerifier::trusting(*key.public_key()).unwrap_or_else(|e| panic!("verifier: {e}"));
    let control = resolve_at_verified(
        &store,
        VOLUME,
        1,
        &right,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await;
    assert!(
        !matches!(
            control,
            Err(ResolveError::UnknownSigner { .. }
                | ResolveError::BadSignature { .. }
                | ResolveError::Remote(_))
        ),
        "the control must pass the signature check, got {control:?}"
    );

    let stranger = signing_key(11);
    let wrong =
        RootVerifier::trusting(*stranger.public_key()).unwrap_or_else(|e| panic!("verifier: {e}"));
    let got = resolve_at_verified(
        &store,
        VOLUME,
        1,
        &wrong,
        None,
        ResolveTarget::WholeTree,
        &mut |_, _| Ok(()),
    )
    .await;
    assert!(
        matches!(got, Err(ResolveError::UnknownSigner { .. })),
        "a flipped anchor is a signature refusal, not a transport one: {got:?}"
    );
    assert!(
        stub.seen()
            .iter()
            .any(|r| r.path.ends_with("/root/00000000000000000001")),
        "TLS stayed intact: the root was fetched over the same pinned connection"
    );
}

// ----------------------------------------------- the default publish route

/// The default publish route, exercised on the wire: with pins configured
/// the shipped client publishes THROUGH THE SERVER, and the observation is
/// that a stub-pinned endpoint receives the request. A route enum that
/// merely *said* `Server` would be satisfied by a constructor pointed
/// anywhere.
#[tokio::test]
async fn publish_defaults_to_the_server_route_when_pins_are_configured() {
    let stub = stub(answering(|_| {
        refusal(StatusCode::NOT_FOUND, Some("not-found"))
    }))
    .await;
    let route = open_publish_route(&stub.base(), Some(vec![stub.pin]), false, None, &|_| None)
        .unwrap_or_else(|e| panic!("route: {e}"));
    let PublishRoute::Server(store) = route else {
        panic!("pins configured must route through the server, not the bucket");
    };
    assert_eq!(store.max_seq(VOLUME).await, Ok(None));
    let seen = stub.seen();
    let [only] = seen.as_slice() else {
        panic!("the pinned endpoint must receive the request, saw {seen:?}");
    };
    assert_eq!(only.path, format!("/volume/{VOLUME}/max-seq"));
}

/// The direct-S3 path survives ONLY behind the explicit opt-out — kept for
/// the `MinIO` conformance harness and local dev.
#[tokio::test]
async fn publish_with_the_opt_out_and_no_pins_goes_direct_to_s3() {
    let route = open_publish_route("http://127.0.0.1:9000", None, true, Some("b"), &|_| None)
        .unwrap_or_else(|e| panic!("route: {e}"));
    assert!(
        matches!(route, PublishRoute::DirectS3(_)),
        "--direct-s3 is the only way to the bucket"
    );
}

/// NEITHER is a usage error naming BOTH options — never a silent fallback
/// to S3, which is exactly how "the client holds no bucket
/// credentials" stops being true without anyone noticing.
#[tokio::test]
async fn publish_without_pins_or_the_opt_out_refuses() {
    let err = open_publish_route("https://example.invalid", None, false, Some("b"), &|_| None)
        .expect_err("no transport chosen must not fall back to the bucket");
    assert!(matches!(err, RouteError::NoTransport), "got {err:?}");
}

/// BOTH is a usage error too. `--direct-s3` is an opt-OUT of pinning, so
/// an invocation that also supplies pins is asking for two different trust
/// models and must be told, not silently given one of them.
#[tokio::test]
async fn publish_with_both_pins_and_the_opt_out_refuses() {
    let err = open_publish_route(
        "https://example.invalid",
        Some(vec![[9_u8; 32]]),
        true,
        Some("b"),
        &|_| None,
    )
    .expect_err("pins plus the opt-out is two trust models");
    assert!(matches!(err, RouteError::BothTransports), "got {err:?}");
}

/// **An EMPTY pin set is not a server route.** `parse_pin_set` answers
/// `Ok(vec![])` for a blank list and `PinnedServerVerifier::new` accepts
/// one on purpose ("not configured yet must never mean accept anything"),
/// so `Some(vec![])` arriving here would select the through-the-server
/// path with a verifier that refuses every certificate — a route that
/// fails closed, which is why this is a diagnosis defect and not a hole,
/// and fails as a handshake error rather than as the configuration error
/// it is. The CLI refuses it at both entry points; the library refuses it
/// too, so `granary-sim` and any other caller get the same answer.
#[tokio::test]
async fn an_empty_pin_set_is_not_a_server_route() {
    let err = open_publish_route(
        "https://example.invalid",
        Some(Vec::new()),
        false,
        None,
        &|_| None,
    )
    .expect_err("an empty pin set refuses every certificate; it names no server");
    assert!(matches!(err, RouteError::EmptyPins), "got {err:?}");
}

/// R11-d/e: the direct-S3 builder reads credentials BY NAME and never
/// sweeps the environment. The only other names it reads are the ambient proxy
/// variables, to report that the route ignores them. `AWS_ALLOW_HTTP` sitting in a shell for some
/// other tool must not reach this builder — the scheme of the endpoint the
/// operator wrote is the only input to `allow_http`.
#[tokio::test]
async fn the_direct_s3_route_reads_credentials_by_name_and_never_sweeps() {
    let asked: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&asked);
    let env = move |name: &str| -> Option<String> {
        if let Ok(mut g) = seen.lock() {
            g.push(name.to_owned());
        }
        match name {
            granary_client::ENV_AWS_ACCESS_KEY_ID => Some("id".to_owned()),
            granary_client::ENV_AWS_SECRET_ACCESS_KEY => Some("secret".to_owned()),
            _ => None,
        }
    };
    let route = open_publish_route("https://s3.example.invalid", None, true, Some("b"), &env)
        .unwrap_or_else(|e| panic!("route: {e}"));
    assert!(matches!(route, PublishRoute::DirectS3(_)));
    let names = asked
        .lock()
        .unwrap_or_else(|e| panic!("poisoned: {e}"))
        .clone();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    // The four credential variables, each named, plus the six proxy
    // variables, read only so the route can report that it ignores them.
    let mut expected: Vec<String> = [
        granary_client::ENV_AWS_ACCESS_KEY_ID,
        granary_client::ENV_AWS_REGION,
        granary_client::ENV_AWS_SECRET_ACCESS_KEY,
        granary_client::ENV_AWS_SESSION_TOKEN,
    ]
    .into_iter()
    .chain(granary_store::http_client::AMBIENT_PROXY_VARIABLES)
    .map(str::to_owned)
    .collect();
    expected.sort_unstable();
    assert_eq!(
        sorted, expected,
        "exactly these variables, each named; a sweep would read the namespace"
    );
}

/// A schemeless endpoint is refused where it is READ, not where it is
/// used: a client that came up and then failed every request is the
/// failure this comparison exists to prevent.
#[tokio::test]
async fn a_schemeless_direct_s3_endpoint_is_refused() {
    let err = open_publish_route("127.0.0.1:9000", None, true, Some("b"), &|_| None)
        .expect_err("a schemeless endpoint must be refused at configuration");
    assert!(matches!(err, RouteError::Endpoint(_)), "got {err:?}");
}

// ------------------------------------------------------ the seam deadline

/// A one-file source tree and the local store beside it, in a scratch dir
/// removed on drop.
///
/// The store writes its objects `0444`, which resists removal of the
/// PARENT on some systems — hence the chmod retry.
struct Scratch(PathBuf);

impl Scratch {
    #[expect(
        clippy::disallowed_methods,
        reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
    )]
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "granary-deadline-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir.join("source")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(dir.join("source/a.txt"), b"d-42 fixture\n")
            .unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }

    fn source(&self) -> PathBuf {
        self.0.join("source")
    }

    fn store(&self) -> Store {
        Store::open(&self.0.join("store")).unwrap_or_else(|e| panic!("local store: {e}"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::fs::remove_dir_all(&self.0).is_err() {
            chmod_tree(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn chmod_tree(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
            if path.is_dir() {
                chmod_tree(&path);
            }
        }
    }
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
}

/// How long a ROW in this file is prepared to wait before it calls a
/// stub-driven seam call hung. Nothing about the product depends on it:
/// it is the harness's own bound, and it exists so a MISSING deadline
/// (or a broken test double) fails as an assertion rather than as a
/// wedged test binary. Retained with per-call deadlines: [`guarded`]'s
/// own doc explains why the raw-h2 rows below still need it even though
/// the per-call seam deadline (`SEAM_DEADLINE_BASE`) is now what bounds
/// the PRODUCT side of the same shape.
const GUARD: Duration = Duration::from_secs(45);

// "A silent peer must not hang the command" is pinned in this file's own
// seam-deadline section below, at the SEAM rather than the whole flow:
// `a_blackholed_get_is_cut_at_base_plus_size_over_rate` and the `put_root`
// rows each pin ONE seam call's own deadline rather than a whole command's.

// ------------------------------------------------- raw-h2 retry stub
//
// The stub above speaks HTTP through hyper's own `auto::Builder`, which
// negotiates HTTP/2 but exposes no way to reset ONE stream, send a
// GOAWAY, or drop a connection mid-handshake at will. The retry
// rows need exactly that frame-level control, and h2 is now a REGULAR
// dependency of `granary-client` rather than a dev-only one — so these
// stubs drive it directly instead of going through hyper's server.

/// A raw-h2 stub: `addr`/`pin` build an [`HttpStore`] against it exactly
/// like [`Stub`] above.
struct H2Stub {
    addr: SocketAddr,
    pin: SpkiPin,
    _accepting: AcceptTask,
}

impl H2Stub {
    fn base(&self) -> String {
        base_url(self.addr)
    }

    fn store(&self) -> HttpStore {
        HttpStore::new(&self.base(), vec![self.pin], &AmbientNetwork)
            .unwrap_or_else(|e| panic!("http store: {e}"))
    }
}

/// TLS + TCP bootstrap shared by every raw-h2 stub below — the same
/// minted certificate and `server_tls_config` [`stub_with_alpn`] uses,
/// restricted to the `h2` ALPN token alone: these rows are about h2
/// framing, so there is nothing to prove by also offering HTTP/1.1.
async fn h2_only_listener() -> (TcpListener, TlsAcceptor, SpkiPin) {
    let party = mint();
    let pin = party.pin();
    let mut tls = server_tls_config(vec![party.cert.clone()], party.key(), ClientAuth::None)
        .unwrap_or_else(|e| panic!("server tls: {e}"));
    tls.alpn_protocols = vec![ALPN_H2.to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    (listener, acceptor, pin)
}

/// The stub's generic answer to any request it decides not to refuse or
/// drop: a `PUT` gets `201 Created`; a ranged `GET` gets a `206` whose
/// `Content-Range` and body echo exactly the extent the client asked
/// for. One responder serves `put_bin`/`put_root` and `get_bin_range`
/// alike, so no test below needs its own response closure.
fn h2_default_answer(request: &Request<h2::RecvStream>) -> (Response<()>, Vec<u8>) {
    if request.method() == Method::GET {
        if let Some((first, last)) = request
            .headers()
            .get(RANGE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("bytes="))
            .and_then(|v| v.split_once('-'))
            .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?)))
        {
            // Checked, not `last - first + 1`: unreachable against every
            // row this file drives today (every `Range` comes out of
            // `HttpStore`'s own well-formed `RequestedExtent`), but a
            // `first > last` — or a span too wide for this platform's
            // `usize` — is adversarial-shaped input a STUB should answer
            // like a server would, not panic on, so a row added later
            // that DOES send one gets a `416` rather than a wedged task.
            let width = last
                .checked_sub(first)
                .and_then(|span| span.checked_add(1))
                .and_then(|span| usize::try_from(span).ok());
            let Some(width) = width else {
                let resp = Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .body(())
                    .unwrap_or_else(|e| panic!("response: {e}"));
                return (resp, Vec::new());
            };
            let body = vec![0x42_u8; width];
            let resp = Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header("content-range", format!("bytes {first}-{last}/*"))
                .body(())
                .unwrap_or_else(|e| panic!("response: {e}"));
            return (resp, body);
        }
        let resp = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap_or_else(|e| panic!("response: {e}"));
        return (resp, Vec::new());
    }
    let resp = Response::builder()
        .status(StatusCode::CREATED)
        .body(())
        .unwrap_or_else(|e| panic!("response: {e}"));
    (resp, Vec::new())
}

/// Send `(resp, body)` on `respond`, dropping a send failure — the stub
/// is a test peer, not a target, and a client that already has what it
/// needs racing a stub write is not this row's concern.
fn h2_send(respond: &mut h2::server::SendResponse<Bytes>, resp: Response<()>, body: Vec<u8>) {
    let Ok(mut send) = respond.send_response(resp, body.is_empty()) else {
        return;
    };
    if !body.is_empty() {
        let _ = send.send_data(Bytes::from(body), true);
    }
}

/// Read an h2 request body to completion — the stub is a test peer, not
/// a target, so no cap: every body driven at it here is test-sized.
async fn drain_h2(mut body: h2::RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap_or_else(|e| panic!("h2 request body: {e}"));
        out.extend_from_slice(&chunk);
    }
    out
}

/// **`a_refused_stream_is_retried_once_and_succeeds` /
/// `a_second_refusal_surfaces_and_is_not_retried_again` /
/// `a_non_refusal_reset_on_put_root_is_not_retried`.** ONE h2
/// connection; the first `refuse` streams it accepts get
/// `RST_STREAM(reason)` (h2's `send_reset` on the accepted request),
/// every later one gets [`h2_default_answer`]. The returned counter is
/// the WIRE counter every row built on this stub asserts on. `reason`
/// is a parameter and not a hard-coded `REFUSED_STREAM`: the
/// `NotRetryable`-reset row needs the SAME stub shape with a reason RFC
/// 9113 §8.7 does not bless (`INTERNAL_ERROR`), to witness that `send()`
/// does not retry it.
async fn h2_stub_reset_first_n_streams(
    refuse: usize,
    reason: h2::Reason,
) -> (H2Stub, Arc<AtomicUsize>) {
    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let seen = Arc::new(AtomicUsize::new(0));
    let task_seen = Arc::clone(&seen);
    let accepting = spawn_accepting(move |accept_error| async move {
        let sock = accept(&listener, &accept_error).await;
        let Ok(tls) = acceptor.accept(sock).await else {
            return;
        };
        let Ok(mut conn) = h2::server::handshake(tls).await else {
            return;
        };
        while let Some(Ok((request, mut respond))) = conn.accept().await {
            let n = task_seen.fetch_add(1, Ordering::SeqCst);
            if n < refuse {
                respond.send_reset(reason);
            } else {
                let (resp, body) = h2_default_answer(&request);
                h2_send(&mut respond, resp, body);
            }
        }
    });
    (
        H2Stub {
            addr,
            pin,
            _accepting: accepting,
        },
        seen,
    )
}

/// **`put_root_never_retries_a_connection_failure` /
/// `a_get_retries_a_cut_connection_once`.** The first `drop` TCP
/// connections complete TLS, read at least one byte (proving the
/// session was live), then are DROPPED with no h2 handshake at all — the
/// cut-established-connection shape `RetryClass::ConnectionFailed`'s
/// io-kind arm covers. Every later connection is answered normally via
/// [`h2_default_answer`]. The returned counter is the DIAL counter both
/// rows assert on: a `ConnectionFailed` retry always redials, it never
/// reuses the dead connection.
async fn h2_stub_drop_first_n_connections(drop_first: usize) -> (H2Stub, Arc<AtomicUsize>) {
    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let dials = Arc::new(AtomicUsize::new(0));
    let task_dials = Arc::clone(&dials);
    let accepting = spawn_accepting(move |accept_error| async move {
        loop {
            let sock = accept(&listener, &accept_error).await;
            let index = task_dials.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let _served = spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                if index < drop_first {
                    let mut byte = [0_u8; 1];
                    let _ = tls.read(&mut byte).await;
                    return; // `tls` drops here — no h2 handshake ever runs.
                }
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = conn.accept().await {
                    let (resp, body) = h2_default_answer(&request);
                    h2_send(&mut respond, resp, body);
                }
            });
        }
    });
    (
        H2Stub {
            addr,
            pin,
            _accepting: accepting,
        },
        dials,
    )
}

/// **`a_get_survives_a_drain_goaway_with_one_redial`.** The first
/// connection sends a remote `GOAWAY(NO_ERROR)` BEFORE ever accepting a
/// stream — `last_stream_id` is then 0, so the client attributes its
/// concurrently in-flight request to "never processed", exercising a drain
/// fault — then parks (never dropping the connection
/// value out from under a frame still queued for flush). Every later
/// connection answers normally. The returned counter is the DIAL counter
/// the row asserts reads 2.
async fn h2_stub_goaway_then_answer() -> (H2Stub, Arc<AtomicUsize>) {
    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let dials = Arc::new(AtomicUsize::new(0));
    let task_dials = Arc::clone(&dials);
    let accepting = spawn_accepting(move |accept_error| async move {
        loop {
            let sock = accept(&listener, &accept_error).await;
            let index = task_dials.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let _served = spawn(async move {
                let Ok(tls) = acceptor.accept(sock).await else {
                    return;
                };
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                if index == 0 {
                    conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                    loop {
                        if conn.accept().await.is_none() {
                            std::future::pending::<()>().await;
                        }
                    }
                }
                while let Some(Ok((request, mut respond))) = conn.accept().await {
                    let (resp, body) = h2_default_answer(&request);
                    h2_send(&mut respond, resp, body);
                }
            });
        }
    });
    (
        H2Stub {
            addr,
            pin,
            _accepting: accepting,
        },
        dials,
    )
}

/// **`refused_stream_on_a_lying_server_converges_through_the_probe`.**
/// ONE h2 connection, serving as many requests as arrive: the FIRST
/// `PUT` LANDS the body in `landed` (proving the server actually stored
/// it, not merely claiming to) and THEN refuses the stream; a LATER
/// `PUT`, once something has landed, answers `409`; a `GET` answers the
/// landed bytes if there are any, else a success-`404`.
async fn h2_stub_lying_root() -> (H2Stub, Arc<Mutex<Option<Vec<u8>>>>) {
    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let landed: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let task_landed = Arc::clone(&landed);
    let accepting = spawn_accepting(move |accept_error| async move {
        let sock = accept(&listener, &accept_error).await;
        let Ok(tls) = acceptor.accept(sock).await else {
            return;
        };
        let Ok(mut conn) = h2::server::handshake(tls).await else {
            return;
        };
        // **A task PER accepted request, not handled inline.** Reading
        // a request's body is a SEPARATE await from `conn.accept()`,
        // and per `Connection::poll_closed`'s own doc, it is
        // `conn.accept()` (via `poll_closed`) that "advances the
        // internal connection state, driving progress on all the other
        // handles" — the `RecvStream` a handler awaits included. Loop
        // body that awaited a body inline would starve every stream on
        // the connection, its own included, the moment the FIRST byte
        // wasn't already buffered: `conn.accept()` has to keep being
        // polled by the OUTER loop for a spawned handler's `.data()` to
        // ever resolve.
        while let Some(Ok((request, respond))) = conn.accept().await {
            let landed = Arc::clone(&task_landed);
            let _handled = spawn(h2_lying_root_reply(request, respond, landed));
        }
    });
    (
        H2Stub {
            addr,
            pin,
            _accepting: accepting,
        },
        landed,
    )
}

/// One request's worth of [`h2_stub_lying_root`]'s logic, run in its own
/// task (see the doc on that function's accept loop for why).
async fn h2_lying_root_reply(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    landed: Arc<Mutex<Option<Vec<u8>>>>,
) {
    if request.method() == Method::PUT {
        let body = drain_h2(request.into_body()).await;
        let mut guard = landed
            .lock()
            .unwrap_or_else(|e| panic!("landed lock poisoned: {e}"));
        if guard.is_none() {
            *guard = Some(body);
            drop(guard);
            // The lie: the bytes are ALREADY stored above, but the
            // stream is reset as if nothing had landed.
            respond.send_reset(h2::Reason::REFUSED_STREAM);
        } else {
            drop(guard);
            let resp = Response::builder()
                .status(StatusCode::CONFLICT)
                .body(())
                .unwrap_or_else(|e| panic!("response: {e}"));
            h2_send(&mut respond, resp, Vec::new());
        }
    } else {
        let present = landed
            .lock()
            .unwrap_or_else(|e| panic!("landed lock poisoned: {e}"))
            .clone();
        if let Some(bytes) = present {
            let resp = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .unwrap_or_else(|e| panic!("response: {e}"));
            h2_send(&mut respond, resp, bytes);
        } else {
            let resp = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("granary-error", "not-found")
                .body(())
                .unwrap_or_else(|e| panic!("response: {e}"));
            h2_send(&mut respond, resp, Vec::new());
        }
    }
}

// -------------------------------------------------- reason-scoped seam retry

/// Bound one seam call under this file's own [`GUARD`] — a stub bug
/// must fail fast as an assertion, never wedge the test
/// binary forever.
///
/// **Why the raw-h2 stubs below still need this even though
/// `HttpStore` now carries a per-call deadline of its own.**
/// `SEAM_DEADLINE_BASE` is thirty seconds — a production figure, not a
/// test one — and none of the raw-h2 rows below run under
/// `tokio::time::pause()` (the paused rows, further down, are their
/// own section). A stub bug here (a dropped `respond` handle, a
/// `conn.accept()` that never resolves) would therefore cost the FULL
/// production deadline in REAL wall-clock time before `HttpStore`
/// itself even produces an error, and nextest's own terminate-after
/// only covers `granary-sim`. Every seam call these rows make is
/// wrapped in this file's own, much shorter guard instead, so a stub
/// bug fails fast as an assertion rather than as a slow, silent wedge.
async fn guarded<F: Future>(seam_call: F) -> F::Output {
    tokio::time::timeout(GUARD, seam_call)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "a seam call outlived this row's own {GUARD:?} guard — the \
                 likeliest cause is a stub bug (a dropped `respond` handle, \
                 a connection driver that stopped being polled) leaving the \
                 client awaiting a response that will never arrive"
            )
        })
}

/// **Positive control.** A REAL wire `RST_STREAM(REFUSED_STREAM)`
/// through the shipped connector, client and classifier — CLASS A, all
/// nine seams. `put_bin` refused once, answered the second time: the
/// seam call succeeds and the wire counter proves exactly 2 attempts.
#[tokio::test]
async fn a_refused_stream_is_retried_once_and_succeeds() {
    let (stub, attempts) = h2_stub_reset_first_n_streams(1, h2::Reason::REFUSED_STREAM).await;
    let store = stub.store();
    let got = guarded(store.put_bin(&DIGEST, b"t4 refused-once payload".to_vec())).await;
    assert_eq!(
        got,
        Ok(true),
        "the retried attempt must land as a fresh object"
    );
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "one refused attempt plus one retried attempt — never more"
    );
}

/// A server that refuses EVERY stream: the retry's own failure surfaces
/// as the call's error (at most one retry per call), the wire
/// counter still reads exactly 2, and the rendered message names the
/// refusal rather than stopping at `hyper_util`'s generic `SendRequest`
/// kind name.
#[tokio::test]
async fn a_second_refusal_surfaces_and_is_not_retried_again() {
    let (stub, attempts) =
        h2_stub_reset_first_n_streams(usize::MAX, h2::Reason::REFUSED_STREAM).await;
    let store = stub.store();
    let err = guarded(store.put_bin(&DIGEST, b"t4 refused-twice payload".to_vec()))
        .await
        .expect_err("a server that never stops refusing must not be retried a second time");
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "exactly 2 attempts — the one retry, no more"
    );
    let RootStoreError::Backend(text) = err else {
        panic!("got {err:?}");
    };
    assert!(
        text.to_lowercase().contains("refused"),
        "the rendered message must name the refusal, not stop at hyper_util's \
         generic SendRequest kind — got {text:?}"
    );
}

/// **The `NotRetryable` → no-retry arm of `send()`, witnessed end to
/// end.** A REMOTE reset with reason `INTERNAL_ERROR`
/// classifies `NotRetryable` — RFC 9113 §8.7's non-processing guarantee
/// is SPECIFIC to `REFUSED_STREAM`, and an `INTERNAL_ERROR` reset (even
/// though it is remote, even though it IS a reset) carries none of it.
/// `put_root` must not retry it: the error surfaces from the FIRST and
/// only attempt, and the wire counter proves exactly one — a stub that
/// keeps resetting every stream it sees would show 2 (or more) the
/// moment `send()` retried a `NotRetryable` class. This is also
/// the integration witness for the unit-level
/// `a_remote_internal_error_reset_is_not_class_a` row: a real wire
/// `RST_STREAM(INTERNAL_ERROR)` through the shipped connector, client
/// and classifier.
#[tokio::test]
async fn a_non_refusal_reset_on_put_root_is_not_retried() {
    let (stub, attempts) =
        h2_stub_reset_first_n_streams(usize::MAX, h2::Reason::INTERNAL_ERROR).await;
    let store = stub.store();
    guarded(store.put_root(VOLUME, 1, b"t4 internal-error-reset root bytes".to_vec()))
        .await
        .expect_err("an INTERNAL_ERROR reset carries no non-processing guarantee and must surface");
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "NotRetryable must not retry — exactly one wire attempt reaches the stub"
    );
}

/// `put_root` NEVER retries a `ConnectionFailed` — the ONE-PROBE RULE is
/// its only ambiguity resolution except for a remote `RST_STREAM(REFUSED_STREAM)`. Exactly one
/// TCP connection, dropped after the TLS session (and at least one byte)
/// lands, and the caller's error surfaces. The probe choreography ABOVE
/// this seam is exercised by the `commit()` tests instead:
/// `own_landed_root_is_not_a_lost_race`
/// (`tests/publish_inmemory.rs`) is the one that drives the
/// `AlreadyExists` probe path end to end.
#[tokio::test]
async fn put_root_never_retries_a_connection_failure() {
    let (stub, dials) = h2_stub_drop_first_n_connections(1).await;
    let store = stub.store();
    guarded(store.put_root(VOLUME, 1, b"t4 dropped-root bytes".to_vec()))
        .await
        .expect_err("a cut connection must surface, not silently succeed");
    assert_eq!(
        dials.load(Ordering::SeqCst),
        1,
        "put_root must not redial — allow_connection_retry is false there"
    );
}

/// The eight non-root seams DO retry a `ConnectionFailed` once, on a
/// FRESH connection (a dead connection is never reused): `get_bin_range`
/// against a stub that drops the first connection and answers the
/// second completes, and the dial counter reads 2.
#[tokio::test]
async fn a_get_retries_a_cut_connection_once() {
    let (stub, dials) = h2_stub_drop_first_n_connections(1).await;
    let store = stub.store();
    let got = guarded(store.get_bin_range(&DIGEST, 0, 4)).await;
    assert_eq!(
        got,
        Ok(vec![0x42; 4]),
        "the redialed attempt must complete the read"
    );
    assert_eq!(
        dials.load(Ordering::SeqCst),
        2,
        "one dropped dial plus one redial — never more"
    );
}

/// A remote drain `GOAWAY` is recoverable on the eight non-root seams
/// (as exercised here): on the live connection it is `ConnectionFailed`,
/// `get_bin_range` redials once on a fresh connection, and the affected
/// read completes.
#[tokio::test]
async fn a_get_survives_a_drain_goaway_with_one_redial() {
    let (stub, dials) = h2_stub_goaway_then_answer().await;
    let store = stub.store();
    let got = guarded(store.get_bin_range(&DIGEST, 0, 4)).await;
    assert_eq!(
        got,
        Ok(vec![0x42; 4]),
        "the redialed attempt must complete the read"
    );
    assert_eq!(
        dials.load(Ordering::SeqCst),
        2,
        "one GOAWAY'd dial plus one redial — never more"
    );
}

/// **The negative test: a server lies about refusing a stream.** The
/// stub REFUSES the stream but has ALREADY landed the root bytes before
/// resetting: the CLASS A retry collides create-only (`409`), the call
/// surfaces the collision as `AlreadyExists`, and a follow-up `get_root`
/// proves the root REALLY landed — byte-identical to what was attempted,
/// not merely that SOME conflict came back — which is exactly the
/// precondition `commit()`'s existing probe
/// (`own_landed_root_is_not_a_lost_race`, `tests/publish_inmemory.rs`)
/// reads as SUCCESS.
#[tokio::test]
async fn refused_stream_on_a_lying_server_converges_through_the_probe() {
    let (stub, landed) = h2_stub_lying_root().await;
    let store = stub.store();
    let attempted = b"t4 lying-server root bytes".to_vec();
    let err = guarded(store.put_root(VOLUME, 1, attempted.clone()))
        .await
        .expect_err("a server that lands the root and then refuses must still surface a collision");
    assert!(
        matches!(err, RootStoreError::AlreadyExists),
        "the retry's own CONFLICT is what a lying REFUSED_STREAM converges to; got {err:?}"
    );
    // Proves the root REALLY landed rather than merely that A conflict
    // came back — the fact `commit()`'s probe (cited above) depends on:
    // read-after-write, byte for byte.
    assert_eq!(
        guarded(store.get_root(VOLUME, 1)).await,
        Ok(Some(attempted)),
        "the root must read back exactly what was PUT — the stub's own \
         `landed` slot backs this, but the seam-level read is the proof \
         that matters"
    );
    assert!(
        landed
            .lock()
            .unwrap_or_else(|e| panic!("landed lock poisoned: {e}"))
            .is_some(),
        "sanity: the stub's fake store must hold something by now"
    );
}

// --------------------------------------------------- per-call seam deadline
//
// `HttpStore` bounds every seam call individually — the idle form: a
// call that neither completes nor fails within `SEAM_DEADLINE_BASE +
// transfer_size / SEAM_FLOOR_RATE_BYTES_PER_SEC` is a wedged peer, cut
// (`RootStoreError::Elapsed`). No whole-flow total bounds the sum.
//
// Every row below calls `tokio::time::pause()` PARTWAY THROUGH, never at
// the start (`#[tokio::test(start_paused = true)]` is deliberately NOT
// used here): `tokio::time::pause`'s own "Auto-advance" rule is that
// when the runtime has nothing ready, it jumps straight to the NEXT
// pending timer rather than waiting any real time — and it does this
// unconditionally, with no allowance for real I/O that has not resolved
// yet. A fresh TCP connect (three real packets even on loopback: SYN,
// SYN-ACK, ACK) never wins that race: the very first `tokio::time::
// advance` call would jump the clock straight past `CONNECT_TIMEOUT`
// before the handshake has a chance to be noticed: an unwarmed row
// measured red with `Backend("transport: client error (Connect): tcp
// connect error: deadline has elapsed")` at 0.04s, nowhere near any
// seam deadline. Every row
// therefore WARMS its connection with one ordinary, un-paused
// `max_seq` call first — real wall-clock time, sub-millisecond on
// loopback — and only calls `pause()` once that has returned, so the
// only timer left to advance past is the one under test. Every stub
// below answers `GET .../max-seq` instantly for exactly this reason,
// distinct from whatever it does to the call actually being tested.
//
// WHAT THESE ROWS ALSO PIN. Three of them — the two `put_root`-deadline
// rows and the fully-parked-peer row — go RED on Linux (measured on
// every Linux CI leg, x64 included) if `HttpStore`'s connector leaves NAGLE'S ALGORITHM ON:
// `hyper_util`'s `HttpConnector` defaults `nodelay: false`, and this
// client owns its connector rather than letting `build()` make one
// to set its connect timeout. Under Nagle, a small write issued while earlier bytes are
// still unacknowledged waits for the peer's delayed ACK — up to ~40 ms
// on Linux — and every one of these three rows issues a PROBE
// immediately behind a cut call's `RST_STREAM`. Measured with Nagle on:
// the probe's `HEADERS` reached the stub only after ~15 real
// milliseconds, while `advance_settled` had already spent the whole
// 45-second virtual deadline in ~0.3 ms of real time. On macOS the
// stall was not observed.
//
// So these three rows are the STANDING REGRESSION GATE for
// `set_nodelay(true)` in `HttpStore::new`, and they are a gate with a
// demonstrated positive control: on aarch64 Linux, on one commit and
// one container, all three FAIL with that line removed and PASS with it
// present. Do not "fix" a future recurrence by weakening the counts
// below — a wire count that drops from 2 to 1 here means a request the
// client believes it sent never left the kernel.
//
// Extra scheduling rounds did not resolve the Nagle stall: 4 extra
// zero-duration rounds per step, 64 at the end and 512 more in a bounded
// settle loop changed nothing. Clients dial the bound numeric address,
// so DNS resolution and address-family selection are absent here.

/// One ordinary `max_seq` call against `store`, run in REAL (unpaused)
/// time to force the TCP connect + TLS handshake + h2 negotiation to
/// complete before any row calls `tokio::time::pause()` — see this
/// section's own module note for why that order is load-bearing. The
/// answer is discarded; every stub in this section maps `GET
/// .../max-seq` to an instant, harmless response for exactly this call.
async fn warm_up(store: &HttpStore) {
    store
        .max_seq(VOLUME)
        .await
        .unwrap_or_else(|e| panic!("connection warm-up failed: {e}"));
}

/// Let REAL time pass, in one-millisecond parks, while a row is
/// otherwise driving VIRTUAL time.
///
/// **Why a paused-clock row needs this at all.** Everything these rows
/// call `advance` over is real loopback I/O: a real TCP socket, a real
/// TLS session, a real h2 codec, and a stub server on the same
/// single-threaded runtime. `tokio::time::advance` moves the clock and
/// then `yield_now`s, and a `yield_now` round never lets the runtime
/// BLOCK on the I/O driver — it polls it with a zero timeout and moves
/// on. So a row that only advances can spend its whole virtual budget
/// in a few hundred microseconds of real time and cut a call whose
/// bytes are still in the kernel. Measured on Linux: 5000
/// bare `yield_now` rounds took 7 real milliseconds and the stub never
/// saw the request; 15 rounds of THIS helper and it did.
///
/// The clock is unfrozen for the park and refrozen after it, so each
/// round costs the row as much virtual time as it takes real time: a
/// millisecond nominally, and far more on a loaded host. That is
/// negligible where a row has tens of seconds of slack, and the rows
/// that assert an exact figure assert the deadline the error REPORTS,
/// never elapsed time; [`drive_delayed_call`], whose rows have a few
/// seconds of slack, measures what its rounds cost.
async fn settle_real(rounds: u32) {
    for _ in 0..rounds {
        tokio::time::resume();
        // The re-freeze is a DROP GUARD, not the next statement, and the
        // difference is cancellation: a row whose future is dropped while
        // parked here would otherwise leave the clock RUNNING for the rest
        // of the process, and the next `advance` or `resume` anywhere would
        // panic on a clock that is not paused. Nothing cancels these
        // helpers today — no caller wraps them in a `timeout`, and
        // `select!` is banned in this crate — but "no caller does" is a
        // claim that expires, and the guard costs one line.
        //
        // It cannot double-pause: the guard is constructed with no `.await`
        // between it and `resume()`, so it is the ONLY thing that pauses,
        // on the normal path and the cancelled one alike.
        let _refreeze = RePause;
        park_for(Duration::from_millis(1)).await;
    }
}

/// Re-freezes the paused clock on drop — see [`settle_real`].
#[derive(Debug)]
struct RePause;

impl Drop for RePause {
    fn drop(&mut self) {
        tokio::time::pause();
    }
}

/// How many virtual steps [`advance_settled`], [`drive_to_completion`]
/// and [`drive_delayed_call`]'s phase 2 take between [`settle_real`]
/// rounds. One blocking park delivers what
/// thousands of yields cannot, so this does not need to be small: at
/// 200ms per step it is one real millisecond per 6.4 virtual seconds.
const STEPS_PER_REAL_SETTLE: u32 = 32;

/// Advance virtual time up to `total`, in SMALL steps rather than one
/// big jump, each followed by [`tokio::time::advance`]'s own
/// `yield_now`.
///
/// **Why steps and not one call.** `tokio::time::advance` gives the
/// executor exactly ONE scheduling round per call (its own source is
/// `clock.advance(duration); yield_now().await;`) — real I/O that has
/// not yet been noticed by the reactor (a response write that just
/// landed on a loopback socket, say) gets exactly that one round to
/// surface before the runtime, finding nothing else ready, falls back
/// to auto-advancing PAST it to whatever timer is next. A single large
/// jump gives every real-I/O step on the way at most one such round; many
/// small steps give it many, which is what let this row go from red
/// (`Elapsed` firing on an operation a slower, correctly-sequenced
/// advance lets complete) to green without changing anything about the
/// product under test.
async fn advance_settled(total: Duration) {
    let step = Duration::from_millis(200);
    let mut remaining = total;
    let mut taken = 0_u32;
    while remaining > Duration::ZERO {
        let this_step = remaining.min(step);
        tokio::time::advance(this_step).await;
        remaining -= this_step;
        taken += 1;
        if taken.is_multiple_of(STEPS_PER_REAL_SETTLE) {
            settle_real(1).await;
        }
    }
    // A handful of zero-duration rounds at the end: the LAST real I/O
    // event of the operation (the final response byte arriving) may
    // still not have been noticed when the last non-zero step's own
    // single round ran.
    for _ in 0..16 {
        tokio::time::advance(Duration::ZERO).await;
    }
    // And a real settle LAST: the caller's next act is usually
    // `task.is_finished()`, which must not be racing bytes that are
    // still in the kernel.
    settle_real(2).await;
}

/// Advance virtual time in [`advance_settled`]-sized small steps,
/// checking after EACH one whether `task` has already finished, and
/// stopping the moment it has — never advancing further than the
/// operation actually needed. Panics if `guard` (comfortably inside the
/// call's own deadline, never at or past it) is exhausted first.
///
/// **Why step-and-check rather than [`advance_settled`]'s fixed
/// total.** A fixed total picks ONE point to stop stepping and hands
/// off to auto-advance from there. If the stub's own delay timer was
/// registered later than that total assumed, the total runs out before
/// the timer fires, auto-advance jumps to the next timer instead — which
/// can be the CLIENT's own deadline — and a call that should have
/// succeeded elapses. Stepping-and-checking stops at whichever step the
/// operation actually finishes on, so it never overshoots into a timer
/// that fires only because nothing checked sooner.
///
/// **What it does NOT remove:** every step taken before the stub has
/// even SEEN the request is virtual time the call's deadline spends and
/// the stub's delay does not: a stub made to arm its delay 20 real
/// milliseconds late turns a row with five seconds of slack red under
/// this driver. The rows whose stub delays an answer by a fixed time use
/// [`drive_delayed_call`] instead, which passes that same late stub
/// because it STEPS virtual time only while the delay is running. The
/// rows left here drive a stub that parks until the client's own
/// deadline cuts the call and then answers a follow-up at once; that
/// follow-up still runs on this driver's cadence.
async fn drive_to_completion<T>(task: &mut tokio::task::JoinHandle<T>, guard: Duration) {
    let step = Duration::from_millis(200);
    let mut waited = Duration::ZERO;
    let mut taken = 0_u32;
    while !task.is_finished() {
        assert!(
            waited < guard,
            "the operation under test did not finish within this row's own {guard:?} guard \
             — comfortably inside the call's real deadline, so this is a test failure, not \
             the product cutting a call it should not have"
        );
        tokio::time::advance(step).await;
        waited += step;
        taken += 1;
        if taken.is_multiple_of(STEPS_PER_REAL_SETTLE) {
            settle_real(1).await;
        }
    }
}

/// The SLACK past which [`drive_delayed_call`] panics, checked after each
/// real-time round of its phases 1 and 3 and once when its phase 2 ends:
/// virtual time since the call started, beyond the stub's own delay.
/// The clock runs while [`settle_real`] parks, so every real-time wait
/// before the stub arms and after it answers spends slack — whatever
/// real time it takes, far more than a round's nominal millisecond on a
/// loaded host — and so does phase 2's last step overshooting the
/// delay. Phase 1 charges its last round whole even when the stub
/// armed partway through it, so the check errs early, never late. Every
/// row using the driver asserts that its slack between the stub's delay
/// and the call's deadline exceeds this; the smallest is five seconds.
const REAL_WAIT_MAX: Duration = Duration::from_secs(3);

/// The PAUSED test clock's current instant, for measuring how much
/// virtual time a real-time wait has cost.
///
/// `tokio::time::Instant::now` is banned workspace-wide
/// (`clippy.toml`'s `disallowed-methods`) as a clock read outside the
/// `Clock` seam. This is harness code on the far side of the line the
/// [`spawn`] and [`park_for`] exemptions draw, and it reads the virtual
/// clock the client's own deadline runs on — never a production
/// wall-clock read. Every clock read in this file goes through it.
#[expect(
    clippy::disallowed_methods,
    reason = "reads the paused test clock the client's deadline runs on, not a production clock read — park_for above draws the identical line"
)]
fn virtual_now() -> tokio::time::Instant {
    tokio::time::Instant::now()
}

/// Panic if the call started at `started` has spent [`REAL_WAIT_MAX`] of
/// slack — its virtual time so far beyond `allowed`, the part of the
/// stub's delay that has legitimately run — naming the wait it was in
/// and whether what that wait expected (`done`) has happened by now.
///
/// Past that bound the call's deadline is closer than its row assumed,
/// so what the row reports next would not be about the product: either
/// the host stalled, or the client never did what the driver was waiting
/// for. The panic says which wait it was and leaves that to the reader.
fn assert_slack(
    started: tokio::time::Instant,
    allowed: Duration,
    waiting_for: &str,
    request: usize,
    done: bool,
) {
    let spent = (virtual_now() - started).saturating_sub(allowed);
    assert!(
        spent < REAL_WAIT_MAX,
        "delayed request {request} has spent {spent:?} of slack, past {REAL_WAIT_MAX:?}, while \
         waiting for {waiting_for} (which {}) — the host stalled or the client never got there; \
         either way the stub's delay and the call's deadline are not what ran out",
        if done {
            "has now happened"
        } else {
            "had not happened"
        },
    );
}

/// Drive ONE call against a stub that reports [`DelayProgress`] to
/// completion, STEPPING virtual time only while the stub's delay is
/// actually running. The real-time waits either side of the delay still
/// let the clock run, for as long as each wait takes; the slack they
/// spend is checked against [`REAL_WAIT_MAX`] after every one.
///
/// `task` must have been spawned with no `.await` before this is
/// called, so the call starts when the driver does, and its request is
/// the stub's next delayed one: phase 1 waits for the stub's arm count to
/// pass the value it had when the driver started, and phase 2 for every
/// request armed by then to be answered, so a request the client happens
/// to send twice cannot end a later call's phase early.
///
/// Three phases, each keyed on what the stub REPORTS rather than on a
/// virtual-time budget:
///
/// 1. Until the stub has armed its delay for this call, let REAL time
///    pass and do not step the clock: the request is still in the client,
///    the TLS layer or the kernel, and the virtual time these waits let
///    run is spent by the call's deadline and not by the stub's delay.
/// 2. From there until the stub has sent its answer, step virtual time as
///    [`drive_to_completion`] does, with a real settle every
///    [`STEPS_PER_REAL_SETTLE`] steps so request-body bytes still move
///    while the delay runs. Panics if the STEPS alone reach `delay` plus a
///    second with no answer — its timer never fired, or the task answering
///    the request died; a test fault either way. The settles are left out
///    of that count, so a host stall during the delay cannot trip it.
/// 3. Until `task` finishes, let REAL time pass again and do not step the
///    clock: the answer's bytes are on their way back and need the I/O
///    driver.
///
/// Slack is checked after every real round of phases 1 and 3 and once
/// when phase 2 ends, which covers a phase-2 round that straddled the
/// stub's timer. The checks run after a round, so they report a stall
/// once it has happened and cannot stop one that outlasts the row's
/// slack. A call the client ends early — a deadline shorter than
/// `delay`, or any whole-operation total — finishes `task` during phase
/// 2 with slack to spare, every phase stops, and the row's own assertion
/// reports the `Elapsed`.
async fn drive_delayed_call<T>(
    task: &tokio::task::JoinHandle<T>,
    progress: &DelayProgress,
    delay: Duration,
) {
    let started = virtual_now();
    let armed_before = progress.armed.load(Ordering::SeqCst);
    let request = armed_before + 1;
    let armed = || progress.armed.load(Ordering::SeqCst) > armed_before;
    while !armed() && !task.is_finished() {
        settle_real(1).await;
        assert_slack(
            started,
            Duration::ZERO,
            "the stub to see it",
            request,
            armed(),
        );
    }
    let armed_by_now = progress.armed.load(Ordering::SeqCst);
    let answered = || progress.answered.load(Ordering::SeqCst) >= armed_by_now;
    let step = Duration::from_millis(200);
    let stepping_guard = delay + Duration::from_secs(1);
    let mut taken = 0_u32;
    while !answered() && !task.is_finished() {
        assert!(
            step * taken < stepping_guard,
            "the stub armed delayed request {request} but did not answer within \
             {stepping_guard:?} of stepped virtual time — its delay timer never fired, or the \
             task answering that request died"
        );
        tokio::time::advance(step).await;
        taken += 1;
        if taken.is_multiple_of(STEPS_PER_REAL_SETTLE) {
            settle_real(1).await;
        }
    }
    assert_slack(started, delay, "the stub's answer", request, answered());
    while !task.is_finished() {
        settle_real(1).await;
        assert_slack(
            started,
            delay,
            "the client to receive the answer",
            request,
            task.is_finished(),
        );
    }
}

/// Is this an h2 request this section's stubs treat as a WARM-UP call
/// rather than the thing under test — a `GET` to a path ending
/// `/max-seq`, answered instantly regardless of what the rest of the
/// stub does?
fn is_warm_up(request: &Request<h2::RecvStream>) -> bool {
    request.method() == Method::GET && request.uri().path().ends_with("/max-seq")
}

/// The instant, harmless answer to a warm-up `max_seq` call: "no
/// roots", the same shape [`h2_stub_delayed_absent_max_seq`] gives every
/// OTHER `max_seq` call too, just without the delay.
fn warm_up_answer() -> (Response<()>, Vec<u8>) {
    let resp = Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("granary-error", "not-found")
        .body(())
        .unwrap_or_else(|e| panic!("response: {e}"));
    (resp, Vec::new())
}

/// A stub that accepts h2 connections and, for every stream it accepts,
/// counts it and then PARKS FOREVER: the `respond` handle is held alive
/// in a task that never completes, so the client sees the stream stay
/// open with no response ever arriving — never a reset, which is what
/// dropping `respond` outright would signal instead. [`is_warm_up`]
/// calls are answered instantly and never counted.
async fn h2_stub_parking() -> (H2Stub, Arc<AtomicUsize>) {
    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let seen = Arc::new(AtomicUsize::new(0));
    let task_seen = Arc::clone(&seen);
    let accepting = spawn_accepting(move |accept_error| async move {
        loop {
            let sock = accept(&listener, &accept_error).await;
            let acceptor = acceptor.clone();
            let task_seen = Arc::clone(&task_seen);
            let _served = spawn(async move {
                let Ok(tls) = acceptor.accept(sock).await else {
                    return;
                };
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = conn.accept().await {
                    if is_warm_up(&request) {
                        let (resp, body) = warm_up_answer();
                        h2_send(&mut respond, resp, body);
                        continue;
                    }
                    task_seen.fetch_add(1, Ordering::SeqCst);
                    let _held = spawn(async move {
                        // BOTH halves held: dropping the RecvStream would
                        // reset a stream whose PUT body is still owed,
                        // and a reset is a signal where this stub must be
                        // silence.
                        let _request = request;
                        let _respond = respond;
                        std::future::pending::<()>().await;
                    });
                }
            });
        }
    });
    (
        H2Stub {
            addr,
            pin,
            _accepting: accepting,
        },
        seen,
    )
}

/// A stub that accepts requests over h2 connections and, for each
/// non-warm-up call, waits `delay` (via [`park_for`] — a paused-clock
/// timer, never a real slow socket) before answering via
/// [`h2_default_answer`]. Serves any number of SEQUENTIAL requests on
/// one connection, so the same stub covers both a single delayed call
/// and a long run of them.
///
/// A task PER accepted stream, not handled inline in the accept loop:
/// per [`h2_stub_lying_root`]'s own doc, `conn.accept()` is what drives
/// the connection's I/O (flushing a QUEUED response among other
/// things), so a loop body that awaits `park_for` before looping back to
/// `conn.accept()` again stalls that driving for every stream on the
/// connection, not only its own — harmless for a single delayed call,
/// measured to matter over a long SEQUENTIAL run of them.
///
/// The returned [`DelayProgress`] counts the non-warm-up requests that
/// have armed their delay and been answered — what [`drive_delayed_call`]
/// keys its phases on.
async fn h2_stub_delayed(delay: Duration) -> (H2Stub, Arc<DelayProgress>) {
    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let progress = Arc::new(DelayProgress::default());
    let stub_progress = Arc::clone(&progress);
    let accepting = spawn_accepting(move |accept_error| async move {
        let sock = accept(&listener, &accept_error).await;
        let Ok(tls) = acceptor.accept(sock).await else {
            return;
        };
        let Ok(mut conn) = h2::server::handshake(tls).await else {
            return;
        };
        while let Some(Ok((request, respond))) = conn.accept().await {
            let progress = Arc::clone(&stub_progress);
            let _handled = spawn(async move {
                let mut respond = respond;
                if is_warm_up(&request) {
                    let (resp, body) = warm_up_answer();
                    h2_send(&mut respond, resp, body);
                    return;
                }
                // No `.await` between the count and the timer's creation,
                // so the delay starts at the virtual instant the count
                // reports.
                progress.armed.fetch_add(1, Ordering::SeqCst);
                park_for(delay).await;
                let (resp, body) = h2_default_answer(&request);
                h2_send(&mut respond, resp, body);
                progress.answered.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    (
        H2Stub {
            addr,
            pin,
            _accepting: accepting,
        },
        progress,
    )
}

/// Like [`h2_stub_delayed`], but answers every NON-warm-up request as
/// `max_seq`'s own "no roots" success shape (`404` + `Granary-Error:
/// not-found`) rather than [`h2_default_answer`]'s generic
/// PUT/ranged-GET shape: §5.7 makes a bare `200` on this endpoint a HARD
/// ERROR rather than a degrade, so the generic answer cannot stand in
/// for it here. Every request this stub sees IS a `max_seq` call —
/// [`is_warm_up`] cannot distinguish the warm-up call from the ones
/// under test by shape alone, so a request counter does instead: the
/// FIRST is the warm-up (answered instantly, uncounted against `delay`),
/// every one after it is delayed. A task per stream, for
/// [`h2_stub_delayed`]'s own reason.
///
/// The returned [`DelayProgress`] counts, for the delayed requests only,
/// how many have armed their delay and how many have been answered — what
/// [`drive_delayed_call`] keys its phases on.
async fn h2_stub_delayed_absent_max_seq(delay: Duration) -> (H2Stub, Arc<DelayProgress>) {
    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let progress = Arc::new(DelayProgress::default());
    let stub_progress = Arc::clone(&progress);
    let accepting = spawn_accepting(move |accept_error| async move {
        let sock = accept(&listener, &accept_error).await;
        let Ok(tls) = acceptor.accept(sock).await else {
            return;
        };
        let Ok(mut conn) = h2::server::handshake(tls).await else {
            return;
        };
        let first = Arc::new(AtomicBool::new(true));
        while let Some(Ok((_request, respond))) = conn.accept().await {
            let first = Arc::clone(&first);
            let progress = Arc::clone(&stub_progress);
            let _handled = spawn(async move {
                let delayed = !first.swap(false, Ordering::SeqCst);
                if delayed {
                    // No `.await` between the count and the timer's
                    // creation, so the delay starts at the virtual instant
                    // the count reports.
                    progress.armed.fetch_add(1, Ordering::SeqCst);
                    park_for(delay).await;
                }
                let mut respond = respond;
                let (resp, body) = warm_up_answer();
                h2_send(&mut respond, resp, body);
                if delayed {
                    progress.answered.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    (
        H2Stub {
            addr,
            pin,
            _accepting: accepting,
        },
        progress,
    )
}

/// What [`h2_stub_delayed`] and [`h2_stub_delayed_absent_max_seq`]
/// report about their delayed requests: how many have ARMED their
/// delay timer, and how many have been ANSWERED (the response handed
/// to h2, not yet necessarily read by the client).
#[derive(Debug, Default)]
struct DelayProgress {
    armed: AtomicUsize,
    answered: AtomicUsize,
}

/// Behaviour for the ONE root key [`h2_stub_root_deadline`] answers
/// about — parked with nothing stored, or parked with the bytes already
/// landed — a missing PUT response requires §5.5's probe to find out.
#[derive(Debug, Clone, Copy)]
enum RootPutBehavior {
    /// The `PUT root` is drained and then its response is never sent.
    /// Nothing is stored: the probe must find NOTHING there.
    ParkVacant,
    /// The `PUT root` is drained, its bytes are STORED as if the write
    /// had landed, and then its response is never sent. The probe must
    /// find the LANDED bytes, byte-identical.
    ParkLanded,
}

/// A stub for exactly the `commit()` choreography: `PUT .../root/{seq}`
/// PARKS per [`RootPutBehavior`]; `GET .../root/{seq}` (the probe)
/// answers from what was (or was not) landed, and is COUNTED;
/// `PUT .../hint` and warm-up `max_seq` calls both answer immediately so
/// neither ever waits out a deadline of its own.
///
/// Loops over CONNECTIONS, not just streams: the `put_root` call this
/// stub parks is the one the CLIENT itself cancels (the seam deadline
/// drops the in-flight request), and whether hyper-util's pool then
/// hands the probe a REUSED connection or dials a fresh one is an
/// internal pooling detail this test does not pin — the stub answers
/// either way.
async fn h2_stub_root_deadline(behavior: RootPutBehavior) -> (H2Stub, Arc<AtomicUsize>) {
    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let get_root_calls = Arc::new(AtomicUsize::new(0));
    let task_calls = Arc::clone(&get_root_calls);
    let landed: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let accepting = spawn_accepting(move |accept_error| async move {
        loop {
            let sock = accept(&listener, &accept_error).await;
            let acceptor = acceptor.clone();
            let landed = Arc::clone(&landed);
            let calls = Arc::clone(&task_calls);
            let _served = spawn(async move {
                let Ok(tls) = acceptor.accept(sock).await else {
                    return;
                };
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, respond))) = conn.accept().await {
                    let landed = Arc::clone(&landed);
                    let calls = Arc::clone(&calls);
                    let _handled = spawn(h2_root_deadline_reply(
                        request, respond, landed, calls, behavior,
                    ));
                }
            });
        }
    });
    (
        H2Stub {
            addr,
            pin,
            _accepting: accepting,
        },
        get_root_calls,
    )
}

/// One request's worth of [`h2_stub_root_deadline`]'s logic, run in its
/// own task (the same reason [`h2_stub_lying_root`]'s sibling function
/// gives: `conn.accept()` must keep being polled by the OUTER loop for
/// this handler's own awaits — the body drain, the PARK — to make
/// progress).
async fn h2_root_deadline_reply(
    request: Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    landed: Arc<Mutex<Option<Vec<u8>>>>,
    get_root_calls: Arc<AtomicUsize>,
    behavior: RootPutBehavior,
) {
    if is_warm_up(&request) {
        let mut respond = respond;
        let (resp, body) = warm_up_answer();
        h2_send(&mut respond, resp, body);
        return;
    }
    let path = request.uri().path().to_owned();
    if request.method() == Method::PUT && path.contains("/root/") {
        let body = drain_h2(request.into_body()).await;
        if matches!(behavior, RootPutBehavior::ParkLanded) {
            let mut guard = landed
                .lock()
                .unwrap_or_else(|e| panic!("landed lock poisoned: {e}"));
            *guard = Some(body);
        }
        // PARK: `respond` is held alive and never answered — the same
        // "held, not dropped" shape every silent-peer fixture in this
        // file uses, so the client sees silence rather than a reset.
        let _respond = respond;
        std::future::pending::<()>().await;
    } else if request.method() == Method::PUT {
        // The advisory hint PUT (or anything else this test never
        // sends): answered immediately so it costs no deadline of its
        // own.
        let _ = drain_h2(request.into_body()).await;
        let mut respond = respond;
        let resp = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(())
            .unwrap_or_else(|e| panic!("response: {e}"));
        h2_send(&mut respond, resp, Vec::new());
    } else {
        // GET root: the probe.
        get_root_calls.fetch_add(1, Ordering::SeqCst);
        let present = landed
            .lock()
            .unwrap_or_else(|e| panic!("landed lock poisoned: {e}"))
            .clone();
        let mut respond = respond;
        if let Some(bytes) = present {
            let resp = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .unwrap_or_else(|e| panic!("response: {e}"));
            h2_send(&mut respond, resp, bytes);
        } else {
            let resp = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("granary-error", "not-found")
                .body(())
                .unwrap_or_else(|e| panic!("response: {e}"));
            h2_send(&mut respond, resp, Vec::new());
        }
    }
}

/// An ordinary, fully-answering stub for the PREPARE half of a publish:
/// `max_seq` answers "no roots" (so `remote_state` short-circuits to an
/// empty volume and fetches nothing else), every PUT answers `201`.
/// Nothing about the stub built here is under test — it exists only to
/// reach a real [`Prepared`] value, the way a real `gran publish` would,
/// and it never runs under a paused clock (`prepared_for_a_trivial_tree`
/// is always called before this file's own `tokio::time::pause()`).
async fn h2_stub_prep() -> H2Stub {
    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let accepting = spawn_accepting(move |accept_error| async move {
        let sock = accept(&listener, &accept_error).await;
        let Ok(tls) = acceptor.accept(sock).await else {
            return;
        };
        let Ok(mut conn) = h2::server::handshake(tls).await else {
            return;
        };
        while let Some(Ok((request, mut respond))) = conn.accept().await {
            let (resp, body) = if is_warm_up(&request) {
                warm_up_answer()
            } else {
                h2_default_answer(&request)
            };
            h2_send(&mut respond, resp, body);
        }
    });
    H2Stub {
        addr,
        pin,
        _accepting: accepting,
    }
}

/// A real [`Prepared`] for a trivial one-file tree, built against
/// [`h2_stub_prep`] — the setup every `put_root`-deadline row below
/// shares, factored out because none of them are testing THIS half of
/// the flow. Always runs in REAL time: no row calls `tokio::time::
/// pause()` before this returns.
async fn prepared_for_a_trivial_tree(seed: u8) -> Prepared {
    let prep = h2_stub_prep().await;
    let prep_remote = prep.store();
    let scratch = Scratch::new();
    let store = scratch.store();
    let (manifest_root, harvest_stats) = granary_client::harvest(&scratch.source(), &store)
        .unwrap_or_else(|e| panic!("harvest: {e}"));
    let key = signing_key(seed);
    let identity = WriterIdentity::from_bytes(*b"deadline-writer!");
    let now = Timestamp {
        secs: 1_700_000_000,
        nanos: 0,
    };
    granary_client::prepare_from_manifest(
        &prep_remote,
        &store,
        manifest_root,
        harvest_stats,
        &volume(),
        &key,
        &identity,
        now,
        Policy::default(),
    )
    .await
    .unwrap_or_else(|e| panic!("prepare_from_manifest: {e}"))
}

/// The constants are the behavioural row: the base is 45 seconds and the
/// floor is `65_536` bytes/s; this asserts those VALUES, not a relation.
#[test]
fn the_deadline_constants_are_pinned() {
    assert_eq!(SEAM_DEADLINE_BASE, Duration::from_secs(45));
    assert_eq!(SEAM_FLOOR_RATE_BYTES_PER_SEC, 65_536);
}

/// The expected per-call deadline, restated locally: the assertion
/// stays an independent oracle of the production `seam_deadline` (which
/// is deliberately private — calling it would make the `after ==`
/// checks tautological) while a formula change is a one-place test
/// edit. The rows that hand-pick a size as `rate × N` and assert
/// `base + N` keep their own arithmetic — those are the genuinely
/// independent derivations.
fn expected_seam_deadline(transfer: u64) -> Duration {
    SEAM_DEADLINE_BASE + Duration::from_secs(transfer / SEAM_FLOOR_RATE_BYTES_PER_SEC)
}

/// A peer that accepts a `GET` and then answers nothing is cut at
/// `SEAM_DEADLINE_BASE + transfer_size / SEAM_FLOOR_RATE_BYTES_PER_SEC`
/// for a KNOWN size — the behavioural row — and never retried: the wire
/// counter reads exactly 1, pinning `Elapsed` as NEVER-RETRY for the
/// whole call. `Elapsed` is produced
/// by the deadline TIMEOUT dropping the whole in-flight call (both of
/// `send`'s own attempts, had a first one failed and qualified for a
/// retry) rather than by anything `retry::classify` inspects, so a
/// second attempt reaching the stub would mean the deadline had been
/// applied per-attempt instead of per-call — exactly the "retrying a
/// wedged peer inside the same call defeats the bound" failure this row
/// exists to catch.
#[tokio::test]
async fn a_blackholed_get_is_cut_at_base_plus_size_over_rate() {
    let (stub, seen) = h2_stub_parking().await;
    let store = stub.store();
    warm_up(&store).await;

    // A known size: exactly 5 seconds' worth at the floor rate.
    let len = u32::try_from(SEAM_FLOOR_RATE_BYTES_PER_SEC * 5).unwrap_or_else(|e| panic!("{e}"));
    let want_after = SEAM_DEADLINE_BASE + Duration::from_secs(5);

    tokio::time::pause();
    let task = spawn(async move { store.get_bin_range(&DIGEST, 0, len).await });
    advance_settled(want_after + Duration::from_secs(2)).await;
    // Fail closed: if the deadline regressed (a seam un-wrapped), the
    // task is still parked on a silent socket with NO timer registered —
    // awaiting it would wedge this binary instead of failing it.
    assert!(
        task.is_finished(),
        "the seam call is still running past its own deadline — the wrap is missing"
    );
    let got = task
        .await
        .unwrap_or_else(|e| panic!("client task panicked: {e}"));

    match got {
        Err(RootStoreError::Elapsed { operation, after }) => {
            assert_eq!(operation, "GET bin");
            assert_eq!(
                after, want_after,
                "the deadline must scale with the DECLARED size, not a flat figure"
            );
        }
        other => panic!("a blackholed GET must be cut on its own deadline; got {other:?}"),
    }
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "exactly one attempt reached the stub — a cut call is never retried"
    );
}

/// `put_root` parked with NOTHING landed: the probe (`get_root`) runs
/// exactly once and finds nothing there (`Ok(None)`), so the outcome is
/// `PublishError::Unresolved`, carrying the ORIGINAL `Elapsed` — this is
/// the probe-ANSWERED arm; the probe-FAILED arm (`ProbeUnresolved`) is
/// exercised below. The ONE-PROBE RULE (`granary_core::rootstore` module
/// doc) treats "nothing there" as UNRESOLVED, never as the original
/// failure restated, because no adapter here can prove the elapsed
/// `put_root`'s own attempt was the only one sent. This h2/TLS run is
/// also the REACHABILITY evidence for that row: a real peer parking the
/// PUT and then answering `404` on the probe reaches it.
#[tokio::test]
async fn a_blackholed_put_root_probes_before_surfacing() {
    let prepared = prepared_for_a_trivial_tree(0x10).await;
    let root_bytes = prepared.root_bytes.clone();
    let (stub, get_root_calls) = h2_stub_root_deadline(RootPutBehavior::ParkVacant).await;
    let remote = stub.store();
    warm_up(&remote).await;
    let deadline = SEAM_DEADLINE_BASE
        + Duration::from_secs(root_bytes.len() as u64 / SEAM_FLOOR_RATE_BYTES_PER_SEC);

    tokio::time::pause();
    let task = spawn(async move { granary_client::commit(&remote, prepared).await });
    advance_settled(deadline + Duration::from_secs(2)).await;
    // Fail closed — same reason as the sibling rows: a regressed
    // deadline leaves the task parked with no timer, and awaiting it
    // wedges the binary instead of failing it.
    assert!(
        task.is_finished(),
        "commit is still running past the put deadline — the wrap is missing"
    );
    let got = task
        .await
        .unwrap_or_else(|e| panic!("client task panicked: {e}"));

    match got {
        Err(PublishError::Unresolved {
            put_error: RootStoreError::Elapsed { operation, .. },
        }) => {
            assert_eq!(operation, "PUT root");
        }
        other => panic!(
            "a parked put_root with nothing landed must be UNRESOLVED, carrying the ORIGINAL \
             elapse, once the probe finds it vacant; got {other:?}"
        ),
    }
    assert_eq!(
        get_root_calls.load(Ordering::SeqCst),
        1,
        "the ONE-PROBE RULE: the probe must run exactly once"
    );
}

/// `put_root` LANDS its bytes and then parks the response: the probe
/// reads them back byte-identical and `commit()` reports SUCCESS — the
/// lost-response scenario for a completed write, bounded at
/// `SEAM_DEADLINE_BASE` with the probe run.
#[tokio::test]
async fn a_landed_but_blackholed_put_root_reports_success_via_the_probe() {
    let prepared = prepared_for_a_trivial_tree(0x11).await;
    let root_bytes = prepared.root_bytes.clone();
    let want_seq = prepared.seq();
    let (stub, get_root_calls) = h2_stub_root_deadline(RootPutBehavior::ParkLanded).await;
    let remote = stub.store();
    warm_up(&remote).await;
    let deadline = SEAM_DEADLINE_BASE
        + Duration::from_secs(root_bytes.len() as u64 / SEAM_FLOOR_RATE_BYTES_PER_SEC);

    tokio::time::pause();
    let mut task = spawn(async move { granary_client::commit(&remote, prepared).await });
    // `put_root` itself must elapse (~`deadline`) before the probe even
    // runs; the guard leaves it room to do that AND complete the fast
    // probe afterward, while staying well inside what a SECOND elapse
    // (the probe timing out too) would need.
    drive_to_completion(&mut task, deadline + Duration::from_secs(10)).await;
    let got = task
        .await
        .unwrap_or_else(|e| panic!("client task panicked: {e}"));

    let summary = got.unwrap_or_else(|e| {
        panic!(
            "a landed-but-lost-response put_root must resolve to success via the probe; got {e:?}"
        )
    });
    assert_eq!(summary.seq, want_seq);
    assert_eq!(
        get_root_calls.load(Ordering::SeqCst),
        1,
        "the ONE-PROBE RULE: the probe must run exactly once"
    );
}

/// Negative control: a transfer whose HONEST duration sits strictly
/// between `SEAM_DEADLINE_BASE` and its own scaled deadline completes —
/// the scaled term admitting real traffic, not merely delaying a cut.
///
/// What this row exercises is the TIMING property (a call running
/// well past the base but inside its scaled deadline is not cut), and
/// only that: under h2 flow control the stub never drains the PUT
/// body, so the bytes themselves mostly do not move — the delayed 201
/// resolves the call early, which h2 permits. No row here drives
/// sustained slow BYTE progress; a defect that cut on per-read idle
/// rather than whole-call elapsed would pass this row.
#[tokio::test]
async fn a_slow_honest_transfer_survives_the_scaled_deadline() {
    // 20 seconds' worth at the floor rate: the scaled deadline is
    // `SEAM_DEADLINE_BASE + 20s`.
    let body_len =
        usize::try_from(SEAM_FLOOR_RATE_BYTES_PER_SEC * 20).unwrap_or_else(|e| panic!("{e}"));
    let scaled_deadline = SEAM_DEADLINE_BASE + Duration::from_secs(20);
    // Slower than the base alone would admit, faster than the scaled
    // deadline — the exact honest-but-slow shape the floor rate exists
    // to distinguish from a wedge.
    let delay = SEAM_DEADLINE_BASE + Duration::from_secs(10);
    assert!(
        delay > SEAM_DEADLINE_BASE && delay < scaled_deadline,
        "test setup: the delay must sit strictly inside the scaled deadline's admitted range"
    );
    assert!(
        delay + REAL_WAIT_MAX < scaled_deadline,
        "test setup: drive_delayed_call needs more slack than REAL_WAIT_MAX"
    );
    let (stub, progress) = h2_stub_delayed(delay).await;
    let store = stub.store();
    warm_up(&store).await;

    let bytes = vec![0x11_u8; body_len];
    tokio::time::pause();
    let task = spawn(async move { store.put_bin(&DIGEST, bytes).await });
    drive_delayed_call(&task, &progress, delay).await;
    let got = task
        .await
        .unwrap_or_else(|e| panic!("client task panicked: {e}"));

    assert_eq!(
        got,
        Ok(true),
        "a transfer slower than the base but inside its own scaled deadline must complete, not be cut"
    );
}

/// With no whole-operation total, this acceptance property is testable:
/// a long OPERATION built from many individually-bounded calls, whose
/// SUM exceeds an hour, completes — because nothing bounds the sum,
/// only each call.
#[tokio::test]
async fn a_long_operation_of_bounded_calls_is_not_cut() {
    const CALLS: usize = 150;
    // `max_seq`'s own deadline is the base alone (transfer size 0):
    // each call waits `SEAM_DEADLINE_BASE - 5 s` (40 s at the current
    // 45 s base), inside it, and 150 of them sum to 6 000 s — well past
    // an hour.
    let per_call_delay = SEAM_DEADLINE_BASE
        .checked_sub(Duration::from_secs(5))
        .unwrap_or_else(|| panic!("test setup: SEAM_DEADLINE_BASE must exceed 5s"));
    assert!(
        per_call_delay + REAL_WAIT_MAX < SEAM_DEADLINE_BASE,
        "test setup: drive_delayed_call needs more slack than REAL_WAIT_MAX"
    );
    let (stub, progress) = h2_stub_delayed_absent_max_seq(per_call_delay).await;
    let store = Arc::new(stub.store());
    // The stub's OWN first answer is the warm-up (undelayed) — real
    // time, before `pause()`, for this section's own reason.
    warm_up(&store).await;

    tokio::time::pause();
    for _ in 0..CALLS {
        let store = Arc::clone(&store);
        let task = spawn(async move { store.max_seq(VOLUME).await });
        // Five seconds of slack separate each call's delay from its
        // deadline — too little to step the clock before the stub has
        // seen the request, and `drive_delayed_call` does not step it
        // until the stub has armed.
        drive_delayed_call(&task, &progress, per_call_delay).await;
        let got = task
            .await
            .unwrap_or_else(|e| panic!("client task panicked: {e}"));
        assert_eq!(
            got,
            Ok(None),
            "every call in the sequence must complete honestly inside its own deadline"
        );
    }
}

// -------------------- Quality probes: the four grep-evidence-only seams.
// Each parks one of put_meta/get_meta/read_hint/write_hint in the same
// blackhole stub the committed GET row uses, and asserts the EXACT
// `Elapsed { operation, after }` — the asserted `after` VALUE is what
// pins the seam to its OWN transfer-size source rather than to a flat
// figure or another seam's.

/// `put_meta` parked: cut at base + BODY LEN / rate — the asserted
/// deadline is three seconds over base, which only the request body's
/// own length produces.
#[tokio::test]
async fn a_blackholed_put_meta_is_cut_at_base_plus_body_over_rate() {
    let (stub, seen) = h2_stub_parking().await;
    let store = stub.store();
    warm_up(&store).await;

    // Exactly 3 seconds' worth of body at the floor rate.
    let body_len =
        usize::try_from(SEAM_FLOOR_RATE_BYTES_PER_SEC * 3).unwrap_or_else(|e| panic!("{e}"));
    let want_after = SEAM_DEADLINE_BASE + Duration::from_secs(3);
    let id = GrainId::of(b"t10 quality probe: put_meta");
    let bytes = vec![0x22_u8; body_len];

    tokio::time::pause();
    let task = spawn(async move { store.put_meta(VOLUME, &id, bytes).await });
    advance_settled(want_after + Duration::from_secs(2)).await;
    // Fail closed: if the deadline regressed (a seam un-wrapped), the
    // task is still parked on a silent socket with NO timer registered —
    // awaiting it would wedge this binary instead of failing it.
    assert!(
        task.is_finished(),
        "the seam call is still running past its own deadline — the wrap is missing"
    );
    let got = task
        .await
        .unwrap_or_else(|e| panic!("client task panicked: {e}"));

    match got {
        Err(RootStoreError::Elapsed { operation, after }) => {
            assert_eq!(operation, "PUT meta");
            assert_eq!(
                after, want_after,
                "put_meta's deadline must scale with the request BODY length"
            );
        }
        other => panic!("a blackholed put_meta must be cut on its own deadline; got {other:?}"),
    }
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "a cut call is never retried"
    );
}

/// `get_meta` parked: cut at base + `META_MAX_BYTES` / rate (16 MiB →
/// base + 256 s) — the asserted deadline is what pins the size source
/// to the READ CAP this call is already bounded to.
#[tokio::test]
async fn a_blackholed_get_meta_is_cut_at_base_plus_cap_over_rate() {
    let (stub, seen) = h2_stub_parking().await;
    let store = stub.store();
    warm_up(&store).await;

    let want_after = expected_seam_deadline(META_MAX_BYTES);
    let id = GrainId::of(b"t10 quality probe: get_meta");

    tokio::time::pause();
    let task = spawn(async move { store.get_meta(VOLUME, &id).await });
    advance_settled(want_after + Duration::from_secs(2)).await;
    // Fail closed: if the deadline regressed (a seam un-wrapped), the
    // task is still parked on a silent socket with NO timer registered —
    // awaiting it would wedge this binary instead of failing it.
    assert!(
        task.is_finished(),
        "the seam call is still running past its own deadline — the wrap is missing"
    );
    let got = task
        .await
        .unwrap_or_else(|e| panic!("client task panicked: {e}"));

    match got {
        Err(RootStoreError::Elapsed { operation, after }) => {
            assert_eq!(operation, "GET meta");
            assert_eq!(
                after, want_after,
                "get_meta's deadline must scale with META_MAX_BYTES, its own read cap"
            );
        }
        other => panic!("a blackholed get_meta must be cut on its own deadline; got {other:?}"),
    }
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "a cut call is never retried"
    );
}

/// `read_hint` parked: cut at exactly the base — its cap
/// (`SEQ_KEY_DIGITS`, 20 bytes) floors to zero seconds at the rate, so
/// the exact-base `after` is as much as a value assertion CAN pin here
/// (any size under one second's worth is indistinguishable by value).
#[tokio::test]
async fn a_blackholed_read_hint_is_cut_at_the_base() {
    let (stub, seen) = h2_stub_parking().await;
    let store = stub.store();
    warm_up(&store).await;

    let want_after = SEAM_DEADLINE_BASE;

    tokio::time::pause();
    let task = spawn(async move { store.read_hint(VOLUME, None).await });
    advance_settled(want_after + Duration::from_secs(2)).await;
    // Fail closed: if the deadline regressed (a seam un-wrapped), the
    // task is still parked on a silent socket with NO timer registered —
    // awaiting it would wedge this binary instead of failing it.
    assert!(
        task.is_finished(),
        "the seam call is still running past its own deadline — the wrap is missing"
    );
    let got = task
        .await
        .unwrap_or_else(|e| panic!("client task panicked: {e}"));

    match got {
        Err(RootStoreError::Elapsed { operation, after }) => {
            assert_eq!(operation, "GET hint");
            assert_eq!(after, want_after, "read_hint's deadline is the base alone");
        }
        other => panic!("a blackholed read_hint must be cut on its own deadline; got {other:?}"),
    }
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "a cut call is never retried"
    );
}

/// `write_hint` parked: cut at exactly the base — the 20-digit body
/// floors to zero seconds at the rate; same value-assertion limit as
/// `read_hint`'s row.
#[tokio::test]
async fn a_blackholed_write_hint_is_cut_at_the_base() {
    let (stub, seen) = h2_stub_parking().await;
    let store = stub.store();
    warm_up(&store).await;

    let want_after = SEAM_DEADLINE_BASE;

    tokio::time::pause();
    let task = spawn(async move { store.write_hint(VOLUME, 7).await });
    advance_settled(want_after + Duration::from_secs(2)).await;
    // Fail closed: if the deadline regressed (a seam un-wrapped), the
    // task is still parked on a silent socket with NO timer registered —
    // awaiting it would wedge this binary instead of failing it.
    assert!(
        task.is_finished(),
        "the seam call is still running past its own deadline — the wrap is missing"
    );
    let got = task
        .await
        .unwrap_or_else(|e| panic!("client task panicked: {e}"));

    match got {
        Err(RootStoreError::Elapsed { operation, after }) => {
            assert_eq!(operation, "PUT hint");
            assert_eq!(after, want_after, "write_hint's deadline is the base alone");
        }
        other => panic!("a blackholed write_hint must be cut on its own deadline; got {other:?}"),
    }
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "a cut call is never retried"
    );
}

/// A stub that answers the response HEAD (200, no trailers promised)
/// for every non-warm-up request and then parks the BODY stream
/// forever: the `SendStream` is held alive with no data and no
/// end-of-stream, so the client's header exchange completes and its
/// body read then hangs — a deadline that
/// covered only the send half would never fire here.
async fn h2_stub_headers_then_parked_body() -> H2Stub {
    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    let accepting = spawn_accepting(move |accept_error| async move {
        let sock = accept(&listener, &accept_error).await;
        let Ok(tls) = acceptor.accept(sock).await else {
            return;
        };
        let Ok(mut conn) = h2::server::handshake(tls).await else {
            return;
        };
        while let Some(Ok((request, mut respond))) = conn.accept().await {
            if is_warm_up(&request) {
                let (resp, body) = warm_up_answer();
                h2_send(&mut respond, resp, body);
                continue;
            }
            let resp = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .unwrap_or_else(|e| panic!("response: {e}"));
            // `end_of_stream: false`: the head goes out, the body is
            // promised and never delivered.
            let Ok(send) = respond.send_response(resp, false) else {
                continue;
            };
            let _held = spawn(async move {
                let _request = request;
                let _send = send;
                std::future::pending::<()>().await;
            });
        }
    });
    H2Stub {
        addr,
        pin,
        _accepting: accepting,
    }
}

/// A peer that answers HEADERS promptly and
/// then stalls the BODY is still a wedged peer, and the deadline must
/// cover the body read — `under_seam_deadline`'s own doc says so. This
/// drives `get_root` (`put_root`'s probe, the §5.5 call): headers arrive
/// instantly, no body byte ever does, and the call must still be cut at
/// base + `ROOT_MAX_BYTES` / rate.
#[tokio::test]
async fn a_parked_response_body_is_still_cut_by_the_seam_deadline() {
    let stub = h2_stub_headers_then_parked_body().await;
    let store = stub.store();
    warm_up(&store).await;

    let want_after = expected_seam_deadline(ROOT_MAX_BYTES);

    tokio::time::pause();
    let task = spawn(async move { store.get_root(VOLUME, 1).await });
    advance_settled(want_after + Duration::from_secs(2)).await;
    assert!(
        task.is_finished(),
        "a body-read stall ESCAPED the seam deadline: the header exchange completed, \
         the body never arrived, and the call is still running past its own deadline \
         — the wrap must cover the response-body read, not only the send"
    );
    let got = task
        .await
        .unwrap_or_else(|e| panic!("client task panicked: {e}"));

    match got {
        Err(RootStoreError::Elapsed { operation, after }) => {
            assert_eq!(operation, "GET root");
            assert_eq!(after, want_after);
        }
        other => panic!("a parked response body must elapse the seam deadline; got {other:?}"),
    }
}

/// The choreography's own bound: park BOTH `put_root` AND the
/// probe (`get_root`) — the fully-wedged peer — and `commit()`
/// must still return within put-deadline + probe-deadline of
/// paused time, surfacing `PublishError::ProbeUnresolved` carrying
/// BOTH elapses (the probe
/// itself failed, so the outcome is UNKNOWN; surfacing
/// `Unresolved { put_error }` is the `Ok(None)` arm's answer, not this
/// one's). A probe with no
/// deadline of its own would wedge the whole operation here, and
/// no whole-operation total exists to catch it — the probe's own deadline must.
#[tokio::test]
async fn a_fully_parked_peer_cannot_wedge_commit_past_both_deadlines() {
    let prepared = prepared_for_a_trivial_tree(0x12).await;
    let root_bytes = prepared.root_bytes.clone();
    let (stub, seen) = h2_stub_parking().await;
    let remote = stub.store();
    warm_up(&remote).await;
    let put_deadline = SEAM_DEADLINE_BASE
        + Duration::from_secs(root_bytes.len() as u64 / SEAM_FLOOR_RATE_BYTES_PER_SEC);
    let probe_deadline = expected_seam_deadline(ROOT_MAX_BYTES);

    tokio::time::pause();
    let task = spawn(async move { granary_client::commit(&remote, prepared).await });
    advance_settled(put_deadline + probe_deadline + Duration::from_secs(4)).await;
    assert!(
        task.is_finished(),
        "a parked PROBE wedged the whole commit: the put elapsed, the probe ran with \
         no deadline of its own, and the operation is still running past \
         put-deadline + probe-deadline — the probe must carry its OWN seam deadline"
    );
    let got = task
        .await
        .unwrap_or_else(|e| panic!("client task panicked: {e}"));

    match got {
        Err(PublishError::ProbeUnresolved {
            put_error,
            probe_error,
        }) => {
            match put_error {
                RootStoreError::Elapsed { operation, .. } => {
                    assert_eq!(
                        operation, "PUT root",
                        "the put half must name the PUT's seam"
                    );
                }
                other => panic!("the put half must be an Elapsed, got {other:?}"),
            }
            match probe_error {
                RootStoreError::Elapsed { operation, .. } => {
                    assert_eq!(
                        operation, "GET root",
                        "the probe half must name the PROBE's own seam"
                    );
                }
                other => panic!("the probe half must be an Elapsed, got {other:?}"),
            }
        }
        other => {
            panic!(
                "a fully-parked peer must surface ProbeUnresolved carrying BOTH elapses; got \
                 {other:?}"
            )
        }
    }
    assert_eq!(
        seen.load(Ordering::SeqCst),
        2,
        "exactly two streams reached the wire: the parked PUT and the parked probe, once each"
    );
}

#[tokio::test]
async fn wire_429_never_serves_stale_anchor() {
    use granary_client::{Cache, CacheOrigin, HeadContext, HintUpdate, resolve_head_verified};
    use granary_core::{clock::Clock, manifest, rng::SeededRng, sheaf};
    struct Frozen;
    impl Clock for Frozen {
        fn now(&self) -> Timestamp {
            Timestamp {
                secs: 1_700_000_000,
                nanos: 0,
            }
        }
    }
    let key = signing_key(19);
    let dir = manifest::build_dir(&[]).unwrap();
    let sheaf_bytes = sheaf::encode_sheaf(&sheaf::SheafDoc {
        parent: None,
        manifest_root: dir.root,
        timestamp: Timestamp {
            secs: 1_700_000_000,
            nanos: 0,
        },
        ops: vec![sheaf::SheafOp::PublishTree],
    })
    .unwrap();
    let mut doc = root::decode_root(&signed_root(&key)).unwrap();
    doc.manifest_root = dir.root;
    doc.sheaf_head = GrainId::of(&sheaf_bytes);
    let unsigned = root::encode_root(&doc).unwrap();
    doc.sigs[0].sig = key.sign(root::signed_prefix(&unsigned).unwrap());
    let root_bytes = root::encode_root(&doc).unwrap();
    let stub = stub(answering(|_| {
        refusal(StatusCode::TOO_MANY_REQUESTS, Some("rate-limited"))
    }))
    .await;
    let scratch = Scratch::new();
    let mut cache = Cache::open(
        &scratch.0.join("cache"),
        64 * 1024 * 1024,
        &CacheOrigin {
            endpoint_url: stub.base(),
            pin_set_digest: CacheOrigin::pin_set_digest(&[stub.pin]),
            root_key_id: Some(CacheOrigin::root_key_digest(key.public_key())),
        },
    )
    .unwrap();
    for (id, bytes) in dir.nodes {
        cache.insert(&id, &bytes);
    }
    cache.insert(&doc.sheaf_head, &sheaf_bytes);
    cache.put_root_bytes(&volume(), 1, &root_bytes);
    cache.raise_anchor(&volume(), Some(1), HintUpdate::Unchanged);
    assert_eq!(cache.read_anchor(&volume()).unwrap().seq, 1);
    assert_eq!(cache.get_root_bytes(&volume(), 1).unwrap(), root_bytes);
    let mut emitted = 0;
    let result = resolve_head_verified(
        &stub.store(),
        VOLUME,
        &RootVerifier::trusting(*key.public_key()).unwrap(),
        &HeadContext::new(Box::new(Frozen), Box::new(SeededRng::new(1))),
        Some(&mut cache),
        ResolveTarget::WholeTree,
        &mut |_, _| {
            emitted += 1;
            Ok(())
        },
    )
    .await;
    assert!(
        matches!(
            result,
            Err(ResolveError::Remote(RootStoreError::Unavailable {
                status: 429,
                ..
            }))
        ),
        "wire 429 must surface, never serve a stale anchor: {result:?}"
    );
    assert_eq!(emitted, 0, "no degraded emission on an answered refusal");
}

mod authority;

/// A sink for the one retry diagnostic each failed first attempt leaves.
#[derive(Clone, Default)]
struct DiagnosticLog(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for DiagnosticLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DiagnosticLog {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

/// The retry diagnostic names the failure's own class: a certificate the pin
/// refuses is a refusal, an unreachable peer is unavailable.
#[tokio::test]
async fn the_retry_diagnostic_classifies_a_pin_rejection_apart_from_an_unreachable_peer() {
    let log = DiagnosticLog::default();
    let _guard = tracing::subscriber::set_default(granary_client::subscriber(
        granary_client::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("debug"),
        log.clone(),
    ));
    let stub = stub(answering(|_| ok_body(&b"x"[..]))).await;
    let wrong = HttpStore::new(&stub.base(), vec![mint().pin()], &AmbientNetwork)
        .unwrap_or_else(|e| panic!("http store: {e}"));
    wrong
        .get_root(VOLUME, 1)
        .await
        .expect_err("a stranger's pin gets nothing");

    let doomed = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = doomed
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));
    drop(doomed);
    let dead = HttpStore::new(&base_url(addr), vec![mint().pin()], &AmbientNetwork)
        .unwrap_or_else(|e| panic!("http store: {e}"));
    dead.get_root(VOLUME, 1)
        .await
        .expect_err("nothing is listening on that port");

    let text = String::from_utf8(log.0.lock().unwrap_or_else(|e| panic!("{e}")).clone())
        .unwrap_or_else(|e| panic!("{e}"));
    let classes: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("client.seam.attempt.failed.retrying.once"))
        .map(|line| {
            if line.contains("\"error\":\"refused\"") {
                "refused"
            } else if line.contains("\"error\":\"unavailable\"") {
                "unavailable"
            } else {
                "other"
            }
        })
        .collect();
    assert_eq!(
        classes,
        ["refused", "unavailable"],
        "retry diagnostic classes: {text}"
    );
}

struct SeededId([u8; 8]);
impl granary_core::secure_random::SecureRandom for SeededId {
    fn fill(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        for (slot, byte) in dest.iter_mut().zip(self.0.iter().cycle()) {
            *slot = *byte;
        }
        Ok(())
    }
}

struct ExhaustedEntropy;
impl granary_core::secure_random::SecureRandom for ExhaustedEntropy {
    fn fill(
        &mut self,
        _: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        Err(granary_core::secure_random::EntropyUnavailable)
    }
}

#[tokio::test]
async fn retry_attempts_carry_the_same_request_id_across_stream_and_connection_resets() {
    use tracing::Instrument as _;

    let log = DiagnosticLog::default();
    let _guard = tracing::subscriber::set_default(granary_client::closed_subscriber(
        granary_client::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("info"),
        log,
    ));
    let id = granary_client::CorrelationId::draw(&mut SeededId([0x5a; 8])).unwrap();
    let expected = id.to_string();
    let req_id = |req: &Request<h2::RecvStream>| {
        req.headers()
            .get("granary-request-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };

    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener.local_addr().unwrap();
    let stream_ids: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let task_stream_ids = Arc::clone(&stream_ids);
    let stream_stub = H2Stub {
        addr,
        pin,
        _accepting: spawn_accepting(move |accept_error| async move {
            let sock = accept(&listener, &accept_error).await;
            let tls = acceptor.accept(sock).await.unwrap();
            let mut conn = h2::server::handshake(tls).await.unwrap();
            let mut idx = 0_usize;
            while let Some(Ok((request, mut respond))) = conn.accept().await {
                task_stream_ids.lock().unwrap().push(req_id(&request));
                if idx == 0 {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                } else {
                    let (resp, body) = h2_default_answer(&request);
                    h2_send(&mut respond, resp, body);
                }
                idx += 1;
            }
        }),
    };
    let span = granary_client::operation_span(granary_client::OperationKind::Session, &id);
    let root_got = guarded(stream_stub.store().get_root(VOLUME, 1).instrument(span)).await;

    let (listener, acceptor, pin) = h2_only_listener().await;
    let addr = listener.local_addr().unwrap();
    let conn_ids: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let task_conn_ids = Arc::clone(&conn_ids);
    let dials = Arc::new(AtomicUsize::new(0));
    let conn_stub = H2Stub {
        addr,
        pin,
        _accepting: spawn_accepting(move |accept_error| async move {
            loop {
                let sock = accept(&listener, &accept_error).await;
                let index = dials.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let recorded = Arc::clone(&task_conn_ids);
                let _served = spawn(async move {
                    let tls = acceptor.accept(sock).await.unwrap();
                    let mut conn = h2::server::handshake(tls).await.unwrap();
                    while let Some(Ok((request, mut respond))) = conn.accept().await {
                        recorded.lock().unwrap().push(req_id(&request));
                        if index == 0 {
                            return;
                        }
                        let (resp, body) = h2_default_answer(&request);
                        h2_send(&mut respond, resp, body);
                    }
                });
            }
        }),
    };
    let span = granary_client::operation_span(granary_client::OperationKind::Session, &id);
    let bin_got = guarded(
        conn_stub
            .store()
            .get_bin_range(&DIGEST, 0, 4)
            .instrument(span),
    )
    .await;
    assert_eq!(
        (
            root_got,
            stream_ids.lock().unwrap().clone(),
            bin_got,
            conn_ids.lock().unwrap().clone()
        ),
        (
            Ok(Some(vec![])),
            vec![Some(expected.clone()), Some(expected.clone())],
            Ok(vec![0x42; 4]),
            vec![Some(expected.clone()), Some(expected)],
        ),
    );
}

#[tokio::test]
async fn request_id_uses_innermost_operation_span_and_omits_header_when_absent() {
    use tracing::Instrument as _;

    let peer = stub(answering(|_| ok_body(&b"00000000000000000001"[..]))).await;
    let store = peer.store();
    let log = DiagnosticLog::default();
    let _guard = tracing::subscriber::set_default(granary_client::closed_subscriber(
        granary_client::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("info"),
        log,
    ));

    store.max_seq(VOLUME).await.unwrap();

    let outer_id = granary_client::CorrelationId::draw(&mut SeededId([0xaa; 8])).unwrap();
    let inner_id = granary_client::CorrelationId::draw(&mut SeededId([0xbb; 8])).unwrap();
    let outer_span =
        granary_client::operation_span(granary_client::OperationKind::Session, &outer_id);
    async {
        let inner_span =
            granary_client::operation_span(granary_client::OperationKind::Commit, &inner_id);
        store.max_seq(VOLUME).instrument(inner_span).await.unwrap();

        let nested_draw = granary_client::CorrelationId::draw(&mut ExhaustedEntropy);
        assert!(nested_draw.is_err());
        let failed_nested = nested_draw.map_or_else(
            |_| tracing::Span::none(),
            |id| granary_client::operation_span(granary_client::OperationKind::Fsync, &id),
        );
        store
            .max_seq(VOLUME)
            .instrument(failed_nested)
            .await
            .unwrap();
    }
    .instrument(outer_span)
    .await;

    let seen: Vec<Option<String>> = peer
        .seen()
        .iter()
        .map(|r| {
            r.headers
                .get("granary-request-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(
        seen,
        vec![None, Some(inner_id.to_string()), Some(outer_id.to_string()),],
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "single table exercises publish, cat, mount start, commit with cold fetch, and a construction moved between subscribers against the HTTP recording stub"
)]
async fn user_operations_send_their_logged_correlation_id_on_every_http_request() {
    use granary_client::{
        ClientMetrics, CoordinationError, HeadContext, InstantClock, MountOptions, MountSession,
        OverlayConfig, OverlayError, Policy, PublicationOutcome, RecoveryDelay, RecoveryIntent,
        RecoveryParts, ResolveTarget, RootVerifier, Store, SyncContent, SyncEngine, SyncOptions,
        SyncRuntime, TokioSyncRuntime, WritableStore, begin_publication, harvest, op_begin, op_end,
        operation_span, resolve_head_verified,
    };
    use granary_core::{
        authlog::Epoch,
        authority_answer::{self, Position, PublishAnswer, Receipt as AuthReceipt, VolumeStatus},
        clock::Clock,
        grainsource::{GrainSource, GrainSourceError},
        intent::{self, Grant, Receipt as IntentReceipt, ReceiptState},
        manifest::{self, FileGrains, Name},
        overlay_journal::{Location, Parent},
        retained_submission::Scope,
        rng::SeededRng,
    };
    use granary_store::crypto::TrustedKeys;
    use std::collections::BTreeMap;
    use std::os::unix::fs::MetadataExt as _;
    use tracing::Instrument as _;

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            Timestamp {
                secs: 1_700_000_000,
                nanos: 0,
            }
        }
    }
    struct NoDelay;
    impl RecoveryDelay for NoDelay {
        fn jitter(&mut self, _: Duration) -> Duration {
            Duration::ZERO
        }
        fn wait(&mut self, _: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async {})
        }
    }
    #[derive(Clone)]
    struct ColdHttpContent {
        objects: Arc<Mutex<BTreeMap<GrainId, Vec<u8>>>>,
        payloads: Arc<Mutex<BTreeMap<GrainId, (u64, FileGrains)>>>,
        remote: Arc<HttpStore>,
        cold_on_next_get: Arc<AtomicBool>,
        cold_fetched: Arc<AtomicUsize>,
    }
    impl GrainSource for ColdHttpContent {
        fn has(&self, id: &GrainId) -> bool {
            self.objects.lock().unwrap().contains_key(id)
        }
        fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
            if self.cold_on_next_get.swap(false, Ordering::SeqCst) {
                self.cold_fetched.fetch_add(1, Ordering::SeqCst);
                let remote = Arc::clone(&self.remote);
                let (send, receive) = std::sync::mpsc::sync_channel(1);
                drop(TokioSyncRuntime.spawn(async move {
                    let _ = send.send(remote.get_bin_range(&DIGEST, 0, 4).await);
                }));
                receive
                    .recv()
                    .map_err(|_| GrainSourceError::Missing(*id))?
                    .map_err(|e| GrainSourceError::Backend(e.to_string()))?;
            }
            self.objects
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .ok_or(GrainSourceError::Missing(*id))
        }
    }
    impl SyncContent for ColdHttpContent {
        fn payload(&self, content: GrainId) -> Result<FileGrains, CoordinationError> {
            self.payloads
                .lock()
                .unwrap()
                .get(&content)
                .map(|(_, g)| g.clone())
                .ok_or(CoordinationError::Refused("SyncFixturePayload"))
        }
        fn read_content(
            &self,
            content: GrainId,
            offset: u64,
            length: usize,
        ) -> Result<Vec<u8>, OverlayError> {
            let (size, grains) = self
                .payloads
                .lock()
                .unwrap()
                .get(&content)
                .cloned()
                .unwrap();
            let FileGrains::Inline(refs) = &grains else {
                panic!("expected inline grain refs");
            };
            let data: Vec<u8> = refs.iter().flat_map(|g| self.get(&g.id).unwrap()).collect();
            assert_eq!(data.len() as u64, size);
            let start = usize::try_from(offset).unwrap();
            Ok(data[start..start + length].to_vec())
        }
        fn put_object(&self, id: GrainId, bytes: &[u8]) -> Result<(), CoordinationError> {
            self.objects.lock().unwrap().insert(id, bytes.to_vec());
            Ok(())
        }
        fn remember_payload(
            &self,
            content: GrainId,
            size: u64,
            grains: &FileGrains,
        ) -> Result<(), CoordinationError> {
            self.payloads
                .lock()
                .unwrap()
                .insert(content, (size, grains.clone()));
            Ok(())
        }
    }

    let key = signing_key(23);
    let trusted = TrustedKeys::new([*key.public_key()]).unwrap();
    let scratch = Scratch::new();
    let scratch_root = std::fs::canonicalize(&scratch.0).unwrap();
    let euid = std::fs::metadata(&scratch_root).unwrap().uid();
    let src_dir = scratch_root.join("src");
    std::fs::create_dir(&src_dir).unwrap();
    let pub_store_path = scratch_root.join("pub-store");
    let mut local_pub = Store::open(&pub_store_path).unwrap();
    let (manifest_root, _) = harvest(&src_dir, &local_pub).unwrap();

    let bins: Arc<Mutex<BTreeMap<String, Vec<u8>>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let metas: Arc<Mutex<BTreeMap<String, Vec<u8>>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let roots: Arc<Mutex<BTreeMap<u64, Vec<u8>>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let peer = stub(answering({
        let bins = Arc::clone(&bins);
        let metas = Arc::clone(&metas);
        let roots = Arc::clone(&roots);
        move |req: &Recorded| match (req.method.clone(), req.path.as_str()) {
            (Method::GET, "/volume/http-store-vol/status") => {
                let head = roots.lock().unwrap().last_key_value().map(|(seq, bytes)| {
                    authority_answer::Head::new(Some((*seq, GrainId::of(bytes))))
                });
                let body = authority_answer::encode_status(VolumeStatus {
                    epoch: Epoch::from_bytes([1; 16]),
                    head,
                    open: None,
                })
                .unwrap();
                Response::builder()
                    .status(200)
                    .header("content-type", "application/vnd.granary.volume-status.v1")
                    .body(StubBody::of(body))
                    .unwrap()
            }
            (Method::GET, "/volume/http-store-vol/max-seq") => {
                if let Some((seq, _)) = roots.lock().unwrap().last_key_value() {
                    ok_body(format!("{seq:020}").into_bytes())
                } else {
                    refusal(StatusCode::NOT_FOUND, Some("not-found"))
                }
            }
            (Method::GET, "/volume/http-store-vol/hint") => {
                let seq = roots
                    .lock()
                    .unwrap()
                    .last_key_value()
                    .map_or(1, |(s, _)| *s);
                Response::builder()
                    .status(200)
                    .header("etag", "\"hint-1\"")
                    .body(StubBody::of(format!("{seq:020}").into_bytes()))
                    .unwrap()
            }
            (Method::PUT, "/volume/http-store-vol/hint") => Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(StubBody::empty())
                .unwrap(),
            (Method::PUT, p) if p.starts_with("/bin/") => {
                bins.lock().unwrap().insert(p.to_owned(), req.body.clone());
                Response::builder()
                    .status(201)
                    .body(StubBody::empty())
                    .unwrap()
            }
            (Method::GET, p) if p.starts_with("/bin/") => {
                let range = req.headers.get(RANGE).unwrap().to_str().unwrap();
                let spec = range.strip_prefix("bytes=").unwrap();
                let (start, end) = spec.split_once('-').unwrap();
                let start: usize = start.parse().unwrap();
                let end: usize = end.parse().unwrap();
                let stored = bins
                    .lock()
                    .unwrap()
                    .get(p)
                    .cloned()
                    .unwrap_or_else(|| vec![0x42; end + 1]);
                let slice = stored[start..=end].to_vec();
                Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header("content-type", "application/vnd.granary.bin.v1")
                    .header("content-range", format!("bytes {start}-{end}/*"))
                    .body(StubBody::of(slice))
                    .unwrap()
            }
            (Method::PUT, p) if p.contains("/meta/") => {
                metas.lock().unwrap().insert(p.to_owned(), req.body.clone());
                Response::builder()
                    .status(201)
                    .body(StubBody::empty())
                    .unwrap()
            }
            (Method::GET, p) if p.contains("/meta/") => {
                let bytes = metas.lock().unwrap().get(p).cloned().unwrap();
                ok_body(bytes)
            }
            (Method::POST, "/volume/http-store-vol/publish") => {
                let doc = root::decode_root(&req.body).unwrap();
                let id = GrainId::of(&req.body);
                roots.lock().unwrap().insert(doc.seq, req.body.clone());
                let body = authority_answer::encode(PublishAnswer::Landed {
                    receipt: AuthReceipt {
                        position: Position {
                            epoch: Epoch::from_bytes([1; 16]),
                            entry_seq: doc.seq,
                        },
                        root_seq: doc.seq,
                        stored_id: id,
                    },
                    head: None,
                })
                .unwrap();
                Response::builder()
                    .status(200)
                    .header(
                        "content-type",
                        "application/vnd.granary.authority-answer.v1",
                    )
                    .body(StubBody::of(body))
                    .unwrap()
            }
            (Method::GET, p) if p.starts_with("/volume/http-store-vol/root/") => {
                let seq: u64 = p.rsplit('/').next().unwrap().parse().unwrap();
                if let Some(bytes) = roots.lock().unwrap().get(&seq).cloned() {
                    ok_body(bytes)
                } else {
                    refusal(StatusCode::NOT_FOUND, Some("not-found"))
                }
            }
            (Method::GET, "/volume/http-store-vol/intent") => {
                let body = intent::encode_readback(0, &[]).unwrap();
                Response::builder()
                    .status(200)
                    .header("cache-control", "no-store")
                    .header("content-type", intent::MEDIA_READBACK)
                    .body(StubBody::of(body))
                    .unwrap()
            }
            (Method::POST, "/volume/http-store-vol/intent/ownership") => {
                let own = intent::decode_ownership(&req.body).unwrap();
                let body = intent::encode_grant(Grant {
                    request_id: GrainId::of(&req.body),
                    receipt: IntentReceipt {
                        writer: own.writer,
                        epoch: 1,
                        instance: own.instance,
                        generation: 0,
                        state: ReceiptState::Released,
                    },
                })
                .unwrap();
                Response::builder()
                    .status(200)
                    .header("cache-control", "no-store")
                    .header("content-type", intent::MEDIA_GRANT)
                    .body(StubBody::of(body))
                    .unwrap()
            }
            (Method::POST, "/volume/http-store-vol/intent") => {
                let reg = intent::decode_register(&req.body, &volume(), |_, _| true).unwrap();
                let body = intent::encode_receipt(IntentReceipt {
                    writer: reg.writer,
                    epoch: reg.epoch,
                    instance: reg.instance,
                    generation: reg.generation,
                    state: ReceiptState::Live {
                        prepared_root_id: reg.root_id(),
                    },
                })
                .unwrap();
                Response::builder()
                    .status(200)
                    .header("cache-control", "no-store")
                    .header("content-type", intent::MEDIA_RECEIPT)
                    .body(StubBody::of(body))
                    .unwrap()
            }
            other => panic!("unexpected stub request: {other:?}"),
        }
    }))
    .await;

    let log = DiagnosticLog::default();
    let _guard = tracing::subscriber::set_default(granary_client::closed_subscriber(
        granary_client::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("debug"),
        log.clone(),
    ));
    let extract_op = |line: &str| -> String {
        let marker = "\"op\":\"";
        let start = line.find(marker).unwrap() + marker.len();
        let rest = &line[start..];
        rest[..rest.find('"').unwrap()].to_owned()
    };
    let scope = Scope {
        authority_base: peer.base().into_bytes(),
        pins: vec![peer.pin],
        credential_context: b"test".to_vec(),
    };

    // 1. publish (`begin_publication` + `write_hint`)
    let pub_id = granary_client::CorrelationId::draw(&mut SeededId([0x10; 8])).unwrap();
    let pub_span = operation_span(granary_client::OperationKind::Session, &pub_id);
    async {
        op_begin(granary_client::OperationKind::Session);
        let store = peer.store();
        let mut journal = local_pub.publications(euid).unwrap();
        let mut rng = SeededId([0x15; 8]);
        let mut delay = NoDelay;
        let res = begin_publication(
            RecoveryParts {
                transport: &store,
                journal: &mut journal,
                publisher_keys: &trusted,
                signer: &key,
                secure: &mut rng,
                clock: &FixedClock,
                delay: &mut delay,
            },
            scope.clone(),
            volume(),
            manifest_root,
            Policy { min_prefix_bits: 0 },
        )
        .await
        .unwrap();
        assert!(matches!(res.outcome, PublicationOutcome::Landed(_)));
        store.write_hint(VOLUME, 1).await.unwrap();
        op_end(
            granary_client::OperationKind::Session,
            granary_client::Outcome::Ok,
        );
    }
    .instrument(pub_span)
    .await;
    let after_publish = peer.seen().len();

    // 2. cat (`resolve_head_verified`)
    let cat_id = granary_client::CorrelationId::draw(&mut SeededId([0x20; 8])).unwrap();
    let cat_span = operation_span(granary_client::OperationKind::Session, &cat_id);
    let mut emitted_bytes = Vec::new();
    async {
        op_begin(granary_client::OperationKind::Session);
        resolve_head_verified(
            &peer.store(),
            VOLUME,
            &RootVerifier::trusting(*key.public_key()).unwrap(),
            &HeadContext::new(Box::new(FixedClock), Box::new(SeededRng::new(1))),
            None,
            ResolveTarget::WholeTree,
            &mut |_, bytes| {
                emitted_bytes.extend_from_slice(bytes);
                Ok(())
            },
        )
        .await
        .unwrap();
        op_end(
            granary_client::OperationKind::Session,
            granary_client::Outcome::Ok,
        );
    }
    .instrument(cat_span)
    .await;
    assert!(!emitted_bytes.is_empty());
    let after_cat = peer.seen().len();

    // 3. mount start (`MountSession::open` + writable admission + `SyncEngine::new`)
    let base_root_bytes = roots.lock().unwrap().get(&1).cloned().unwrap();
    let base_doc = root::decode_root(&base_root_bytes).unwrap();
    let commit_base_id = GrainId::of(&base_root_bytes);
    let mount_id = granary_client::CorrelationId::draw(&mut SeededId([0x30; 8])).unwrap();
    let mount_span = operation_span(granary_client::OperationKind::Session, &mount_id);
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let mount_cache = scratch_root.join("mount-cache");
    let origin = granary_client::CacheOrigin {
        endpoint_url: peer.base(),
        pin_set_digest: granary_client::CacheOrigin::pin_set_digest(&[peer.pin]),
        root_key_id: Some(granary_client::CacheOrigin::root_key_digest(
            key.public_key(),
        )),
    };
    let session_store = peer.store();
    let mount_pub = *key.public_key();
    let open_span = mount_span.clone();
    #[expect(
        clippy::disallowed_methods,
        reason = "the session opens on a blocking thread, as the mount does off its runtime; this is the test's runtime hop, not a way around the runtime-concurrency seam"
    )]
    tokio::task::spawn_blocking(move || {
        std::thread::spawn(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                let _entered = open_span.enter();
                op_begin(granary_client::OperationKind::Session);
                let _session = MountSession::open(
                    session_store,
                    volume(),
                    Some(Box::new(mount_pub)),
                    None,
                    false,
                    None,
                    &mount_cache,
                    64 * 1024 * 1024,
                    &origin,
                    MountOptions::default(),
                    &mut std::io::sink(),
                )
                .unwrap();
            });
        })
        .join()
        .unwrap();
    })
    .await
    .unwrap();

    let empty_dir = manifest::build_dir(&[]).unwrap();
    let mut objects: BTreeMap<GrainId, Vec<u8>> = empty_dir.nodes.into_iter().collect();
    let base_sheaf = metas
        .lock()
        .unwrap()
        .get(&format!("/volume/{VOLUME}/meta/{}", base_doc.sheaf_head))
        .cloned()
        .unwrap();
    objects.insert(base_doc.sheaf_head, base_sheaf);

    let commit_store_path = scratch_root.join("commit-store");
    let local_commit = Store::open(&commit_store_path).unwrap();
    let io = granary_client::OverlayDisk::new(&commit_store_path, euid);
    let commit_http = Arc::new(peer.store());
    let cold_on_next_get = Arc::new(AtomicBool::new(false));
    let cold_fetched = Arc::new(AtomicUsize::new(0));
    let content = Arc::new(ColdHttpContent {
        objects: Arc::new(Mutex::new(objects)),
        payloads: Arc::new(Mutex::new(BTreeMap::new())),
        remote: Arc::clone(&commit_http),
        cold_on_next_get: Arc::clone(&cold_on_next_get),
        cold_fetched: Arc::clone(&cold_fetched),
    });
    let (shared_writable, engine) = async {
        commit_http.status_once(VOLUME).await.unwrap();
        commit_http
            .intent_readback_once(&scope, &volume(), |_, _| true)
            .await
            .unwrap();
        let mut writable = WritableStore::new(
            local_commit,
            OverlayConfig {
                scope: scope.clone(),
                volume: volume(),
                euid,
                cap: 64 * 1024 * 1024,
                ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
                instance: [7; 16],
            },
            io.clone(),
            &mut SeededId([0x40; 8]),
            granary_client::FaultControl::default(),
            |_, _| true,
        )
        .unwrap();
        let acq = writable.prepare_acquire(0, &FixedClock).unwrap();
        writable.dispatch(&acq, &FixedClock).unwrap();
        let acq_reply = commit_http
            .intent_acquire_once(&scope, &volume(), acq.bytes())
            .await
            .unwrap();
        let mut rng = SeededRng::new(1);
        writable
            .complete(&acq, Ok(&acq_reply), &FixedClock, &mut rng, 0, None)
            .unwrap();
        writable
            .open_overlay_local(
                granary_core::overlay_journal::JournalHeader {
                    writer: writable.writer_uuid(),
                    base_root: commit_base_id,
                    base_seq: 1,
                    next_stage_id: 1,
                    receipt_generation: 0,
                },
                vec![],
                io,
                false,
            )
            .unwrap();
        let mut reg_doc = base_doc.clone();
        reg_doc.seq = 2;
        reg_doc.parent = Some(commit_base_id);
        reg_doc.writer_uuid = writable.writer_uuid();
        reg_doc.sigs.clear();
        let prefix = root::signing_prefix_of(&reg_doc).unwrap();
        reg_doc.sigs.push(RootSig {
            key_id: key.key_id(),
            sig: key.sign(&prefix),
        });
        let reg_root = root::encode_root(&reg_doc).unwrap();
        let reg_req = writable
            .prepare_registration(&reg_root, vec![], &FixedClock, |_, _| true)
            .unwrap();
        writable.dispatch(&reg_req, &FixedClock).unwrap();
        let reg_reply = commit_http
            .intent_register_once(&scope, &volume(), reg_req.bytes(), |_, _| true)
            .await
            .unwrap();
        writable
            .complete(&reg_req, Ok(&reg_reply), &FixedClock, &mut rng, 0, None)
            .unwrap();
        let shared_writable = Arc::new(Mutex::new(writable));
        let engine = SyncEngine::new(
            Arc::clone(&shared_writable),
            Arc::clone(&commit_http),
            content,
            Arc::new(FixedClock),
            Arc::new(InstantClock::default()),
            signing_key(23),
            trusted,
            base_root_bytes,
            ClientMetrics::new(&mut SeededId([0x41; 8])),
        )
        .await
        .unwrap();
        op_end(
            granary_client::OperationKind::Session,
            granary_client::Outcome::Ok,
        );
        (shared_writable, engine)
    }
    .instrument(mount_span)
    .await;
    let after_mount = peer.seen().len();
    let pre_commit_requests = after_mount;

    // 4. commit (`construct_commit` with cold object fetch + `drive_commit`)
    cold_on_next_get.store(true, Ordering::SeqCst);
    shared_writable
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            let loc = Location {
                parent: Parent::new(vec![]).unwrap(),
                name: Name::new("added.txt".into()).unwrap(),
            };
            let stage = t.create_file(loc, false)?;
            t.write(stage, 0, b"commit-body")?;
            Ok(())
        })
        .unwrap();
    let lane = engine
        .construct_commit(SyncOptions::default(), &mut SeededId([0x42; 8]))
        .await
        .unwrap();
    let constructed_requests = peer.seen().len() - pre_commit_requests;
    Box::pin(engine.drive_commit(
        &lane,
        &mut SeededId([0x43; 8]),
        &mut NoDelay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();

    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let commit_begin = text
        .lines()
        .find(|l| l.contains("\"event\":\"op.begin\"") && l.contains("\"kind\":\"commit\""))
        .unwrap();
    let commit_end = text
        .lines()
        .find(|l| l.contains("\"event\":\"op.end\"") && l.contains("\"kind\":\"commit\""))
        .unwrap();
    let commit_op = extract_op(commit_begin);
    assert_eq!(commit_op, extract_op(commit_end));

    let all_seen = peer.seen();
    for (label, expected_op, requests) in [
        ("publish", pub_id.to_string(), &all_seen[..after_publish]),
        (
            "cat",
            cat_id.to_string(),
            &all_seen[after_publish..after_cat],
        ),
        (
            "mount",
            mount_id.to_string(),
            &all_seen[after_cat..after_mount],
        ),
        ("commit", commit_op, &all_seen[pre_commit_requests..]),
    ] {
        assert!(!requests.is_empty(), "{label} recorded zero HTTP requests");
        for (idx, req) in requests.iter().enumerate() {
            let values: Vec<_> = req
                .headers
                .get_all("granary-request-id")
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .collect();
            assert_eq!(
                values,
                vec![expected_op.clone()],
                "{label} request {idx} ({} {}): {values:?}",
                req.method,
                req.path
            );
        }
    }
    assert!(
        constructed_requests >= 1 && cold_fetched.load(Ordering::SeqCst) >= 1,
        "construct_commit must drive at least one cold HTTP fetch: constructed_requests={constructed_requests}"
    );

    // 5. A construction future built under one subscriber and polled under
    // another sends the id of the operation it was built in.
    shared_writable
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            let loc = Location {
                parent: Parent::new(vec![]).unwrap(),
                name: Name::new("moved.txt".into()).unwrap(),
            };
            let stage = t.create_file(loc, false)?;
            t.write(stage, 0, b"built elsewhere")?;
            Ok(())
        })
        .unwrap();
    let construction = {
        let _built = tracing::subscriber::set_default(granary_client::closed_subscriber(
            granary_client::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("debug"),
            DiagnosticLog::default(),
        ));
        engine.construct_commit(SyncOptions::default(), &mut SeededId([0x44; 8]))
    };
    let before_moved = peer.seen().len();
    construction.await.unwrap();
    let moved_id = granary_client::CorrelationId::draw(&mut SeededId([0x44; 8]))
        .unwrap()
        .to_string();
    let moved: Vec<Vec<String>> = peer.seen()[before_moved..]
        .iter()
        .map(|req| {
            req.headers
                .get_all("granary-request-id")
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .collect()
        })
        .collect();
    assert_eq!(
        (
            moved.is_empty(),
            moved
                .iter()
                .all(|values| values == std::slice::from_ref(&moved_id))
        ),
        (false, true),
        "a construction polled under another subscriber: {moved:?}"
    );
}
