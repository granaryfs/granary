// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The end-to-end accept-loop suite: ALPN enforcement in the accept path,
//! the connection cap, the handshake timeout, and the shutdown contract.
//!
//! Real sockets, real TLS, real hyper clients. Server certificates are
//! minted here by `rcgen` and never committed; their private keys stay
//! in memory, and nothing on disk holds one.
//!
//! **"Never reaches a handler" is always a COUNT.** The service increments an
//! `AtomicUsize` on entry, and every refusal test asserts that number. A
//! closed socket proves nothing on its own: a handler that ran and then lost
//! its connection looks identical from the client side.
//!
//! **Every timeout arm is paired with a positive arm in the same test.** A
//! bounded wait that expires is also what a hung harness produces, so a test
//! written as "it did not happen within 400 ms" alone passes over a suite
//! that never got as far as trying. The positive arms are generous (they must
//! survive macOS scheduling jitter).
//!
//! **`BRIEF` is short because the condition it waits on is unreachable, and
//! that claim has to be checked per arm.** Most negative arms block on
//! something a correct implementation never produces, so no amount of
//! scheduling delay can make them flake. The exceptions are the arms whose
//! condition is a timeout the test itself configures — a staller's handshake
//! bound, a silent peer's header bound — where the real budget is that
//! timeout minus `BRIEF`. Those timeouts are set an order of magnitude above
//! `BRIEF`, not merely above it, and adding an arm of that shape means
//! setting its timeout the same way.
//!
//! **No `sleep` anywhere** — it is banned, and every wait here is a
//! `tokio::time::timeout` around a completion channel.
//!
//! **`unwrap()` is a hard error in the helpers below.** `clippy.toml`'s
//! `allow-unwrap-in-tests` covers `#[test]` items, not the plain functions in
//! an integration-test target. The workspace idiom is
//! `.unwrap_or_else(|e| panic!("{e}"))`.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use granary_net::accept::{
    AcceptConfig, H2_ADVERTISED_STREAM_FLOOR, H2_MAX_CONCURRENT_STREAMS, Listener, ShutdownOutcome,
    serve,
};
use granary_net::alpn::{ALPN_H2, ALPN_HTTP11, GRANARY_ALPN};
use granary_net::pin::{PinnedServerVerifier, SpkiPin, spki_digest};
use granary_net::tls::{ClientAuth, server_tls_config};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::Service;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// The name every minted certificate carries and every client asks for.
const TEST_HOST: &str = "granary.test";

/// The bound on a POSITIVE arm. Every expectation it covers is sub-second on
/// an idle machine; the margin is for macOS scheduling jitter, not for the
/// behaviour.
const GENEROUS: Duration = Duration::from_secs(15);

/// The bound on a NEGATIVE arm — an event a correct implementation never
/// produces, so a short bound cannot flake and a long one only slows the
/// suite.
const BRIEF: Duration = Duration::from_millis(400);

/// The ALPN token this suite appends to the production offer for the
/// non-member test. It is a real registered token that granary does not
/// admit, so the refusal cannot be an artefact of a malformed offer.
const OUTSIDER_ALPN: &[u8] = b"h3";

/// The HTTP/2 client connection preface (RFC 9113 §3.4).
///
/// These are the bytes that RESOLVE hyper's h2 handshake, which is the moment
/// it arms the keep-alive machinery. Sending them and then nothing is the only
/// way to reach the established-but-silent state from a test.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The length is the whole point of the fixture, and it is the boundary the
/// preface bound disarms on: at 23 bytes a peer is still inside that bound and
/// its permit is reclaimed (test 19), at 24 the bound is gone for good and the
/// keep-alive pair is what holds a clock (test 18). Checked at compile time so
/// an edit to the literal cannot quietly move either test to the other side of
/// that line and leave it passing for the wrong reason.
const _: () = assert!(H2_PREFACE.len() == 24);

/// One byte short of the whole preface: test 19's peer, sliced from the
/// constant above rather than spelled a second time.
const H2_PREFACE_SHORT: usize = 23;

/// The one spawn site in this file.
///
/// The transport crate's own tests sit outside the sim boundary: nothing here
/// is replayed by `granary-sim`, which replaces this layer wholesale. Routing
/// every task through one wrapper is what keeps that exemption to a single
/// reviewable site.
#[expect(
    clippy::disallowed_methods,
    reason = "the transport layer's own tests sit outside the sim boundary — granary-sim replaces this layer rather than driving it"
)]
fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future)
}

/// A spawned client connection task, stopped when its handle goes out of
/// scope.
///
/// The refusal paths below return early — that is what they are testing — and
/// an early return must not leave a client connection running against a server
/// the next assertion is about to inspect. Tying the task's life to a value
/// means no exit path can forget; writing the abort at each `?` site means one
/// of them eventually does.
struct Pump(JoinHandle<()>);

impl Drop for Pump {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn pump<F>(future: F) -> Pump
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    Pump(spawn(async move {
        let _ = future.await;
    }))
}

// ------------------------------------------------- the certificate factory

/// A minted certificate and the private key that matches it.
struct Party {
    cert: CertificateDer<'static>,
    pkcs8: Vec<u8>,
}

impl Party {
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pkcs8.clone()))
    }

    #[track_caller]
    fn pin(&self) -> SpkiPin {
        spki_digest(&self.cert).unwrap_or_else(|e| panic!("spki digest: {e}"))
    }
}

fn mint() -> Party {
    let key = rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("keypair: {e}"));
    let mut params = rcgen::CertificateParams::new(vec![TEST_HOST.to_owned()])
        .unwrap_or_else(|e| panic!("cert params: {e}"));
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let cert = params
        .self_signed(&key)
        .unwrap_or_else(|e| panic!("self-sign: {e}"))
        .der()
        .clone();
    Party {
        cert,
        pkcs8: key.serialize_der(),
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(granary_net::crypto_provider())
}

// ------------------------------------------------------- the test service

/// Counts handler entries, announces each one, and can be held mid-request.
///
/// The gate is a `Semaphore` rather than a `Notify` because a `Notify` only
/// wakes waiters that have already parked: releasing it before the handler
/// arrives would be lost, and the release/arrival order here is scheduler
/// business. A permit added to a semaphore is never lost.
#[derive(Clone)]
struct CountingService {
    calls: Arc<AtomicUsize>,
    entered: mpsc::UnboundedSender<()>,
    gate: Arc<Semaphore>,
    charged_body: Option<(usize, std::sync::Weak<()>)>,
}

struct ChargedPayload {
    bytes: Vec<u8>,
    _charge: Arc<()>,
}

impl AsRef<[u8]> for ChargedPayload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Service<Request<Incoming>> for CountingService {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, _request: Request<Incoming>) -> Self::Future {
        let calls = Arc::clone(&self.calls);
        let entered = self.entered.clone();
        let gate = Arc::clone(&self.gate);
        let charged_body = self.charged_body.clone();
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            let _ = entered.send(());
            if let Ok(permit) = gate.acquire().await {
                permit.forget();
            }
            let body = charged_body
                .and_then(|(len, charge)| {
                    charge.upgrade().map(|charge| {
                        Bytes::from_owner(ChargedPayload {
                            bytes: vec![b'x'; len],
                            _charge: charge,
                        })
                    })
                })
                .unwrap_or_else(|| Bytes::from_static(b"granary"));
            Ok(Response::new(Full::new(body)))
        })
    }
}

/// Everything a test needs to observe and steer the service.
struct Handlers {
    service: CountingService,
    calls: Arc<AtomicUsize>,
    entered: mpsc::UnboundedReceiver<()>,
    gate: Arc<Semaphore>,
}

impl Handlers {
    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Let one held request proceed.
    fn release(&self) {
        self.gate.add_permits(1);
    }

    /// Wait for the next handler entry, or panic on the bound.
    async fn await_entry(&mut self) {
        match timeout(GENEROUS, self.entered.recv()).await {
            Ok(Some(())) => {}
            Ok(None) => panic!("the service was dropped before a handler ran"),
            Err(elapsed) => panic!("no handler ran within {GENEROUS:?} ({elapsed})"),
        }
    }
}

/// `permits` is how many requests may complete; 0 holds the first one.
fn handlers(permits: usize) -> Handlers {
    let calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered) = mpsc::unbounded_channel();
    let gate = Arc::new(Semaphore::new(permits));
    Handlers {
        service: CountingService {
            calls: Arc::clone(&calls),
            entered: entered_tx,
            gate: Arc::clone(&gate),
            charged_body: None,
        },
        calls,
        entered,
        gate,
    }
}

fn handlers_with_charged_body(len: usize, charge: std::sync::Weak<()>) -> Handlers {
    let mut handlers = handlers(UNGATED);
    handlers.service.charged_body = Some((len, charge));
    handlers
}

/// Enough permits that the gate never holds anything.
const UNGATED: usize = 64;

// ---------------------------------------------------------- the TLS configs

/// The PRODUCTION server config, optionally with the ONE permitted delta:
/// a single extra offered token, for the non-member test.
fn production_tls(party: &Party, extra_alpn: Option<&[u8]>) -> Arc<ServerConfig> {
    let mut config = server_tls_config(vec![party.cert.clone()], party.key(), ClientAuth::None)
        .unwrap_or_else(|e| panic!("server tls config: {e}"));
    if let Some(token) = extra_alpn {
        config.alpn_protocols.push(token.to_vec());
    }
    Arc::new(config)
}

fn verifier(pin: SpkiPin) -> Arc<PinnedServerVerifier> {
    Arc::new(
        PinnedServerVerifier::new(vec![pin], provider())
            .unwrap_or_else(|e| panic!("pin set rejected: {e}")),
    )
}

/// A TLS-1.3 client pinned to `pin`, offering exactly `alpn`.
fn client_config(pin: SpkiPin, alpn: &[&[u8]]) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic!("client versions: {e}"))
        .dangerous()
        .with_custom_certificate_verifier(verifier(pin))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

/// A TLS-1.2-only client. It exists only to be refused by the production
/// server config's version restriction.
fn tls12_client_config(pin: SpkiPin) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap_or_else(|e| panic!("client versions: {e}"))
        .dangerous()
        .with_custom_certificate_verifier(verifier(pin))
        .with_no_client_auth();
    config.alpn_protocols = GRANARY_ALPN.iter().map(|p| p.to_vec()).collect();
    config
}

// --------------------------------------------------------- the client side

async fn tls_handshake<IO>(
    io: IO,
    config: ClientConfig,
) -> std::io::Result<tokio_rustls::client::TlsStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(TEST_HOST).unwrap_or_else(|e| panic!("server name: {e}"));
    TlsConnector::from(Arc::new(config)).connect(name, io).await
}

async fn tls_connect(
    addr: SocketAddr,
    config: ClientConfig,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    tls_handshake(tcp, config).await
}

/// Errors are `String` so a failing attempt can cross a channel and be
/// asserted on by shape without dragging hyper's error types into the test
/// bodies.
type Attempt = Result<StatusCode, String>;

/// One HTTP/1.1 request, driven to completion.
async fn h1_request<IO>(io: IO) -> Attempt
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| format!("h1 handshake: {e}"))?;
    let _pump = pump(conn);
    let request = Request::builder()
        .uri("/")
        .header(hyper::header::HOST, TEST_HOST)
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("request: {e}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("h1 send: {e}"))?;
    let status = response.status();
    response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("h1 body: {e}"))?;
    Ok(status)
}

/// One HTTP/2 request, driven to completion.
async fn h2_request<IO>(io: IO) -> Attempt
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .map_err(|e| format!("h2 handshake: {e}"))?;
    let _pump = pump(conn);
    let request = Request::builder()
        .uri(format!("https://{TEST_HOST}/"))
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("request: {e}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("h2 send: {e}"))?;
    let status = response.status();
    response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("h2 body: {e}"))?;
    Ok(status)
}

/// A whole client attempt — TCP, TLS, one HTTP/1.1 request — as one future,
/// so a test can start it and then assert about whether it completes.
async fn attempt(addr: SocketAddr, config: ClientConfig) -> Attempt {
    let stream = tls_connect(addr, config)
        .await
        .map_err(|e| format!("tls: {e}"))?;
    h1_request(stream).await
}

/// The same, over HTTP/2 — used where the point is that a real `h2` client is
/// still served, and not merely that the accept loop admitted something.
async fn h2_attempt(addr: SocketAddr, config: ClientConfig) -> Attempt {
    let stream = tls_connect(addr, config)
        .await
        .map_err(|e| format!("tls: {e}"))?;
    h2_request(stream).await
}

/// A connection that stays OPEN after its request, holding its permit the way
/// a keep-alive client does.
struct Parked {
    sender: hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    pump: Pump,
}

impl Parked {
    async fn open(addr: SocketAddr, config: ClientConfig) -> Self {
        let stream = tls_connect(addr, config)
            .await
            .unwrap_or_else(|e| panic!("parked tls: {e}"));
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap_or_else(|e| panic!("parked handshake: {e}"));
        Self {
            sender,
            pump: pump(conn),
        }
    }

    async fn request(&mut self) -> StatusCode {
        self.sender
            .ready()
            .await
            .unwrap_or_else(|e| panic!("parked ready: {e}"));
        let request = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, TEST_HOST)
            .body(Empty::<Bytes>::new())
            .unwrap_or_else(|e| panic!("parked request: {e}"));
        let response = self
            .sender
            .send_request(request)
            .await
            .unwrap_or_else(|e| panic!("parked send: {e}"));
        let status = response.status();
        response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|e| panic!("parked body: {e}"));
        status
    }

    /// Close the connection for real: drop the request sender AND stop the
    /// connection task, so the socket is gone rather than merely idle.
    fn close(self) {
        drop(self.sender);
        drop(self.pump);
    }
}

// ---------------------------------------------------------- the server side

/// A running `serve` over a real TCP listener.
struct Server {
    addr: SocketAddr,
    pin: SpkiPin,
    shutdown: watch::Sender<bool>,
    done: JoinHandle<std::io::Result<ShutdownOutcome>>,
}

impl Server {
    /// Wait for `serve` to return, or panic on the bound.
    async fn outcome(self) -> ShutdownOutcome {
        match timeout(GENEROUS, self.done).await {
            Ok(Ok(Ok(outcome))) => outcome,
            Ok(Ok(Err(e))) => panic!("serve failed: {e}"),
            Ok(Err(e)) => panic!("serve task panicked: {e}"),
            Err(elapsed) => panic!("serve did not return within {GENEROUS:?} ({elapsed})"),
        }
    }
}

async fn start(
    config: AcceptConfig,
    service: CountingService,
    extra_alpn: Option<&[u8]>,
) -> Server {
    let party = mint();
    let pin = party.pin();
    let tls = production_tls(&party, extra_alpn);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local addr: {e}"));
    let (shutdown, rx) = watch::channel(false);
    let done = spawn(serve(listener, tls, service, rx, config));
    Server {
        addr,
        pin,
        shutdown,
        done,
    }
}

#[track_caller]
fn trigger(shutdown: &watch::Sender<bool>, value: bool) {
    shutdown
        .send(value)
        .unwrap_or_else(|e| panic!("shutdown send: {e}"));
}

// ------------------------------------------------------ the scripted listener

/// One accept outcome the scripted listener will produce.
enum Step {
    Fail,
    Give(DuplexStream),
}

/// A `Listener` whose accept results are dictated by a script.
///
/// `TcpListener` cannot be made to fail on demand, so the accept-ERROR branch
/// has no other way to be reached. This seam injects accept failures for
/// testing, not for simulation.
struct ScriptedListener {
    steps: VecDeque<Step>,
    /// Pings once per `accept` call, so a test can wait until the loop is
    /// genuinely cycling before it triggers shutdown — the alternative would
    /// be a sleep, which is banned.
    probe: mpsc::UnboundedSender<()>,
    /// What an exhausted script does: keep failing, or never return.
    fail_forever: bool,
}

fn scripted_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "scripted accept failure",
    )
}

impl Listener for ScriptedListener {
    type Io = DuplexStream;

    async fn accept(&mut self) -> std::io::Result<Self::Io> {
        let _ = self.probe.send(());
        match self.steps.pop_front() {
            Some(Step::Fail) => Err(scripted_error()),
            Some(Step::Give(io)) => Ok(io),
            None if self.fail_forever => Err(scripted_error()),
            None => std::future::pending().await,
        }
    }
}

/// Wait for the loop to make `n` accept attempts, or panic on the bound.
async fn await_accepts(probe: &mut mpsc::UnboundedReceiver<()>, n: usize) {
    for i in 0..n {
        match timeout(GENEROUS, probe.recv()).await {
            Ok(Some(())) => {}
            Ok(None) => panic!("the listener was dropped after {i} accept attempts"),
            Err(elapsed) => panic!("only {i} accept attempts within {GENEROUS:?} ({elapsed})"),
        }
    }
}

/// The duplex buffer: larger than any handshake flight or body this suite
/// sends, so nothing here can deadlock on a full pipe.
const DUPLEX_BUF: usize = 64 * 1024;

// ------------------------------------------------------------- the dribblers

/// Wait `interval` — the file's no-`sleep` rule, obeyed literally.
///
/// The sender is held for the whole call and nothing is ever sent on it, so
/// the receive can only ever expire: the `timeout` IS the wait.
async fn gap(interval: Duration) {
    let (_alive, mut idle) = mpsc::channel::<()>(1);
    let _ = timeout(interval, idle.recv()).await;
}

/// Write `bytes` into `io` ONE AT A TIME, `interval` apart, then hold the
/// connection open and silent forever.
///
/// Each byte is flushed on its own, so it crosses TLS as its own record and
/// arrives at the server as its own read — which is the point: the bound under
/// test counts plaintext bytes across polls, not writes.
async fn dribble<IO>(mut io: IO, bytes: &'static [u8], interval: Duration)
where
    IO: AsyncWrite + Unpin,
{
    for byte in bytes {
        gap(interval).await;
        if io.write_all(std::slice::from_ref(byte)).await.is_err() {
            break;
        }
        if io.flush().await.is_err() {
            break;
        }
    }
    std::future::pending::<()>().await;
}

/// Forward `from` into `to` one byte per `interval` for the first `slow`
/// bytes, then as fast as it arrives.
///
/// This is the same dribble seen from the other side: a real hyper client
/// writes into `from`, so its preface reaches the server a byte at a time and
/// everything after it flows normally.
async fn dribble_then_forward<R, W>(mut from: R, mut to: W, slow: usize, interval: Duration)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    for _ in 0..slow {
        gap(interval).await;
        let mut one = [0_u8; 1];
        if from.read_exact(&mut one).await.is_err() {
            return;
        }
        if to.write_all(&one).await.is_err() {
            return;
        }
        if to.flush().await.is_err() {
            return;
        }
    }
    let _ = tokio::io::copy(&mut from, &mut to).await;
}

/// Write `head`, read whatever comes back, and return `None` if the connection
/// was closed instead of answered. A stalled exchange fails on the bound.
///
/// The raw client leaves connection closure to the server and can send
/// request heads shorter than hyper's client would construct.
async fn exchange<IO>(io: &mut IO, head: &[u8]) -> Option<String>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    timeout(GENEROUS, async {
        io.write_all(head).await.ok()?;
        io.flush().await.ok()?;
        let mut buf = [0_u8; 256];
        let read = io.read(&mut buf).await.ok()?;
        if read == 0 {
            return None;
        }
        Some(String::from_utf8_lossy(buf.get(..read)?).into_owned())
    })
    .await
    .unwrap_or_else(|_| panic!("the peer neither answered nor closed within {GENEROUS:?}"))
}

// ================================================================ the tests

/// 1. The production constructor populates ALPN from the constant.
///
/// Kills: a constructor offering `{h2}` alone and
/// one that forgets the assignment entirely, which rustls defaults to EMPTY.
#[test]
fn production_config_offers_exactly_the_granary_alpn_set() {
    let party = mint();
    let config = server_tls_config(vec![party.cert.clone()], party.key(), ClientAuth::None)
        .unwrap_or_else(|e| panic!("server tls config: {e}"));

    let offered: Vec<&[u8]> = config.alpn_protocols.iter().map(Vec::as_slice).collect();
    assert_eq!(
        offered,
        GRANARY_ALPN.to_vec(),
        "the production config must offer exactly GRANARY_ALPN, h2 first"
    );
}

/// 1, arm two. The production constructor leaves TLS early data OFF.
///
/// RFC 8470's processing-safety obligation is discharged by the write semantics:
/// `put_bin`, `put_meta` and `put_root` are put-if-absent, so replaying a write
/// whose first copy landed produces no new side effect; `write_hint` can
/// regress the advisory hint, but readers forward-probe and correctness
/// does not depend on that hint. TLS early data stays disabled server-side,
/// and this constructor's zero is the tripwire that keeps it disabled.
/// `max_early_data_size` is a plain `pub` field with a documented default of
/// zero, so enabling it is a one-line edit nothing else in the crate would
/// notice.
#[test]
fn production_config_leaves_early_data_disabled() {
    let party = mint();
    let config = server_tls_config(vec![party.cert.clone()], party.key(), ClientAuth::None)
        .unwrap_or_else(|e| panic!("server tls config: {e}"));

    assert_eq!(
        config.max_early_data_size, 0,
        "granary does not accept TLS early data"
    );
}

/// 2. A TLS-1.2-only client is refused BY THE PRODUCTION SERVER CONFIG,
///    end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls12_client_is_refused_by_the_production_config() {
    let mut handlers = handlers(UNGATED);
    let server = start(AcceptConfig::default(), handlers.service.clone(), None).await;

    let error = tls_connect(server.addr, tls12_client_config(server.pin))
        .await
        .err()
        .unwrap_or_else(|| panic!("a TLS-1.2-only client completed the handshake"));

    let inner = error
        .get_ref()
        .unwrap_or_else(|| panic!("no inner error on {error:?}"));
    let rustls_error = inner
        .downcast_ref::<rustls::Error>()
        .unwrap_or_else(|| panic!("inner error was not a rustls error: {inner:?}"));
    assert_eq!(
        *rustls_error,
        rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion),
        "expected the server's protocol-version alert"
    );
    assert_eq!(handlers.count(), 0, "no handler may run for a refused peer");

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
    assert_eq!(handlers.count(), 0);
    assert!(handlers.entered.try_recv().is_err());
}

/// 3. An `h2` client reaches a handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_client_reaches_a_handler() {
    let handlers = handlers(UNGATED);
    let server = start(AcceptConfig::default(), handlers.service.clone(), None).await;

    let stream = tls_connect(server.addr, client_config(server.pin, &[ALPN_H2]))
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"));
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(ALPN_H2),
        "the client must have negotiated h2 by value"
    );

    let status = timeout(GENEROUS, h2_request(stream))
        .await
        .unwrap_or_else(|_| panic!("the h2 request did not complete within {GENEROUS:?}"))
        .unwrap_or_else(|e| panic!("h2 request: {e}"));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(handlers.count(), 1);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 4. An `http/1.1` client reaches a handler — the mandatory baseline.
///    With test 3, this kills the `{h2}`-wired-loop degenerate that motivated
///    the four ALPN admission tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http11_client_reaches_a_handler() {
    let handlers = handlers(UNGATED);
    let server = start(AcceptConfig::default(), handlers.service.clone(), None).await;

    let stream = tls_connect(server.addr, client_config(server.pin, &[ALPN_HTTP11]))
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"));
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(ALPN_HTTP11),
        "the client must have negotiated http/1.1 by value"
    );

    let status = timeout(GENEROUS, h1_request(stream))
        .await
        .unwrap_or_else(|_| panic!("the h1 request did not complete within {GENEROUS:?}"))
        .unwrap_or_else(|e| panic!("h1 request: {e}"));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(handlers.count(), 1);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 5. An ALPN-omitting client never reaches a handler.
///
/// Kills a loop that serves without consulting the predicate — the measured
/// preface-sniffing hazard, where hyper's `auto` builder hands such a client
/// real HTTP/2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alpn_omitting_client_never_reaches_a_handler() {
    let mut handlers = handlers(UNGATED);
    let server = start(AcceptConfig::default(), handlers.service.clone(), None).await;

    let stream = tls_connect(server.addr, client_config(server.pin, &[]))
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"));
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        None,
        "an empty offer omits the extension, and the handshake still completes"
    );

    let outcome = timeout(GENEROUS, h1_request(stream))
        .await
        .unwrap_or_else(|_| panic!("the refused request hung for {GENEROUS:?}"));
    assert!(
        outcome.is_err(),
        "an ALPN-omitting client must not get a response, got {outcome:?}"
    );
    assert_eq!(handlers.count(), 0);
    assert!(handlers.entered.try_recv().is_err());

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 6. A NON-MEMBER token is refused AFTER successful negotiation.
///
/// The server offers `h3` as well, so rustls's own `NoApplicationProtocol`
/// alert cannot fire and masquerade as the gate — the handshake COMPLETES and
/// the accept path is what refuses. Kills `negotiated.is_some()` in the accept
/// path, and consulting the predicate only on `None`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_member_token_is_refused_after_negotiation_succeeds() {
    let mut handlers = handlers(UNGATED);
    let server = start(
        AcceptConfig::default(),
        handlers.service.clone(),
        Some(OUTSIDER_ALPN),
    )
    .await;

    let stream = tls_connect(server.addr, client_config(server.pin, &[OUTSIDER_ALPN]))
        .await
        .unwrap_or_else(|e| panic!("the h3 handshake must COMPLETE, got {e}"));
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(OUTSIDER_ALPN),
        "negotiation must have succeeded, or the refusal below is rustls's and not ours"
    );

    let outcome = timeout(GENEROUS, h1_request(stream))
        .await
        .unwrap_or_else(|_| panic!("the refused request hung for {GENEROUS:?}"));
    assert!(
        outcome.is_err(),
        "a non-member token must not reach a handler, got {outcome:?}"
    );
    assert_eq!(handlers.count(), 0);
    assert!(handlers.entered.try_recv().is_err());

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 7, arm one. The cap holds, and a slot returns.
///
/// Kills a loop with no cap anywhere (B succeeds immediately) and a permit
/// leak on connection end (B never succeeds after A closes). It does NOT kill
/// the permit-acquired-inside-the-spawned-task shape — that order is
/// reading-gated, not test-gated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cap_holds_and_a_slot_returns() {
    let handlers = handlers(UNGATED);
    let config = AcceptConfig {
        max_connections: 1,
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    // A takes the only slot and PARKS on it.
    let mut a = Parked::open(server.addr, client_config(server.pin, &[ALPN_HTTP11])).await;
    assert_eq!(a.request().await, StatusCode::OK);
    assert_eq!(handlers.count(), 1);

    // B cannot get in while A holds the slot.
    let (b_tx, mut b_rx) = oneshot::channel();
    let b_config = client_config(server.pin, &[ALPN_HTTP11]);
    let b_addr = server.addr;
    let b = spawn(async move {
        let _ = b_tx.send(attempt(b_addr, b_config).await);
    });
    assert!(
        timeout(BRIEF, &mut b_rx).await.is_err(),
        "B completed while the only connection slot was held"
    );
    assert_eq!(handlers.count(), 1, "B must not have reached a handler yet");

    // The slot returns when A goes away — the positive arm.
    a.close();
    let b_result = timeout(GENEROUS, b_rx)
        .await
        .unwrap_or_else(|_| panic!("B never got the slot back within {GENEROUS:?}"))
        .unwrap_or_else(|e| panic!("B's channel closed: {e}"));
    assert_eq!(
        b_result.unwrap_or_else(|e| panic!("B failed: {e}")),
        StatusCode::OK
    );
    assert_eq!(handlers.count(), 2);
    let _ = b.await;

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 7, arm two. A connection REFUSED for its ALPN returns its permit.
///
/// The cap counts ADMITTED connections, and the ALPN refusal is the one exit
/// path that returns before `serve_connection` — so it is the one a permit can
/// go missing on without any client noticing: the refused peer sees the same
/// closed socket either way, and every other test in this file runs with slots
/// to spare.
///
/// Kills a `std::mem::forget(_permit)` on the refusal branch alone. At
/// `max_connections = 1` the refused peer holds the only slot, so the h2
/// client below can be served only if that slot came back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alpn_refusal_returns_the_permit() {
    let mut handlers = handlers(UNGATED);
    let config = AcceptConfig {
        max_connections: 1,
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    // The refused peer's handshake COMPLETES, which is what proves it was
    // admitted and is holding the only permit — rather than a connection that
    // never got in at all, which would make the positive arm below vacuous.
    let refused = tls_connect(server.addr, client_config(server.pin, &[]))
        .await
        .unwrap_or_else(|e| panic!("the ALPN-omitting handshake must COMPLETE, got {e}"));
    assert_eq!(
        refused.get_ref().1.alpn_protocol(),
        None,
        "an empty offer omits the extension, and the handshake still completes"
    );

    let outcome = timeout(GENEROUS, h1_request(refused))
        .await
        .unwrap_or_else(|_| panic!("the refused request hung for {GENEROUS:?}"));
    assert!(
        outcome.is_err(),
        "an ALPN-omitting client must not get a response, got {outcome:?}"
    );
    assert_eq!(handlers.count(), 0, "no handler may run for a refused peer");
    assert!(handlers.entered.try_recv().is_err());

    // The positive arm, and the whole point: a real client on the SAME `serve`
    // instance gets the slot. With the permit leaked on the refusal branch the
    // loop never acquires again, so this handshake never sees a ServerHello.
    let stream = timeout(
        GENEROUS,
        tls_connect(server.addr, client_config(server.pin, &[ALPN_H2])),
    )
    .await
    .unwrap_or_else(|_| panic!("the refused connection's permit never returned ({GENEROUS:?})"))
    .unwrap_or_else(|e| panic!("h2 tls: {e}"));
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(ALPN_H2),
        "the client must have negotiated h2 by value"
    );

    let status = timeout(GENEROUS, h2_request(stream))
        .await
        .unwrap_or_else(|_| panic!("the h2 request did not complete within {GENEROUS:?}"))
        .unwrap_or_else(|e| panic!("h2 request: {e}"));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        handlers.count(),
        1,
        "exactly the admitted connection's handler ran"
    );

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 8. A TLS-handshake staller cannot hold a permit past the timeout.
///
/// Kills an unwrapped TLS accept: `header_read_timeout` does not start until
/// TLS completes, so without this bound a peer that connects and sends
/// nothing holds its permit forever and the real client below hangs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tls_staller_cannot_hold_a_permit_forever() {
    let handlers = handlers(UNGATED);
    let config = AcceptConfig {
        max_connections: 1,
        // An order of magnitude above BRIEF. The negative arm below expires on
        // THIS bound rather than on an unreachable condition, so at 2s it was
        // asserting that ~1.6s of scheduling never slips — the one arm in the
        // file for which the header's "shortness cannot flake" was untrue.
        tls_handshake_timeout: Duration::from_secs(5),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    // The staller connects FIRST, so it is the one the loop admits, and then
    // says nothing at all — not even a ClientHello.
    let staller = TcpStream::connect(server.addr)
        .await
        .unwrap_or_else(|e| panic!("staller connect: {e}"));

    let (tx, mut rx) = oneshot::channel();
    let real_config = client_config(server.pin, &[ALPN_HTTP11]);
    let addr = server.addr;
    let real = spawn(async move {
        let _ = tx.send(attempt(addr, real_config).await);
    });

    // While the staller holds the only permit, nothing else gets in.
    assert!(
        timeout(BRIEF, &mut rx).await.is_err(),
        "the real client got in while the staller held the only permit"
    );
    assert_eq!(handlers.count(), 0);

    // The handshake timeout reclaims the permit — the positive arm.
    let result = timeout(GENEROUS, rx)
        .await
        .unwrap_or_else(|_| panic!("the staller's permit was never reclaimed ({GENEROUS:?})"))
        .unwrap_or_else(|e| panic!("the real client's channel closed: {e}"));
    assert_eq!(
        result.unwrap_or_else(|e| panic!("the real client failed: {e}")),
        StatusCode::OK
    );
    assert_eq!(handlers.count(), 1);
    let _ = real.await;
    drop(staller);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 9, arm one. An accept error is survived.
///
/// Kills break-on-error: the silently wedged listener F11e measured, which
/// accepts nothing forever at 0% CPU with no log line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accept_error_is_survived() {
    let handlers = handlers(UNGATED);
    let party = mint();
    let pin = party.pin();
    let tls = production_tls(&party, None);
    let (probe_tx, _probe_rx) = mpsc::unbounded_channel();
    let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF);

    let listener = ScriptedListener {
        steps: VecDeque::from([Step::Fail, Step::Give(server_io)]),
        probe: probe_tx,
        fail_forever: false,
    };
    let (shutdown, rx) = watch::channel(false);
    let done = spawn(serve(
        listener,
        tls,
        handlers.service.clone(),
        rx,
        AcceptConfig::default(),
    ));

    let stream = timeout(
        GENEROUS,
        tls_handshake(client_io, client_config(pin, &[ALPN_HTTP11])),
    )
    .await
    .unwrap_or_else(|_| panic!("the post-error connection never handshook ({GENEROUS:?})"))
    .unwrap_or_else(|e| panic!("post-error tls: {e}"));

    let status = timeout(GENEROUS, h1_request(stream))
        .await
        .unwrap_or_else(|_| panic!("the post-error request did not complete"))
        .unwrap_or_else(|e| panic!("post-error request: {e}"));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        handlers.count(),
        1,
        "the connection after an accept error must still be served"
    );

    trigger(&shutdown, true);
    match timeout(GENEROUS, done).await {
        Ok(Ok(Ok(outcome))) => assert_eq!(outcome, ShutdownOutcome::Drained),
        other => panic!("serve did not drain: {other:?}"),
    }
}

/// 9, arm two. The error arm stays shutdown-responsive when `true` is sent.
///
/// Kills an error arm whose backoff ignores shutdown: it would hold a deploy
/// for a backoff period per pending error, or forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sustained_accept_error_still_observes_a_sent_shutdown() {
    let handlers = handlers(UNGATED);
    let party = mint();
    let tls = production_tls(&party, None);
    let (probe_tx, mut probe_rx) = mpsc::unbounded_channel();

    let listener = ScriptedListener {
        steps: VecDeque::new(),
        probe: probe_tx,
        fail_forever: true,
    };
    let (shutdown, rx) = watch::channel(false);
    let done = spawn(serve(
        listener,
        tls,
        handlers.service.clone(),
        rx,
        AcceptConfig::default(),
    ));

    // The positive arm: the loop is genuinely cycling through the error path
    // before we trigger anything, so the assertion below is about the
    // throttle's wait and not about a loop that already exited.
    await_accepts(&mut probe_rx, 3).await;

    trigger(&shutdown, true);
    match timeout(GENEROUS, done).await {
        Ok(Ok(Ok(outcome))) => assert_eq!(outcome, ShutdownOutcome::Drained),
        other => panic!("a sustained accept error swallowed the shutdown: {other:?}"),
    }
    assert_eq!(handlers.count(), 0);
}

/// 9, arm three. The error arm stays shutdown-responsive when the sender is
/// DROPPED.
///
/// Kills the loop that reads `changed()`'s `Err` as "no shutdown" and
/// re-polls it: that call returns immediately every time, turning the backoff
/// into a hot spin that never exits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sustained_accept_error_still_observes_a_dropped_sender() {
    let handlers = handlers(UNGATED);
    let party = mint();
    let tls = production_tls(&party, None);
    let (probe_tx, mut probe_rx) = mpsc::unbounded_channel();

    let listener = ScriptedListener {
        steps: VecDeque::new(),
        probe: probe_tx,
        fail_forever: true,
    };
    let (shutdown, rx) = watch::channel(false);
    let done = spawn(serve(
        listener,
        tls,
        handlers.service.clone(),
        rx,
        AcceptConfig::default(),
    ));

    await_accepts(&mut probe_rx, 3).await;

    drop(shutdown);
    match timeout(GENEROUS, done).await {
        Ok(Ok(Ok(outcome))) => assert_eq!(outcome, ShutdownOutcome::Drained),
        other => panic!("a dropped sender did not stop the error loop: {other:?}"),
    }
    assert_eq!(handlers.count(), 0);
}

/// 10, arm zero. A receiver that is ALREADY `true` shuts down without
/// accepting anything.
///
/// Kills a loop without the entry level read. The edge for a pre-`serve` send
/// is consumed before the loop exists, so no `changed()` in any arm can
/// observe it — only the entry read can, and no signal-after-start test can
/// see the difference.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_already_true_receiver_shuts_down_without_accepting() {
    let handlers = handlers(UNGATED);
    let party = mint();
    let pin = party.pin();
    let tls = production_tls(&party, None);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local addr: {e}"));

    // A connection attempt that EXISTS before `serve` is called: the kernel
    // completed it into the backlog, so a loop that accepts even once will
    // pick it up.
    let pending = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("pending connect: {e}"));
    let client = spawn(async move {
        let stream = tls_handshake(pending, client_config(pin, &[ALPN_HTTP11])).await?;
        let _ = h1_request(stream).await;
        Ok::<(), std::io::Error>(())
    });

    // The level is true and its EDGE IS ALREADY CONSUMED, which is what makes
    // this the state no `changed()` can ever report.
    let (shutdown, mut rx) = watch::channel(false);
    trigger(&shutdown, true);
    assert!(
        *rx.borrow_and_update(),
        "the receiver must enter `serve` already true"
    );

    let done = spawn(serve(
        listener,
        tls,
        handlers.service.clone(),
        rx,
        AcceptConfig::default(),
    ));
    match timeout(GENEROUS, done).await {
        Ok(Ok(Ok(outcome))) => assert_eq!(outcome, ShutdownOutcome::Drained),
        other => panic!("an already-true receiver did not stop the loop: {other:?}"),
    }
    assert_eq!(
        handlers.count(),
        0,
        "a loop that shut down at entry cannot have run a handler"
    );
    client.abort();
    drop(shutdown);
}

/// 10, arm one. A `true` send drains in-flight work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sent_shutdown_drains_in_flight_work() {
    let mut handlers = handlers(0);
    let config = AcceptConfig {
        shutdown_deadline: Duration::from_secs(30),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    let (tx, client_rx) = oneshot::channel();
    let cfg = client_config(server.pin, &[ALPN_HTTP11]);
    let addr = server.addr;
    let client = spawn(async move {
        let _ = tx.send(attempt(addr, cfg).await);
    });
    handlers.await_entry().await;

    trigger(&server.shutdown, true);
    let Server {
        addr,
        pin,
        shutdown,
        done,
    } = server;
    let mut done = done;

    // Held work keeps `serve` from returning...
    assert!(
        timeout(BRIEF, &mut done).await.is_err(),
        "serve returned while a request was still in flight"
    );
    // ...and a new connection is not accepted while it drains.
    let fresh = timeout(BRIEF, attempt(addr, client_config(pin, &[ALPN_HTTP11]))).await;
    assert!(
        fresh.is_err() || fresh.is_ok_and(|r| r.is_err()),
        "a new connection was served after shutdown began"
    );
    assert_eq!(handlers.count(), 1, "only the in-flight request may run");

    // Releasing it completes both the response and the drain.
    handlers.release();
    let status = timeout(GENEROUS, client_rx)
        .await
        .unwrap_or_else(|_| panic!("the in-flight response never arrived"))
        .unwrap_or_else(|e| panic!("client channel closed: {e}"))
        .unwrap_or_else(|e| panic!("in-flight request failed: {e}"));
    assert_eq!(status, StatusCode::OK);
    match timeout(GENEROUS, done).await {
        Ok(Ok(Ok(outcome))) => assert_eq!(outcome, ShutdownOutcome::Drained),
        other => panic!("serve did not drain: {other:?}"),
    }
    let _ = client.await;
    drop(shutdown);
}

/// 10, arm two. DROPPING the sender drains the same way.
///
/// Kills an accept/permit race that reads `changed()`'s `Err` as "continue".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_sender_drains_in_flight_work() {
    let mut handlers = handlers(0);
    let config = AcceptConfig {
        shutdown_deadline: Duration::from_secs(30),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    let (tx, client_rx) = oneshot::channel();
    let cfg = client_config(server.pin, &[ALPN_HTTP11]);
    let addr = server.addr;
    let client = spawn(async move {
        let _ = tx.send(attempt(addr, cfg).await);
    });
    handlers.await_entry().await;

    let Server { shutdown, done, .. } = server;
    drop(shutdown);
    let mut done = done;

    assert!(
        timeout(BRIEF, &mut done).await.is_err(),
        "serve returned while a request was still in flight"
    );
    assert_eq!(handlers.count(), 1);

    handlers.release();
    let status = timeout(GENEROUS, client_rx)
        .await
        .unwrap_or_else(|_| panic!("the in-flight response never arrived"))
        .unwrap_or_else(|e| panic!("client channel closed: {e}"))
        .unwrap_or_else(|e| panic!("in-flight request failed: {e}"));
    assert_eq!(status, StatusCode::OK);
    match timeout(GENEROUS, done).await {
        Ok(Ok(Ok(outcome))) => assert_eq!(outcome, ShutdownOutcome::Drained),
        other => panic!("a dropped sender did not drain: {other:?}"),
    }
    let _ = client.await;
}

/// 10, arm three. A contract-violating `false` send, landing while a race is
/// PARKED, does not stop the server.
///
/// Kills a race site that treats any completed `changed()` as shutdown without
/// re-reading the level.
///
/// **The park proof is what makes that kill real, and it is why this arm is
/// not simply "send `false`, then connect".** Only a `false` that arrives at
/// an ARMED `changed()` inside a race reaches the level re-read at all: a
/// `false` sent before the loop parks is consumed by the loop's entry level
/// read, which is correct behaviour and exercises nothing. Measured — the
/// send-immediately shape leaves the level-dropping mutant alive.
///
/// The proof rides on `race`'s documented poll order. `race` polls the
/// shutdown arm FIRST, so `ScriptedListener::accept` — which pings before it
/// parks — is reachable only after this race's `changed()` was polled and
/// returned `Pending`, i.e. armed. Observing the ping therefore establishes
/// the park, and the `false` below lands inside it.
///
/// The second `await_accepts` is the positive arm: the loop re-armed and went
/// back to accepting. A site that broke on the `false` instead leaves the loop
/// and drops the listener, which closes the probe channel — reported at once
/// as a dropped listener rather than waited out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_false_send_does_not_stop_the_server() {
    let handlers = handlers(UNGATED);
    let party = mint();
    let tls = production_tls(&party, None);
    let (probe_tx, mut probe_rx) = mpsc::unbounded_channel();

    // An empty script that does NOT fail forever: the first `accept` pings and
    // then parks on `pending()`, which is the state this test needs.
    let listener = ScriptedListener {
        steps: VecDeque::new(),
        probe: probe_tx,
        fail_forever: false,
    };
    let (shutdown, rx) = watch::channel(false);
    let done = spawn(serve(
        listener,
        tls,
        handlers.service.clone(),
        rx,
        AcceptConfig::default(),
    ));

    // The park proof: the loop reached `accept`, so its accept race's
    // `changed()` is armed and nothing but a send can wake it.
    await_accepts(&mut probe_rx, 1).await;

    trigger(&shutdown, false);

    // The server kept accepting.
    await_accepts(&mut probe_rx, 1).await;

    // And a real `true` still drains normally.
    trigger(&shutdown, true);
    match timeout(GENEROUS, done).await {
        Ok(Ok(Ok(outcome))) => assert_eq!(outcome, ShutdownOutcome::Drained),
        other => panic!("a `false` send left the loop unable to shut down: {other:?}"),
    }
    assert_eq!(
        handlers.count(),
        0,
        "the scripted listener never offered a connection"
    );
}

/// 11. A 9-byte partial request cannot hold shutdown (F11f).
///
/// What this gates is the DRAIN closing a connection whose request head never
/// completed — that the connection is watched and that `graceful.shutdown()`
/// is what ends it — not the header timeout. The obvious claim, that it kills
/// a builder missing `.timer(…)`, is FALSE and was measured false: that mutant
/// panics inside the detached connection task, the unwind drops the drain receiver,
/// the drain completes, and this test passes. Removing `header_read_timeout`
/// while leaving the timer is silent here for the same reason — the drain, not
/// the timeout, is what closes this connection.
///
/// So code review must verify that the HTTP/1.1 builder sets both `.timer(...)`
/// and `.header_read_timeout(...)`; this suite does not prove that pairing. Its one
/// suite-visible half is the sibling miswiring, a timeout with no timer, which
/// PANICS on the first connection — every other test in this file is that
/// gate's negative demonstration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_partial_request_cannot_hold_shutdown() {
    let handlers = handlers(UNGATED);
    let config = AcceptConfig {
        header_read_timeout: Duration::from_millis(500),
        // Long enough that `Drained` can only mean the partial connection was
        // evicted, never that the deadline quietly rescued the drain.
        shutdown_deadline: Duration::from_secs(8),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    let mut stream = tls_connect(server.addr, client_config(server.pin, &[ALPN_HTTP11]))
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"));
    stream
        .write_all(b"GET /a HT")
        .await
        .unwrap_or_else(|e| panic!("partial write: {e}"));
    stream
        .flush()
        .await
        .unwrap_or_else(|e| panic!("partial flush: {e}"));

    trigger(&server.shutdown, true);
    assert_eq!(
        server.outcome().await,
        ShutdownOutcome::Drained,
        "the header timeout must evict the partial connection"
    );
    assert_eq!(handlers.count(), 0);
    drop(stream);
}

/// 12. The hard deadline fires (`DeadlineExpired`).
///
/// The deadline is a gate `AcceptConfig::shutdown_deadline` sets; this is its failure-mode
/// demonstration. Without it, this test never returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hard_deadline_fires_on_a_stuck_handler() {
    let mut handlers = handlers(0);
    let config = AcceptConfig {
        shutdown_deadline: Duration::from_millis(500),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    let cfg = client_config(server.pin, &[ALPN_HTTP11]);
    let addr = server.addr;
    let client = spawn(async move { attempt(addr, cfg).await });
    handlers.await_entry().await;

    trigger(&server.shutdown, true);
    assert_eq!(
        server.outcome().await,
        ShutdownOutcome::DeadlineExpired,
        "a handler that never returns must expire the drain deadline"
    );
    assert_eq!(handlers.count(), 1);
    client.abort();
}

/// 13. A peer that COMPLETES TLS and then sends nothing cannot hold a permit
///     forever — the `http/1.1` half.
///
/// The window this covers lies strictly between test 8 (which stalls *before*
/// TLS, so the handshake timeout reclaims it) and test 11 (which writes nine
/// bytes, so a version is decided): handshake done, ALPN admitted, zero
/// application bytes. Kills a loop that hands the stream to a
/// version-sniffing builder — the sniff is an unbounded read, so
/// `header_read_timeout` is never armed and the permit is held until the
/// process dies. At `max_connections = 1` that is the whole cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_peer_past_tls_cannot_hold_a_permit_forever() {
    let handlers = handlers(UNGATED);
    let config = AcceptConfig {
        max_connections: 1,
        // An order of magnitude above BRIEF, so the negative arm below is not
        // racing the very timeout the positive arm is waiting for.
        header_read_timeout: Duration::from_secs(5),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    // The handshake COMPLETES — that is what makes this connection admitted
    // and holding the only permit, rather than one stalled before TLS.
    let silent = tls_connect(server.addr, client_config(server.pin, &[ALPN_HTTP11]))
        .await
        .unwrap_or_else(|e| panic!("the silent peer's handshake must COMPLETE, got {e}"));
    assert_eq!(
        silent.get_ref().1.alpn_protocol(),
        Some(ALPN_HTTP11),
        "the silent peer must have negotiated http/1.1 by value"
    );

    let (tx, mut rx) = oneshot::channel();
    let real_config = client_config(server.pin, &[ALPN_HTTP11]);
    let addr = server.addr;
    let real = spawn(async move {
        let _ = tx.send(attempt(addr, real_config).await);
    });

    // While the silent peer holds the only permit, nothing else gets in.
    assert!(
        timeout(BRIEF, &mut rx).await.is_err(),
        "the real client got in while the silent peer held the only permit"
    );
    assert_eq!(handlers.count(), 0);

    // The header timeout reclaims the permit — the positive arm.
    let result = timeout(GENEROUS, rx)
        .await
        .unwrap_or_else(|_| panic!("the silent peer's permit was never reclaimed ({GENEROUS:?})"))
        .unwrap_or_else(|e| panic!("the real client's channel closed: {e}"));
    assert_eq!(
        result.unwrap_or_else(|e| panic!("the real client failed: {e}")),
        StatusCode::OK
    );
    assert_eq!(handlers.count(), 1);
    let _ = real.await;
    drop(silent);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 14. The same window on the `h2` half — byte 0 of the client preface.
///
/// hyper's HTTP/2 server reads the 24-byte client preface through `h2`'s
/// `ReadPreface`, a bare `poll_read` loop with no timer, and it constructs the
/// keep-alive PING machinery only once that handshake has already resolved.
/// Nothing on the pinned API bounds the interval between "TLS finished" and
/// "the preface arrived", so on an undecorated stream a peer that negotiates
/// `h2` and then says nothing holds its permit until the process exits.
///
/// What this gates is the preface deadline: `header_read_timeout` armed on the
/// `h2` leg by the accept path itself, above TLS, and disarming only once the
/// whole 24-byte preface has been read. With tests 19 and 20 it fixes that
/// bound's near side; test 18 fixes the far side, where the connection is
/// established and the keep-alive pair takes over.
///
/// **Every other bound in this config is a multiple of `GENEROUS` on
/// purpose,** so the reclaim below is evidence about the preface deadline and
/// nothing else: the TLS handshake bound and the keep-alive pair are all 45 s,
/// `shutdown_deadline` is inert until shutdown is triggered (after the
/// assertion), and the silent peer's own socket is held in scope throughout so
/// the close cannot be the client's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_h2_peer_past_tls_cannot_hold_a_permit_forever() {
    let handlers = handlers(UNGATED);
    let config = AcceptConfig {
        max_connections: 1,
        // An order of magnitude above BRIEF: the negative arm below expires on
        // THIS bound rather than on an unreachable condition.
        header_read_timeout: Duration::from_secs(5),
        // All three a multiple of GENEROUS, so none of them can be what
        // reclaims the permit inside the positive arm.
        tls_handshake_timeout: Duration::from_secs(45),
        h2_keep_alive_interval: Duration::from_secs(45),
        h2_keep_alive_timeout: Duration::from_secs(45),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    let silent = tls_connect(server.addr, client_config(server.pin, &[ALPN_H2]))
        .await
        .unwrap_or_else(|e| panic!("the silent peer's handshake must COMPLETE, got {e}"));
    assert_eq!(
        silent.get_ref().1.alpn_protocol(),
        Some(ALPN_H2),
        "the silent peer must have negotiated h2 by value"
    );

    let (tx, mut rx) = oneshot::channel();
    let real_config = client_config(server.pin, &[ALPN_HTTP11]);
    let addr = server.addr;
    let real = spawn(async move {
        let _ = tx.send(attempt(addr, real_config).await);
    });

    assert!(
        timeout(BRIEF, &mut rx).await.is_err(),
        "the real client got in while the silent peer held the only permit"
    );
    assert_eq!(handlers.count(), 0);

    let result = timeout(GENEROUS, rx)
        .await
        .unwrap_or_else(|_| panic!("the silent peer's permit was never reclaimed ({GENEROUS:?})"))
        .unwrap_or_else(|e| panic!("the real client's channel closed: {e}"));
    assert_eq!(
        result.unwrap_or_else(|e| panic!("the real client failed: {e}")),
        StatusCode::OK
    );
    assert_eq!(handlers.count(), 1);
    let _ = real.await;
    drop(silent);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 15. A peer that negotiated `http/1.1` is not served HTTP/2, whatever it
///     sends next (RFC 7301 §3.2).
///
/// Kills a loop that admits the ALPN *set* and then lets the connection
/// builder re-decide by sniffing the first bytes: this client negotiates
/// `http/1.1` honestly and then opens an HTTP/2 connection, and a sniffing
/// builder serves it real HTTP/2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_http11_negotiation_is_not_served_http2() {
    let mut handlers = handlers(UNGATED);
    let server = start(AcceptConfig::default(), handlers.service.clone(), None).await;

    let stream = tls_connect(server.addr, client_config(server.pin, &[ALPN_HTTP11]))
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"));
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(ALPN_HTTP11),
        "the client must have negotiated http/1.1 by value"
    );

    let outcome = timeout(GENEROUS, h2_request(stream))
        .await
        .unwrap_or_else(|_| panic!("the mismatched request hung for {GENEROUS:?}"));
    assert!(
        outcome.is_err(),
        "an http/1.1 negotiation must not be served HTTP/2, got {outcome:?}"
    );
    assert_eq!(handlers.count(), 0);
    assert!(handlers.entered.try_recv().is_err());

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 16. The mirror: a peer that negotiated `h2` is not served HTTP/1.1.
///
/// With test 15 this pins the direction of the binding. A single-sided test
/// passes over a loop that always builds the same protocol.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_h2_negotiation_is_not_served_http11() {
    let mut handlers = handlers(UNGATED);
    let server = start(AcceptConfig::default(), handlers.service.clone(), None).await;

    let stream = tls_connect(server.addr, client_config(server.pin, &[ALPN_H2]))
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"));
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(ALPN_H2),
        "the client must have negotiated h2 by value"
    );

    let outcome = timeout(GENEROUS, h1_request(stream))
        .await
        .unwrap_or_else(|_| panic!("the mismatched request hung for {GENEROUS:?}"));
    assert!(
        outcome.is_err(),
        "an h2 negotiation must not be served HTTP/1.1, got {outcome:?}"
    );
    assert_eq!(handlers.count(), 0);
    assert!(handlers.entered.try_recv().is_err());

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 17. A handshake still pending when shutdown lands cannot expire the drain
///     deadline.
///
/// The drain waits on the drain channel's receiver count, and a task that
/// holds a receiver across its TLS handshake pins that count whether or not it
/// ever watched a connection. So one silent `connect()` immediately before a
/// deploy taxes the drain by the whole handshake timeout — and when that
/// timeout is not strictly shorter than the deadline, it flips the outcome to
/// `DeadlineExpired`, whose documented caller contract is an immediate
/// `std::process::exit`. The constants here make that flip deterministic
/// rather than a scheduling coin-flip: the handshake bound is far longer than
/// the deadline, so a loop that waits for the handshake cannot drain in time.
///
/// The `max_connections = 1` park proof is what makes the assertion real. It
/// establishes that the silent peer WAS admitted and IS holding the permit
/// before shutdown is triggered; without it the test would also pass over a
/// loop that never accepted the connection at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pending_handshake_cannot_expire_the_drain_deadline() {
    let handlers = handlers(UNGATED);
    let config = AcceptConfig {
        max_connections: 1,
        tls_handshake_timeout: Duration::from_secs(30),
        shutdown_deadline: Duration::from_millis(500),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    // Connects and says nothing — not even a ClientHello.
    let staller = TcpStream::connect(server.addr)
        .await
        .unwrap_or_else(|e| panic!("staller connect: {e}"));

    let (tx, mut rx) = oneshot::channel();
    let real_config = client_config(server.pin, &[ALPN_HTTP11]);
    let addr = server.addr;
    let real = spawn(async move {
        let _ = tx.send(attempt(addr, real_config).await);
    });

    // The park proof: the staller holds the only permit, so it is inside the
    // spawned task's handshake and the loop is waiting on `acquire_owned`.
    assert!(
        timeout(BRIEF, &mut rx).await.is_err(),
        "the real client got in while the staller held the only permit"
    );

    trigger(&server.shutdown, true);
    assert_eq!(
        server.outcome().await,
        ShutdownOutcome::Drained,
        "a handshake that had not been admitted must be abandoned, not waited out"
    );
    assert_eq!(handlers.count(), 0);
    real.abort();
    drop(staller);
}

/// 18. The h2 keep-alive pair reclaims the permit of a peer that COMPLETED the
///     handshake and then went silent.
///
/// This is the far side of test 14's gap, and it is a different window rather
/// than a smaller one. Test 14 stops at byte 0 of the client preface, where
/// nothing in the envelope holds a clock; this one sends all 24, which is
/// exactly where hyper's h2 handshake resolves and its keep-alive arms. From
/// that instant the pair on [`AcceptConfig`] is the ONLY bound on the
/// connection — `header_read_timeout` is an HTTP/1.1 knob and the builder is
/// pinned to `http2_only()`, so it is not merely unused here, it is unarmable.
///
/// Until this test that bound was reading-gated, and its failure mode had never
/// been demonstrated. hyper builds its `KeepAlive` from `keep_alive_interval`
/// alone, so DELETING THAT ONE LINE from `envelope()` removes the bound
/// outright rather than lengthening it — `adaptive_window(true)` still leaves
/// the ping channel enabled, just with nothing to time out — and every other
/// test in this file stays green. Measured, not reasoned: with the line removed
/// this test hangs to `GENEROUS` and fails on the positive arm.
///
/// The split values gate the second knob too. Drop `keep_alive_timeout` and
/// hyper's own default of 20 s applies, which puts the close at 23 s — past
/// `GENEROUS`, so this test fails on that mutation as well. Also measured.
///
/// **Every other bound in this config is set beyond `GENEROUS` on purpose,**
/// and that is what makes the positive arm evidence about the keep-alive pair
/// rather than about a permit that came back for some other reason: the TLS
/// handshake bound and the header bound are both 45 s, `shutdown_deadline` is
/// inert until shutdown is triggered (which happens after the assertion), and
/// the silent peer's own socket is held in scope throughout so the close cannot
/// be the client's. Inside the window this test measures, the keep-alive pair
/// is the only clock that can fire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_h2_peer_past_the_preface_cannot_hold_a_permit_forever() {
    let handlers = handlers(UNGATED);
    let config = AcceptConfig {
        max_connections: 1,
        // 3 s + 2 s = 5 s, an order of magnitude above BRIEF for the same
        // reason test 8's handshake bound is: the negative arm below expires on
        // THIS bound rather than on an unreachable condition, so the margin has
        // to be the timeout and not the scheduler.
        h2_keep_alive_interval: Duration::from_secs(3),
        h2_keep_alive_timeout: Duration::from_secs(2),
        // Both a multiple of GENEROUS, so neither can be what reclaims the
        // permit inside the positive arm.
        tls_handshake_timeout: Duration::from_secs(45),
        header_read_timeout: Duration::from_secs(45),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    // The handshake COMPLETES and h2 is negotiated BY VALUE, which is what
    // makes this peer admitted and holding the only permit.
    let mut silent = tls_connect(server.addr, client_config(server.pin, &[ALPN_H2]))
        .await
        .unwrap_or_else(|e| panic!("the silent peer's handshake must COMPLETE, got {e}"));
    assert_eq!(
        silent.get_ref().1.alpn_protocol(),
        Some(ALPN_H2),
        "the silent peer must have negotiated h2 by value"
    );

    // Exactly the preface, and then nothing, ever. No SETTINGS frame follows:
    // hyper's handshake resolves on the 24th byte and does not await one.
    silent
        .write_all(H2_PREFACE)
        .await
        .unwrap_or_else(|e| panic!("preface write: {e}"));
    silent
        .flush()
        .await
        .unwrap_or_else(|e| panic!("preface flush: {e}"));

    let (tx, mut rx) = oneshot::channel();
    let real_config = client_config(server.pin, &[ALPN_H2]);
    let addr = server.addr;
    let real = spawn(async move {
        let _ = tx.send(h2_attempt(addr, real_config).await);
    });

    // While the silent peer holds the only permit, nothing else gets in.
    assert!(
        timeout(BRIEF, &mut rx).await.is_err(),
        "the real client got in while the silent h2 peer held the only permit"
    );
    assert_eq!(handlers.count(), 0);

    // The keep-alive pair evicts it and the permit returns — the positive arm.
    // A second REAL h2 client reaching a handler is the strongest observable
    // available: it can only happen if the slot came back.
    let result = timeout(GENEROUS, rx)
        .await
        .unwrap_or_else(|_| {
            panic!("the silent h2 peer's permit was never reclaimed ({GENEROUS:?})")
        })
        .unwrap_or_else(|e| panic!("the real client's channel closed: {e}"));
    assert_eq!(
        result.unwrap_or_else(|e| panic!("the real h2 client failed: {e}")),
        StatusCode::OK
    );
    assert_eq!(handlers.count(), 1);
    let _ = real.await;
    drop(silent);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 19. An `h2` peer ONE BYTE SHORT of the preface cannot hold a permit forever.
///
/// The seam, and the reason it is its own test: 23 bytes lies strictly between
/// test 14 (zero bytes, nothing read at all) and test 18 (all twenty-four,
/// where hyper's keep-alive takes over). It is also where a first-BYTE disarm
/// dies — a decorator that goes transparent once any read succeeds is defeated
/// by exactly this peer, so the bound has to stay armed until the WHOLE
/// preface has arrived.
///
/// Same one-clock config as test 14: every other bound is a multiple of
/// `GENEROUS`, so the reclaim below can only be the preface deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_h2_peer_short_of_the_preface_cannot_hold_a_permit_forever() {
    let handlers = handlers(UNGATED);
    let config = AcceptConfig {
        max_connections: 1,
        header_read_timeout: Duration::from_secs(5),
        tls_handshake_timeout: Duration::from_secs(45),
        h2_keep_alive_interval: Duration::from_secs(45),
        h2_keep_alive_timeout: Duration::from_secs(45),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    let mut silent = tls_connect(server.addr, client_config(server.pin, &[ALPN_H2]))
        .await
        .unwrap_or_else(|e| panic!("the short peer's handshake must COMPLETE, got {e}"));
    assert_eq!(
        silent.get_ref().1.alpn_protocol(),
        Some(ALPN_H2),
        "the short peer must have negotiated h2 by value"
    );

    // Sliced from the one preface constant, so the fixture cannot drift away
    // from the length the bound is written against.
    let short = H2_PREFACE
        .get(..H2_PREFACE_SHORT)
        .unwrap_or_else(|| panic!("the preface is shorter than {H2_PREFACE_SHORT} bytes"));
    silent
        .write_all(short)
        .await
        .unwrap_or_else(|e| panic!("short preface write: {e}"));
    silent
        .flush()
        .await
        .unwrap_or_else(|e| panic!("short preface flush: {e}"));

    let (tx, mut rx) = oneshot::channel();
    let real_config = client_config(server.pin, &[ALPN_H2]);
    let addr = server.addr;
    let real = spawn(async move {
        let _ = tx.send(h2_attempt(addr, real_config).await);
    });

    // While the short peer holds the only permit, nothing else gets in.
    assert!(
        timeout(BRIEF, &mut rx).await.is_err(),
        "the real client got in while the short h2 peer held the only permit"
    );
    assert_eq!(handlers.count(), 0);

    // The preface deadline reclaims the permit — the positive arm, and a REAL
    // h2 client on the same decorated leg is what proves the slot came back.
    let result = timeout(GENEROUS, rx)
        .await
        .unwrap_or_else(|_| panic!("the short h2 peer's permit was never reclaimed ({GENEROUS:?})"))
        .unwrap_or_else(|e| panic!("the real client's channel closed: {e}"));
    assert_eq!(
        result.unwrap_or_else(|e| panic!("the real h2 client failed: {e}")),
        StatusCode::OK
    );
    assert_eq!(handlers.count(), 1);
    let _ = real.await;
    drop(silent);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 20. A dribbler whose preface NEVER arrives cannot hold a permit forever.
///
/// One byte every 500 ms against a 3 s bound: six bytes in, nowhere near the
/// twenty-four that end the window. **This is the mutation-killer for an
/// idle-reset deadline** — a timeout that re-arms on activity never fires for
/// this peer, and every other test in the file stays green under that mutation
/// because their peers are silent rather than slow. The deadline is absolute:
/// created once, at construction, and never pushed back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_h2_dribbler_that_never_arrives_loses_its_permit() {
    let handlers = handlers(UNGATED);
    let config = AcceptConfig {
        max_connections: 1,
        header_read_timeout: Duration::from_secs(3),
        tls_handshake_timeout: Duration::from_secs(45),
        h2_keep_alive_interval: Duration::from_secs(45),
        h2_keep_alive_timeout: Duration::from_secs(45),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    let dribbler = tls_connect(server.addr, client_config(server.pin, &[ALPN_H2]))
        .await
        .unwrap_or_else(|e| panic!("the dribbler's handshake must COMPLETE, got {e}"));
    assert_eq!(
        dribbler.get_ref().1.alpn_protocol(),
        Some(ALPN_H2),
        "the dribbler must have negotiated h2 by value"
    );
    let feed = pump(dribble(dribbler, H2_PREFACE, Duration::from_millis(500)));

    let (tx, mut rx) = oneshot::channel();
    let real_config = client_config(server.pin, &[ALPN_H2]);
    let addr = server.addr;
    let real = spawn(async move {
        let _ = tx.send(h2_attempt(addr, real_config).await);
    });

    // While the dribbler holds the only permit, nothing else gets in.
    assert!(
        timeout(BRIEF, &mut rx).await.is_err(),
        "the real client got in while the dribbler held the only permit"
    );
    assert_eq!(handlers.count(), 0);

    // The absolute deadline reclaims the permit — the positive arm.
    let result = timeout(GENEROUS, rx)
        .await
        .unwrap_or_else(|_| panic!("the dribbler's permit was never reclaimed ({GENEROUS:?})"))
        .unwrap_or_else(|e| panic!("the real client's channel closed: {e}"));
    assert_eq!(
        result.unwrap_or_else(|e| panic!("the real h2 client failed: {e}")),
        StatusCode::OK
    );
    assert_eq!(handlers.count(), 1);
    let _ = real.await;
    drop(feed);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 21. A dribbler whose preface DOES arrive is served, and stays served past
///     the deadline.
///
/// A real hyper `h2` client whose bytes reach the server one at a time: the
/// twenty-four preface bytes cross TLS as twenty-four records, so the server
/// sees them as twenty-four separate reads. What it gates is the other
/// direction from tests 14, 19 and 20 — that the bound lets go of a connection
/// whose preface arrives in pieces, rather than only that it holds one whose
/// preface never does.
///
/// **The liveness probe after the deadline is what gives that any teeth at
/// all,** and it is the one place this test goes past what a response can
/// show: the response arrives ~1.5 s in, well before the 3 s bound, so a
/// decorator that never disarmed would kill the connection AFTER the request
/// had already succeeded and every other assertion here would still pass. The
/// probe waits the bound out and then asks whether the connection is still
/// there.
///
/// **What it does NOT gate, measured rather than assumed:** a bound that
/// counted each read on its own instead of accumulating survives this test.
/// The request that follows the preface arrives as one read of well over
/// twenty-four bytes, so it disarms such a bound anyway, a beat later. The
/// accumulation itself is pinned by `preface`'s own unit tests, where nothing
/// but single bytes ever arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dribbled_h2_preface_that_arrives_is_served_and_survives() {
    let handlers = handlers(UNGATED);
    let preface_bound = Duration::from_secs(3);
    let config = AcceptConfig {
        header_read_timeout: preface_bound,
        tls_handshake_timeout: Duration::from_secs(45),
        h2_keep_alive_interval: Duration::from_secs(45),
        h2_keep_alive_timeout: Duration::from_secs(45),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    let tls = tls_connect(server.addr, client_config(server.pin, &[ALPN_H2]))
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"));
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(ALPN_H2),
        "the dribbled client must have negotiated h2 by value"
    );

    // hyper's client writes into `near` at full speed; the pump drains `far`
    // into the TLS stream a byte at a time until the preface is through, and
    // forwards the request behind it normally.
    let (near, far) = tokio::io::duplex(DUPLEX_BUF);
    let (far_rx, far_tx) = tokio::io::split(far);
    let (tls_rx, tls_tx) = tokio::io::split(tls);
    let outbound = pump(dribble_then_forward(
        far_rx,
        tls_tx,
        H2_PREFACE.len(),
        Duration::from_millis(50),
    ));
    let inbound = pump(async move {
        let mut from = tls_rx;
        let mut to = far_tx;
        let _ = tokio::io::copy(&mut from, &mut to).await;
    });

    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(near))
            .await
            .unwrap_or_else(|e| panic!("h2 handshake: {e}"));
    let driver = pump(conn);
    let request = Request::builder()
        .uri(format!("https://{TEST_HOST}/"))
        .body(Empty::<Bytes>::new())
        .unwrap_or_else(|e| panic!("request: {e}"));
    let response = timeout(GENEROUS, sender.send_request(request))
        .await
        .unwrap_or_else(|_| panic!("the dribbled h2 request did not complete ({GENEROUS:?})"))
        .unwrap_or_else(|e| panic!("dribbled h2 send: {e}"));
    assert_eq!(response.status(), StatusCode::OK);
    response
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("dribbled h2 body: {e}"));
    assert_eq!(handlers.count(), 1);

    // Outlive the bound, then prove the connection is still there: a decorator
    // that never disarmed closes it somewhere inside this wait.
    gap(preface_bound + BRIEF).await;
    timeout(GENEROUS, sender.ready())
        .await
        .unwrap_or_else(|_| panic!("the disarmed connection never became ready ({GENEROUS:?})"))
        .unwrap_or_else(|e| panic!("the disarmed connection was closed: {e}"));
    assert_eq!(handlers.count(), 1, "exactly one request was ever sent");

    drop(sender);
    drop(driver);
    drop(outbound);
    drop(inbound);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 22. The preface bound is the HTTP/2 leg's and ONLY the HTTP/2 leg's.
///
/// Without this test the h2-only property is a reading gate: wrapping the
/// HTTP/1.1 leg as well survives every other test in this file, because a
/// conventional request head runs past 24 bytes and disarms the bound during
/// the first exchange. **hyper does not require `Host` on HTTP/1.1** — no
/// enforcement exists in its `proto::h1::role` — so a SIXTEEN-byte head is
/// answered `200` on a connection that stays reusable, and such a connection
/// never reaches 24 bytes at all. That is the peer a misapplied bound kills.
///
/// The two clocks differ in kind, and the timing is built on that. hyper's
/// `header_read_timeout` RE-ARMS per message; a preface bound is absolute from
/// admission. So the second request is issued past where an absolute bound
/// would have fired, while hyper's own clock — re-armed by the first
/// exchange — still has most of a bound left to run.
///
/// The schedule is stated as fractions of the bound so the margins can be
/// checked rather than trusted, and every one of them is `bound / 4` = 1.5 s.
/// Both are POSITIVE arms, so `BRIEF` is not the right unit for either: this
/// file reserves `BRIEF` for a condition a correct implementation never
/// produces, and both waits here are conditions it must survive.
///
/// | moment | t | why it is safe |
/// |---|---|---|
/// | first exchange | `bound/2` = 3 s | 3 s inside an absolute bound |
/// | second exchange | `bound*5/4` = 7.5 s | 1.5 s PAST an absolute bound |
/// | hyper's re-armed clock | `bound/2 + bound` = 9 s | 1.5 s after the probe |
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_preface_bound_is_not_applied_to_the_http11_leg() {
    /// A complete, reusable HTTP/1.1 head in under 24 bytes. `X` is a method
    /// token like any other, and no `Host` is sent.
    const TINY: &[u8] = b"X / HTTP/1.1\r\n\r\n";
    const _: () = assert!(TINY.len() < 24);

    let handlers = handlers(UNGATED);
    let bound = Duration::from_secs(6);
    // Half a bound in: an absolute bound has half of itself still to run, so
    // this exchange succeeds either way and cannot be what fails the test.
    let first_at = bound / 2;
    // Three quarters of a bound later — 1.25 bounds from admission. Past where
    // an absolute bound fires, and short of hyper's clock, which the first
    // response re-armed.
    let then = bound * 3 / 4;
    let config = AcceptConfig {
        // The only clock that may move inside this test. The other three are a
        // multiple of it, so a closed connection can only be this bound.
        header_read_timeout: bound,
        tls_handshake_timeout: Duration::from_secs(45),
        h2_keep_alive_interval: Duration::from_secs(45),
        h2_keep_alive_timeout: Duration::from_secs(45),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    let mut tls = tls_connect(server.addr, client_config(server.pin, &[ALPN_HTTP11]))
        .await
        .unwrap_or_else(|e| panic!("the handshake must COMPLETE, got {e}"));
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(ALPN_HTTP11),
        "this peer must be on the http/1.1 leg by value"
    );

    gap(first_at).await;
    let first = exchange(&mut tls, TINY)
        .await
        .unwrap_or_else(|| panic!("a 16-byte head must be answered on the http/1.1 leg"));
    assert!(
        first.starts_with("HTTP/1.1 200 OK"),
        "the first exchange must be a keep-alive 200, got {first:?}"
    );

    // Past where an absolute bound would have fired, short of hyper's clock,
    // which the exchange above re-armed. Fewer than 24 bytes have ever been
    // read, so a misapplied bound is still armed and kills this connection.
    gap(then).await;
    let second = exchange(&mut tls, TINY).await.unwrap_or_else(|| {
        panic!("the keep-alive connection was closed: the preface bound is on the http/1.1 leg")
    });
    assert!(
        second.starts_with("HTTP/1.1 200 OK"),
        "the connection must still serve, got {second:?}"
    );
    assert_eq!(handlers.count(), 2);
    drop(tls);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 23. The connection lifetime closes an ESTABLISHED, healthy, serving
///     connection — the one clock in this envelope a peer cannot re-arm.
///
/// **What this bound exists for is not this connection.** `granary-server`'s
/// read-response budget charges the bytes a range response holds resident and
/// sheds `503` when the budget is full; those charges are released only when
/// the transport drops the response, which happens at the CLIENT's pace. Every
/// other clock here is re-armed by peer activity — hyper schedules its h2 PING
/// at `last_read_at + interval`, and a `WINDOW_UPDATE` is a frame read — so a
/// peer trickling window updates holds its charge forever and the shed becomes
/// permanent. A budget whose recovery depends on peer goodwill is worse than
/// no budget: the process would otherwise die and be restarted. This clock is
/// what makes the charge's hold finite, and it is the reason the charge ships
/// at all.
///
/// **The park proof is the FIRST exchange, and it is load-bearing.** Without
/// it, a `None` at the second exchange is equally consistent with a connection
/// that was never admitted, never negotiated, or refused at the gate — and the
/// row would pass on a server that closed everything. The first exchange
/// proves this connection completed TLS, was ALPN-admitted, reached a handler
/// and was serving keep-alive traffic at the moment the clock was running.
///
/// **Every other bound is set to 45 s** — three times `GENEROUS` — so the
/// close inside this window cannot be the handshake bound, the header bound or
/// the keep-alive pair, and the client's own socket is held in scope
/// throughout so it cannot be the client's. The lifetime is the only clock
/// that can fire here.
///
/// Schedule stated as fractions of the bound, the way test 22 states its own:
///
/// | moment | t | why |
/// |---|---|---|
/// | first exchange | `bound/2` = 2 s | inside the bound: must be served |
/// | second exchange | `bound*5/4` = 5 s | past the bound: must be closed |
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_connection_lifetime_closes_an_established_connection() {
    const TINY: &[u8] = b"X / HTTP/1.1\r\n\r\n";
    let bound = Duration::from_secs(4);
    let first_at = bound / 2;
    let then = bound * 3 / 4;

    let handlers = handlers(UNGATED);
    let config = AcceptConfig {
        connection_max_lifetime: bound,
        // All beyond GENEROUS, so none of them can be what closes this
        // connection inside the window measured below.
        tls_handshake_timeout: Duration::from_secs(45),
        header_read_timeout: Duration::from_secs(45),
        h2_keep_alive_interval: Duration::from_secs(45),
        h2_keep_alive_timeout: Duration::from_secs(45),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    let mut tls = tls_connect(server.addr, client_config(server.pin, &[ALPN_HTTP11]))
        .await
        .unwrap_or_else(|e| panic!("the handshake must COMPLETE, got {e}"));
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(ALPN_HTTP11),
        "this peer must be on the http/1.1 leg by value"
    );

    // THE PARK PROOF: admitted, serving, and inside the bound.
    gap(first_at).await;
    let first = exchange(&mut tls, TINY)
        .await
        .unwrap_or_else(|| panic!("the connection must be serving inside the lifetime bound"));
    assert!(
        first.starts_with("HTTP/1.1 200 OK"),
        "the first exchange must be a keep-alive 200, got {first:?}"
    );
    assert_eq!(handlers.count(), 1);

    // Past the bound. The peer is healthy, the connection is idle, and nothing
    // the peer could do would extend this clock.
    gap(then).await;
    assert!(
        exchange(&mut tls, TINY).await.is_none(),
        "the lifetime bound did not close an established connection: a charge \
         held over this connection could be held forever"
    );
    assert_eq!(
        handlers.count(),
        1,
        "the closed connection served nothing more"
    );
    drop(tls);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// 24. The lifetime bound fires at its OWN value and not before — the control
///     for test 23.
///
/// Test 23 alone passes on a server that closes every connection immediately,
/// on one that closes at the header bound, and on one that arms the lifetime
/// with whatever `Duration` happened to be in scope. This row is what
/// distinguishes those: the same schedule, the same two exchanges at 2 s and
/// 5 s, and a lifetime of 20 s — so both exchanges are INSIDE the bound and
/// both must be served. Only a clock armed with the configured value passes
/// both rows.
///
/// It is not test 22 restated. Test 22 measures the preface bound against a
/// default lifetime three hundred seconds away; this one puts the lifetime
/// twenty seconds out, where an implementation that fired it early has
/// somewhere to fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_connection_lifetime_does_not_fire_early() {
    const TINY: &[u8] = b"X / HTTP/1.1\r\n\r\n";
    let first_at = Duration::from_secs(2);
    let then = Duration::from_secs(3);

    let handlers = handlers(UNGATED);
    let config = AcceptConfig {
        connection_max_lifetime: Duration::from_secs(20),
        tls_handshake_timeout: Duration::from_secs(45),
        header_read_timeout: Duration::from_secs(45),
        h2_keep_alive_interval: Duration::from_secs(45),
        h2_keep_alive_timeout: Duration::from_secs(45),
        ..AcceptConfig::default()
    };
    let server = start(config, handlers.service.clone(), None).await;

    let mut tls = tls_connect(server.addr, client_config(server.pin, &[ALPN_HTTP11]))
        .await
        .unwrap_or_else(|e| panic!("the handshake must COMPLETE, got {e}"));

    gap(first_at).await;
    let first = exchange(&mut tls, TINY)
        .await
        .unwrap_or_else(|| panic!("2 s is inside a 20 s lifetime"));
    assert!(first.starts_with("HTTP/1.1 200 OK"), "got {first:?}");

    gap(then).await;
    let second = exchange(&mut tls, TINY)
        .await
        .unwrap_or_else(|| panic!("5 s is inside a 20 s lifetime: the bound fired early"));
    assert!(second.starts_with("HTTP/1.1 200 OK"), "got {second:?}");
    assert_eq!(handlers.count(), 2);
    drop(tls);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// Graceful rotation stops new h2 streams before the hard lifetime while an
/// already-running stream is allowed to finish inside the grace window. This
/// distinguishes rotation from an implementation that only retains the hard
/// lifetime: without the GOAWAY, the second request reaches the handler and
/// raises its count to two before the hard lifetime ends either request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_h2_request_finishes_after_graceful_rotation_starts() {
    let lifetime = Duration::from_secs(6);
    let grace = Duration::from_secs(4);
    let rotation = Duration::from_secs(2);
    let mut handlers = handlers(0);
    let server = start(
        AcceptConfig {
            connection_max_lifetime: lifetime,
            connection_drain_grace: grace,
            ..AcceptConfig::default()
        },
        handlers.service.clone(),
        None,
    )
    .await;
    let stream = tls_connect(server.addr, client_config(server.pin, &[ALPN_H2]))
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"));
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap_or_else(|e| panic!("h2 handshake: {e}"));
    let _pump = pump(connection);
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://{TEST_HOST}/"))
        .body(Empty::<Bytes>::new())
        .unwrap_or_else(|e| panic!("request: {e}"));
    let response = sender.send_request(request);
    let in_flight = spawn(async move {
        let response = response.await.map_err(|e| format!("h2 response: {e}"))?;
        let status = response.status();
        response
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("h2 body: {e}"))?;
        Ok::<_, String>(status)
    });
    handlers.await_entry().await;

    gap(rotation + Duration::from_millis(500)).await;
    let second = Request::builder()
        .method("POST")
        .uri(format!("https://{TEST_HOST}/"))
        .body(Empty::<Bytes>::new())
        .unwrap_or_else(|e| panic!("second request: {e}"));
    let second = timeout(GENEROUS, sender.send_request(second))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "second h2 request did not resolve after graceful rotation; handler count={}",
                handlers.count()
            )
        });
    assert_eq!(
        (second.is_err(), handlers.count()),
        (true, 1),
        "a post-rotation h2 request must return an error without reaching the handler"
    );
    handlers.release();
    let status = timeout(GENEROUS, in_flight)
        .await
        .unwrap_or_else(|_| panic!("in-flight h2 response did not finish inside the grace"))
        .unwrap_or_else(|e| panic!("in-flight task: {e}"))
        .unwrap_or_else(|e| panic!("in-flight request: {e}"));
    assert_eq!(
        (status, handlers.count()),
        (StatusCode::OK, 1),
        "rotation must complete the one handler already running after rejecting a new stream"
    );

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// HTTP/1.1 rotation finishes the active response with `Connection: close`
/// and closes the stream without admitting a second request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http11_rotation_finishes_in_flight_and_closes_before_a_second_request() {
    let lifetime = Duration::from_secs(6);
    let grace = Duration::from_secs(4);
    let rotation = Duration::from_secs(2);
    let mut handlers = handlers(0);
    let server = start(
        AcceptConfig {
            connection_max_lifetime: lifetime,
            connection_drain_grace: grace,
            ..AcceptConfig::default()
        },
        handlers.service.clone(),
        None,
    )
    .await;
    let stream = tls_connect(server.addr, client_config(server.pin, &[ALPN_HTTP11]))
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"));
    let mut stream = BufReader::new(stream);
    let request = format!("GET / HTTP/1.1\r\nHost: {TEST_HOST}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("request write: {e}"));
    stream
        .flush()
        .await
        .unwrap_or_else(|e| panic!("request flush: {e}"));
    handlers.await_entry().await;
    gap(rotation + Duration::from_millis(500)).await;
    handlers.release();

    let (head, body) = timeout(GENEROUS, async {
        let mut head = String::new();
        while !head.ends_with("\r\n\r\n") {
            assert_ne!(stream.read_line(&mut head).await?, 0, "truncated h1 head");
        }
        let mut body = [0; b"granary".len()];
        stream.read_exact(&mut body).await?;
        Ok::<_, std::io::Error>((head, body))
    })
    .await
    .unwrap_or_else(|_| panic!("in-flight h1 response did not finish inside the grace"))
    .unwrap_or_else(|e| panic!("h1 response: {e}"));
    assert!(
        head.starts_with("HTTP/1.1 200 OK")
            && head
                .lines()
                .any(|line| line.eq_ignore_ascii_case("connection: close")),
        "the completed response must be a 200 and announce close, got {head:?}"
    );
    assert_eq!(&body, b"granary");

    assert!(
        exchange(&mut stream, request.as_bytes()).await.is_none(),
        "the server must close the stream without answering the second h1 request"
    );
    assert_eq!(
        handlers.count(),
        1,
        "the second h1 request must never reach the handler"
    );

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// A peer that never reads a large response loses both its sole connection
/// permit and the response's ownership charge at the hard lifetime. The fresh
/// request is the positive permit proof; the weak owner distinguishes a real
/// response drop from merely opening another slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hard_lifetime_releases_a_never_read_response_and_its_permit() {
    let lifetime = Duration::from_secs(4);
    let charge = Arc::new(());
    let weak_charge = Arc::downgrade(&charge);
    let mut handlers = handlers_with_charged_body(32 * 1024 * 1024, weak_charge.clone());
    let server = start(
        AcceptConfig {
            max_connections: 1,
            connection_max_lifetime: lifetime,
            connection_drain_grace: Duration::from_secs(2),
            ..AcceptConfig::default()
        },
        handlers.service.clone(),
        None,
    )
    .await;
    let mut stream = tls_connect(server.addr, client_config(server.pin, &[ALPN_HTTP11]))
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"));
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: granary.test\r\n\r\n")
        .await
        .unwrap_or_else(|e| panic!("request write: {e}"));
    stream
        .flush()
        .await
        .unwrap_or_else(|e| panic!("request flush: {e}"));
    handlers.await_entry().await;
    let mut response_head = [0_u8; 256];
    let read = timeout(GENEROUS, stream.read(&mut response_head))
        .await
        .unwrap_or_else(|_| panic!("the charged response did not start"))
        .unwrap_or_else(|e| panic!("response read: {e}"));
    let head = String::from_utf8_lossy(response_head.get(..read).unwrap_or(&[]));
    assert!(
        head.starts_with("HTTP/1.1 200 OK") && Arc::strong_count(&charge) >= 2,
        "premise: the response must own the charge before the test drops its copy; head={head:?}, strong_count={}",
        Arc::strong_count(&charge)
    );
    drop(charge);

    gap(lifetime + Duration::from_millis(500)).await;
    let fresh = timeout(
        GENEROUS,
        attempt(server.addr, client_config(server.pin, &[ALPN_HTTP11])),
    )
    .await
    .unwrap_or_else(|_| panic!("the hard lifetime did not return the sole connection permit"));
    assert_eq!(
        (weak_charge.upgrade().is_none(), fresh, handlers.count()),
        (true, Ok(StatusCode::OK), 2),
        "the old response charge and permit must both be released before a fresh request completes"
    );
    drop(stream);

    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}

/// A connection remains in the global drain count after its rotation receiver
/// has fired. A phase-two implementation that drops that receiver lets
/// `serve` report `Drained` while this handler is still parked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rotated_connection_remains_counted_by_deploy_drain() {
    let lifetime = Duration::from_secs(10);
    let grace = Duration::from_secs(8);
    let rotation = Duration::from_secs(2);
    let mut handlers = handlers(0);
    let server = start(
        AcceptConfig {
            connection_max_lifetime: lifetime,
            connection_drain_grace: grace,
            shutdown_deadline: Duration::from_secs(8),
            ..AcceptConfig::default()
        },
        handlers.service.clone(),
        None,
    )
    .await;
    let stream = tls_connect(server.addr, client_config(server.pin, &[ALPN_H2]))
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"));
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap_or_else(|e| panic!("h2 handshake: {e}"));
    let _pump = pump(connection);
    let request = Request::builder()
        .uri(format!("https://{TEST_HOST}/"))
        .body(Empty::<Bytes>::new())
        .unwrap_or_else(|e| panic!("request: {e}"));
    let response = sender.send_request(request);
    let client = spawn(async move {
        let response = response.await;
        if let Ok(response) = response {
            let _ = response.into_body().collect().await;
        }
    });
    handlers.await_entry().await;
    gap(rotation + Duration::from_millis(500)).await;
    let second = Request::builder()
        .uri(format!("https://{TEST_HOST}/"))
        .body(Empty::<Bytes>::new())
        .unwrap_or_else(|e| panic!("second request: {e}"));
    let second = timeout(GENEROUS, sender.send_request(second))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "second h2 request did not resolve after graceful rotation; handler count={}",
                handlers.count()
            )
        });
    assert_eq!(
        (second.is_err(), handlers.count()),
        (true, 1),
        "the post-rotation request must fail without entering the handler before deploy drain"
    );

    let Server { shutdown, done, .. } = server;
    trigger(&shutdown, true);
    let mut done = done;
    assert!(
        timeout(BRIEF, &mut done).await.is_err(),
        "deploy drain forgot a rotated connection whose handler is still running"
    );
    handlers.release();
    match timeout(GENEROUS, done).await {
        Ok(Ok(Ok(outcome))) => assert_eq!(outcome, ShutdownOutcome::Drained),
        other => panic!("serve did not drain the rotated connection: {other:?}"),
    }
    let _ = client.await;
}

/// 25. THE DERIVATION GATE: hyper's pre-SETTINGS optimistic cap IS
///     `H2_ADVERTISED_STREAM_FLOOR`.
///
/// **This is the row that fails the day the premise moves, and the two-sided
/// control does not exist without it.** `H2_MAX_CONCURRENT_STREAMS`'s floor
/// is not a granary number: it is hyper's `DEFAULT_INITIAL_MAX_SEND_STREAMS`
/// (`hyper-1.11.0/src/proto/h2/client.rs:54-62`), the cap a hyper client
/// opens streams against BEFORE the server's SETTINGS arrives — RFC 9113
/// §3.4 authorises the burst and §6.5.2 recommends exactly 100. The shed
/// controls in `granary-server`'s `stream_floor` prove that going below the
/// floor loses `min(fan, cap) − limit` requests; they stay green, and stay
/// true, the day a hyper bump raises `cap` above 100 and granary's 100
/// silently stops being enough. Only this row notices that.
///
/// **PRE-SETTINGS is a property of the PEER here, not of when this row
/// reads.** "Read it before polling the connection" is not sufficient on
/// hyper 1.11: `proto::h2::client::handshake` hands the h2 connection to the
/// executor itself (`exec.execute_h2_future(...)`, `:192-194`), so by the
/// time `handshake().await` returns, a peer's SETTINGS could already have
/// been applied by that task and `apply_remote_settings` would have replaced
/// the value (`h2-0.4.18/src/proto/streams/counts.rs:232-238`). Polling
/// discipline cannot close that race. What closes it is the peer: the far
/// end of this duplex is HELD and never written to, so no SETTINGS frame
/// exists to be applied and the reading is the optimistic default by
/// construction — deterministically, at any moment, with no timing in the
/// row at all.
///
/// **Held, not dropped.** Dropping the far half is an EOF, which ends the
/// connection task; the accessor would still answer (nothing but
/// `apply_remote_settings` writes that field), but the row would then be
/// reading off a corpse and would go on passing if hyper ever made the
/// accessor report a closed connection's state differently.
///
/// **The MIRROR of row 26, and neither replaces the other.** This row reads
/// `current_max_send_streams()` BEFORE any SETTINGS, so what it reads is the
/// CLIENT's own optimistic default — the premise the floor is derived from.
/// Row 26 reads the same accessor AFTER a real exchange with the shipped
/// `serve()`, so what it reads is the SERVER's declaration as it arrived on
/// the wire. This row cannot see `envelope()` dropping its
/// `.max_concurrent_streams(..)`; that row cannot see hyper moving its
/// default.
///
/// The value is compared against `H2_ADVERTISED_STREAM_FLOOR` and NOT
/// against `H2_MAX_CONCURRENT_STREAMS`: the floor is the claim about the
/// client population, the advertised value is granary's response to it, and
/// a row that compared the advertised value would go green again the moment
/// someone raised BOTH — which is the edit this gate exists to make
/// impossible to do quietly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hypers_pre_settings_optimistic_cap_is_the_advertised_floor() {
    let (near, far) = tokio::io::duplex(DUPLEX_BUF);

    let (_sender, conn) = hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(
        TokioExecutor::new(),
        TokioIo::new(near),
    )
    .await
    .unwrap_or_else(|e| panic!("h2 client handshake: {e}"));

    let optimistic = conn.current_max_send_streams();

    // A CAP OF ZERO IS A VACUOUS READ, not a small one. `Counts::new` seeds
    // this field from `initial_max_send_streams` and nothing else touches it
    // until a peer's SETTINGS arrives, so a zero here means the accessor
    // stopped reporting what this row believes it reports — which would
    // otherwise fail only as an unequal comparison, indistinguishable from a
    // genuine hyper change.
    assert_ne!(
        optimistic, 0,
        "hyper reports a pre-SETTINGS optimistic cap of 0, which is not a \
         value `Counts::new` can produce from `initial_max_send_streams` — \
         the accessor is no longer reporting the field this row reads"
    );
    assert_eq!(
        optimistic, H2_ADVERTISED_STREAM_FLOOR as usize,
        "hyper's pre-SETTINGS optimistic cap is {optimistic}, and \
         `H2_ADVERTISED_STREAM_FLOOR` claims it is \
         {H2_ADVERTISED_STREAM_FLOOR}. The floor is DERIVED from that cap — \
         it is the largest number of streams a hyper client opens before it \
         has seen this server's SETTINGS, and every stream past what \
         `H2_MAX_CONCURRENT_STREAMS` then announces is refused and not \
         retried. If hyper RAISED it, granary's advertised value has \
         silently stopped being enough and the shed controls in \
         granary-server's `stream_floor` will not notice: they measure the \
         rate below the floor, not whether the floor is still where the \
         client population put it. Re-measure the shed rate \
         of HttpStore's cold parallel burst, pinned to ONE h2 \
         connection, over a range of round-trip times before moving either constant"
    );

    // The peer, still unwritten-to and still alive — see the header above for
    // why the row would be weaker if this had been dropped instead.
    drop(far);
}

/// 26. THE WIRE GATE: what the shipped `envelope()` ACTUALLY ADVERTISES is
///     `H2_MAX_CONCURRENT_STREAMS`.
///
/// **The mirror of row 25, and neither one is the other's substitute.** Row
/// 25 reads `current_max_send_streams()` BEFORE any SETTINGS, against a peer
/// that never sends one, so what it reads is the CLIENT's own optimistic
/// default — the premise the floor is derived from. This row reads the SAME
/// accessor AFTER a real exchange with the shipped `serve()`, so what it
/// reads is the SERVER's declaration as it arrived on the wire.
///
/// **Why it exists: every other gate on this constant reads a DECLARATION.**
/// The `const _`, the floor's derivation, row 25, the three shed controls in
/// `granary-server` and `scripts/check-protocol-constants.py` all compare
/// numbers written down in the tree. Not one of them observes
/// `envelope()`. Delete `.max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS)`
/// from that builder and the server advertises hyper's default instead —
/// twice §9.2's figure and twice `REQUESTS_IN_FLIGHT` — with every one of
/// those gates still green, and since the constant became `pub` not even a
/// dead-code warning is left to notice. This row is the only thing in the
/// tree that fails on that edit.
///
/// **A SENTINEL, because the shipped value and hyper's client default are
/// both 100.** Reading the accessor on a default-configured client cannot
/// distinguish "the server advertised 100" from "no SETTINGS ever arrived
/// and this is the client's own number" — the two answers are the same
/// integer, which is a gate that cannot tell clean from blind. So the client
/// is built with `initial_max_send_streams(SENTINEL)`, a value that is
/// neither, and the row proves that call TOOK EFFECT on a second connection
/// whose peer never sends SETTINGS, then asserts the reading AFTER the
/// exchange is the advertised constant. The `assert_ne!` below is what keeps
/// that true if someone edits the sentinel.
///
/// **WHY THE SENTINEL IS PROVED ON A SILENT PEER and not by reading THIS
/// connection before the exchange.** That was the shape once, and it is a
/// race rather than an invariant — the same race row 25 above is built to
/// avoid, arrived at from the other direction. `handshake().await` hands the
/// h2 connection to the executor (`hyper-1.11.0/src/proto/h2/client.rs`,
/// `exec.execute_h2_future`), so this server's SETTINGS can already have
/// been applied by the time it returns, and the pre-exchange reading is then
/// 100 — the server's number — not the sentinel. Whether it is depends on
/// the machine: x86-64 wins that race and aarch64 Linux does not, so the
/// assertion held everywhere it was ever run and failed intermittently the
/// first time an aarch64 runner executed it. Inserting one 100 ms await
/// before the read reproduces it anywhere (`left: 100, right: 7`). What is
/// NOT a race is a peer that never sends SETTINGS at all: the far half of
/// the duplex below is held until the reading is taken, so nothing exists to
/// replace the field and the value read is this builder's own by
/// construction. **Both connections come from ONE builder** — `handshake`
/// takes `&self` — so the sentinel cannot drift between the connection that
/// proves it took effect and the connection that relies on it.
///
/// **The exchange is what proves SETTINGS was applied**, and it is not
/// decoration: a `200` cannot arrive before the server's connection preface,
/// so a server that sent no SETTINGS at all leaves this row reading the
/// sentinel rather than passing.
///
/// **No `pump`.** `SendRequest` does nothing unless the `Connection` is
/// polled, and the accessor lives on the `Connection` — so handing it to a
/// spawned task would put the value out of reach. The two futures are raced
/// in one hand-rolled `poll_fn` with the connection polled first, which is
/// this crate's own idiom for a biased race without `select!`.
///
/// **The residual, stated rather than left to be found.** This row observes
/// ONE server, built from `AcceptConfig::default()`. If the stream limit
/// ever became an `AcceptConfig` FIELD — the "a knob the caller picks is not
/// a gate" mistake this repo has already paid for once — this row would go
/// on reading the default while a caller advertised anything it liked, and
/// it would stay green. Nothing in a test can see a configuration field that
/// does not exist yet; what holds that line is
/// `H2_MAX_CONCURRENT_STREAMS`'s own doc comment saying so, and this
/// paragraph is the second place it is written down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_shipped_envelope_advertises_the_stream_limit_on_the_wire() {
    /// Neither hyper's client default nor the shipped value, so the reading
    /// says which of the two it is.
    const SENTINEL: usize = 7;
    assert_ne!(
        SENTINEL, H2_MAX_CONCURRENT_STREAMS as usize,
        "a sentinel equal to the advertised value makes the two readings \
         below indistinguishable, and this row would pass against a server \
         that never sent SETTINGS at all"
    );

    let handlers = handlers(UNGATED);
    let server = start(AcceptConfig::default(), handlers.service.clone(), None).await;
    let tls = tls_connect(server.addr, client_config(server.pin, &[ALPN_H2]))
        .await
        .unwrap_or_else(|e| panic!("the handshake must COMPLETE, got {e}"));

    // ONE builder for both handshakes below: `handshake` takes `&self`, so
    // the connection that PROVES the sentinel took effect and the connection
    // that RELIES on it cannot be configured differently.
    let mut client = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    client.initial_max_send_streams(SENTINEL);

    // The sentinel proof, against a peer that never sends SETTINGS — see the
    // header for why this is not read off the connection below instead. The
    // far half is HELD until the reading is taken: dropping it is an EOF that
    // ends the connection task, and the reading would then come off a corpse.
    let (near, far) = tokio::io::duplex(DUPLEX_BUF);
    let (silent_sender, silent) = client
        .handshake::<_, Empty<Bytes>>(TokioIo::new(near))
        .await
        .unwrap_or_else(|e| panic!("h2 handshake against the silent peer: {e}"));
    let configured = silent.current_max_send_streams();
    assert_eq!(
        configured, SENTINEL,
        "`initial_max_send_streams(SENTINEL)` did not take effect: a client \
         built with it, against a peer that has sent no SETTINGS at all, \
         reports {configured} rather than {SENTINEL}. The reading after the \
         exchange below is only the SERVER's because the client started \
         somewhere the server's value is not, and hyper's own client default \
         is {H2_MAX_CONCURRENT_STREAMS} — the very number that row would \
         then be comparing against itself"
    );
    drop(silent_sender);
    drop(far);

    let (mut sender, conn) = client
        .handshake::<_, Empty<Bytes>>(TokioIo::new(tls))
        .await
        .unwrap_or_else(|e| panic!("h2 handshake: {e}"));
    let mut conn = std::pin::pin!(conn);

    let request = Request::builder()
        .uri("/")
        .header(hyper::header::HOST, TEST_HOST)
        .body(Empty::<Bytes>::new())
        .unwrap_or_else(|e| panic!("request: {e}"));
    // The in-flight request lives in its OWN block: it borrows `sender`
    // mutably for as long as it exists, and `drop(sender)` below is what
    // actually closes the connection — hyper's spawned h2 task ends when the
    // last `SendRequest` goes, which is what lets the drain finish.
    let response = {
        let mut sending = std::pin::pin!(sender.send_request(request));
        timeout(
            GENEROUS,
            std::future::poll_fn(|cx| {
                // The connection FIRST and unconditionally: it is what
                // drives the dispatcher, and a race that polled the request
                // first would park with nothing to move it.
                if let std::task::Poll::Ready(ended) = conn.as_mut().poll(cx) {
                    panic!("the connection ended before the exchange completed: {ended:?}");
                }
                sending.as_mut().poll(cx)
            }),
        )
        .await
        .unwrap_or_else(|_| panic!("the exchange did not complete within {GENEROUS:?}"))
        .unwrap_or_else(|e| panic!("h2 send: {e}"))
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(handlers.count(), 1);

    let advertised = conn.as_ref().get_ref().current_max_send_streams();
    assert_eq!(
        advertised, H2_MAX_CONCURRENT_STREAMS as usize,
        "the shipped accept envelope advertised {advertised} concurrent \
         streams and `H2_MAX_CONCURRENT_STREAMS` is \
         {H2_MAX_CONCURRENT_STREAMS}. This is the value the SERVER put on \
         the wire, read back off a completed exchange, so a disagreement \
         means `envelope()` and the constant have come apart — the likeliest \
         way being that `.max_concurrent_streams(..)` was dropped from the \
         builder and hyper's own default took over. Every other gate on this \
         constant compares written-down numbers and would still be green"
    );

    drop(sender);
    trigger(&server.shutdown, true);
    assert_eq!(server.outcome().await, ShutdownOutcome::Drained);
}
