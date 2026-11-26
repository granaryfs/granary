// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The connection's identity, as the shipped accept loop hands it to every
//! request: on both protocol legs, anonymous without a certificate, the
//! verified leaf's enrollment digest with one, and distinct per connection
//! however the streams of two connections interleave.
//!
//! Real sockets, real TLS, the shipped `serve` and `server_tls_config`. The
//! service answers each request with the identity it found in the request's
//! extensions, and with `missing` when there was none.
//!
//! **`unwrap()` is a hard error in the helpers below.** `clippy.toml`'s
//! `allow-unwrap-in-tests` covers `#[test]` items, not the plain functions
//! of an integration-test target. The workspace idiom is
//! `.unwrap_or_else(|e| panic!("{e}"))`.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use granary_core::clock::Clock;
use granary_core::enrollment::ClientSpkiDigest;
use granary_core::sheaf::Timestamp;
use granary_net::accept::{AcceptConfig, ShutdownOutcome, serve};
use granary_net::alpn::{ALPN_H2, ALPN_HTTP11};
use granary_net::identity::ConnectionIdentity;
use granary_net::pin::{PinnedServerVerifier, spki_digest};
use granary_net::tls::{ClientAuth, server_tls_config};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::Service;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::PublicKeyData as _;
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const HOST: &str = "granary.test";

/// The bound on a positive arm; the margin is for scheduling jitter.
const GENEROUS: Duration = Duration::from_secs(15);

/// 2050-01-01T00:00:00Z: inside every fixture's validity.
const IN_VALIDITY: i64 = 2_524_608_000;

/// The one spawn site in this file. The transport crate's own tests sit
/// outside the sim boundary, which replaces this layer rather than driving
/// it.
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

/// A spawned task stopped when its handle goes out of scope.
struct Task(JoinHandle<()>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn task<F>(future: F) -> Task
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    Task(spawn(async move {
        let _ = future.await;
    }))
}

#[derive(Debug)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: IN_VALIDITY,
            nanos: 0,
        }
    }
}

// --------------------------------------------- the certificate factory

struct Party {
    cert: CertificateDer<'static>,
    key: rcgen::KeyPair,
}

impl Party {
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.serialize_der()))
    }

    /// The identity the server must report for this credential, from the
    /// SPKI rcgen encoded.
    fn expected(&self) -> String {
        render(ConnectionIdentity::Verified(
            ClientSpkiDigest::from_spki_der(&self.key.subject_public_key_info()),
        ))
    }
}

struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    cert: CertificateDer<'static>,
}

fn keypair() -> rcgen::KeyPair {
    rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("keypair: {e}"))
}

fn mint_ca() -> Ca {
    let key = keypair();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| panic!("ca params: {e}"));
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let cert = params
        .self_signed(&key)
        .unwrap_or_else(|e| panic!("ca self-sign: {e}"))
        .der()
        .clone();
    Ca { params, key, cert }
}

fn client_leaf(ca: &Ca) -> Party {
    let key = keypair();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| panic!("leaf params: {e}"));
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key);
    let cert = params
        .signed_by(&key, &issuer)
        .unwrap_or_else(|e| panic!("sign leaf: {e}"))
        .der()
        .clone();
    Party { cert, key }
}

fn server_party() -> Party {
    let key = keypair();
    let mut params = rcgen::CertificateParams::new(vec![HOST.to_owned()])
        .unwrap_or_else(|e| panic!("server params: {e}"));
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let cert = params
        .self_signed(&key)
        .unwrap_or_else(|e| panic!("server self-sign: {e}"))
        .der()
        .clone();
    Party { cert, key }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(granary_net::crypto_provider())
}

/// A TLS-1.3 client pinned to `server`, offering `alpn`, presenting
/// `credential` if given.
fn client(server: &Party, alpn: &[u8], credential: Option<&Party>) -> ClientConfig {
    let pin = spki_digest(&server.cert).unwrap_or_else(|e| panic!("pin: {e}"));
    let verifier = PinnedServerVerifier::new(vec![pin], provider())
        .unwrap_or_else(|e| panic!("pin verifier: {e}"));
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic!("client versions: {e}"))
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier));
    let mut config = match credential {
        Some(party) => builder
            .with_client_auth_cert(vec![party.cert.clone()], party.key())
            .unwrap_or_else(|e| panic!("client credential: {e}")),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

// ------------------------------------------------------------ the service

fn render(identity: ConnectionIdentity) -> String {
    match identity {
        ConnectionIdentity::Anonymous => "anonymous".to_owned(),
        ConnectionIdentity::Verified(digest) => {
            digest.as_bytes().iter().fold(String::new(), |mut out, b| {
                use std::fmt::Write as _;
                let _ = write!(out, "{b:02x}");
                out
            })
        }
    }
}

/// Answers each request with the identity in its extensions, after
/// announcing it and waiting for one permit of `gate`.
#[derive(Clone)]
struct Echo {
    entered: mpsc::UnboundedSender<()>,
    gate: Arc<Semaphore>,
}

impl Service<Request<Incoming>> for Echo {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let seen = request
            .extensions()
            .get::<ConnectionIdentity>()
            .map_or_else(|| "missing".to_owned(), |identity| render(*identity));
        let entered = self.entered.clone();
        let gate = Arc::clone(&self.gate);
        Box::pin(async move {
            let _ = entered.send(());
            if let Ok(permit) = gate.acquire().await {
                permit.forget();
            }
            Ok(Response::new(Full::new(Bytes::from(seen))))
        })
    }
}

struct Server {
    addr: SocketAddr,
    entered: mpsc::UnboundedReceiver<()>,
    gate: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
    served: JoinHandle<std::io::Result<ShutdownOutcome>>,
}

impl Server {
    async fn start(server: &Party, client_auth: ClientAuth, permits: usize) -> Self {
        let tls = server_tls_config(vec![server.cert.clone()], server.key(), client_auth)
            .unwrap_or_else(|e| panic!("server config: {e}"));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("addr: {e}"));
        let (entered_tx, entered) = mpsc::unbounded_channel();
        let gate = Arc::new(Semaphore::new(permits));
        let service = Echo {
            entered: entered_tx,
            gate: Arc::clone(&gate),
        };
        let (shutdown, shutdown_rx) = watch::channel(false);
        let serving = spawn(serve(
            listener,
            Arc::new(tls),
            service,
            shutdown_rx,
            AcceptConfig::default(),
        ));
        Self {
            addr,
            entered,
            gate,
            shutdown,
            served: serving,
        }
    }

    async fn await_entries(&mut self, n: usize) {
        for _ in 0..n {
            match timeout(GENEROUS, self.entered.recv()).await {
                Ok(Some(())) => {}
                Ok(None) => panic!("the service was dropped"),
                Err(e) => panic!("no handler entry within {GENEROUS:?} ({e})"),
            }
        }
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let outcome = timeout(GENEROUS, self.served)
            .await
            .unwrap_or_else(|e| panic!("serve did not stop: {e}"))
            .unwrap_or_else(|e| panic!("serve task: {e}"))
            .unwrap_or_else(|e| panic!("serve: {e}"));
        assert_eq!(outcome, ShutdownOutcome::Drained);
    }
}

async fn tls_connect(
    addr: SocketAddr,
    config: ClientConfig,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("tcp: {e}"));
    let name = ServerName::try_from(HOST).unwrap_or_else(|e| panic!("name: {e}"));
    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"))
}

async fn body_text(response: Response<Incoming>) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body: {e}"))
        .to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// One HTTP/1.1 connection and its sender.
struct H1 {
    sender: hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    _conn: Task,
}

impl H1 {
    async fn open(addr: SocketAddr, config: ClientConfig) -> Self {
        let stream = tls_connect(addr, config).await;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap_or_else(|e| panic!("h1 handshake: {e}"));
        Self {
            sender,
            _conn: task(conn),
        }
    }

    async fn identity(&mut self) -> String {
        self.sender
            .ready()
            .await
            .unwrap_or_else(|e| panic!("h1 ready: {e}"));
        let request = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, HOST)
            .body(Empty::<Bytes>::new())
            .unwrap_or_else(|e| panic!("request: {e}"));
        let response = self
            .sender
            .send_request(request)
            .await
            .unwrap_or_else(|e| panic!("h1 send: {e}"));
        body_text(response).await
    }
}

/// One HTTP/2 connection and its sender.
struct H2 {
    sender: hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    _conn: Task,
}

impl H2 {
    async fn open(addr: SocketAddr, config: ClientConfig) -> Self {
        let stream = tls_connect(addr, config).await;
        let (sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap_or_else(|e| panic!("h2 handshake: {e}"));
        Self {
            sender,
            _conn: task(conn),
        }
    }

    /// Start one request; its answer arrives on the handle.
    fn start(&self) -> JoinHandle<String> {
        let mut sender = self.sender.clone();
        spawn(async move {
            sender
                .ready()
                .await
                .unwrap_or_else(|e| panic!("h2 ready: {e}"));
            let request = Request::builder()
                .uri(format!("https://{HOST}/"))
                .body(Empty::<Bytes>::new())
                .unwrap_or_else(|e| panic!("request: {e}"));
            let response = sender
                .send_request(request)
                .await
                .unwrap_or_else(|e| panic!("h2 send: {e}"));
            body_text(response).await
        })
    }
}

async fn answer(handle: JoinHandle<String>) -> String {
    timeout(GENEROUS, handle)
        .await
        .unwrap_or_else(|e| panic!("no answer within {GENEROUS:?}: {e}"))
        .unwrap_or_else(|e| panic!("request task: {e}"))
}

fn enrolled(ca: &Ca) -> ClientAuth {
    ClientAuth::Enrolled {
        ca: vec![ca.cert.clone()],
        clock: Arc::new(FixedClock),
    }
}

// ================================================================ the rows

/// Both legs carry the identity on every request: the verified digest for
/// a presented certificate, anonymous without one, and anonymous on every
/// connection of a server without client authentication.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_request_on_both_legs_carries_its_connections_identity() {
    let ca = mint_ca();
    let server = server_party();
    let credential = client_leaf(&ca);

    let mut running = Server::start(&server, enrolled(&ca), usize::MAX >> 4).await;
    let mut h1 = H1::open(
        running.addr,
        client(&server, ALPN_HTTP11, Some(&credential)),
    )
    .await;
    assert_eq!(h1.identity().await, credential.expected());
    assert_eq!(
        h1.identity().await,
        credential.expected(),
        "a reused connection"
    );
    let h2 = H2::open(running.addr, client(&server, ALPN_H2, Some(&credential))).await;
    assert_eq!(answer(h2.start()).await, credential.expected());
    assert_eq!(answer(h2.start()).await, credential.expected());
    let mut anonymous = H1::open(running.addr, client(&server, ALPN_HTTP11, None)).await;
    assert_eq!(anonymous.identity().await, "anonymous");
    let anonymous_h2 = H2::open(running.addr, client(&server, ALPN_H2, None)).await;
    assert_eq!(answer(anonymous_h2.start()).await, "anonymous");
    running.await_entries(6).await;
    drop((h1, h2, anonymous, anonymous_h2));
    running.stop().await;

    let running = Server::start(&server, ClientAuth::None, usize::MAX >> 4).await;
    let mut h1 = H1::open(
        running.addr,
        client(&server, ALPN_HTTP11, Some(&credential)),
    )
    .await;
    assert_eq!(h1.identity().await, "anonymous", "no client authentication");
    let h2 = H2::open(running.addr, client(&server, ALPN_H2, Some(&credential))).await;
    assert_eq!(answer(h2.start()).await, "anonymous");
    drop((h1, h2));
    running.stop().await;
}

/// Two concurrent HTTP/2 connections with different credentials, their
/// streams interleaved and all in flight at once: each stream reports its
/// own connection's identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_connections_keep_distinct_identities_across_interleaved_streams() {
    const STREAMS: usize = 3;
    let ca = mint_ca();
    let server = server_party();
    let alice = client_leaf(&ca);
    let bob = client_leaf(&ca);
    assert_ne!(alice.expected(), bob.expected());

    let mut running = Server::start(&server, enrolled(&ca), 0).await;
    let a = H2::open(running.addr, client(&server, ALPN_H2, Some(&alice))).await;
    let b = H2::open(running.addr, client(&server, ALPN_H2, Some(&bob))).await;

    let mut pending = Vec::new();
    for _ in 0..STREAMS {
        pending.push((alice.expected(), a.start()));
        pending.push((bob.expected(), b.start()));
    }
    // Every stream is inside the service before any is answered.
    running.await_entries(2 * STREAMS).await;
    running.gate.add_permits(2 * STREAMS);
    for (expected, handle) in pending {
        assert_eq!(answer(handle).await, expected);
    }
    drop((a, b));
    running.stop().await;
}
