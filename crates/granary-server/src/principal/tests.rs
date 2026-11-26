// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The per-write principal: each identity and lookup answer through the
//! helper over a real reader, then revocation and an unavailable set
//! observed on live connections (§13.2 item 17).
//!
//! The served rows run the shipped TLS configuration and accept loop with
//! client authentication on, over a small service that resolves the
//! principal of every `PUT` through [`resolve_write_principal`] and answers
//! every `GET` without consulting anything. The enrollment set is written
//! by the real verbs, in a scratch directory; every walk passes the
//! filesystem acknowledgement, as macOS has no type table.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use granary_client::{AmbientNetwork, ClientCredential, HttpStore};
use granary_core::binstore::BinStore as _;
use granary_core::clock::Clock;
use granary_core::enrollment::{ClientSpkiDigest, PrincipalId, TenantName};
use granary_core::hash::GrainId;
use granary_core::rootstore::RootStoreError;
use granary_core::secure_random::{EntropyUnavailable, SecureRandom};
use granary_core::sheaf::Timestamp;
use granary_net::accept::{AcceptConfig, ShutdownOutcome, serve};
use granary_net::alpn::{ALPN_H2, ALPN_HTTP11};
use granary_net::identity::ConnectionIdentity;
use granary_net::pin::{SpkiPin, spki_digest};
use granary_net::tls::{ClientAuth, server_tls_config};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::http::Extensions;
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode};
use rcgen::PublicKeyData as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::{PrincipalRefusal, WritePrincipal, resolve_write_principal};
use crate::enrollment::{EnrollmentReader, UnavailableReason, VerbOptions, mint, revoke};
use crate::loopback::{HOST, base_url, spawn};
use crate::protected_dir::tests::{chmod, scratch};
use crate::wire::{ErrorToken, Status};

/// The bound on a positive arm; the margin is for scheduling jitter.
const GENEROUS: Duration = Duration::from_secs(15);

/// 2050-01-01T00:00:00Z: inside every fixture's validity.
const IN_VALIDITY: i64 = 2_524_608_000;

const OPTS: VerbOptions = VerbOptions {
    accept_unsupported_filesystem: true,
};

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

/// A door that yields `0x11` bytes, so each minted principal id is known.
struct Door;

impl SecureRandom for Door {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        dest.fill(0x11);
        Ok(())
    }
}

const MINTED: PrincipalId = PrincipalId::from_bytes([0x11; 16]);

fn tenant() -> TenantName {
    TenantName::parse("acme").unwrap()
}

/// A protected enrollment directory under a fresh scratch base.
struct Fx {
    dir: PathBuf,
}

impl Fx {
    fn new(tag: &str) -> Self {
        let dir = scratch(tag).join("enroll");
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o700);
        Self { dir }
    }

    fn set_path(&self) -> PathBuf {
        self.dir.join("ENROLLMENT")
    }

    fn reader(&self) -> EnrollmentReader {
        EnrollmentReader::open(&self.dir, true).unwrap()
    }

    fn mint(&self, digest: ClientSpkiDigest) {
        let (principal, _) = mint(&self.dir, OPTS, &tenant(), digest, &mut Door).unwrap();
        assert_eq!(principal, MINTED);
    }

    fn revoke(&self, digest: ClientSpkiDigest) {
        revoke(&self.dir, OPTS, digest).unwrap();
    }
}

fn verified(digest: ClientSpkiDigest) -> Extensions {
    let mut extensions = Extensions::new();
    extensions.insert(ConnectionIdentity::Verified(digest));
    extensions
}

fn bound() -> WritePrincipal {
    WritePrincipal {
        principal: MINTED,
        tenant: tenant(),
    }
}

// ===================================================== the helper alone

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_identity_and_an_anonymous_one_are_no_principal_and_consult_nothing() {
    let fx = Fx::new("principal-none");
    let digest = ClientSpkiDigest::from_bytes([7; 32]);
    fx.mint(digest);
    let reader = fx.reader();
    let before = reader.snapshot().sequence;

    let mut anonymous = Extensions::new();
    anonymous.insert(ConnectionIdentity::Anonymous);
    for extensions in [Extensions::new(), anonymous] {
        assert_eq!(
            resolve_write_principal(&extensions, &reader).await,
            Err(PrincipalRefusal::NoPrincipal)
        );
    }
    assert_eq!(
        reader.snapshot().sequence,
        before,
        "the enrollment set was not consulted"
    );

    // The control: a verified identity does consult it.
    assert_eq!(
        resolve_write_principal(&verified(digest), &reader).await,
        Ok(bound())
    );
    assert!(reader.snapshot().sequence > before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verified_identity_gets_the_lookups_answer_every_time() {
    let fx = Fx::new("principal-lookup");
    let reader = fx.reader();
    let digest = ClientSpkiDigest::from_bytes([7; 32]);
    assert_eq!(
        resolve_write_principal(&verified(digest), &reader).await,
        Err(PrincipalRefusal::EnrollmentUnavailable(
            UnavailableReason::Missing
        )),
        "no set yet"
    );
    fx.mint(digest);
    assert_eq!(
        resolve_write_principal(&verified(digest), &reader).await,
        Ok(bound())
    );
    assert_eq!(
        resolve_write_principal(&verified(ClientSpkiDigest::from_bytes([8; 32])), &reader).await,
        Err(PrincipalRefusal::NotEnrolled)
    );
    fx.revoke(digest);
    assert_eq!(
        resolve_write_principal(&verified(digest), &reader).await,
        Err(PrincipalRefusal::NotEnrolled),
        "the call after a revoke returned"
    );
}

#[test]
fn each_refusal_answers_its_protocol_status_and_token_without_retry_after() {
    let cases = [
        (
            PrincipalRefusal::NoPrincipal,
            Status::Forbidden,
            ErrorToken::NoPrincipal,
        ),
        (
            PrincipalRefusal::NotEnrolled,
            Status::Forbidden,
            ErrorToken::NotEnrolled,
        ),
        (
            PrincipalRefusal::EnrollmentUnavailable(UnavailableReason::Corrupt),
            Status::ServiceUnavailable,
            ErrorToken::EnrollmentUnavailable,
        ),
    ];
    for (refusal, status, token) in cases {
        let outcome = refusal.outcome();
        assert_eq!(outcome.status(), status, "{refusal:?}");
        assert_eq!(outcome.error(), Some(token), "{refusal:?}");
        assert_eq!(outcome.retry_after(), None, "{refusal:?}");
    }
}

// ========================================================= the served rows

/// A client CA and one credential it issued.
struct Credential {
    ca: CertificateDer<'static>,
    cert: CertificateDer<'static>,
    cert_pem: String,
    key: rcgen::KeyPair,
}

impl Credential {
    fn mint() -> Self {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        ca_params.not_after = rcgen::date_time_ymd(2099, 1, 1);
        let ca = ca_params.self_signed(&ca_key).unwrap().der().clone();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2099, 1, 1);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let signed = params.signed_by(&key, &issuer).unwrap();
        Self {
            ca,
            cert: signed.der().clone(),
            cert_pem: signed.pem(),
            key,
        }
    }

    fn digest(&self) -> ClientSpkiDigest {
        ClientSpkiDigest::from_spki_der(&self.key.subject_public_key_info())
    }
}

/// The served rows' service: a `PUT` is a write and resolves its
/// principal; a `GET` is a read and consults nothing. A write carrying a
/// `hold` field announces its admission and waits for a permit before
/// answering.
#[derive(Clone)]
struct Writes {
    reader: EnrollmentReader,
    admitted: mpsc::UnboundedSender<()>,
    gate: Arc<Semaphore>,
}

impl Service<Request<Incoming>> for Writes {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            if request.method() != Method::PUT {
                return Ok(Response::new(Full::new(Bytes::from_static(b"read"))));
            }
            match resolve_write_principal(request.extensions(), &this.reader).await {
                Ok(_principal) => {
                    if request.headers().contains_key("hold") {
                        let _ = this.admitted.send(());
                        if let Ok(permit) = this.gate.acquire().await {
                            permit.forget();
                        }
                    }
                    let mut response = Response::new(Full::new(Bytes::new()));
                    *response.status_mut() = StatusCode::CREATED;
                    Ok(response)
                }
                Err(refusal) => {
                    let outcome = refusal.outcome();
                    let mut response = Response::new(Full::new(Bytes::new()));
                    *response.status_mut() =
                        StatusCode::from_u16(outcome.status().as_u16()).unwrap();
                    if let Some(token) = outcome.error() {
                        response.headers_mut().insert(
                            "granary-error",
                            hyper::header::HeaderValue::from_static(token.as_str()),
                        );
                    }
                    if let Some(seconds) = outcome.retry_after() {
                        response
                            .headers_mut()
                            .insert(hyper::header::RETRY_AFTER, seconds.into());
                    }
                    Ok(response)
                }
            }
        })
    }
}

struct Served {
    addr: SocketAddr,
    server_ca: CertificateDer<'static>,
    pin: SpkiPin,
    admitted: mpsc::UnboundedReceiver<()>,
    gate: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
    serving: JoinHandle<std::io::Result<ShutdownOutcome>>,
}

impl Served {
    async fn start(fx: &Fx, client_ca: &CertificateDer<'static>) -> Self {
        let certs = crate::loopback::mint();
        let pin = spki_digest(&certs.leaf).unwrap();
        let tls = server_tls_config(
            vec![certs.leaf.clone()],
            certs.key,
            ClientAuth::Enrolled {
                ca: vec![client_ca.clone()],
                clock: Arc::new(FixedClock),
            },
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (admitted_tx, admitted) = mpsc::unbounded_channel();
        let gate = Arc::new(Semaphore::new(0));
        let service = Writes {
            reader: fx.reader(),
            admitted: admitted_tx,
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
            server_ca: certs.ca,
            pin,
            admitted,
            gate,
            shutdown,
            serving,
        }
    }

    fn client(&self, credential: &Credential, alpn: &[u8]) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(self.server_ca.clone()).unwrap();
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(granary_net::crypto_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    vec![credential.cert.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(credential.key.serialize_der())),
                )
                .unwrap();
        config.alpn_protocols = vec![alpn.to_vec()];
        config
    }

    async fn connect(&self, config: ClientConfig) -> tokio_rustls::client::TlsStream<TcpStream> {
        let tcp = TcpStream::connect(self.addr).await.unwrap();
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(HOST).unwrap(), tcp)
            .await
            .unwrap()
    }

    async fn await_admission(&mut self) {
        match timeout(GENEROUS, self.admitted.recv()).await {
            Ok(Some(())) => {}
            Ok(None) => panic!("the service was dropped"),
            Err(e) => panic!("no write admitted within {GENEROUS:?} ({e})"),
        }
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let outcome = timeout(GENEROUS, self.serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(outcome, ShutdownOutcome::Drained);
    }
}

/// One answer: the status, `Granary-Error`, and whether `Retry-After` was
/// present.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    status: u16,
    token: Option<String>,
    retry_after: bool,
}

fn answer(status: u16, token: Option<&str>) -> Answer {
    Answer {
        status,
        token: token.map(str::to_owned),
        retry_after: false,
    }
}

/// One HTTP/1.1 connection, written and read by hand: every request on it
/// is on the same TLS session.
struct H1 {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    buffered: Vec<u8>,
}

impl H1 {
    async fn request(&mut self, method: &str) -> Answer {
        let head = format!("{method} /w HTTP/1.1\r\nhost: {HOST}\r\ncontent-length: 0\r\n\r\n");
        self.request_head(&head).await.0
    }

    async fn request_head(&mut self, head: &str) -> (Answer, Option<String>) {
        self.stream.write_all(head.as_bytes()).await.unwrap();
        self.stream.flush().await.unwrap();
        let end = loop {
            if let Some(at) = self.buffered.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let mut chunk = vec![0_u8; 4096];
            let read = timeout(GENEROUS, self.stream.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            assert!(read > 0, "the connection closed before a response head");
            self.buffered.extend_from_slice(&chunk[..read]);
        };
        let rest = self.buffered.split_off(end);
        let head = String::from_utf8(std::mem::replace(&mut self.buffered, rest)).unwrap();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split(' ').nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap();
        let fields: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        let field = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        let length: usize = field("content-length").map_or(0, |v| v.parse().unwrap());
        while self.buffered.len() < length {
            let mut chunk = vec![0_u8; 4096];
            let read = timeout(GENEROUS, self.stream.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            assert!(read > 0, "the connection closed inside a response body");
            self.buffered.extend_from_slice(&chunk[..read]);
        }
        self.buffered.drain(..length);
        (
            Answer {
                status,
                token: field("granary-error"),
                retry_after: field("retry-after").is_some(),
            },
            field("connection"),
        )
    }
}

/// One HTTP/2 connection.
struct H2 {
    send: h2::client::SendRequest<Bytes>,
    conn: JoinHandle<()>,
}

impl Drop for H2 {
    fn drop(&mut self) {
        self.conn.abort();
    }
}

impl H2 {
    async fn open(stream: tokio_rustls::client::TlsStream<TcpStream>) -> Self {
        let (send, connection) = h2::client::handshake(stream).await.unwrap();
        let conn = spawn(async move {
            let _ = connection.await;
        });
        Self { send, conn }
    }

    /// Start a request on its own stream; its answer arrives on the handle.
    async fn start(&mut self, method: Method, hold: bool) -> JoinHandle<Answer> {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("https://{HOST}/w"))
            .body(())
            .unwrap();
        if hold {
            request
                .headers_mut()
                .insert("hold", hyper::header::HeaderValue::from_static("1"));
        }
        self.send = timeout(GENEROUS, self.send.clone().ready())
            .await
            .unwrap()
            .unwrap();
        let (response, _body) = self.send.send_request(request, true).unwrap();
        spawn(async move {
            let response = response.await.unwrap();
            let (parts, mut body) = response.into_parts();
            while let Some(piece) = body.data().await {
                let piece = piece.unwrap();
                let _ = body.flow_control().release_capacity(piece.len());
            }
            let field = |name: &str| {
                parts
                    .headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            };
            Answer {
                status: parts.status.as_u16(),
                token: field("granary-error"),
                retry_after: field("retry-after").is_some(),
            }
        })
    }

    async fn request(&mut self, method: Method) -> Answer {
        finish(self.start(method, false).await).await
    }
}

async fn finish(handle: JoinHandle<Answer>) -> Answer {
    timeout(GENEROUS, handle).await.unwrap().unwrap()
}

/// §13.2 item 17 on HTTP/1.1: a revocation between two writes on one
/// connection refuses the second, and a read after it is still served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoke_between_two_writes_on_one_http1_connection_refuses_the_second() {
    let fx = Fx::new("principal-h1");
    let credential = Credential::mint();
    fx.mint(credential.digest());
    let served = Served::start(&fx, &credential.ca).await;
    let mut h1 = H1 {
        stream: served
            .connect(served.client(&credential, ALPN_HTTP11))
            .await,
        buffered: Vec::new(),
    };

    assert_eq!(h1.request("PUT").await, answer(201, None), "enrolled");
    fx.revoke(credential.digest());
    assert_eq!(
        h1.request("PUT").await,
        answer(403, Some("not-enrolled")),
        "the next write after the revoke returned"
    );
    assert_eq!(
        h1.request("GET").await,
        answer(200, None),
        "a read is served"
    );
    drop(h1);
    served.stop().await;
}

/// §13.2 item 17 across HTTP/2 streams: a write admitted before the revoke
/// runs to its end, a write whose admission begins after it is refused,
/// and a read on the same connection is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_admitted_after_a_revoke_is_refused_while_an_earlier_one_finishes() {
    let fx = Fx::new("principal-h2");
    let credential = Credential::mint();
    fx.mint(credential.digest());
    let mut served = Served::start(&fx, &credential.ca).await;
    let mut h2 = H2::open(served.connect(served.client(&credential, ALPN_H2)).await).await;

    let a = h2.start(Method::PUT, true).await;
    served.await_admission().await;
    fx.revoke(credential.digest());
    assert_eq!(
        h2.request(Method::PUT).await,
        answer(403, Some("not-enrolled")),
        "stream B, admitted after the revoke returned"
    );
    assert_eq!(h2.request(Method::GET).await, answer(200, None), "a read");
    served.gate.add_permits(1);
    assert_eq!(finish(a).await, answer(201, None), "stream A finishes");
    drop(h2);
    served.stop().await;
}

/// §13.2 item 18's unavailable arm on a live connection: while the set is
/// unprotected, and while it is missing, a write is `503` +
/// `enrollment-unavailable` with no `Retry-After` and a read is served;
/// when the set is restored, the next write is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unavailable_set_refuses_writes_with_503_serves_reads_and_recovers() {
    let fx = Fx::new("principal-unavailable");
    let credential = Credential::mint();
    fx.mint(credential.digest());
    let served = Served::start(&fx, &credential.ca).await;
    let unavailable = Answer {
        status: 503,
        token: Some("enrollment-unavailable".to_owned()),
        retry_after: false,
    };

    let mut h1 = H1 {
        stream: served
            .connect(served.client(&credential, ALPN_HTTP11))
            .await,
        buffered: Vec::new(),
    };
    assert_eq!(h1.request("PUT").await, answer(201, None), "the control");
    chmod(&fx.set_path(), 0o602);
    assert_eq!(h1.request("PUT").await, unavailable, "unprotected");
    assert_eq!(h1.request("GET").await, answer(200, None));
    chmod(&fx.set_path(), 0o600);
    assert_eq!(h1.request("PUT").await, answer(201, None), "recovered");

    let mut h2 = H2::open(served.connect(served.client(&credential, ALPN_H2)).await).await;
    assert_eq!(h2.request(Method::PUT).await, answer(201, None));
    let aside = fx.dir.with_file_name("ENROLLMENT.aside");
    rename(&fx.set_path(), &aside);
    assert_eq!(h2.request(Method::PUT).await, unavailable, "missing");
    assert_eq!(h2.request(Method::GET).await, answer(200, None));
    rename(&aside, &fx.set_path());
    assert_eq!(
        h2.request(Method::PUT).await,
        answer(201, None),
        "recovered"
    );

    drop((h1, h2));
    served.stop().await;
}

fn rename(from: &Path, to: &Path) {
    std::fs::rename(from, to).unwrap();
}

/// §3.2 rule 4 as the client reports it: an `HttpStore` with no credential,
/// writing to a server whose writes resolve their principal, reports the
/// server's answer, `403` and `no-principal`, and not a transport failure.
/// The control is the same write from a store configured with an enrolled
/// credential, loaded from its files: it is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_http_store_without_a_credential_reports_403_no_principal() {
    let fx = Fx::new("principal-client");
    let credential = Credential::mint();
    fx.mint(credential.digest());
    let served = Served::start(&fx, &credential.ca).await;
    let base = base_url(served.addr);
    let bytes = b"a bin".to_vec();
    let digest = *GrainId::of(&bytes).digest();

    let anonymous = HttpStore::new(&base, vec![served.pin], &AmbientNetwork).unwrap();
    assert_eq!(
        anonymous.put_bin(&digest, bytes.clone()).await,
        Err(RootStoreError::UnexpectedStatus {
            operation: "PUT bin",
            status: 403,
            token: Some("no-principal".to_owned()),
        })
    );

    let files = scratch("principal-client-files");
    let (certificate, key) = (files.join("client.crt"), files.join("client.key"));
    std::fs::write(&certificate, &credential.cert_pem).unwrap();
    std::fs::write(&key, credential.key.serialize_pem()).unwrap();
    chmod(&key, 0o600);
    let loaded =
        ClientCredential::load(&certificate, &key, nix::unistd::geteuid().as_raw()).unwrap();
    let enrolled =
        HttpStore::with_client_credential(&base, vec![served.pin], &AmbientNetwork, Some(loaded))
            .unwrap();
    assert_eq!(enrolled.put_bin(&digest, bytes).await, Ok(true));

    drop((anonymous, enrolled));
    served.stop().await;
}

impl Served {
    async fn controls(
        fx: &Fx,
        credential: &Credential,
        controls: Arc<crate::controls::PrincipalControls>,
    ) -> (Self, Arc<crate::adapter::WriteBudget>) {
        let certs = crate::loopback::mint();
        let tls = server_tls_config(
            vec![certs.leaf.clone()],
            certs.key,
            ClientAuth::Enrolled {
                ca: vec![credential.ca.clone()],
                clock: Arc::new(FixedClock),
            },
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let service =
            crate::adapter::GrainService::new(Arc::new(crate::fake::FakeSeam::default()), "", 2)
                .with_test_write_controls(fx.reader(), controls);
        let bytes = Arc::clone(service.write_budget());
        let (shutdown, rx) = watch::channel(false);
        let serving = spawn(serve(
            listener,
            Arc::new(tls),
            service,
            rx,
            AcceptConfig::default(),
        ));
        (
            Self {
                addr,
                pin: spki_digest(&certs.leaf).unwrap(),
                server_ca: certs.ca,
                admitted: mpsc::unbounded_channel().1,
                gate: Arc::new(Semaphore::new(0)),
                shutdown,
                serving,
            },
            bytes,
        )
    }
}

/// Exercise the adapter's drain decision, beyond the principal-only service above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_refused_empty_write_keeps_http1_connection_for_reads() {
    use crate::controls::{ControlsConfig, PrincipalControls};
    let fx = Fx::new("principal-adapter-empty");
    let credential = Credential::mint();
    fx.mint(credential.digest());
    let controls = Arc::new(PrincipalControls::new(
        ControlsConfig::default(),
        Arc::new(FixedClock),
    ));
    let (served, _) = Served::controls(&fx, &credential, controls).await;
    let mut h1 = H1 {
        stream: served
            .connect(served.client(&credential, ALPN_HTTP11))
            .await,
        buffered: Vec::new(),
    };
    fx.revoke(credential.digest());

    let (refused, connection) = h1
        .request_head("PUT /volume/v/root/00000000000000000001 HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\n\r\n")
        .await;
    assert_eq!(refused, answer(403, Some("not-enrolled")));
    assert_eq!(
        h1.request_head("GET /volume/v/max-seq HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await,
        (answer(404, Some("not-found")), None),
        "the read on the same connection reaches the empty store"
    );
    assert_eq!(connection, None, "no content remains unread");
    drop(h1);
    served.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_refused_unread_write_closes_http1_connection() {
    use crate::controls::{ControlsConfig, PrincipalControls};
    let fx = Fx::new("principal-adapter-unread");
    let credential = Credential::mint();
    fx.mint(credential.digest());
    fx.revoke(credential.digest());
    let controls = Arc::new(PrincipalControls::new(
        ControlsConfig::default(),
        Arc::new(FixedClock),
    ));
    let (served, _) = Served::controls(&fx, &credential, controls).await;

    // Neither a positive declared length nor an unknown length is empty.
    for framing in ["content-length: 10", "transfer-encoding: chunked"] {
        let mut h1 = H1 {
            stream: served
                .connect(served.client(&credential, ALPN_HTTP11))
                .await,
            buffered: Vec::new(),
        };
        let head = format!(
            "PUT /volume/v/root/00000000000000000001 HTTP/1.1\r\nhost: localhost\r\n{framing}\r\n\r\n"
        );
        // Withhold all content: admission must refuse without waiting for it.
        assert_eq!(
            h1.request_head(&head).await,
            (answer(403, Some("not-enrolled")), Some("close".to_owned())),
            "{framing}"
        );
        let mut byte = [0];
        assert_eq!(
            timeout(GENEROUS, h1.stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0,
            "the refused connection closes: {framing}"
        );
    }
    served.stop().await;
}

async fn occupancy(controls: &crate::controls::PrincipalControls, expected: usize) {
    timeout(GENEROUS, async {
        while controls.in_flight(MINTED) != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("request occupancy must reach the expected value");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_permit_drops_on_every_exit_http1_disconnect_and_http2_reset() {
    use crate::controls::{ControlsConfig, PrincipalControls};
    let fx = Fx::new("controls-transport");
    let credential = Credential::mint();
    fx.mint(credential.digest());
    let controls = Arc::new(PrincipalControls::new(
        ControlsConfig::default(),
        Arc::new(FixedClock),
    ));
    let held: Vec<_> = (0..3)
        .map(|_| controls.admit(MINTED, false).unwrap())
        .collect();
    let (served, bytes) = Served::controls(&fx, &credential, controls.clone()).await;
    let mut h1 = served
        .connect(served.client(&credential, ALPN_HTTP11))
        .await;
    h1.write_all(b"PUT /volume/v/root/00000000000000000001 HTTP/1.1\r\nhost: localhost\r\ncontent-length: 10\r\n\r\nx").await.unwrap();
    h1.flush().await.unwrap();
    occupancy(&controls, 4).await;
    received_bytes(&bytes, 1).await;
    assert!(controls.admit(MINTED, false).is_err());
    drop(h1);
    occupancy(&controls, 3).await;
    let mut h2 = H2::open(served.connect(served.client(&credential, ALPN_H2)).await).await;
    for disconnect in [false, true] {
        let (response, mut body) = h2
            .send
            .send_request(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/volume/v/root/00000000000000000001")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        body.send_data(Bytes::from_static(b"x"), false).unwrap();
        occupancy(&controls, 4).await;
        received_bytes(&bytes, if disconnect { 3 } else { 2 }).await;
        if disconnect {
            h2.conn.abort();
        } else {
            body.send_reset(h2::Reason::CANCEL);
        }
        drop((body, response));
        occupancy(&controls, 3).await;
    }
    drop((h2, held));
    occupancy(&controls, 0).await;
    let permit = controls.admit(MINTED, false).unwrap();
    assert!(
        permit
            .charge_bytes(granary_core::binfmt::BIN_MAX_BYTES)
            .is_err(),
        "transport cancellation never refunds arrived bytes"
    );
    drop(permit);
    served.stop().await;
}

async fn received_bytes(budget: &crate::adapter::WriteBudget, expected: u64) {
    timeout(GENEROUS, async {
        while budget.request_bytes() != Some(expected) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the bytes must arrive before cancellation is injected");
}
