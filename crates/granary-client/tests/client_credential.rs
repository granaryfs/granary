// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The client's TLS credential: loading it from its two files under the
//! key file's custody, presenting it on every `HttpStore` connection, and
//! a write refusal surfacing as the server's answer.
//!
//! **Loading.** Each refusal row first loads the unmodified pair (its
//! control), then changes one thing. The files live in a per-test scratch
//! directory: on Linux a fresh one under the canonical temp dir, elsewhere
//! one resolved at runtime from the test executable's build directory.
//!
//! **Presentation** runs the shipped accept loop and `server_tls_config`
//! over real sockets, with a service that records the
//! [`ConnectionIdentity`] each request arrived with and answers every `PUT`
//! `201`. The client is an actual `HttpStore`.
//!
//! **`unwrap()` is a hard error in the helpers below.** `clippy.toml`'s
//! `allow-unwrap-in-tests` covers `#[test]` items, not the plain functions
//! of an integration-test target. The workspace idiom is
//! `.unwrap_or_else(|e| panic!("{e}"))`.

#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; \
              disallowed_methods has no allow-in-tests knob"
)]

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use granary_client::{
    ClientCredential, CredentialError, CredentialFile, HttpStore, WritableAuthority as _,
};
use granary_core::binstore::BinStore as _;
use granary_core::clock::Clock;
use granary_core::hash::GrainId;
use granary_core::rootstore::{RootStore as _, RootStoreError, filter_above};
use granary_core::sheaf::Timestamp;
use granary_net::accept::{AcceptConfig, serve};
use granary_net::credential::{CredentialError as ContentError, PemRefusal};
use granary_net::identity::{ConnectionIdentity, client_spki_digest};
use granary_net::pin::{SpkiPin, spki_digest};
use granary_net::tls::{ClientAuth, server_tls_config};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::HeaderValue;
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

mod support;
use support::base_url;

#[derive(Clone)]
struct TraceWriter(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("trace lock poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn trace_capture<T>(action: impl FnOnce() -> T) -> (T, String) {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let writer = TraceWriter(Arc::clone(&bytes));
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let result = tracing::subscriber::with_default(subscriber, action);
    let text = String::from_utf8(bytes.lock().unwrap_or_else(|e| panic!("{e}")).clone())
        .unwrap_or_else(|e| panic!("{e}"));
    (result, text)
}

/// 2050-01-01T00:00:00Z: inside every fixture's validity.
const IN_VALIDITY: i64 = 2_524_608_000;

// ------------------------------------------------------------ scratch

/// A fresh directory for one test, named for it, removed on drop. Linux
/// creates it exclusively under the canonical temp dir: a build root on
/// virtiofs (the podman lanes) cannot hold a FIFO and does not keep a
/// replaced file's identity. macOS keeps the build root, because a store
/// under its `/tmp` is refused by the publication store's walk.
struct Scratch(PathBuf);

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::disallowed_methods,
        reason = "the process id only distinguishes concurrent runs' scratch directories"
    )
)]
fn scratch(name: &str) -> Scratch {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical temp dir: {error}"));
        let process = std::process::id();
        loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("granary-client-credential-{name}-{process}-{n}"));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Scratch(dir),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("{}: {error}", dir.display()),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let executable =
            std::env::current_exe().unwrap_or_else(|error| panic!("test executable path: {error}"));
        let build_root = executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .unwrap_or_else(|| panic!("test executable has a build root"));
        let dir = build_root.join("tmp").join("client-credential").join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        Scratch(dir)
    }
}

fn write(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

/// The uid that owns what this process creates: the effective uid.
fn euid_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .uid()
}

// ------------------------------------------------------- certificates

struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    der: CertificateDer<'static>,
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
    let der = params
        .self_signed(&key)
        .unwrap_or_else(|e| panic!("ca: {e}"))
        .der()
        .clone();
    Ca { params, key, der }
}

/// A client leaf the CA issued, as PEM, with its key as PEM.
struct Leaf {
    der: CertificateDer<'static>,
    pem: String,
    key_pem: String,
}

fn mint_leaf(ca: &Ca) -> Leaf {
    let key = keypair();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| panic!("leaf params: {e}"));
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key);
    let cert = params
        .signed_by(&key, &issuer)
        .unwrap_or_else(|e| panic!("leaf: {e}"));
    Leaf {
        der: cert.der().clone(),
        pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// A credential's two files in `dir`: the certificate file `0644`, the key
/// file `0600`.
struct Files {
    certificate: PathBuf,
    key: PathBuf,
    euid: u32,
}

impl Files {
    fn write(dir: &Path, leaf: &Leaf) -> Self {
        let certificate = dir.join("client.crt");
        let key = dir.join("client.key");
        write(&certificate, leaf.pem.as_bytes(), 0o644);
        write(&key, leaf.key_pem.as_bytes(), 0o600);
        let euid = euid_of(&key);
        Self {
            certificate,
            key,
            euid,
        }
    }

    fn load(&self) -> Result<ClientCredential, CredentialError> {
        ClientCredential::load(&self.certificate, &self.key, self.euid)
    }

    /// The control: these files load.
    fn loads(&self) -> ClientCredential {
        self.load()
            .unwrap_or_else(|e| panic!("the control pair must load: {e}"))
    }

    fn refused(&self) -> CredentialError {
        match self.load() {
            Ok(credential) => panic!("loaded, but should have been refused: {credential:?}"),
            Err(error) => error,
        }
    }
}

fn setup(name: &str) -> (Scratch, Leaf, Files) {
    let dir = scratch(name);
    let leaf = mint_leaf(&mint_ca());
    let files = Files::write(&dir, &leaf);
    files.loads();
    (dir, leaf, files)
}

/// The key-file refusal's text, asserting it is one.
fn key_file_refusal(error: CredentialError) -> String {
    let display = error.to_string();
    let debug = format!("{error:?}");
    match error {
        CredentialError::File {
            file: CredentialFile::Key,
            reason,
            ..
        } => {
            assert!(display.contains(&reason), "{display}");
            // Debug is a telemetry-safe class; Display is the local refusal channel.
            assert_eq!(debug, "<credential-error>");
            reason
        }
        other => panic!("want a key-file refusal, got {other:?}"),
    }
}

fn certificate_file_refusal(error: CredentialError) -> String {
    let display = error.to_string();
    let debug = format!("{error:?}");
    match error {
        CredentialError::File {
            file: CredentialFile::Certificate,
            reason,
            ..
        } => {
            assert!(display.contains(&reason), "{display}");
            // A custody reason can name a path or file and must stay out of Debug.
            assert_eq!(debug, "<credential-error>");
            assert!(!display.contains("or failed custody"));
            assert!(!debug.contains("or failed custody"));
            reason
        }
        other => panic!("want a certificate-file refusal, got {other:?}"),
    }
}

fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap_or_else(|e| panic!("mkfifo: {e}"));
    assert!(status.success(), "mkfifo {} failed", path.display());
}

// ================================================== loading: custody

#[test]
fn a_0400_key_file_is_admitted() {
    let (_dir, _leaf, files) = setup("key-0400");
    std::fs::set_permissions(&files.key, std::fs::Permissions::from_mode(0o400)).unwrap();
    files.loads();
}

#[test]
fn a_group_or_other_readable_key_file_is_refused_on_its_descriptor() {
    let (_dir, _leaf, files) = setup("key-mode");
    for mode in [0o640, 0o604, 0o660, 0o602] {
        std::fs::set_permissions(&files.key, std::fs::Permissions::from_mode(mode)).unwrap();
        let text = key_file_refusal(files.refused());
        assert!(
            text.contains(&format!("key permissions are {mode:03o}")) && text.contains("chmod 600"),
            "{mode:03o}: {text}"
        );
    }
}

#[test]
fn a_key_file_owned_by_another_uid_is_refused() {
    let (_dir, _leaf, files) = setup("key-owner");
    let other = files.euid.wrapping_add(1);
    let text = key_file_refusal(
        ClientCredential::load(&files.certificate, &files.key, other).unwrap_err(),
    );
    assert!(
        text.contains(&format!("owned by uid {}", files.euid))
            && text.contains(&format!("running uid is {other}")),
        "{text}"
    );
}

#[test]
fn a_symlinked_or_hard_linked_key_file_is_refused() {
    let (dir, _leaf, files) = setup("key-links");
    let link = dir.join("link.key");
    std::os::unix::fs::symlink(&files.key, &link).unwrap();
    let text = key_file_refusal(
        ClientCredential::load(&files.certificate, &link, files.euid).unwrap_err(),
    );
    assert!(
        text.contains("is a symlink; a private key must not be followed"),
        "{text}"
    );

    let hard = dir.join("hard.key");
    std::fs::hard_link(&files.key, &hard).unwrap();
    let text = key_file_refusal(
        ClientCredential::load(&files.certificate, &hard, files.euid).unwrap_err(),
    );
    assert!(
        text.contains("has 2 links; a private key must have exactly one"),
        "{text}"
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn a_key_file_with_a_granting_acl_is_refused() {
    let (_dir, _leaf, files) = setup("key-acl");
    let output = std::process::Command::new("/bin/chmod")
        .arg("+a")
        .arg("everyone allow read")
        .arg(&files.key)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = key_file_refusal(files.refused());
    assert!(
        text.contains("an ACL entry grants access") && text.contains("chmod -N"),
        "{text}"
    );
    let cleared = std::process::Command::new("/bin/chmod")
        .arg("-N")
        .arg(&files.key)
        .output()
        .unwrap();
    assert!(cleared.status.success(), "{cleared:?}");
    files.loads();
}

// ============================================= loading: the files

#[test]
fn a_missing_file_is_refused_naming_it() {
    let (dir, _leaf, files) = setup("missing");
    let absent = dir.join("absent");
    let text = certificate_file_refusal(
        ClientCredential::load(&absent, &files.key, files.euid).unwrap_err(),
    );
    assert!(text.contains(&absent.display().to_string()), "{text}");
    let text = key_file_refusal(
        ClientCredential::load(&files.certificate, &absent, files.euid).unwrap_err(),
    );
    assert!(text.contains(&absent.display().to_string()), "{text}");
}

#[test]
fn an_unreadable_certificate_file_is_refused() {
    let (_dir, _leaf, files) = setup("unreadable");
    std::fs::set_permissions(&files.certificate, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root reads through mode bits, so the row has nothing to show there.
    if std::fs::File::open(&files.certificate).is_ok() {
        return;
    }
    let text = certificate_file_refusal(files.refused());
    assert!(
        text.contains(&files.certificate.display().to_string()),
        "{text}"
    );
}

#[test]
fn a_file_that_is_not_regular_is_refused_without_blocking() {
    let (dir, _leaf, files) = setup("wrong-type");
    let fifo = dir.join("fifo");
    mkfifo(&fifo);
    let text = certificate_file_refusal(
        ClientCredential::load(&fifo, &files.key, files.euid).unwrap_err(),
    );
    assert!(text.contains("not a regular file"), "{text}");
    let text = key_file_refusal(
        ClientCredential::load(&files.certificate, &fifo, files.euid).unwrap_err(),
    );
    assert!(text.contains("not a regular file"), "{text}");
    let text =
        certificate_file_refusal(ClientCredential::load(&dir, &files.key, files.euid).unwrap_err());
    assert!(text.contains("not a regular file"), "{text}");
}

#[test]
fn a_file_over_the_bound_is_refused_before_its_content_is_judged() {
    let (_dir, leaf, files) = setup("oversized");
    let padded = format!("{}{}", leaf.key_pem, "\n".repeat(64 * 1024));
    write(&files.key, padded.as_bytes(), 0o600);
    let text = key_file_refusal(files.refused());
    assert!(text.contains("larger than 65536 bytes"), "{text}");
}

#[test]
fn a_content_refusal_names_the_file_it_is_in() {
    let (_dir, leaf, files) = setup("content");
    write(
        &files.certificate,
        format!("{}junk\n", leaf.pem).as_bytes(),
        0o644,
    );
    let error = files.refused();
    let text = error.to_string();
    assert!(
        matches!(
            &error,
            CredentialError::Content { error, .. }
                if matches!(**error, ContentError::Certificate(PemRefusal::Text { .. }))
        ),
        "{error:?}"
    );
    assert!(
        text.contains(&files.certificate.display().to_string()),
        "{text}"
    );
}

#[test]
fn a_key_that_is_not_the_certificates_is_refused() {
    let (_dir, _leaf, files) = setup("mismatch");
    let other = mint_leaf(&mint_ca());
    write(&files.key, other.key_pem.as_bytes(), 0o600);
    assert!(matches!(
        files.refused(),
        CredentialError::Content { error, .. } if matches!(*error, ContentError::Mismatch(_))
    ));
}

#[test]
fn a_configuration_names_both_files_or_neither() {
    let (dir, _leaf, files) = setup("configured");
    let euid = files.euid;
    assert!(
        ClientCredential::from_configured(None, None, euid)
            .unwrap()
            .is_none()
    );
    assert!(
        ClientCredential::from_configured(Some(&files.certificate), Some(&files.key), euid)
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        ClientCredential::from_configured(Some(&files.certificate), None, euid),
        Err(CredentialError::Incomplete {
            missing: CredentialFile::Key
        })
    ));
    assert!(matches!(
        ClientCredential::from_configured(None, Some(&files.key), euid),
        Err(CredentialError::Incomplete {
            missing: CredentialFile::Certificate
        })
    ));
    // Both named and one failing to load is a refusal, never anonymous.
    let absent = dir.join("absent");
    assert!(matches!(
        ClientCredential::from_configured(Some(&files.certificate), Some(&absent), euid),
        Err(CredentialError::File {
            file: CredentialFile::Key,
            ..
        })
    ));
}

// ================================================ the served rows

/// The one spawn site in this file: the accept loop, the layer the
/// simulator replaces rather than drives.
#[expect(
    clippy::disallowed_methods,
    reason = "the accept loop is the layer granary-sim replaces rather than drives: test harness concurrency the sim never replays"
)]
fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future)
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

/// How the service answers a `PUT`: its status and its `Granary-Error`
/// field values.
type Answer = (StatusCode, Vec<&'static str>);

/// What the service saw: each request's method and connection identity.
type Seen = Arc<Mutex<Vec<(Method, Option<ConnectionIdentity>)>>>;

/// Records each request's connection identity and method; answers a `PUT`
/// with [`Answer`] and anything else `404`.
#[derive(Clone)]
struct Recorder {
    seen: Seen,
    answer: Arc<Answer>,
    close_connections: bool,
}

impl Service<Request<Incoming>> for Recorder {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let identity = request.extensions().get::<ConnectionIdentity>().copied();
        let method = request.method().clone();
        self.seen
            .lock()
            .unwrap_or_else(|e| panic!("{e}"))
            .push((method.clone(), identity));
        let (status, tokens) = if method == Method::PUT {
            (self.answer.0, self.answer.1.clone())
        } else {
            (StatusCode::NOT_FOUND, vec!["not-found"])
        };
        let close_connections = self.close_connections;
        Box::pin(async move {
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = status;
            if close_connections {
                response
                    .headers_mut()
                    .insert(hyper::header::CONNECTION, HeaderValue::from_static("close"));
            }
            for token in tokens {
                response
                    .headers_mut()
                    .append("granary-error", HeaderValue::from_static(token));
            }
            Ok(response)
        })
    }
}

struct Server {
    addr: SocketAddr,
    pin: SpkiPin,
    seen: Seen,
    _shutdown: watch::Sender<bool>,
    serving: JoinHandle<std::io::Result<granary_net::accept::ShutdownOutcome>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

impl Server {
    async fn start(client_auth: ClientAuth, answer: Answer) -> Self {
        Self::start_transport(client_auth, answer, false).await
    }

    async fn start_transport(
        client_auth: ClientAuth,
        answer: Answer,
        close_connections: bool,
    ) -> Self {
        let key = keypair();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap_or_else(|e| panic!("server params: {e}"));
        let cert = params
            .self_signed(&key)
            .unwrap_or_else(|e| panic!("server cert: {e}"))
            .der()
            .clone();
        let pin = spki_digest(&cert).unwrap_or_else(|e| panic!("pin: {e}"));
        let mut tls = server_tls_config(
            vec![cert],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            client_auth,
        )
        .unwrap_or_else(|e| panic!("server tls: {e}"));
        if close_connections {
            tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("addr: {e}"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let service = Recorder {
            seen: Arc::clone(&seen),
            answer: Arc::new(answer),
            close_connections,
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
            pin,
            seen,
            _shutdown: shutdown,
            serving,
        }
    }

    fn store(&self, credential: Option<ClientCredential>) -> HttpStore {
        match granary_client::open_publish_route_with_client_credential(
            &base_url(self.addr),
            Some(vec![self.pin]),
            false,
            None,
            credential,
            &|_| panic!("a server route must not discover credentials"),
        )
        .unwrap_or_else(|e| panic!("route: {e}"))
        {
            granary_client::PublishRoute::Server(store) => *store,
            granary_client::PublishRoute::DirectS3(_) => panic!("expected server"),
        }
    }

    fn seen(&self) -> Vec<(Method, Option<ConnectionIdentity>)> {
        self.seen.lock().unwrap_or_else(|e| panic!("{e}")).clone()
    }
}

fn enrolled(ca: &Ca) -> ClientAuth {
    ClientAuth::Enrolled {
        ca: vec![ca.der.clone()],
        clock: Arc::new(FixedClock),
    }
}

fn created() -> Answer {
    (StatusCode::CREATED, Vec::new())
}

async fn put_one(store: &HttpStore) -> Result<bool, RootStoreError> {
    let bytes = b"a bin".to_vec();
    let digest = *GrainId::of(&bytes).digest();
    store.put_bin(&digest, bytes).await
}

/// A credential from `ca`, loaded from files in `dir`; and the identity a
/// server must see for it.
fn credential(dir: &Path, ca: &Ca) -> (ClientCredential, ConnectionIdentity) {
    let leaf = mint_leaf(ca);
    let credential = Files::write(dir, &leaf).loads();
    let digest = client_spki_digest(&leaf.der).unwrap_or_else(|e| panic!("digest: {e}"));
    (credential, ConnectionIdentity::Verified(digest))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_configured_clients_connection_carries_its_certificates_digest() {
    let ca = mint_ca();
    let server = Server::start(enrolled(&ca), created()).await;
    let dir_present = scratch("present");
    let (credential, identity) = credential(&dir_present, &ca);
    let store = server.store(Some(credential));
    let facade = store.read_facade();
    assert_eq!(put_one(&store).await, Ok(true));
    assert_eq!(put_one(&store).await, Ok(true));
    assert_eq!(put_one(&facade).await, Ok(true));
    assert_eq!(
        server.seen(),
        vec![
            (Method::PUT, Some(identity)),
            (Method::PUT, Some(identity)),
            (Method::PUT, Some(identity)),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unconfigured_client_connects_anonymously() {
    let ca = mint_ca();
    let server = Server::start(enrolled(&ca), created()).await;
    let store = server.store(None);
    assert_eq!(put_one(&store).await, Ok(true));
    assert_eq!(
        server.seen(),
        vec![(Method::PUT, Some(ConnectionIdentity::Anonymous))]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_configured_client_still_connects_to_a_server_with_no_authority() {
    let ca = mint_ca();
    let server = Server::start(ClientAuth::None, created()).await;
    let dir_phase_one = scratch("phase-one");
    let (credential, _) = credential(&dir_phase_one, &ca);
    let store = server.store(Some(credential));
    assert_eq!(put_one(&store).await, Ok(true));
    // No certificate was requested, so none was presented.
    assert_eq!(
        server.seen(),
        vec![(Method::PUT, Some(ConnectionIdentity::Anonymous))]
    );
}

// ======================================== a write refusal's token

fn no_principal() -> Answer {
    (StatusCode::FORBIDDEN, vec!["no-principal"])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_403_no_principal_is_reported_with_its_token_on_every_write_seam_and_not_retried() {
    let ca = mint_ca();
    let server = Server::start(enrolled(&ca), no_principal()).await;
    let store = server.store(None);
    let bytes = b"a bin".to_vec();
    let id = GrainId::of(&bytes);
    let answers = [
        (
            "PUT bin",
            store.put_bin(id.digest(), bytes.clone()).await.map(|_| ()),
        ),
        (
            "PUT meta",
            store.put_meta("vol", &id, bytes.clone()).await.map(|_| ()),
        ),
        ("PUT root", store.put_root("vol", 1, bytes).await),
        ("PUT hint", store.write_hint("vol", 1).await),
    ];
    for (endpoint, answer) in answers {
        assert_eq!(
            answer,
            Err(RootStoreError::UnexpectedStatus {
                operation: endpoint,
                status: 403,
                token: Some("no-principal".to_owned()),
            }),
            "{endpoint}: the server's refusal, status and token, never a transport failure"
        );
    }
    // One request per write: the refusal is not retried, anonymously or
    // otherwise.
    assert_eq!(server.seen().len(), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_403_without_one_valid_token_is_reported_by_its_status_alone() {
    let ca = mint_ca();
    for tokens in [
        Vec::new(),
        vec!["no-principal", "not-enrolled"],
        vec!["No Principal!"],
    ] {
        let server = Server::start(enrolled(&ca), (StatusCode::FORBIDDEN, tokens.clone())).await;
        let store = server.store(None);
        assert_eq!(
            put_one(&store).await,
            Err(RootStoreError::UnexpectedStatus {
                operation: "PUT bin",
                status: 403,
                token: None,
            }),
            "{tokens:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authority_pools_keep_concurrent_and_rotated_credentials_separate() {
    use granary_client::{AuthorityError, OwnedCandidate, PublishRequest};
    use granary_core::root::{self, RootDoc, RootSig, VolumeName};
    let ca = mint_ca();
    let server = Server::start(enrolled(&ca), created()).await;
    let dir_authority_pool_a = scratch("authority-pool-a");
    let (a, identity_a) = credential(&dir_authority_pool_a, &ca);
    let dir_authority_pool_b = scratch("authority-pool-b");
    let (b, identity_b) = credential(&dir_authority_pool_b, &ca);
    let dir_authority_pool_rotated = scratch("authority-pool-rotated");
    let (rotated, identity_rotated) = credential(&dir_authority_pool_rotated, &ca);
    let a = Arc::new(server.store(Some(a)));
    let b = Arc::new(server.store(Some(b)));
    let rotated = Arc::new(server.store(Some(rotated)));
    let id = GrainId::of(b"fixture");
    let doc = RootDoc {
        volume: VolumeName::new("vol".into()).unwrap(),
        seq: 1,
        parent: None,
        writer_uuid: [1; 16],
        epoch: 1,
        timestamp: root::Timestamp { secs: 1, nanos: 0 },
        chunker_spec: "opaque spec".into(),
        manifest_root: id,
        binmap_index: id,
        sheaf_head: id,
        sigs: vec![RootSig {
            key_id: [1; 32],
            sig: [2; 64],
        }],
    };
    let candidate = OwnedCandidate::new("vol", root::encode_root(&doc).unwrap().into()).unwrap();
    let request = PublishRequest::new(
        "vol",
        granary_core::authlog::Epoch::from_bytes([1; 16]),
        b"operation",
        candidate.clone(),
        vec![candidate],
    )
    .unwrap();
    let mut calls = Vec::new();
    for store in [&a, &b] {
        let store = store.clone();
        let request = request.clone();
        calls.push(spawn(async move {
            assert!(matches!(
                store.publish_once(&request).await,
                Err(AuthorityError::Backend(_))
            ));
            assert!(store.status_once("vol").await.is_err());
            assert_eq!(store.probe_root_once("vol", 1).await.unwrap(), None);
        }));
    }
    for call in calls {
        call.await.unwrap();
    }
    assert!(rotated.status_once("vol").await.is_err());
    assert!(a.status_once("vol").await.is_err());
    let seen = server.seen();
    for (identity, count) in [(identity_a, 4), (identity_b, 3), (identity_rotated, 1)] {
        assert_eq!(
            seen.iter().filter(|(_, i)| *i == Some(identity)).count(),
            count
        );
    }
    assert!(
        seen.iter()
            .all(|(_, identity)| *identity != Some(ConnectionIdentity::Anonymous))
    );
}

#[test]
fn client_error_layers_redact_display_debug_and_sources() {
    use std::error::Error as _;
    use std::io::Write as _;
    let (_dir, leaf, files) = setup("redacted-errors");
    let sentinel = "SECRET_SENTINEL";
    let bad = format!("-----BEGIN {sentinel}-----\n{sentinel}\n-----END {sentinel}-----\n");
    write(&files.key, bad.as_bytes(), 0o600);
    let (loaded_error, load_trace) = trace_capture(|| files.refused());
    assert!(!load_trace.contains(sentinel));
    let provider = || rustls::Error::General(sentinel.into());
    let errors = [
        loaded_error,
        CredentialError::File {
            file: CredentialFile::Key,
            path: files.key.clone(),
            reason: "key file could not be opened".into(),
        },
        CredentialError::Content {
            certificate: files.certificate.clone(),
            key: files.key.clone(),
            error: Box::new(ContentError::Mismatch(provider())),
        },
        CredentialError::Content {
            certificate: files.certificate.clone(),
            key: files.key.clone(),
            error: Box::new(ContentError::Certificate(PemRefusal::Certificate {
                block: 1,
                error: provider(),
            })),
        },
    ];
    for error in errors {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        write!(stdout, "{error:?}").unwrap();
        writeln!(stderr, "{error}").unwrap();
        for bytes in [stdout, stderr] {
            let text = String::from_utf8(bytes).unwrap();
            assert!(!text.contains(sentinel));
            assert!(!text.contains(&leaf.key_pem));
        }
        assert!(error.source().is_none());
        let ((), trace) = trace_capture(
            || tracing::warn!(error = ?error, display = %error, "credential refusal"),
        );
        assert!(trace.contains("credential refusal"));
        assert!(!trace.contains(sentinel));
        assert!(!trace.contains(&leaf.key_pem));
    }
}

#[test]
fn credential_route_refuses_direct_before_discovery() {
    let (_dir, leaf, files) = setup("route-credential");
    let credential = files.loads();
    assert!(!format!("{credential:?}").contains(&leaf.key_pem));
    assert!(matches!(
        granary_client::open_publish_route_with_client_credential(
            "http://bucket",
            None,
            true,
            Some("bucket"),
            Some(credential),
            &|_| panic!("credential route reached discovery")
        ),
        Err(granary_client::RouteError::DirectCredential)
    ));
}

#[test]
fn loaded_tls_identity_survives_closed_descriptor_and_path_replacement() {
    use granary_client::{FileIdentity, HarvestError, Store, harvest_excluding_files};
    use granary_core::grainsource::GrainSource as _;
    let (dir, leaf, files) = setup("protected-identities");
    let credential = files.loads();
    let original = std::fs::File::open(&files.key).unwrap();
    assert_eq!(
        credential.key_file_identity(),
        FileIdentity::from_file(&original).unwrap()
    );
    drop(original);
    let seed = dir.join("seed");
    write(&seed, &[17; 32], 0o600);
    let seed_file = std::fs::File::open(&seed).unwrap();
    let seed_id = FileIdentity::from_file(&seed_file).unwrap();
    drop(seed_file);
    let protected =
        granary_client::publication_config::protected_private_files(seed_id, Some(&credential));
    assert_eq!(protected, vec![seed_id, credential.key_file_identity()]);
    assert_eq!(
        granary_client::publication_config::protected_private_files(seed_id, None),
        vec![seed_id]
    );
    let source = dir.join("source");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    let alias = source.join("nested/alias");
    // Sole-link custody succeeded before this link was created.
    std::fs::hard_link(&files.key, &alias).unwrap();
    let old = dir.join("old-key");
    std::fs::rename(&files.key, &old).unwrap();
    write(&files.key, b"replacement public content", 0o600);
    for refused in [
        protected,
        vec![credential.key_file_identity(), seed_id],
        vec![credential.key_file_identity()],
        vec![
            seed_id,
            credential.key_file_identity(),
            credential.key_file_identity(),
        ],
    ] {
        let store = Store::open(&dir.join(format!("store-{}", refused.len()))).unwrap();
        let result = harvest_excluding_files(&source, &store, &refused);
        assert!(matches!(
            result,
            Err(HarvestError::RefusedFileIdentity { .. })
        ));
        assert!(store.get(&GrainId::of(leaf.key_pem.as_bytes())).is_err());
    }
    std::fs::remove_file(&alias).unwrap();
    std::fs::hard_link(&seed, &alias).unwrap();
    let store = Store::open(&dir.join("seed-store")).unwrap();
    assert!(matches!(
        harvest_excluding_files(&source, &store, &[credential.key_file_identity(), seed_id]),
        Err(HarvestError::RefusedFileIdentity { .. })
    ));
    assert!(store.get(&GrainId::of(&[17; 32])).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::hard_link(&files.key, &alias).unwrap();
    assert!(
        harvest_excluding_files(&source, &store, &[seed_id, credential.key_file_identity()])
            .is_ok()
    );
    assert!(harvest_excluding_files(&source, &store, &[]).is_ok());
}

#[test]
fn publisher_trust_never_comes_from_transport() {
    use granary_client::publication_config::PublisherTrust;
    use granary_store::crypto::{SigningKey, TrustedKeys};
    let dir = scratch("transport-trust");
    let signer = SigningKey::from_seed(&[1; 32]).unwrap();
    let foreign = SigningKey::from_seed(&[2; 32]).unwrap();
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[2; 32]);
    let tls_key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(der),
        &rcgen::PKCS_ED25519,
    )
    .unwrap();
    let cert = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .self_signed(&tls_key)
        .unwrap();
    let leaf = Leaf {
        der: cert.der().clone(),
        pem: cert.pem(),
        key_pem: tls_key.serialize_pem(),
    };
    let files = Files::write(&dir, &leaf);
    let credential = files.loads();
    let trust = PublisherTrust::default()
        .build(*signer.public_key())
        .unwrap();
    let route = granary_client::open_publish_route_with_client_credential(
        "https://host",
        Some(vec![*foreign.public_key()]),
        false,
        None,
        Some(credential),
        &|_| panic!("server discovery"),
    )
    .unwrap();
    assert!(matches!(route, granary_client::PublishRoute::Server(_)));
    for line in leaf
        .key_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
    {
        assert!(!format!("{route:?}").contains(line));
    }
    assert_eq!(trust, TrustedKeys::new([*signer.public_key()]).unwrap());
    assert_ne!(trust, TrustedKeys::new([*foreign.public_key()]).unwrap());
    for key in [&signer, &foreign] {
        let id = GrainId::of(b"trust-fixture");
        let mut doc = granary_core::root::RootDoc {
            volume: granary_core::root::VolumeName::new("vol".into()).unwrap(),
            seq: 1,
            parent: None,
            writer_uuid: [1; 16],
            epoch: 1,
            timestamp: Timestamp { secs: 1, nanos: 0 },
            chunker_spec: "opaque".into(),
            manifest_root: id,
            binmap_index: id,
            sheaf_head: id,
            sigs: vec![granary_core::root::RootSig {
                key_id: key.key_id(),
                sig: [0; 64],
            }],
        };
        let bytes = granary_core::root::encode_root(&doc).unwrap();
        doc.sigs.first_mut().unwrap().sig =
            key.sign(granary_core::root::signed_prefix(&bytes).unwrap());
        let bytes = granary_core::root::encode_root(&doc).unwrap();
        assert_eq!(
            granary_store::crypto::check_head(&bytes, "vol", 1, &trust).is_ok(),
            key.public_key() == signer.public_key()
        );
    }
}

#[derive(Default)]
struct RemoteCalls(std::sync::atomic::AtomicUsize);
impl RemoteCalls {
    fn refused<T>(&self) -> Result<T, RootStoreError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Err(RootStoreError::Backend("fixture refusal".to_owned()))
    }
}
impl granary_core::rootstore::RootStore for RemoteCalls {
    async fn put_root(&self, _: &str, _: u64, _: Vec<u8>) -> Result<(), RootStoreError> {
        self.refused()
    }
    async fn get_root(&self, _: &str, _: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.refused()
    }
    async fn read_hint(
        &self,
        _: &str,
        _: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
        self.refused()
    }
    async fn write_hint(&self, _: &str, _: u64) -> Result<(), RootStoreError> {
        self.refused()
    }
    async fn max_seq(&self, _: &str) -> Result<Option<u64>, RootStoreError> {
        self.refused()
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}
impl granary_core::binstore::BinStore for RemoteCalls {
    async fn put_bin(&self, _: &[u8; 32], _: Vec<u8>) -> Result<bool, RootStoreError> {
        self.refused()
    }
    async fn put_meta(&self, _: &str, _: &GrainId, _: Vec<u8>) -> Result<bool, RootStoreError> {
        self.refused()
    }
    async fn get_meta(&self, _: &str, _: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.refused()
    }
    async fn get_bin_range(&self, _: &[u8; 32], _: u64, _: u32) -> Result<Vec<u8>, RootStoreError> {
        self.refused()
    }
}

#[tokio::test]
async fn plural_prepare_and_publish_refuse_before_remote_calls() {
    use granary_client::{
        FileIdentity, Policy, PublishError, Store, prepare_excluding_files, publish_excluding_files,
    };
    use granary_core::grainsource::GrainSource as _;
    use granary_core::identity::WriterIdentity;
    use granary_core::root::VolumeName;
    use granary_store::crypto::SigningKey;
    let (dir, leaf, files) = setup("protected-preparation");
    let credential = files.loads();
    let seed = dir.join("seed");
    write(&seed, &[17; 32], 0o600);
    let held = std::fs::File::open(&seed).unwrap();
    let seed_id = FileIdentity::from_file(&held).unwrap();
    drop(held);
    let source = dir.join("source");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    std::fs::hard_link(&files.key, source.join("nested/key-alias")).unwrap();
    let store = Store::open(&dir.join("store")).unwrap();
    let remote = RemoteCalls::default();
    let signer = SigningKey::from_seed(&[17; 32]).unwrap();
    let volume = VolumeName::new("vol".into()).unwrap();
    let writer = WriterIdentity::from_bytes([1; 16]);
    let protected =
        granary_client::publication_config::protected_private_files(seed_id, Some(&credential));
    for publish in [false, true] {
        let result = if publish {
            publish_excluding_files(
                &remote,
                &store,
                &source,
                &protected,
                &volume,
                &signer,
                &writer,
                Timestamp { secs: 1, nanos: 0 },
                Policy::default(),
            )
            .await
            .map(|_| ())
        } else {
            prepare_excluding_files(
                &remote,
                &store,
                &source,
                &protected,
                &volume,
                &signer,
                &writer,
                Timestamp { secs: 1, nanos: 0 },
                Policy::default(),
            )
            .await
            .map(|_| ())
        };
        assert!(matches!(
            result,
            Err(PublishError::Harvest(
                granary_client::HarvestError::RefusedFileIdentity { .. }
            ))
        ));
        assert_eq!(remote.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(store.get(&GrainId::of(leaf.key_pem.as_bytes())).is_err());
    }
    std::fs::remove_file(source.join("nested/key-alias")).unwrap();
    std::fs::write(source.join("ordinary"), b"ordinary").unwrap();
    assert!(
        prepare_excluding_files(
            &remote,
            &store,
            &source,
            &protected,
            &volume,
            &signer,
            &writer,
            Timestamp { secs: 1, nanos: 0 },
            Policy::default()
        )
        .await
        .is_err()
    );
    assert_eq!(remote.0.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_store_presents_credential_on_every_operation_after_reconnect() {
    use granary_client::{OwnedCandidate, PublishRequest};
    use granary_core::root::{self, RootDoc, RootSig, VolumeName};
    let ca = mint_ca();
    let server = Server::start_transport(enrolled(&ca), created(), true).await;
    let dir_route_reconnect = scratch("route-reconnect");
    let (credential, identity) = credential(&dir_route_reconnect, &ca);
    let store = server.store(Some(credential));
    let id = GrainId::of(b"fixture");
    let doc = RootDoc {
        volume: VolumeName::new("vol".into()).unwrap(),
        seq: 1,
        parent: None,
        writer_uuid: [1; 16],
        epoch: 1,
        timestamp: Timestamp { secs: 1, nanos: 0 },
        chunker_spec: "opaque".into(),
        manifest_root: id,
        binmap_index: id,
        sheaf_head: id,
        sigs: vec![RootSig {
            key_id: [1; 32],
            sig: [2; 64],
        }],
    };
    let bytes = root::encode_root(&doc).unwrap();
    let candidate = OwnedCandidate::new("vol", bytes.clone().into()).unwrap();
    let request = PublishRequest::new(
        "vol",
        granary_core::authlog::Epoch::from_bytes([1; 16]),
        b"operation",
        candidate.clone(),
        vec![candidate],
    )
    .unwrap();
    assert!(store.status_once("vol").await.is_err());
    assert!(store.publish_once(&request).await.is_err());
    assert_eq!(store.probe_root_once("vol", 1).await.unwrap(), None);
    assert_eq!(store.get_root("vol", 1).await.unwrap(), None);
    assert!(store.read_hint("vol", None).await.is_ok());
    assert!(store.get_meta("vol", &id).await.is_err());
    assert!(store.get_bin_range(id.digest(), 0, 1).await.is_err());
    assert!(
        store
            .put_bin(id.digest(), b"fixture".to_vec())
            .await
            .is_ok()
    );
    assert!(
        store
            .put_meta("vol", &id, b"fixture".to_vec())
            .await
            .is_ok()
    );
    assert!(store.put_root("vol", 1, bytes).await.is_ok());
    // The peer's seam response deliberately uses 201 rather than hint's 204.
    assert!(store.write_hint("vol", 1).await.is_err());
    let seen = server.seen();
    assert_eq!(seen.len(), 11);
    assert!(seen.iter().all(|(_, seen)| *seen == Some(identity)));
}

#[tokio::test]
async fn tls_key_identity_survives_route_construction_for_publication_exclusion() {
    use granary_client::{FileIdentity, Policy, PublishError, Store, publish_excluding_files};
    use granary_core::grainsource::GrainSource as _;
    use granary_core::identity::WriterIdentity;
    use granary_core::root::VolumeName;
    use granary_store::crypto::SigningKey;

    let (dir, leaf, files) = setup("route-key-identity");
    let credential = files.loads();
    let identity = credential.key_file_identity();
    let route = granary_client::open_publish_route_with_client_credential(
        "https://host",
        Some(vec![[1; 32]]),
        false,
        None,
        Some(credential),
        &|_| panic!("server discovery"),
    )
    .unwrap();
    let granary_client::PublishRoute::Server(server) = route else {
        panic!("expected server route");
    };
    assert_eq!(server.key_file_identity(), Some(identity));
    let anonymous = HttpStore::new(
        "https://host",
        vec![[1; 32]],
        &granary_client::AmbientNetwork,
    )
    .unwrap();
    assert_eq!(anonymous.key_file_identity(), None);
    let seed = dir.join("seed");
    write(&seed, &[17; 32], 0o600);
    let held = std::fs::File::open(&seed).unwrap();
    let seed_identity = FileIdentity::from_file(&held).unwrap();
    drop(held);
    let source = dir.join("source");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::hard_link(&files.key, source.join("key-alias")).unwrap();
    let protected = [seed_identity, server.key_file_identity().unwrap()];
    let store = Store::open(&dir.join("store")).unwrap();
    let remote = RemoteCalls::default();
    let signer = SigningKey::from_seed(&[17; 32]).unwrap();
    let result = publish_excluding_files(
        &remote,
        &store,
        &source,
        &protected,
        &VolumeName::new("vol".into()).unwrap(),
        &signer,
        &WriterIdentity::from_bytes([1; 16]),
        Timestamp { secs: 1, nanos: 0 },
        Policy::default(),
    )
    .await;
    assert!(matches!(
        result,
        Err(PublishError::Harvest(
            granary_client::HarvestError::RefusedFileIdentity { .. }
        ))
    ));
    assert_eq!(remote.0.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(store.get(&GrainId::of(leaf.key_pem.as_bytes())).is_err());
}
