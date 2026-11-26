// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One production credential pool against the routed service and real TLS.

use super::observers::{Attempts, ObservedService};
use super::output::{distribution, write};
use super::rows::{DEFAULT, Fixture, RAISED, WallClock, fields, number, runtime_thread};
use super::trace::{Attempt, checked_label, checked_outcome, checked_trace};
use super::*;
use granary_client::{HttpStore, OwnedCandidate, PublishRequest, PublishResponse, StatusResponse};
use granary_core::binstore::BinStore;
use granary_core::enrollment::ClientSpkiDigest;
use granary_net::accept::Listener;
use rustls::server::{ClientHello, ResolvesServerCert};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize};

#[derive(Debug)]
struct CountListener {
    inner: tokio::net::TcpListener,
    connections: Arc<AtomicUsize>,
}
impl Listener for CountListener {
    type Io = tokio::net::TcpStream;
    async fn accept(&mut self) -> std::io::Result<Self::Io> {
        let stream = Listener::accept(&mut self.inner).await?;
        self.connections.fetch_add(1, Ordering::Relaxed);
        Ok(stream)
    }
}
#[derive(Debug)]
struct Resolver {
    good: Arc<dyn ResolvesServerCert>,
    bad: Arc<dyn ResolvesServerCert>,
    substituted: Arc<AtomicBool>,
    handshakes: Arc<AtomicUsize>,
}
impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.handshakes.fetch_add(1, Ordering::Relaxed);
        if self.substituted.load(Ordering::SeqCst) {
            self.bad.resolve(hello)
        } else {
            self.good.resolve(hello)
        }
    }
}
pub(super) struct Peer {
    pub client: Arc<HttpStore>,
    stop: tokio::sync::watch::Sender<bool>,
    run: ServerRun,
    connections: Arc<AtomicUsize>,
    handshakes: Arc<AtomicUsize>,
    substituted: Arc<AtomicBool>,
    close: Arc<AtomicBool>,
    pub base: String,
    pub pin: [u8; 32],
}
enum ServerRun {
    Current(tokio::task::JoinHandle<std::io::Result<granary_net::accept::ShutdownOutcome>>),
    Dedicated(std::thread::JoinHandle<std::io::Result<granary_net::accept::ShutdownOutcome>>),
}
pub(super) struct Material {
    ca: rcgen::Certificate,
    client: rcgen::Certificate,
    client_key: rcgen::KeyPair,
    server: rcgen::Certificate,
    server_key: rcgen::KeyPair,
}
pub(super) struct CredentialPaths {
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub credential: PathBuf,
}
impl Material {
    pub(super) fn for_host(host: &str) -> Result<Self, String> {
        let ca_key = rcgen::KeyPair::generate().map_err(|error| error.to_string())?;
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // Strict X.509 verifiers (OpenSSL with VERIFY_X509_STRICT, the default
        // in current Python) refuse a CA certificate without key usage.
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca = params
            .self_signed(&ca_key)
            .map_err(|error| error.to_string())?;
        let issuer = rcgen::Issuer::from_params(&params, &ca_key);
        let server_key = rcgen::KeyPair::generate().map_err(|error| error.to_string())?;
        let server = rcgen::CertificateParams::new(vec![host.to_owned()])
            .map_err(|error| error.to_string())?
            .signed_by(&server_key, &issuer)
            .map_err(|error| error.to_string())?;
        let client_key = rcgen::KeyPair::generate().map_err(|error| error.to_string())?;
        let mut params = rcgen::CertificateParams::default();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let client = params
            .signed_by(&client_key, &issuer)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            ca,
            client,
            client_key,
            server,
            server_key,
        })
    }
    pub(super) fn digest(&self) -> ClientSpkiDigest {
        granary_net::identity::client_spki_digest(self.client.der()).unwrap()
    }
    fn tls(&self) -> rustls::ServerConfig {
        granary_net::tls::server_tls_config(
            vec![self.server.der().clone()],
            rustls_pki_types::PrivatePkcs8KeyDer::from(self.server_key.serialize_der()).into(),
            granary_net::tls::ClientAuth::Enrolled {
                ca: vec![self.ca.der().clone()],
                clock: Arc::new(WallClock),
            },
        )
        .unwrap()
    }
    fn credential_files(
        &self,
        dir: &Path,
    ) -> Result<([u8; 32], granary_client::ClientCredential, CredentialPaths), String> {
        let pin =
            granary_net::pin::spki_digest(self.server.der()).map_err(|error| error.to_string())?;
        let paths = CredentialPaths {
            ca: dir.join("ca.pem"),
            certificate: dir.join("client.pem"),
            credential: dir.join("client.key"),
        };
        for (path, bytes) in [
            (&paths.ca, self.ca.pem()),
            (&paths.certificate, self.client.pem()),
            (&paths.credential, self.client_key.serialize_pem()),
        ] {
            std::fs::write(path, bytes)
                .map_err(|error| format!("server observer credential write failed: {error}"))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("server observer credential mode failed: {error}"))?;
        }
        let credential = granary_client::ClientCredential::load(
            &paths.certificate,
            &paths.credential,
            nix::unistd::geteuid().as_raw(),
        )
        .map_err(|error| error.to_string())?;
        Ok((pin, credential, paths))
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "one real TLS fixture keeps credentials, listener, pool and replacement key together"
    )]
    pub(super) async fn serve<R>(self, service: crate::GrainService<R>, dir: &Path) -> Peer
    where
        R: RootStore + BinStore + 'static,
    {
        let mut tls = self.tls();
        // The baseline is HTTP/1.1, so a forced Connection: close has its
        // protocol-defined meaning. Both peers otherwise use shipped TLS config.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let bad_key = rcgen::KeyPair::generate().unwrap();
        let bad_cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&bad_key)
            .unwrap();
        assert_ne!(
            granary_net::pin::spki_digest(bad_cert.der()).unwrap(),
            granary_net::pin::spki_digest(self.server.der()).unwrap(),
            "replacement must have a different key"
        );
        let bad = granary_net::tls::server_tls_config(
            vec![bad_cert.der().clone()],
            rustls_pki_types::PrivatePkcs8KeyDer::from(bad_key.serialize_der()).into(),
            granary_net::tls::ClientAuth::None,
        )
        .unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let handshakes = Arc::new(AtomicUsize::new(0));
        let substituted = Arc::new(AtomicBool::new(false));
        let close = Arc::new(AtomicBool::new(false));
        tls.cert_resolver = Arc::new(Resolver {
            good: tls.cert_resolver.clone(),
            bad: bad.cert_resolver,
            substituted: substituted.clone(),
            handshakes: handshakes.clone(),
        });
        let (pin, credential, _) = self.credential_files(dir).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let closing = close.clone();
        let tap = hyper::service::service_fn(move |r| {
            let service = service.clone();
            let closing = closing.clone();
            async move {
                use hyper::service::Service as _;
                let mut response = service.call(r).await.unwrap_or_else(|never| match never {});
                if closing.swap(false, Ordering::SeqCst) {
                    response.headers_mut().insert(
                        "connection",
                        hyper::header::HeaderValue::from_static("close"),
                    );
                }
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let run = tokio::spawn(granary_net::accept::serve(
            CountListener {
                inner: listener,
                connections: connections.clone(),
            },
            Arc::new(tls),
            tap,
            stopped,
            granary_net::accept::AcceptConfig::default(),
        ));
        let client = Arc::new(
            HttpStore::with_client_credential(
                &base,
                vec![pin],
                &granary_client::AmbientNetwork,
                Some(credential),
            )
            .unwrap(),
        );
        Peer {
            client,
            stop,
            run: ServerRun::Current(run),
            connections,
            handshakes,
            substituted,
            close,
            base,
            pin,
        }
    }

    pub(super) fn serve_observed_bound<S>(
        self,
        service: S,
        dir: &Path,
        bind: SocketAddr,
        authority_host: &str,
        dispatch: tracing::Dispatch,
    ) -> Result<(Peer, Attempts, CredentialPaths), String>
    where
        S: hyper::service::Service<
                hyper::Request<hyper::body::Incoming>,
                Response = hyper::Response<http_body_util::Full<hyper::body::Bytes>>,
                Error = std::convert::Infallible,
            > + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        let tls = self.tls();
        let (pin, credential, paths) = self.credential_files(dir)?;
        let listener = std::net::TcpListener::bind(bind)
            .map_err(|error| format!("server observer listener failed: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("server observer listener failed: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("server observer listener failed: {error}"))?
            .port();
        let base = if authority_host.contains(':') {
            format!("https://[{authority_host}]:{port}")
        } else {
            format!("https://{authority_host}:{port}")
        };
        let attempts = Attempts::new(262_144);
        let service = ObservedService::new(service, attempts.clone());
        let connections = Arc::new(AtomicUsize::new(0));
        let server_connections = connections.clone();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let substituted = Arc::new(AtomicBool::new(false));
        let close = Arc::new(AtomicBool::new(false));
        let tap = hyper::service::service_fn(move |request| {
            let service = service.clone();
            async move {
                use hyper::service::Service as _;
                service.call(request).await
            }
        });
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let run = runtime_thread(
            async move {
                let listener = tokio::net::TcpListener::from_std(listener)?;
                granary_net::accept::serve(
                    CountListener {
                        inner: listener,
                        connections: server_connections,
                    },
                    Arc::new(tls),
                    tap,
                    stopped,
                    granary_net::accept::AcceptConfig::default(),
                )
                .await
            },
            dispatch,
        );
        let client = Arc::new(
            HttpStore::with_client_credential(
                &base,
                vec![pin],
                &granary_client::AmbientNetwork,
                Some(credential),
            )
            .map_err(|error| error.to_string())?,
        );
        Ok((
            Peer {
                client,
                stop,
                run: ServerRun::Dedicated(run),
                connections,
                handshakes,
                substituted,
                close,
                base,
                pin,
            },
            attempts,
            paths,
        ))
    }
}
impl Peer {
    pub(super) async fn finish(self) {
        drop(self.client);
        self.stop.send(true).unwrap();
        let outcome = match self.run {
            ServerRun::Current(run) => run.await.unwrap().unwrap(),
            ServerRun::Dedicated(run) => run.join().unwrap().unwrap(),
        };
        assert_eq!(outcome, granary_net::accept::ShutdownOutcome::Drained);
    }
}
pub(super) fn observed(value: StatusResponse) -> granary_core::authority_answer::VolumeStatus {
    match value {
        StatusResponse::Observed(status) => status.observation(),
        other => panic!("routed status did not decode as success: {other:?}"),
    }
}

fn checked_pin_refusal(transport: bool, detail: &str) -> Result<(), &'static str> {
    // The transport API renders the typed pin rejection before flattening its
    // error. A generic transport failure supplies no re-verification evidence.
    if transport && detail.contains("pin mismatch: ") {
        Ok(())
    } else {
        Err("reconnect did not identify a pin refusal")
    }
}

#[test]
fn authority_measurement_reconnect_failure_controls() {
    assert_eq!(
        checked_pin_refusal(
            true,
            "transport: certificate failure — pin mismatch: sha256/fixture"
        ),
        Ok(())
    );
    let cases = [
        (true, "transport: connection reset"),
        (false, "pin mismatch: sha256/fixture"),
    ];
    assert!(!cases.is_empty());
    for (transport, detail) in cases {
        assert_eq!(
            checked_pin_refusal(transport, detail),
            Err("reconnect did not identify a pin refusal")
        );
    }
}

#[test]
fn authority_measurement_observed_server_offers_production_alpn() {
    let tls = Material::for_host("localhost").unwrap().tls();
    assert_eq!(
        tls.alpn_protocols,
        granary_net::alpn::GRANARY_ALPN
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
#[ignore = "real pooled TLS and sync latency; use the measurement runner"]
#[expect(
    clippy::too_many_lines,
    reason = "one pooled connection experiment retains baseline and forced-reconnect counts"
)]
async fn authority_measurement_pooled_transport() {
    let n = number("GRANARY_MEASURE_REQUESTS", 1000);
    assert!(n > 0);
    let material = Material::for_host("localhost").unwrap();
    let v = vol("v000");
    let (fx, driver) = Fixture::local(
        "pooled",
        std::slice::from_ref(&v),
        1,
        false,
        RAISED,
        material.digest(),
    )
    .await;
    let run = runtime_thread(
        driver.run(),
        tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
    );
    let peer = material.serve(fx.service.clone(), &fx.dir).await;
    observed(peer.client.status_once(v.as_str()).await.unwrap());
    let mut samples = Vec::with_capacity(n);
    let mut publication = Vec::with_capacity(n);
    let mut parent = None;
    let mut extra_statuses = 0;
    for i in 0..n {
        let at = stopwatch();
        observed(peer.client.status_once(v.as_str()).await.unwrap());
        samples.push(at.elapsed().as_nanos());
        let seq = i as u64 + 1;
        let bytes = good_root(&v, seq, parent, 1);
        let owned = OwnedCandidate::new(v.as_str(), Arc::from(bytes)).unwrap();
        let request = PublishRequest::new(
            v.as_str(),
            Epoch::from_bytes([WORLD_EPOCH; 16]),
            &seq.to_be_bytes(),
            owned.clone(),
            vec![owned.clone()],
        )
        .unwrap();
        let at = stopwatch();
        let response = peer.client.publish_once(&request).await.unwrap();
        assert!(
            matches!(
                response,
                PublishResponse::Accepted(_) | PublishResponse::Landed(_)
            ),
            "{response:?}"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let value = observed(peer.client.status_once(v.as_str()).await.unwrap());
                extra_statuses += 1;
                if value.open.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("publication remained open after its durable decision");
        publication.push(at.elapsed().as_nanos());
        assert_eq!(
            peer.client
                .probe_root_once(v.as_str(), seq)
                .await
                .unwrap()
                .as_deref(),
            Some(owned.bytes().as_ref())
        );
        parent = Some(owned.id());
    }
    let baseline = (
        peer.connections.load(Ordering::Relaxed),
        peer.handshakes.load(Ordering::Relaxed),
    );
    peer.close.store(true, Ordering::SeqCst);
    peer.substituted.store(true, Ordering::SeqCst);
    observed(peer.client.status_once(v.as_str()).await.unwrap());
    let bad = peer.client.status_once(v.as_str()).await;
    let refused = match &bad {
        Err(error) => checked_pin_refusal(
            matches!(error, granary_client::AuthorityError::Transport(_)),
            &error.to_string(),
        )
        .is_ok(),
        Ok(_) => false,
    };
    peer.substituted.store(false, Ordering::SeqCst);
    observed(peer.client.status_once(v.as_str()).await.unwrap());
    let after = (
        peer.connections.load(Ordering::Relaxed),
        peer.handshakes.load(Ordering::Relaxed),
    );
    let mut result = fields("pooled_transport", RAISED, n);
    distribution(&mut result, "status", &samples);
    distribution(&mut result, "publication", &publication);
    for (key, value) in [
        ("connections", baseline.0.to_string()),
        ("handshakes", baseline.1.to_string()),
        ("reconnect_connections", after.0.to_string()),
        ("reconnect_handshakes", after.1.to_string()),
        ("reconnect_unpinned_refused", refused.to_string()),
        ("extra_status_gets", extra_statuses.to_string()),
        ("status_gets", (n + extra_statuses + 3).to_string()),
        ("client_verification_gets", n.to_string()),
        ("publish_calls", n.to_string()),
        ("sample_loss", "0".into()),
        ("protocol", "http/1.1".into()),
        ("status_errors", "0".into()),
    ] {
        result.insert(key.into(), value);
    }
    write("pooled_transport", &result);
    peer.finish().await;
    fx.handle.stop().await;
    assert_eq!(run.join().unwrap(), RunEnd::Stopped);
    assert_eq!(
        baseline,
        (1, 1),
        "warm requests must use one connection and handshake"
    );
    assert!(
        refused && after.0 > baseline.0 && after.1 > baseline.1,
        "forced reconnect did not reject an unpinned peer: {bad:?}, before={baseline:?}, after={after:?}"
    );
    assert!(
        super::output::quantile(&samples, 50).unwrap() <= 2_000_000,
        "warm status p50 exceeds 2 ms"
    );
}

#[derive(Debug)]
struct Cadence {
    inner: Arc<HttpStore>,
    start: Instant,
    attempts: Mutex<Vec<Attempt>>,
    submissions: AtomicUsize,
    publication: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    max_body_bytes: AtomicUsize,
    lost: AtomicUsize,
    rate_limited: AtomicUsize,
}
impl RootStore for Cadence {
    async fn put_root(&self, v: &str, n: u64, b: Vec<u8>) -> Result<(), RootStoreError> {
        self.inner.put_root(v, n, b).await
    }
    async fn get_root(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.inner.get_root(v, n).await
    }
    async fn max_seq(&self, v: &str) -> Result<Option<u64>, RootStoreError> {
        self.inner.max_seq(v).await
    }
    async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.inner.max_seq_above(v, floor).await
    }
    async fn read_hint(&self, v: &str, t: Option<&HintToken>) -> Result<HintRead, RootStoreError> {
        self.inner.read_hint(v, t).await
    }
    async fn write_hint(&self, v: &str, n: u64) -> Result<(), RootStoreError> {
        self.inner.write_hint(v, n).await
    }
}
impl BinStore for Cadence {
    async fn put_meta(&self, v: &str, id: &GrainId, b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.inner.put_meta(v, id, b).await
    }
    async fn get_meta(&self, v: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.inner.get_meta(v, id).await
    }
    async fn put_bin(&self, d: &[u8; 32], b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.inner.put_bin(d, b).await
    }
    async fn get_bin_range(&self, d: &[u8; 32], o: u64, n: u32) -> Result<Vec<u8>, RootStoreError> {
        self.inner.get_bin_range(d, o, n).await
    }
}
impl granary_client::AuthorityTransport for Cadence {
    async fn publish_once(
        &self,
        r: &PublishRequest,
    ) -> Result<PublishResponse, granary_client::AuthorityError> {
        let at = stopwatch();
        let attempt = self.submissions.fetch_add(1, Ordering::Relaxed);
        let occupancy = self.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        self.max_in_flight.fetch_max(occupancy, Ordering::Relaxed);
        self.max_body_bytes
            .fetch_max(r.candidate().bytes().len(), Ordering::Relaxed);
        let response = self.inner.publish_once(r).await;
        let end = stopwatch();
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        let (status, token) = match &response {
            Ok(answer) => {
                let (status, token) = answer.identification();
                (status, token.unwrap_or("").to_owned())
            }
            Err(granary_client::AuthorityError::Backend(error)) => (
                error.status(),
                error.token().unwrap_or("protocol-error").to_owned(),
            ),
            Err(granary_client::AuthorityError::Transport(_)) => (0, "transport-error".into()),
            Err(granary_client::AuthorityError::Elapsed) => (0, "elapsed".into()),
            Err(granary_client::AuthorityError::Request(_)) => (0, "request-error".into()),
        };
        if status == 429 {
            self.rate_limited.fetch_add(1, Ordering::Relaxed);
        }
        let mut attempts = self.attempts.lock().unwrap();
        if attempts.len() < attempts.capacity() {
            attempts.push(Attempt {
                index: attempt,
                send_ns: at.duration_since(self.start).as_nanos(),
                end_ns: end.duration_since(self.start).as_nanos(),
                publication: self.publication.load(Ordering::Relaxed),
                operation: r.operation().iter().fold(String::new(), |mut hex, byte| {
                    write!(&mut hex, "{byte:02x}").unwrap();
                    hex
                }),
                volume: r.volume().to_owned(),
                status,
                token,
                body_bytes: r.candidate().bytes().len(),
            });
        } else {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
        response
    }

    async fn status_once(&self, v: &str) -> Result<StatusResponse, granary_client::AuthorityError> {
        self.inner.status_once(v).await
    }
    async fn probe_root_once(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.inner.probe_root_once(v, n).await
    }
}

#[tokio::test]
#[ignore = "production recovery cadence at an explicit control tuple; use the measurement runner"]
#[expect(
    clippy::too_many_lines,
    reason = "one production-coordinator experiment keeps the durable journal and all retransmission times together"
)]
async fn authority_measurement_defaults_cadence() {
    use granary_client::{
        PublicationHandle, PublicationOutcome, RecoveryBackoff, RecoveryIntent, RecoveryParts,
        resume_publication,
    };
    use granary_core::retained_submission as retained;
    let n = number("GRANARY_MEASURE_CADENCE", 1000);
    assert!((2..=1000).contains(&n));
    let tuple = std::env::var("GRANARY_MEASURE_TUPLE").unwrap_or_else(|_| DEFAULT.into());
    let label = std::env::var("GRANARY_MEASURE_LABEL").unwrap_or_else(|_| "defaults".into());
    checked_label(&label, &tuple).unwrap();
    let seed = super::rows::seed();
    let distinct = std::env::var("GRANARY_MEASURE_DISTINCT").as_deref() == Ok("1");
    assert!(!distinct || n <= 64);
    let volumes: Vec<_> = (0..if distinct { n } else { 1 })
        .map(|i| vol(&format!("v{i:03}")))
        .collect();
    let material = Material::for_host("localhost").unwrap();
    let (fx, driver) =
        Fixture::local("cadence", &volumes, 1, false, &tuple, material.digest()).await;
    if label == "defaults" {
        assert_eq!(
            crate::ControlsConfig::default().tuple(),
            (46, 5, 33_554_432, 268_435_456, 4),
            "production default differs from shipped tuple {DEFAULT}"
        );
        assert_eq!(tuple, DEFAULT, "defaults label requires shipped tuple");
    }
    let run = runtime_thread(
        driver.run(),
        tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
    );
    let peer = material.serve(fx.service.clone(), &fx.dir).await;
    let client = Cadence {
        inner: peer.client.clone(),
        start: stopwatch(),
        attempts: Mutex::new(Vec::with_capacity(n * 64)),
        submissions: AtomicUsize::new(0),
        publication: AtomicUsize::new(0),
        in_flight: AtomicUsize::new(0),
        max_in_flight: AtomicUsize::new(0),
        max_body_bytes: AtomicUsize::new(0),
        lost: AtomicUsize::new(0),
        rate_limited: AtomicUsize::new(0),
    };
    let mut local = granary_client::Store::open(&fx.dir.join("client-store")).unwrap();
    let mut journal = local.publications(nix::unistd::geteuid().as_raw()).unwrap();
    let scope = retained::Scope {
        authority_base: peer.base.as_bytes().to_vec(),
        pins: vec![peer.pin],
        credential_context: b"measure".to_vec(),
    };
    let keys = TrustedKeys::new([*publisher().public_key()]).unwrap();
    let signer = publisher();
    let mut entropy = secure(seed);
    let mut delay = RecoveryBackoff { rng: rng(seed) };
    let mut completed = 0;
    let mut rounds = 0;
    for i in 0..n {
        client.publication.store(i, Ordering::Relaxed);
        let v = volumes.get(if distinct { i } else { 0 }).unwrap();
        observed(peer.client.status_once(v.as_str()).await.unwrap());
        let seq = if distinct { 1 } else { i as u64 + 1 };
        let parent = if seq == 1 {
            None
        } else {
            Some(GrainId::of(
                &fx.store
                    .inner
                    .get_root(v.as_str(), seq - 1)
                    .await
                    .unwrap()
                    .unwrap(),
            ))
        };
        let bytes = good_root(v, seq, parent, 1);
        let doc = root::decode_root(&bytes).unwrap();
        let identity = retained::RequestIdentity {
            epoch: [WORLD_EPOCH; 16],
            operation: (i as u128 + 1).to_be_bytes(),
        };
        let record = retained::Submission {
            generation: 1,
            publication_id: (i as u128 + 1).to_be_bytes(),
            scope: scope.clone(),
            volume: v.clone(),
            frozen: retained::FrozenIntent {
                writer_identity: doc.writer_uuid,
                min_prefix_bits: 0,
                initial_root: bytes.clone(),
            },
            current: Some(identity),
            candidates: vec![retained::Candidate {
                number: 1,
                role: retained::Role::Active,
                request: identity,
                seq,
                id: GrainId::of(&bytes),
                root: bytes,
                evidence: retained::Evidence::default(),
            }],
            phase: retained::Phase::Ready,
            last_response: None,
            unavailable_exemptions: 0,
        };
        journal.begin(&record).unwrap();
        let handle = PublicationHandle {
            scope: scope.clone(),
            volume: v.clone(),
            publication_id: record.publication_id,
        };
        loop {
            rounds += 1;
            let result = resume_publication(
                RecoveryParts {
                    transport: &client,
                    journal: &mut journal,
                    publisher_keys: &keys,
                    signer: &signer,
                    secure: &mut entropy,
                    clock: &WallClock,
                    delay: &mut delay,
                },
                &handle,
                RecoveryIntent::Continue,
            )
            .await
            .unwrap();
            if matches!(result.outcome, PublicationOutcome::Landed(_)) {
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if observed(peer.client.status_once(v.as_str()).await.unwrap())
                            .open
                            .is_none()
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("serial publication remained open");
                completed += 1;
                break;
            }
            assert!(rounds < n * 8, "coordinator did not settle: {result:?}");
        }
    }
    let result = {
        let attempts = client.attempts.lock().unwrap();
        checked_trace(
            &attempts,
            client.submissions.load(Ordering::Relaxed),
            client.rate_limited.load(Ordering::Relaxed),
            completed,
            &tuple,
        )
        .unwrap();
        assert_eq!(
            client.lost.load(Ordering::Relaxed),
            0,
            "attempt trace overflow"
        );
        assert_eq!(
            client.max_in_flight.load(Ordering::Relaxed),
            1,
            "cadence occupancy is not serial"
        );
        let intervals: Vec<_> = attempts
            .windows(2)
            .filter_map(|w| w.get(1)?.send_ns.checked_sub(w.first()?.send_ns))
            .collect();
        let mut result = fields("defaults_cadence", &tuple, n);
        distribution(&mut result, "submission_interarrival", &intervals);
        result.insert(
            "interarrival_ns".into(),
            intervals
                .iter()
                .map(u128::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        result.insert(
            "submissions_including_retransmissions".into(),
            client.submissions.load(Ordering::Relaxed).to_string(),
        );
        result.insert(
            "rate_limited_429".into(),
            client.rate_limited.load(Ordering::Relaxed).to_string(),
        );
        result.insert(
            "sample_loss".into(),
            client.lost.load(Ordering::Relaxed).to_string(),
        );
        result.insert(
            "attempt_trace".into(),
            format!(
                "[{}]",
                attempts
                    .iter()
                    .map(Attempt::json)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        );
        result.insert("label".into(), label.clone());
        result.insert("seed".into(), seed.to_string());
        result.insert(
            "max_in_flight_writes".into(),
            client.max_in_flight.load(Ordering::Relaxed).to_string(),
        );
        result.insert(
            "max_request_body_bytes".into(),
            client.max_body_bytes.load(Ordering::Relaxed).to_string(),
        );
        result.insert("completed_publications".into(), completed.to_string());
        result.insert(
            "sequence".into(),
            if distinct {
                "distinct_volumes"
            } else {
                "get_publish"
            }
            .into(),
        );
        result
    };
    write("defaults_cadence", &result);
    let client_rate_limited = client.rate_limited.load(Ordering::Relaxed);
    drop(client);
    drop(journal);
    drop(local);
    peer.finish().await;
    fx.handle.stop().await;
    assert_eq!(run.join().unwrap(), RunEnd::Stopped);
    assert_eq!(
        checked_outcome(&label, client_rate_limited),
        Ok(()),
        "cadence label={label}, tuple={tuple}, completed={completed}, 429={client_rate_limited}"
    );
}
