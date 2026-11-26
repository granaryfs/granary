// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The production client intent transport against the production TLS service,
//! enrollment reader, controls, authority worker and filesystem intent store.
#![expect(
    clippy::disallowed_methods,
    reason = "isolated fixtures, generated credentials and bounded test runtime orchestration"
)]

#[cfg(feature = "overlay-fault-tests")]
mod convergence;
mod sync_loss;

use crate::authority::intent::tests as wire_fixture;
use crate::{
    AuthorityParts, ControlsConfig, EnrollmentReader, FileLog, GrainService, PrincipalControls,
    RunEnd, VerbOptions, VolumeConfig,
};
use granary_client::{AmbientNetwork, ClientCredential, HttpStore, IntentReply};
use granary_core::clock::Clock;
use granary_core::enrollment::{ClientSpkiDigest, PrincipalId, TenantName};
use granary_core::intent::{self, Ownership, OwnershipMode, Receipt, Verdict};
use granary_core::retained_submission::Scope;
use granary_core::rng::SeededRng;
use granary_core::root::{Timestamp, VolumeName};
use granary_core::rootstore::RootStore as _;
use granary_core::runmarker::BootId;
use granary_net::accept::{AcceptConfig, ShutdownOutcome, serve};
use granary_net::pin::spki_digest;
use granary_net::tls::{ClientAuth, server_tls_config};
use granary_sim::secure_random::SeededSecureRandom;
use granary_store::backend::GranaryStore;
use granary_store::crypto::SigningKey;
use object_store::path::Path as ObjectPath;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use rcgen::PublicKeyData as _;
#[cfg(feature = "crash-points")]
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
struct WallClock;
impl Clock for WallClock {
    fn now(&self) -> Timestamp {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        Timestamp {
            secs: i64::try_from(elapsed.as_secs()).unwrap(),
            nanos: elapsed.subsec_nanos(),
        }
    }
}

#[derive(Debug, Clone)]
struct Ticks(Arc<AtomicU64>);
impl Clock for Ticks {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: i64::try_from(self.0.load(Ordering::Relaxed)).unwrap(),
            nanos: 0,
        }
    }
}
#[derive(Debug)]
struct Pause;
impl crate::Pause for Pause {
    async fn pause(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = object_store::Result<T>> + Send + 'a>>;
type StoreStream<T> =
    Pin<Box<dyn futures_core::Stream<Item = object_store::Result<T>> + Send + 'static>>;

/// Counts requests at the backend shared by the HTTP service and authority.
#[derive(Debug, Default)]
struct ReadCountingStore {
    inner: object_store::memory::InMemory,
    reads: AtomicU64,
}

impl ReadCountingStore {
    fn read_count(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }
}

impl std::fmt::Display for ReadCountingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("read-counting test store")
    }
}

impl ObjectStore for ReadCountingStore {
    fn put_opts<'a, 'b, 'f>(
        &'a self,
        location: &'b ObjectPath,
        payload: PutPayload,
        options: PutOptions,
    ) -> StoreFuture<'f, PutResult>
    where
        'a: 'f,
        'b: 'f,
        Self: 'f,
    {
        self.inner.put_opts(location, payload, options)
    }

    fn put_multipart_opts<'a, 'b, 'f>(
        &'a self,
        location: &'b ObjectPath,
        options: PutMultipartOptions,
    ) -> StoreFuture<'f, Box<dyn MultipartUpload>>
    where
        'a: 'f,
        'b: 'f,
        Self: 'f,
    {
        self.inner.put_multipart_opts(location, options)
    }

    fn get_opts<'a, 'b, 'f>(
        &'a self,
        location: &'b ObjectPath,
        options: GetOptions,
    ) -> StoreFuture<'f, GetResult>
    where
        'a: 'f,
        'b: 'f,
        Self: 'f,
    {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.get_opts(location, options)
    }

    fn delete_stream(&self, locations: StoreStream<ObjectPath>) -> StoreStream<ObjectPath> {
        self.inner.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&ObjectPath>) -> StoreStream<ObjectMeta> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.list(prefix)
    }

    fn list_with_delimiter<'a, 'b, 'f>(
        &'a self,
        prefix: Option<&'b ObjectPath>,
    ) -> StoreFuture<'f, ListResult>
    where
        'a: 'f,
        'b: 'f,
        Self: 'f,
    {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.list_with_delimiter(prefix)
    }

    fn copy_opts<'a, 'b, 'c, 'f>(
        &'a self,
        from: &'b ObjectPath,
        to: &'c ObjectPath,
        options: CopyOptions,
    ) -> StoreFuture<'f, ()>
    where
        'a: 'f,
        'b: 'f,
        'c: 'f,
        Self: 'f,
    {
        self.inner.copy_opts(from, to, options)
    }
}

struct Fixture {
    dir: PathBuf,
    state: PathBuf,
    enrollment: PathBuf,
    tls: Arc<rustls::ServerConfig>,
    pin: [u8; 32],
    principals: Vec<PrincipalId>,
    clock: Ticks,
    objects: Arc<GranaryStore<Arc<dyn object_store::ObjectStore>>>,
    backend: Arc<dyn object_store::ObjectStore>,
    cleanup: bool,
    #[cfg(all(feature = "overlay-fault-tests", feature = "crash-points"))]
    tap: Option<PathBuf>,
}
impl Fixture {
    fn new(backend: Option<Arc<dyn object_store::ObjectStore>>) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let scratch = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = scratch.join(format!(
            "intent-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("state");
        let enrollment = dir.join("enrollment");
        for path in [&dir, &state, &enrollment] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_params(&params, &ca_key);
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&server_key, &issuer)
            .unwrap();
        for (name, pem) in [
            ("server.pem", server.pem()),
            ("server.key", server_key.serialize_pem()),
            ("ca.pem", ca.pem()),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, pem).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let pin = spki_digest(server.der()).unwrap();
        let tls = server_tls_config(
            vec![server.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            ClientAuth::Enrolled {
                ca: vec![ca.der().clone()],
                clock: Arc::new(WallClock),
            },
        )
        .unwrap();
        let mut principals = Vec::new();
        for n in 0..2 {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut client = rcgen::CertificateParams::default();
            client.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            let cert = client.signed_by(&key, &issuer).unwrap();
            let cert_path = dir.join(format!("client-{n}.pem"));
            let key_path = dir.join(format!("client-{n}.key"));
            std::fs::write(&cert_path, cert.pem()).unwrap();
            std::fs::write(&key_path, key.serialize_pem()).unwrap();
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let (principal, _) = crate::mint(
                &enrollment,
                VerbOptions {
                    accept_unsupported_filesystem: true,
                },
                &TenantName::parse("test").unwrap(),
                ClientSpkiDigest::from_spki_der(&key.subject_public_key_info()),
                &mut SeededSecureRandom::from_key([n + 1; 32]),
            )
            .unwrap();
            principals.push(principal);
        }
        let backend = backend.unwrap_or_else(|| Arc::new(object_store::memory::InMemory::new()));
        Self {
            dir,
            state,
            enrollment,
            tls: Arc::new(tls),
            pin,
            principals,
            clock: Ticks(Arc::new(AtomicU64::new(100))),
            objects: Arc::new(GranaryStore::new(backend.clone())),
            backend,
            cleanup: true,
            #[cfg(all(feature = "overlay-fault-tests", feature = "crash-points"))]
            tap: None,
        }
    }
    #[cfg(feature = "crash-points")]
    fn existing(dir: PathBuf, backend: Arc<dyn object_store::ObjectStore>) -> Self {
        let certs = CertificateDer::pem_file_iter(dir.join("server.pem"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(dir.join("server.key")).unwrap();
        let ca = CertificateDer::pem_file_iter(dir.join("ca.pem"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let pin = spki_digest(&certs[0]).unwrap();
        let tls = server_tls_config(
            certs,
            key,
            ClientAuth::Enrolled {
                ca,
                clock: Arc::new(WallClock),
            },
        )
        .unwrap();
        let state = dir.join("state");
        let enrollment = dir.join("enrollment");
        let set = granary_core::enrollment::decode_set(
            &std::fs::read(enrollment.join(crate::enrollment::SET_NAME)).unwrap(),
        )
        .unwrap();
        let principals = set.principals().map(|(id, _, _)| id).collect();
        Self {
            dir,
            state,
            enrollment,
            tls: Arc::new(tls),
            pin,
            principals,
            clock: Ticks(Arc::new(AtomicU64::new(100))),
            objects: Arc::new(GranaryStore::new(backend.clone())),
            backend,
            cleanup: false,
            #[cfg(all(feature = "overlay-fault-tests", feature = "crash-points"))]
            tap: None,
        }
    }
    fn enrolled(&self) -> granary_core::enrollment::EnrollmentSet {
        granary_core::enrollment::decode_set(
            &std::fs::read(self.enrollment.join(crate::enrollment::SET_NAME)).unwrap(),
        )
        .unwrap()
    }
    #[expect(
        clippy::unused_self,
        reason = "fixture operations consistently address the same configured authority volume"
    )]
    fn volume(&self) -> VolumeName {
        wire_fixture::volume()
    }
    fn scope(&self, addr: SocketAddr, principal: usize) -> Scope {
        Scope {
            authority_base: format!("https://{addr}").into_bytes(),
            pins: vec![self.pin],
            credential_context: vec![u8::try_from(principal).unwrap()],
        }
    }
    fn client(&self, addr: SocketAddr, principal: usize) -> HttpStore {
        let key = self.dir.join(format!("client-{principal}.key"));
        let cert = self.dir.join(format!("client-{principal}.pem"));
        let uid = std::fs::metadata(&key).unwrap().uid();
        HttpStore::with_client_credential(
            &format!("https://{addr}"),
            vec![self.pin],
            &AmbientNetwork,
            Some(ClientCredential::load(&cert, &key, uid).unwrap()),
        )
        .unwrap()
    }
    async fn start(
        &self,
        boot: u8,
        controls: ControlsConfig,
        provision: bool,
        addr: Option<SocketAddr>,
    ) -> Server {
        self.start_with_accept_config(boot, controls, provision, addr, AcceptConfig::default())
            .await
    }
    async fn start_with_accept_config(
        &self,
        boot: u8,
        controls: ControlsConfig,
        provision: bool,
        addr: Option<SocketAddr>,
        accept: AcceptConfig,
    ) -> Server {
        let log = FileLog::new(&self.state, true).unwrap();
        let intents = log.intent_store();
        self.start_on_log(boot, controls, provision, addr, accept, log, intents)
            .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "fixture inputs keep log and intent persistence on the same held directory"
    )]
    async fn start_on_log<L: granary_core::decisionlog::DecisionLog + 'static>(
        &self,
        boot: u8,
        controls: ControlsConfig,
        provision: bool,
        addr: Option<SocketAddr>,
        accept: AcceptConfig,
        log: L,
        intents: Arc<crate::authority::intent::persistence::IntentStore>,
    ) -> Server {
        let (handle, driver) = crate::start(
            AuthorityParts {
                admission: crate::Admission::chain_fixture(),
                log,
                store: GranaryStore::new(self.backend.clone()),
                clock: self.clock.clone(),
                rng: SeededRng::new(1),
                secure_random: SeededSecureRandom::from_key([boot; 32]),
                pause: Pause,
            },
            BootId::from_bytes([boot; 16]),
            vec![VolumeConfig::new(self.volume(), wire_fixture::keys()).with_intents(intents)],
        )
        .await
        .unwrap();
        let driver = tokio::spawn(driver.run());
        if provision {
            handle.initialise(&self.volume()).await.unwrap();
        }
        let reader = EnrollmentReader::open(&self.enrollment, true).unwrap();
        let config = crate::config::authority::AuthorityConfig {
            authority_profile: crate::config::authority::AuthorityProfile::SingleProcess,
            state_dir: self.state.clone(),
            enrollment_dir: self.enrollment.clone(),
            client_ca: self.dir.join("unused-ca"),
            volumes: [(
                self.volume(),
                vec![*SigningKey::from_seed(&[23; 32]).unwrap().public_key()],
            )]
            .into_iter()
            .collect(),
            accept_unsupported_filesystem: true,
            controls,
        };
        let service = GrainService::new(self.objects.clone(), "", 1).with_authority_writes(
            reader.clone(),
            Arc::new(PrincipalControls::new(
                controls,
                Arc::new(self.clock.clone()),
            )),
            Arc::new(crate::refusals::RefusalCounters::default()),
            &config,
            handle.clone(),
        );
        let listener = TcpListener::bind(addr.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown, rx) = watch::channel(false);
        #[cfg(all(feature = "overlay-fault-tests", feature = "crash-points"))]
        let service = convergence::server_crash::ObservedService::new(service, self.tap.clone());
        let served = tokio::spawn(serve(listener, self.tls.clone(), service, rx, accept));
        Server {
            addr,
            handle,
            shutdown,
            served,
            driver,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.cleanup {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}
struct Server {
    addr: SocketAddr,
    handle: crate::AuthorityHandle,
    shutdown: watch::Sender<bool>,
    served: JoinHandle<std::io::Result<ShutdownOutcome>>,
    driver: JoinHandle<RunEnd>,
}
impl Server {
    async fn stop(self) -> SocketAddr {
        self.shutdown.send(true).unwrap();
        assert_eq!(
            self.served.await.unwrap().unwrap(),
            ShutdownOutcome::Drained
        );
        assert_eq!(self.handle.stop().await, RunEnd::Stopped);
        assert_eq!(self.driver.await.unwrap(), RunEnd::Stopped);
        self.addr
    }
}
fn roomy() -> ControlsConfig {
    ControlsConfig::parse("1000,1000,33554432,268435456,4").unwrap()
}
fn recovery(
    fx: &Fixture,
    scope: Scope,
    readback: &IntentReply,
    writer: [u8; 16],
    label: &str,
) -> granary_client::WritableStore<granary_client::OverlayDisk> {
    let selection = granary_client::SelectedRecovery::from_readback(
        scope.clone(),
        fx.volume(),
        writer,
        readback,
        |_, _| true,
    )
    .unwrap();
    let path = fx.dir.join(label);
    let store = granary_client::Store::open(&path).unwrap();
    let euid = std::fs::metadata(&path).unwrap().uid();
    let config = granary_client::OverlayConfig {
        scope,
        volume: fx.volume(),
        euid,
        cap: 134_217_728,
        ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
        instance: [0; 16],
    };
    granary_client::WritableStore::adopt_selected(
        store,
        config,
        granary_client::OverlayDisk::new(&path, euid),
        &mut SeededSecureRandom::from_key([7; 32]),
        granary_client::FaultControl::default(),
        selection.acknowledge_displacement(),
    )
    .unwrap()
}

fn acquire(writer: u8, token: u8, cursor: u64) -> Vec<u8> {
    intent::encode_ownership(Ownership {
        writer: [writer; 16],
        instance: [token; 16],
        mode: OwnershipMode::Acquire {
            observed_cursor: cursor,
        },
    })
    .unwrap()
}
fn takeover(row: Receipt, token: u8) -> Vec<u8> {
    intent::encode_ownership(Ownership {
        writer: row.writer,
        instance: [token; 16],
        mode: OwnershipMode::Takeover {
            expected_epoch: row.epoch,
            generation: row.generation,
            state: row.state,
            recovery_ack: true,
        },
    })
    .unwrap()
}
fn granted(reply: &IntentReply) -> intent::Grant {
    intent::decode_grant(reply.body()).unwrap()
}
fn registration(row: Receipt, generation: u64) -> Vec<u8> {
    intent::encode_register(
        &row.writer,
        row.epoch,
        &row.instance,
        generation,
        &wire_fixture::root(row.writer[0], &wire_fixture::volume()),
    )
    .unwrap()
}
fn release(row: Receipt, generation: u64) -> Vec<u8> {
    intent::encode_release(intent::Release {
        writer: row.writer,
        epoch: row.epoch,
        instance: row.instance,
        generation,
    })
    .unwrap()
}

async fn take_over_and_release(
    client: &HttpStore,
    scope: &Scope,
    volume: &VolumeName,
    registered: Receipt,
) {
    let takeover_reply = client
        .intent_takeover_once(scope, volume, &takeover(registered, 3))
        .await
        .unwrap();
    assert_eq!(takeover_reply.status(), 200);
    let row = granted(&takeover_reply).receipt;
    let released = client
        .intent_release_once(scope, volume, &release(row, row.generation))
        .await
        .unwrap();
    assert_eq!(released.status(), 200);
}

#[tokio::test]
async fn real_intent_lost_replies_replay_across_restart() {
    let fx = Fixture::new(None);
    let mut server = fx.start(1, roomy(), true, None).await;
    let acquisition = acquire(1, 2, 0);
    let mut client = fx.client(server.addr, 0);
    let mut scope = fx.scope(server.addr, 0);
    let first = client
        .intent_acquire_once(&scope, &fx.volume(), &acquisition)
        .await
        .unwrap();
    let mut row = granted(&first).receipt;
    // The reply is discarded before restarting; every retry uses identical bytes.
    for operation in 0..4 {
        let body = match operation {
            0 => acquisition.clone(),
            1 => takeover(row, 3),
            2 => registration(row, 1),
            _ => release(row, 1),
        };
        let send = async |client: &HttpStore, scope: &Scope| match operation {
            0 => client
                .intent_acquire_once(scope, &fx.volume(), &body)
                .await
                .unwrap(),
            1 => client
                .intent_takeover_once(scope, &fx.volume(), &body)
                .await
                .unwrap(),
            2 => client
                .intent_register_once(scope, &fx.volume(), &body, |_, _| true)
                .await
                .unwrap(),
            _ => client
                .intent_release_once(scope, &fx.volume(), &body)
                .await
                .unwrap(),
        };
        let lost = send(&client, &scope).await;
        assert_eq!(lost.status(), 200);
        drop(client);
        let addr = server.stop().await;
        server = fx
            .start(
                u8::try_from(operation + 2).unwrap(),
                roomy(),
                true,
                Some(addr),
            )
            .await;
        client = fx.client(server.addr, 0);
        scope = fx.scope(server.addr, 0);
        let replay = send(&client, &scope).await;
        assert_eq!(
            (replay.status(), replay.body()),
            (200, lost.body()),
            "exact replay after authority restart"
        );
        row = if operation < 2 {
            granted(&replay).receipt
        } else {
            intent::decode_receipt(replay.body()).unwrap()
        };
    }
    drop(client);
    server.stop().await;
}

#[tokio::test]
async fn real_intent_principal_isolation_get_is_uncharged_replay_is_charged() {
    let fx = Fixture::new(None);
    let server = fx
        .start(
            1,
            ControlsConfig::parse("1,1,33554432,268435456,4").unwrap(),
            true,
            None,
        )
        .await;
    let client = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let request = acquire(1, 2, 0);
    assert_eq!(
        client
            .intent_acquire_once(&scope, &fx.volume(), &request)
            .await
            .unwrap()
            .status(),
        200
    );
    for _ in 0..20 {
        assert_eq!(
            client
                .intent_readback_once(&scope, &fx.volume(), |_, _| true)
                .await
                .unwrap()
                .status(),
            200
        );
    }
    let limited = client
        .intent_acquire_once(&scope, &fx.volume(), &request)
        .await
        .unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(limited.retry_after(), Some("1"));
    let other = fx.client(server.addr, 1);
    assert_eq!(
        other
            .intent_acquire_once(&fx.scope(server.addr, 1), &fx.volume(), &request)
            .await
            .unwrap()
            .status(),
        200,
        "another principal owns an independent row/cursor"
    );
    drop((client, other));
    server.stop().await;
}

#[tokio::test]
async fn real_intent_registration_release_429_retry_after_and_deadline() {
    let fx = Fixture::new(None);
    let server = fx
        .start(
            1,
            ControlsConfig::parse("1,1,33554432,268435456,4").unwrap(),
            true,
            None,
        )
        .await;
    let client = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let row = granted(
        &client
            .intent_acquire_once(&scope, &fx.volume(), &acquire(1, 2, 0))
            .await
            .unwrap(),
    )
    .receipt;
    let register = registration(row, 1);
    let limited = client
        .intent_register_once(&scope, &fx.volume(), &register, |_, _| true)
        .await
        .unwrap();
    assert_eq!((limited.status(), limited.retry_after()), (429, Some("1")));
    fx.clock.0.fetch_add(1, Ordering::Relaxed);
    let accepted = client
        .intent_register_once(&scope, &fx.volume(), &register, |_, _| true)
        .await
        .unwrap();
    assert_eq!(accepted.status(), 200);
    let release = release(intent::decode_receipt(accepted.body()).unwrap(), 1);
    let limited = client
        .intent_release_once(&scope, &fx.volume(), &release)
        .await
        .unwrap();
    assert_eq!((limited.status(), limited.retry_after()), (429, Some("1")));
    // A deadline shorter than Retry-After leaves exact release bytes unresolved.
    let remaining = Duration::from_millis(100);
    assert!(Duration::from_secs(limited.retry_after().unwrap().parse().unwrap()) > remaining);
    let read = client
        .intent_readback_once(&scope, &fx.volume(), |_, _| true)
        .await
        .unwrap();
    assert_eq!(
        intent::decode_readback(read.body(), &fx.volume(), |_, _| true)
            .unwrap()
            .rows
            .len(),
        1
    );
    fx.clock.0.fetch_add(1, Ordering::Relaxed);
    assert_eq!(
        client
            .intent_release_once(&scope, &fx.volume(), &release)
            .await
            .unwrap()
            .status(),
        200
    );
    drop(client);
    server.stop().await;
    configured_release_deadline().await;
}

struct EmptySource;
impl granary_client::ContentSource for EmptySource {
    fn read_verified(
        &mut self,
        _: granary_core::hash::GrainId,
        _: u64,
        _: usize,
    ) -> Result<Vec<u8>, granary_client::OverlayError> {
        Err(granary_client::OverlayError::ContentUnavailable)
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "bootstrap and a real rate-limited release exercise one configured deadline with retained local and authority evidence"
)]
async fn configured_release_deadline() {
    let fx = Fixture::new(None);
    let server = fx
        .start(
            1,
            ControlsConfig::parse("1,1,33554432,268435456,4").unwrap(),
            true,
            None,
        )
        .await;
    let client = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let path = fx.dir.join("owned-client");
    let store = granary_client::Store::open(&path).unwrap();
    let euid = std::fs::metadata(&path).unwrap().uid();
    let disk = granary_client::OverlayDisk::new(&path, euid);
    let mut owned = granary_client::WritableStore::new(
        store,
        granary_client::OverlayConfig {
            scope: scope.clone(),
            volume: fx.volume(),
            euid,
            cap: 134_217_728,
            ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
            instance: [0; 16],
        },
        granary_client::OverlayDisk::new(&path, euid),
        &mut SeededSecureRandom::from_key([7; 32]),
        granary_client::FaultControl::default(),
        |_, _| true,
    )
    .unwrap();
    let request = owned.prepare_acquire(0, &fx.clock).unwrap();
    owned.dispatch(&request, &fx.clock).unwrap();
    let answer = client
        .intent_acquire_once(&scope, &fx.volume(), request.bytes())
        .await
        .unwrap();
    owned
        .complete(
            &request,
            Ok(&answer),
            &fx.clock,
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    owned
        .open_overlay(
            granary_core::overlay_journal::JournalHeader {
                writer: owned.writer_uuid(),
                base_root: granary_core::hash::GrainId::of(b"base"),
                base_seq: 1,
                next_stage_id: 1,
                receipt_generation: 0,
            },
            vec![],
            &mut EmptySource,
            disk,
        )
        .unwrap();
    let mut root = granary_core::root::decode_root(&wire_fixture::root(1, &fx.volume())).unwrap();
    root.writer_uuid = owned.writer_uuid();
    let signer = SigningKey::from_seed(&[23; 32]).unwrap();
    let bytes = granary_core::root::encode_root(&root).unwrap();
    root.sigs[0].sig = signer.sign(granary_core::root::signed_prefix(&bytes).unwrap());
    let bytes = granary_core::root::encode_root(&root).unwrap();
    fx.clock.0.fetch_add(1, Ordering::Relaxed);
    let request = owned
        .prepare_registration(&bytes, vec![], &fx.clock, |_, _| true)
        .unwrap();
    owned.dispatch(&request, &fx.clock).unwrap();
    let answer = client
        .intent_register_once(&scope, &fx.volume(), request.bytes(), |_, _| true)
        .await
        .unwrap();
    owned
        .complete(
            &request,
            Ok(&answer),
            &fx.clock,
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let deadline = fx.clock.0.load(Ordering::Relaxed) * 1000 + 50;
    let request = owned
        .prepare_release(&fx.clock, Duration::from_millis(100), Some(deadline))
        .unwrap();
    owned.dispatch(&request, &fx.clock).unwrap();
    let answer = client
        .intent_release_once(&scope, &fx.volume(), request.bytes())
        .await
        .unwrap();
    assert_eq!((answer.status(), answer.retry_after()), (429, Some("1")));
    let result = owned.complete(
        &request,
        Ok(&answer),
        &fx.clock,
        &mut SeededRng::new(1),
        1000,
        None,
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("IntentRetryDeadline"),
        "real Retry-After must obey the enclosing client deadline"
    );
    assert_eq!(
        owned.snapshot().phase,
        granary_core::overlay_ownership::Phase::Releasing
    );
    assert_eq!(owned.retained_requests()[0].bytes(), request.bytes());
    let read = client
        .intent_readback_once(&scope, &fx.volume(), |_, _| true)
        .await
        .unwrap();
    assert_eq!(
        intent::decode_readback(read.body(), &fx.volume(), |_, _| true)
            .unwrap()
            .rows
            .len(),
        1,
        "release timeout preserves live authority evidence"
    );
    drop((client, owned));
    server.stop().await;
}

#[tokio::test]
async fn real_intent_conditional_takeover_requires_renewed_exact_selection() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let client = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let row = granted(
        &client
            .intent_acquire_once(&scope, &fx.volume(), &acquire(1, 2, 0))
            .await
            .unwrap(),
    )
    .receipt;
    client
        .intent_register_once(&scope, &fx.volume(), &registration(row, 1), |_, _| true)
        .await
        .unwrap();
    let selected = client
        .intent_readback_once(&scope, &fx.volume(), |_, _| true)
        .await
        .unwrap();
    let mut old = recovery(&fx, scope.clone(), &selected, [1; 16], "old-selection");
    let attempt = old.begin_selected_attempt(&fx.clock).unwrap();
    old.dispatch(&attempt, &fx.clock).unwrap();
    client
        .intent_register_once(&scope, &fx.volume(), &registration(row, 2), |_, _| true)
        .await
        .unwrap();
    let changed = client
        .intent_takeover_once(&scope, &fx.volume(), attempt.bytes())
        .await
        .unwrap();
    assert!(matches!(
        changed.ownership(attempt.bytes()).unwrap(),
        Verdict::Changed(_)
    ));
    assert!(
        old.complete(
            &attempt,
            Ok(&changed),
            &fx.clock,
            &mut SeededRng::new(1),
            0,
            None
        )
        .unwrap_err()
        .to_string()
        .contains("IntentSelectionChanged")
    );
    assert_eq!(
        old.snapshot().selected_root,
        intent::decode_readback(selected.body(), &fx.volume(), |_, _| true)
            .unwrap()
            .rows[0]
            .root
    );
    drop(old);
    let selected = client
        .intent_readback_once(&scope, &fx.volume(), |_, _| true)
        .await
        .unwrap();
    let mut renewed = recovery(&fx, scope.clone(), &selected, [1; 16], "renewed-selection");
    let attempt = renewed.begin_selected_attempt(&fx.clock).unwrap();
    assert!(
        matches!(
            intent::decode_ownership(attempt.bytes()).unwrap().mode,
            OwnershipMode::Takeover {
                recovery_ack: true,
                generation: 2,
                ..
            }
        ),
        "renewed selection carries explicit bound consent"
    );
    renewed.dispatch(&attempt, &fx.clock).unwrap();
    let accepted = client
        .intent_takeover_once(&scope, &fx.volume(), attempt.bytes())
        .await
        .unwrap();
    renewed
        .complete(
            &attempt,
            Ok(&accepted),
            &fx.clock,
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert_eq!(granted(&accepted).receipt.epoch, row.epoch + 1);
    assert_eq!(granted(&accepted).receipt.generation, 2);
    drop((client, renewed));
    server.stop().await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ownership displacement and eviction schedule checks registration and release at both generation extremes"
)]
async fn real_intent_displaced_and_absent_packets_at_lower_and_higher_generations() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let client = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let old = granted(
        &client
            .intent_acquire_once(&scope, &fx.volume(), &acquire(1, 2, 0))
            .await
            .unwrap(),
    )
    .receipt;
    let current = granted(
        &client
            .intent_takeover_once(&scope, &fx.volume(), &takeover(old, 3))
            .await
            .unwrap(),
    )
    .receipt;
    for generation in [1, 99] {
        let body = registration(old, generation);
        let answer = client
            .intent_register_once(&scope, &fx.volume(), &body, |_, _| true)
            .await
            .unwrap();
        let decoded = intent::decode_register(&body, &fx.volume(), |_, _| true).unwrap();
        assert!(matches!(
            answer.registration(&intent::RegisterRequest {
                writer: old.writer,
                epoch: old.epoch,
                instance: old.instance,
                generation,
                root_id: decoded.root_id()
            }),
            Verdict::Superseded(_)
        ));
        let body = release(old, generation);
        let answer = client
            .intent_release_once(&scope, &fx.volume(), &body)
            .await
            .unwrap();
        assert!(matches!(
            answer.release(&intent::ReleaseRequest {
                writer: old.writer,
                epoch: old.epoch,
                instance: old.instance,
                generation
            }),
            Verdict::Superseded(_)
        ));
    }
    let release = release(current, 1);
    assert_eq!(
        client
            .intent_release_once(&scope, &fx.volume(), &release)
            .await
            .unwrap()
            .status(),
        200
    );
    fx.clock.0.store(1_000_000, Ordering::Relaxed);
    assert_eq!(
        server
            .handle
            .maintain_intents(&fx.volume(), &fx.enrolled(), 0)
            .await
            .status()
            .as_u16(),
        200
    );
    for generation in [1, 99] {
        assert_eq!(
            client
                .intent_register_once(
                    &scope,
                    &fx.volume(),
                    &registration(old, generation),
                    |_, _| true
                )
                .await
                .unwrap()
                .status(),
            409
        );
        let absent = client
            .intent_release_once(
                &scope,
                &fx.volume(),
                &super::intents::release(old, generation),
            )
            .await
            .unwrap();
        assert!(matches!(
            absent.release(&intent::ReleaseRequest {
                writer: old.writer,
                epoch: old.epoch,
                instance: old.instance,
                generation
            }),
            Verdict::Absent
        ));
    }
    drop(client);
    server.stop().await;
}

#[tokio::test]
async fn real_intent_cursor_survives_eviction_restart_and_epoch_exhaustion() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), true, None).await;
    let client = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let old = granted(
        &client
            .intent_acquire_once(&scope, &fx.volume(), &acquire(1, 2, 0))
            .await
            .unwrap(),
    )
    .receipt;
    assert_eq!(
        client
            .intent_release_once(&scope, &fx.volume(), &release(old, 1))
            .await
            .unwrap()
            .status(),
        200
    );
    fx.clock.0.store(1_000_000, Ordering::Relaxed);
    server
        .handle
        .maintain_intents(&fx.volume(), &fx.enrolled(), 0)
        .await;
    drop(client);
    let addr = server.stop().await;
    let server = fx.start(2, roomy(), true, Some(addr)).await;
    let client = fx.client(server.addr, 0);
    let row = granted(
        &client
            .intent_acquire_once(&scope, &fx.volume(), &acquire(2, 3, old.epoch))
            .await
            .unwrap(),
    )
    .receipt;
    assert!(
        row.epoch > old.epoch,
        "allocator must not reuse an evicted epoch"
    );
    drop(client);
    let addr = server.stop().await;
    let path = fx.state.join(format!("{}.intent", fx.volume().as_str()));
    let bytes = std::fs::read(&path).unwrap();
    let mut snapshot = crate::authority::intent::codec::decode(
        bytes.as_slice(),
        &fx.volume(),
        None,
        &wire_fixture::keys(),
    )
    .unwrap();
    snapshot.principals.get_mut(&fx.principals[0]).unwrap().h = u64::MAX;
    let mut bytes = Vec::new();
    crate::authority::intent::codec::encode(&snapshot, &mut bytes).unwrap();
    std::fs::write(path, bytes).unwrap();
    let server = fx.start(3, roomy(), true, Some(addr)).await;
    let client = fx.client(server.addr, 0);
    let body = acquire(3, 4, u64::MAX);
    let refused = client
        .intent_acquire_once(&scope, &fx.volume(), &body)
        .await
        .unwrap();
    assert!(matches!(
        refused.ownership(&body).unwrap(),
        Verdict::EpochExhausted
    ));
    drop(client);
    server.stop().await;
}

#[tokio::test]
async fn real_intent_unprovisioned_and_enrollment_unavailable_never_provision() {
    let fx = Fixture::new(None);
    let server = fx.start(1, roomy(), false, None).await;
    let client = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let body = acquire(1, 2, 0);
    let answer = client
        .intent_acquire_once(&scope, &fx.volume(), &body)
        .await
        .unwrap();
    assert_eq!(answer.status(), 503);
    assert!(
        !fx.state
            .join(format!("{}.intent", fx.volume().as_str()))
            .exists()
    );
    drop(client);
    let addr = server.stop().await;
    let saved = std::fs::read(fx.enrollment.join(crate::enrollment::SET_NAME)).unwrap();
    std::fs::write(
        fx.enrollment.join(crate::enrollment::SET_NAME),
        b"invalid enrollment",
    )
    .unwrap();
    let server = fx.start(2, roomy(), true, Some(addr)).await;
    let client = fx.client(server.addr, 0);
    let answer = client
        .intent_acquire_once(&scope, &fx.volume(), &body)
        .await
        .unwrap();
    assert_eq!(answer.status(), 503);
    assert!(matches!(
        answer.ownership(&body).unwrap(),
        Verdict::EnrollmentUnavailable
    ));
    std::fs::write(fx.enrollment.join(crate::enrollment::SET_NAME), saved).unwrap();
    drop(client);
    server.stop().await;
}

#[tokio::test]
async fn real_publication_lands_with_epoch_mismatched_intent_snapshot() {
    use granary_client::{OwnedCandidate, PublishRequest, PublishResponse, StatusResponse};
    use granary_core::authlog::{Envelope, Epoch, encode_envelope};
    use granary_core::authority_answer::Head;
    use granary_core::decisionlog::DecisionLog as _;
    use granary_core::intent::UnknownCause;
    use granary_core::runmarker::{RunMarker, encode_marker};

    let fx = Fixture::new(None);
    let volume = fx.volume();
    let log_epoch = Epoch::from_bytes([8; 16]);
    let snapshot = wire_fixture::snapshot(wire_fixture::owned(1));
    assert_ne!(snapshot.epoch, log_epoch);
    let log = FileLog::new(&fx.state, true).unwrap();
    log.write_marker(&encode_marker(&RunMarker::Clean))
        .await
        .unwrap();
    log.initialise(&encode_envelope(&Envelope::new(volume.clone(), log_epoch)))
        .await
        .unwrap();
    log.intent_store().io.commit(&snapshot).unwrap();
    drop(log);
    let snapshot_path = fx.state.join(format!("{}.intent", volume.as_str()));
    let before = std::fs::read(&snapshot_path).unwrap();

    let server = fx.start(1, roomy(), false, None).await;
    let client = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let check_intent_refusal = async || {
        let reply = client
            .intent_readback_once(&scope, &volume, |_, _| true)
            .await
            .unwrap();
        assert_eq!(reply.status(), 503);
        assert!(matches!(
            reply.readback(&volume, |_, _| true),
            Verdict::Unknown(UnknownCause::Unavailable)
        ));
    };
    let read_status = async || {
        let StatusResponse::Observed(status) = client.status_once(volume.as_str()).await.unwrap()
        else {
            panic!("publication status must be available");
        };
        status.observation()
    };
    check_intent_refusal().await;
    let initial = read_status().await;
    assert_eq!(initial.epoch, log_epoch);

    let root = Arc::from(wire_fixture::root(3, &volume));
    let candidate = OwnedCandidate::new(volume.as_str(), root).unwrap();
    let publish = PublishRequest::new(
        volume.as_str(),
        initial.epoch,
        b"publish-genesis",
        candidate.clone(),
        vec![candidate],
    )
    .unwrap();
    let landed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match client.publish_once(&publish).await.unwrap() {
                PublishResponse::Landed(landed) => break landed.receipt(),
                PublishResponse::Accepted(_) | PublishResponse::Open(_) => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                other => panic!("genesis publication refused: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(landed.root_seq, 1);
    let status = read_status().await;
    assert_eq!(status.epoch, log_epoch);
    assert_eq!(status.head, Some(Head::new(Some((1, landed.stored_id)))));
    check_intent_refusal().await;
    drop(client);
    server.stop().await;
    assert_eq!(std::fs::read(snapshot_path).unwrap(), before);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one counted TLS fixture verifies the intent sequence and its published-root read control"
)]
async fn real_intent_prepared_bytes_do_not_enter_head_max_seq_or_objects() {
    let backend = Arc::new(ReadCountingStore::default());
    let fx = Fixture::new(Some(backend.clone()));
    let server = fx.start(1, roomy(), true, None).await;
    let client = fx.client(server.addr, 0);
    let scope = fx.scope(server.addr, 0);
    let snapshot_path = fx.state.join(format!("{}.intent", fx.volume().as_str()));
    let read_snapshot = || std::fs::read(&snapshot_path).unwrap();
    let initial_snapshot = read_snapshot();
    let before = backend.read_count();
    let acquire_body = acquire(1, 2, 0);
    let acquired = client
        .intent_acquire_once(&scope, &fx.volume(), &acquire_body)
        .await
        .unwrap();
    assert_eq!(acquired.status(), 200);
    let row = granted(&acquired).receipt;
    let acquired_snapshot = read_snapshot();
    assert_ne!(
        acquired_snapshot, initial_snapshot,
        "acquire changed no bytes"
    );

    let before_replay = backend.read_count();
    let replayed = client
        .intent_acquire_once(&scope, &fx.volume(), &acquire_body)
        .await
        .unwrap();
    assert_eq!(replayed.status(), acquired.status());
    assert_eq!(replayed.body(), acquired.body());
    assert_eq!(
        read_snapshot(),
        acquired_snapshot,
        "exact acquire replay changed the snapshot"
    );
    assert_eq!(
        backend.read_count(),
        before_replay,
        "exact acquire replay read the store"
    );

    let request = registration(row, 1);
    let registered = client
        .intent_register_once(&scope, &fx.volume(), &request, |_, _| true)
        .await
        .unwrap();
    assert_eq!(registered.status(), 200);
    let registered_snapshot = read_snapshot();
    assert_ne!(
        registered_snapshot, acquired_snapshot,
        "registration changed no bytes"
    );
    let read = client
        .intent_readback_once(&scope, &fx.volume(), |_, _| true)
        .await
        .unwrap();
    assert_eq!(read.status(), 200);
    let doc = intent::decode_register(&request, &fx.volume(), |_, _| true).unwrap();
    let selected = intent::decode_readback(read.body(), &fx.volume(), |_, _| true).unwrap();
    assert_eq!(selected.rows[0].root, doc.root);
    assert_eq!(
        read_snapshot(),
        registered_snapshot,
        "successful readback changed the snapshot"
    );
    assert_eq!(
        backend.read_count(),
        before,
        "acquire/register/readback read the store"
    );
    assert_eq!(client.max_seq(fx.volume().as_str()).await.unwrap(), None);
    assert!(matches!(
        client.get_root(fx.volume().as_str(), 1).await,
        Ok(None)
    ));
    assert!(
        granary_core::binstore::BinStore::get_meta(&client, fx.volume().as_str(), &doc.root_id())
            .await
            .is_err()
    );

    let before = backend.read_count();
    let row = intent::decode_receipt(registered.body()).unwrap();
    take_over_and_release(&client, &scope, &fx.volume(), row).await;
    assert_eq!(
        backend.read_count(),
        before,
        "takeover/release read the store"
    );
    let granary_client::StatusResponse::Observed(status) =
        client.status_once(fx.volume().as_str()).await.unwrap()
    else {
        panic!("authority status must be available");
    };
    let candidate =
        granary_client::OwnedCandidate::new(fx.volume().as_str(), Arc::from(doc.root)).unwrap();
    let publish = granary_client::PublishRequest::new(
        fx.volume().as_str(),
        status.observation().epoch,
        b"land-prepared",
        candidate.clone(),
        vec![candidate],
    )
    .unwrap();
    let mut landed = false;
    for _ in 0..16 {
        match client.publish_once(&publish).await.unwrap() {
            granary_client::PublishResponse::Landed(_) => {
                landed = true;
                break;
            }
            granary_client::PublishResponse::Accepted(_)
            | granary_client::PublishResponse::Open(_) => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            other => panic!("prepared publication refused: {other:?}"),
        }
    }
    assert!(landed, "only a landed publication permits a head");
    assert_eq!(client.max_seq(fx.volume().as_str()).await.unwrap(), Some(1));
    let before = backend.read_count();
    assert!(
        client
            .get_root(fx.volume().as_str(), 1)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        backend.read_count() > before,
        "published root read did not reach the backend"
    );

    drop(client);
    server.stop().await;
}

#[cfg(feature = "crash-points")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "child helper for the Linux guest crash matrix"]
async fn real_intent_crash_child() {
    let dir = PathBuf::from(std::env::var_os("GRANARY_INTENT_HTTP_CHILD").unwrap());
    let fx = Fixture::existing(dir.clone(), Arc::new(object_store::memory::InMemory::new()));
    let site = std::env::var("GRANARY_INTENT_HTTP_SITE").unwrap();
    let plan = if site == "control" {
        crate::authority::crash::Plan::List
    } else {
        crate::authority::crash::Plan::Kill {
            site: crate::authority::crash::Site::parse(&site).unwrap(),
            k: 1,
        }
    };
    crate::authority::crash::install(&dir.join("points"), plan).unwrap();
    let server = fx.start(9, roomy(), false, None).await;
    std::fs::write(dir.join("ready"), server.addr.to_string()).unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while !dir.join("stop").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    server.stop().await;
}

#[cfg(feature = "crash-points")]
struct Child(std::process::Child);
#[cfg(feature = "crash-points")]
impl Drop for Child {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

#[cfg(feature = "crash-points")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Linux guest: real TLS and filesystem process cuts; no power-loss claim"]
#[expect(
    clippy::too_many_lines,
    reason = "the guest process-cut product keeps fired-seam evidence, child custody, exact replay and disarmed controls in one schedule"
)]
async fn real_intent_linux_guest_crash_cuts_replay_exact_client_packets() {
    assert_eq!(
        std::env::consts::OS,
        "linux",
        "guest process-cut venue requires Linux"
    );
    let sites = [
        "IntentBeforeTemporary",
        "IntentTemporaryCreated",
        "IntentPartialWrite",
        "IntentTemporaryWritten",
        "IntentFileSynced",
        "IntentRenamed",
        "IntentDirectorySynced",
        "IntentStateInstalled",
        "IntentBeforeReply",
        "IntentReplySent",
        "control",
    ];
    let mut cases = 0;
    for operation in ["acquire", "takeover", "register", "release"] {
        for site in sites {
            let fx = Fixture::new(None);
            let server = fx.start(1, roomy(), true, None).await;
            let client = fx.client(server.addr, 0);
            let scope = fx.scope(server.addr, 0);
            let row = granted(
                &client
                    .intent_acquire_once(&scope, &fx.volume(), &acquire(1, 2, 0))
                    .await
                    .unwrap(),
            )
            .receipt;
            let row = if matches!(operation, "takeover" | "release") {
                let answer = client
                    .intent_register_once(&scope, &fx.volume(), &registration(row, 1), |_, _| true)
                    .await
                    .unwrap();
                intent::decode_receipt(answer.body()).unwrap()
            } else {
                row
            };
            let bytes = match operation {
                "acquire" => acquire(2, 3, row.epoch),
                "takeover" => takeover(row, 3),
                "register" => registration(row, 1),
                _ => release(row, 1),
            };
            drop(client);
            server.stop().await;
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "conformance_http::intents::real_intent_crash_child",
                        "--ignored",
                        "--test-threads=1",
                    ])
                    .env("GRANARY_INTENT_HTTP_CHILD", &fx.dir)
                    .env("GRANARY_INTENT_HTTP_SITE", site)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let addr: SocketAddr = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let Ok(text) = std::fs::read_to_string(fx.dir.join("ready")) {
                        break text.parse().unwrap();
                    }
                    assert!(
                        child.0.try_wait().unwrap().is_none(),
                        "crash child exited before readiness"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let client = fx.client(addr, 0);
            let scope = fx.scope(addr, 0);
            let send = async |client: &HttpStore| match operation {
                "acquire" => {
                    client
                        .intent_acquire_once(&scope, &fx.volume(), &bytes)
                        .await
                }
                "takeover" => {
                    client
                        .intent_takeover_once(&scope, &fx.volume(), &bytes)
                        .await
                }
                "register" => {
                    client
                        .intent_register_once(&scope, &fx.volume(), &bytes, |_, _| true)
                        .await
                }
                _ => {
                    client
                        .intent_release_once(&scope, &fx.volume(), &bytes)
                        .await
                }
            };
            let mut exchange = Box::pin(send(&client));
            if site == "control" {
                assert_eq!(
                    exchange.as_mut().await.unwrap().status(),
                    200,
                    "disarmed real-client control"
                );
                std::fs::write(fx.dir.join("stop"), b"stop").unwrap();
                tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        if let Some(status) = child.0.try_wait().unwrap() {
                            assert!(status.success());
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .unwrap();
            } else {
                let mut received = false;
                tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        if received {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        } else if let Ok(result) =
                            tokio::time::timeout(Duration::from_millis(10), exchange.as_mut()).await
                        {
                            assert_eq!(
                                site, "IntentReplySent",
                                "reply preceded fired cut {site}: {result:?}"
                            );
                            assert_eq!(result.unwrap().status(), 200);
                            received = true;
                        }
                        if std::fs::read_to_string(fx.dir.join("points"))
                            .unwrap_or_default()
                            .lines()
                            .any(|line| line == format!("REACHED {site} 1"))
                        {
                            break;
                        }
                        assert!(
                            child.0.try_wait().unwrap().is_none(),
                            "child exited without firing {site}"
                        );
                    }
                })
                .await
                .unwrap();
                child.0.kill().unwrap();
                assert!(!child.0.wait().unwrap().success());
            }
            drop(exchange);
            drop(client);
            let server = fx.start(10, roomy(), false, Some(addr)).await;
            let client = fx.client(server.addr, 0);
            let answer = send(&client).await.unwrap();
            assert_eq!(
                answer.status(),
                200,
                "exact replay after {operation}/{site}"
            );
            if operation == "register" {
                assert_eq!(intent::decode_receipt(answer.body()).unwrap().generation, 1);
            }
            drop(client);
            server.stop().await;
            cases += 1;
        }
    }
    assert_eq!(
        cases, 44,
        "identity-checked nonempty guest cut/control matrix"
    );
}
