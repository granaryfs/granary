// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::config::authority::AuthorityConfig;
use crate::enrollment::{EnrollmentReader, VerbOptions, mint};
use crate::protected_dir::tests::{chmod, scratch};
use granary_core::binstore::BinStore;
use granary_core::enrollment::{ClientSpkiDigest, PrincipalId, TenantName};
use granary_net::identity::ConnectionIdentity;
use granary_store::backend::GranaryStore;
use http_body_util::Full;
use hyper::{
    Request, Response,
    body::{Body, Bytes},
};
use object_store::memory::InMemory;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;

pub(super) const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([1; 16]);
pub(super) const DIGEST: ClientSpkiDigest = ClientSpkiDigest::from_bytes([1; 32]);
pub(super) const OPTIONS: VerbOptions = VerbOptions {
    accept_unsupported_filesystem: true,
};

struct Door;
impl SecureRandom for Door {
    fn fill(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        bytes.fill(1);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(super) enum Log {
    Sim(Arc<SimDecisionLog>, Arc<AtomicUsize>),
    File(Arc<FileLog>, Arc<AtomicUsize>),
}
impl Log {
    pub(super) fn append_calls(&self) -> usize {
        match self {
            Self::Sim(_, calls) | Self::File(_, calls) => calls.load(Ordering::Relaxed),
        }
    }
}
impl DecisionLog for Log {
    async fn read_marker(&self) -> Result<MarkerRead, LogIoError> {
        match self {
            Self::Sim(l, _) => l.read_marker().await,
            Self::File(l, _) => l.read_marker().await,
        }
    }
    async fn write_marker(&self, m: &EncodedMarker) -> Result<(), LogIoError> {
        match self {
            Self::Sim(l, _) => l.write_marker(m).await,
            Self::File(l, _) => l.write_marker(m).await,
        }
    }
    async fn read(&self, v: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        match self {
            Self::Sim(l, _) => l.read(v).await,
            Self::File(l, _) => l.read(v).await,
        }
    }
    async fn remove_temporary(&self, v: &VolumeName) -> Result<bool, LogIoError> {
        match self {
            Self::Sim(l, _) => l.remove_temporary(v).await,
            Self::File(l, _) => l.remove_temporary(v).await,
        }
    }
    async fn initialise(&self, e: &EncodedEnvelope) -> Result<(), LogIoError> {
        match self {
            Self::Sim(l, _) => l.initialise(e).await,
            Self::File(l, _) => l.initialise(e).await,
        }
    }
    async fn complete_namespace(&self, v: &VolumeName) -> Result<(), LogIoError> {
        match self {
            Self::Sim(l, _) => l.complete_namespace(v).await,
            Self::File(l, _) => l.complete_namespace(v).await,
        }
    }
    async fn append(&self, a: &Append) -> Result<(), LogIoError> {
        match self {
            Self::Sim(l, calls) => {
                calls.fetch_add(1, Ordering::Relaxed);
                l.append(a).await
            }
            Self::File(l, calls) => {
                calls.fetch_add(1, Ordering::Relaxed);
                l.append(a).await
            }
        }
    }
    async fn truncate(&self, v: &VolumeName, n: u64) -> Result<(), LogIoError> {
        match self {
            Self::Sim(l, _) => l.truncate(v, n).await,
            Self::File(l, _) => l.truncate(v, n).await,
        }
    }
    async fn resync(&self, v: &VolumeName) -> Result<(), LogIoError> {
        match self {
            Self::Sim(l, _) => l.resync(v).await,
            Self::File(l, _) => l.resync(v).await,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct Store {
    pub inner: TestStore,
    pub calls: Arc<AtomicUsize>,
    memory: Option<Arc<GranaryStore<Arc<InMemory>>>>,
    pub root_puts: Arc<AtomicUsize>,
}
impl Store {
    fn touched(&self) {
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}
impl RootStore for Store {
    async fn put_root(&self, v: &str, n: u64, b: Vec<u8>) -> Result<(), RootStoreError> {
        self.touched();
        self.root_puts.fetch_add(1, Ordering::Relaxed);
        if let Some(store) = &self.memory {
            return store.put_root(v, n, b).await;
        }
        self.inner.put_root(v, n, b).await
    }
    async fn get_root(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.touched();
        if let Some(store) = &self.memory {
            return store.get_root(v, n).await;
        }
        self.inner.get_root(v, n).await
    }
    async fn max_seq(&self, v: &str) -> Result<Option<u64>, RootStoreError> {
        self.touched();
        if let Some(store) = &self.memory {
            return store.max_seq(v).await;
        }
        self.inner.max_seq(v).await
    }
    async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.touched();
        if let Some(store) = &self.memory {
            return store.max_seq_above(v, floor).await;
        }
        self.inner.max_seq_above(v, floor).await
    }
    async fn read_hint(&self, v: &str, t: Option<&HintToken>) -> Result<HintRead, RootStoreError> {
        self.touched();
        if let Some(store) = &self.memory {
            return store.read_hint(v, t).await;
        }
        let unquoted = t.map(|t| HintToken(t.0.trim_matches('"').to_owned()));
        self.inner.read_hint(v, unquoted.as_ref()).await
    }
    async fn write_hint(&self, v: &str, n: u64) -> Result<(), RootStoreError> {
        self.touched();
        if let Some(store) = &self.memory {
            return store.write_hint(v, n).await;
        }
        self.inner.write_hint(v, n).await
    }
}
impl BinStore for Store {
    async fn put_meta(&self, v: &str, id: &GrainId, b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.touched();
        if let Some(store) = &self.memory {
            return BinStore::put_meta(store.as_ref(), v, id, b).await;
        }
        self.inner.inner.put_meta(v, id, b).await
    }
    async fn get_meta(&self, v: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.touched();
        if let Some(store) = &self.memory {
            return BinStore::get_meta(store.as_ref(), v, id).await;
        }
        self.inner.inner.get_meta(v, id).await
    }
    async fn put_bin(&self, d: &[u8; 32], b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.touched();
        if let Some(store) = &self.memory {
            return BinStore::put_bin(store.as_ref(), d, b).await;
        }
        self.inner.inner.put_bin(d, b).await
    }
    async fn get_bin_range(&self, d: &[u8; 32], o: u64, n: u32) -> Result<Vec<u8>, RootStoreError> {
        self.touched();
        if let Some(store) = &self.memory {
            return BinStore::get_bin_range(store.as_ref(), d, o, n).await;
        }
        self.inner.inner.get_bin_range(d, o, n).await
    }
}

pub(super) type GatewayDriver =
    AuthorityDriver<Log, Store, FixedClock, SimRng, SeededSecureRandom, YieldPause>;
pub(super) struct Fx {
    pub service: crate::GrainService<Store>,
    pub handle: AuthorityHandle,
    pub log: Log,
    pub store: Store,
    pub controls: Arc<crate::PrincipalControls>,
    pub clock: Arc<crate::controls::tests::TestClock>,
    pub reader: EnrollmentReader,
    pub dir: PathBuf,
    pub state_dir: PathBuf,
    pub config: AuthorityConfig,
    admission: crate::Admission,
}
impl Fx {
    pub(super) async fn new(
        file: bool,
        logs: &[VolumeName],
        records: &[Record],
    ) -> (Self, GatewayDriver) {
        Self::with_inventory(file, logs, records, &[a()]).await
    }

    pub(super) async fn with_inventory(
        file: bool,
        logs: &[VolumeName],
        records: &[Record],
        volumes: &[VolumeName],
    ) -> (Self, GatewayDriver) {
        Self::with_backend(file, logs, records, volumes, None).await
    }

    pub(super) async fn with_content(
        backend: Arc<InMemory>,
        limits: crate::ValidationLimits,
    ) -> (Self, GatewayDriver) {
        Self::with_backend(false, &[a()], &[], &[a()], Some((backend, limits))).await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one fixture constructs both log backends with the same configured inventory"
    )]
    pub(super) async fn with_backend(
        file: bool,
        logs: &[VolumeName],
        records: &[Record],
        volumes: &[VolumeName],
        backend: Option<(Arc<InMemory>, crate::ValidationLimits)>,
    ) -> (Self, GatewayDriver) {
        let dir = scratch("publish-gateway");
        let state_dir = dir.join("state");
        let enrollment_dir = dir.join("enrollment");
        for p in [&state_dir, &enrollment_dir] {
            std::fs::create_dir(p).unwrap();
            chmod(p, 0o700);
        }
        let sim = Sim::new();
        let append_calls = Arc::new(AtomicUsize::new(0));
        let log = if file {
            Log::File(
                Arc::new(FileLog::new(&state_dir, true).unwrap()),
                append_calls,
            )
        } else {
            Log::Sim(sim_log(&sim, LogFaults::none()), append_calls)
        };
        log.write_marker(&encode_marker(&RunMarker::Clean))
            .await
            .unwrap();
        for v in logs {
            log.initialise(&encode_envelope(&envelope(v, WORLD_EPOCH)))
                .await
                .unwrap();
            for r in records {
                log.append(&encode_append(&envelope(v, WORLD_EPOCH), r).unwrap())
                    .await
                    .unwrap();
            }
        }
        mint(
            &enrollment_dir,
            OPTIONS,
            &TenantName::parse("test").unwrap(),
            DIGEST,
            &mut Door,
        )
        .unwrap();
        let reader = EnrollmentReader::open(&enrollment_dir, true).unwrap();
        let clock = Arc::new(crate::controls::tests::TestClock::default());
        let controls = Arc::new(crate::PrincipalControls::new(
            crate::ControlsConfig::default(),
            clock.clone(),
        ));
        let config = AuthorityConfig {
            authority_profile: crate::config::authority::AuthorityProfile::SingleProcess,
            state_dir: state_dir.clone(),
            enrollment_dir,
            client_ca: dir.join("unused-ca"),
            volumes: volumes
                .iter()
                .map(|v| (v.clone(), vec![*publisher().public_key()]))
                .collect(),
            accept_unsupported_filesystem: true,
            controls: crate::ControlsConfig::default(),
        };
        let admission = backend
            .as_ref()
            .map_or_else(crate::Admission::chain_fixture, |(store, limits)| {
                crate::Admission::memory(store.clone()).with_limits(*limits, 2)
            });
        let store = Store {
            memory: backend.map(|(store, _)| Arc::new(GranaryStore::new(store))),
            root_puts: Arc::new(AtomicUsize::new(0)),
            inner: TestStore::new(sim.node(1, Faults::none())),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let inventory: Vec<_> = config
            .volumes
            .iter()
            .map(|(v, keys)| {
                let config =
                    VolumeConfig::new(v.clone(), TrustedKeys::new(keys.iter().copied()).unwrap());
                match &log {
                    Log::File(log, _) => config.with_intents(log.intent_store()),
                    Log::Sim(..) => config,
                }
            })
            .collect();
        let (handle, driver) = start(
            AuthorityParts {
                admission: admission.clone(),
                log: log.clone(),
                store: store.clone(),
                clock: FixedClock,
                rng: rng(1),
                secure_random: secure(1),
                pause: YieldPause,
            },
            boot(1),
            inventory,
        )
        .await
        .unwrap();
        let service = crate::GrainService::for_test(
            Arc::new(store.clone()),
            "",
            crate::VerifyPolicy::seam_only(),
            Some(crate::admission::DECLARED_MAX_EXTENT),
            crate::adapter::WRITE_BODY_BUDGET_BYTES,
            crate::adapter::READ_BODY_BUDGET_BYTES,
            crate::adapter::VERIFY_PERMIT_MAX_WAIT,
            None,
        )
        .with_authority_writes(
            reader.clone(),
            controls.clone(),
            Arc::new(crate::refusals::RefusalCounters::default()),
            &config,
            handle.clone(),
        );
        (
            Self {
                service,
                handle,
                log,
                store,
                controls,
                clock,
                reader,
                dir,
                state_dir,
                config,
                admission,
            },
            driver,
        )
    }
    pub(super) fn parts(
        &self,
    ) -> AuthorityParts<Log, Store, FixedClock, SimRng, SeededSecureRandom, YieldPause> {
        AuthorityParts {
            admission: self.admission.clone(),
            log: self.log.clone(),
            store: self.store.clone(),
            clock: FixedClock,
            rng: rng(1),
            secure_random: secure(1),
            pause: YieldPause,
        }
    }
    pub(super) fn service_with_budget(
        &self,
        handle: AuthorityHandle,
        budget: u64,
    ) -> crate::GrainService<Store> {
        crate::GrainService::for_test(
            Arc::new(self.store.clone()),
            "",
            crate::VerifyPolicy::seam_only(),
            Some(crate::admission::DECLARED_MAX_EXTENT),
            budget,
            crate::adapter::READ_BODY_BUDGET_BYTES,
            crate::adapter::VERIFY_PERMIT_MAX_WAIT,
            None,
        )
        .with_authority_writes(
            self.reader.clone(),
            self.controls.clone(),
            self.service.refusal_counters().unwrap(),
            &self.config,
            handle,
        )
    }
    pub(super) fn with_dispatch_deadline(mut self, deadline: Duration) -> Self {
        self.service =
            crate::GrainService::with_deadline(Arc::new(self.store.clone()), "", 2, Some(deadline))
                .with_authority_writes(
                    self.reader.clone(),
                    self.controls.clone(),
                    self.service.refusal_counters().unwrap(),
                    &self.config,
                    self.handle.clone(),
                );
        self
    }
    pub(super) async fn send<B>(&self, request: Request<B>) -> Response<Full<Bytes>>
    where
        B: Body<Data = Bytes> + Unpin,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let declared = request
            .headers()
            .get("content-length")
            .map(|h| h.to_str().unwrap().parse().unwrap());
        let request = request.map(|body| Received { body, declared });
        tokio::time::timeout(
            Duration::from_secs(10),
            self.service.request_for_test(request),
        )
        .await
        .unwrap()
    }
    pub(super) fn refill(&self, n: i128) {
        self.clock.set(n * 1_000_000_000);
    }
    pub(super) async fn bytes(&self) -> Vec<Option<Vec<u8>>> {
        let mut out = Vec::new();
        for v in [a(), b(), c()] {
            out.push(match self.log {
                Log::File(..) => {
                    match std::fs::read(self.state_dir.join(format!("{}.log", v.as_str()))) {
                        Ok(bytes) => Some(bytes),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                        Err(e) => panic!("snapshot: {e}"),
                    }
                }
                Log::Sim(..) => self.log.read(&v).await.unwrap(),
            });
        }
        out
    }
    pub(super) async fn records(&self) -> Vec<Record> {
        let bytes = self.log.read(&a()).await.unwrap().unwrap();
        let Classified::Log { records, .. } = classify(&bytes, &a()).unwrap() else {
            panic!("envelope")
        };
        records
    }
}

pub(super) fn request<B>(method: &str, path: &str, body: B) -> Request<B> {
    let mut r = Request::builder()
        .method(method)
        .uri(path)
        .body(body)
        .unwrap();
    r.extensions_mut()
        .insert(ConnectionIdentity::Verified(DIGEST));
    r
}
pub(super) fn publish_to(v: &VolumeName, op: u8, body: Vec<u8>) -> Request<Full<Bytes>> {
    let mut r = request(
        "POST",
        &format!("/volume/{}/publish", v.as_str()),
        Full::new(Bytes::from(body)),
    );
    r.headers_mut()
        .insert("granary-operation", format!("{op:02x}").parse().unwrap());
    r.headers_mut().insert(
        "granary-epoch",
        format!("{WORLD_EPOCH:02x}").repeat(16).parse().unwrap(),
    );
    r
}
pub(super) fn publish(op: u8, body: Vec<u8>) -> Request<Full<Bytes>> {
    publish_to(&a(), op, body)
}
pub(super) fn direct(v: &VolumeName) -> String {
    format!("/volume/{}/root/00000000000000000001", v.as_str())
}

/// Incoming exposes the transport's declared length, not the test buffer's.
struct Received<B> {
    body: B,
    declared: Option<u64>,
}
impl<B: Body + Unpin> Body for Received<B> {
    type Data = B::Data;
    type Error = B::Error;
    fn size_hint(&self) -> hyper::body::SizeHint {
        let mut hint = hyper::body::SizeHint::new();
        if let Some(n) = self.declared {
            hint.set_exact(n);
        }
        hint
    }
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }
}

/// Real enrollment refresh uses the runtime's blocking pool and timers.
/// Held store reads isolate log-comparison intervals from publication.
#[expect(
    clippy::disallowed_methods,
    reason = "HTTP integration uses real enrollment I/O; a JoinSet owns and aborts the driver if a test fails"
)]
pub(super) fn spawn_driver(driver: GatewayDriver) -> tokio::task::JoinSet<RunEnd> {
    let mut run = tokio::task::JoinSet::new();
    run.spawn(driver.run());
    run
}
