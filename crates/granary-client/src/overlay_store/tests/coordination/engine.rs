// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    ClientMetrics, MonotonicClock, MonotonicDomain, MonotonicToken, SyncContent, SyncEngine,
    SyncOptions, SyncRemote, SyncRuntime, SyncTarget, TokioSyncRuntime,
};
use granary_core::{
    binstore::BinStore,
    grainsource::{GrainSource, GrainSourceError},
    manifest::{self, EntryKind, FileGrains},
    rng::Rng as _,
    rootstore::{RootStoreError, filter_above},
};
use granary_store::crypto::{SigningKey, TrustedKeys};
use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};
use tokio::sync::Notify;
use tracing::instrument::WithSubscriber as _;

mod commits;
mod incremental;

#[tokio::test]
async fn checkpoint_growth_then_shrink_syncs_final_bytes() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", &[1; 100]);
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.write(stage, 100, &[2; 100])?;
            t.truncate(stage, 150)
        })
        .unwrap();
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .expect("growth followed by shrink refused final capture");
    let mut expected = vec![1; 100];
    expected.extend([2; 50]);
    commits::assert_file(
        &fixture,
        &fixture.remote.authority.lock().unwrap().root,
        "file",
        &expected,
    );
}

type ObjectPause = (Arc<Notify>, Arc<(Mutex<bool>, std::sync::Condvar)>);

#[derive(Default)]
struct Content {
    unavailable: AtomicBool,
    put_conflict: AtomicBool,
    fail_get: AtomicU64,
    objects: Mutex<BTreeMap<GrainId, Vec<u8>>>,
    /// Objects read through `GrainSource::get`.
    gets: AtomicU64,
    payloads: Mutex<BTreeMap<GrainId, (u64, FileGrains)>>,
    pause: Mutex<Option<ObjectPause>>,
    pause_get: Mutex<Option<ObjectPause>>,
    blocking_completed: Arc<AtomicU64>,
    blocking_finished: Arc<Notify>,
    /// The runtime's retry-jitter words: every draw is this word when set,
    /// and otherwise the next of `jitter`'s stream.
    jitter_word: Mutex<Option<u64>>,
    /// Seeded with 0 at the first draw, so a row's backoffs replay.
    jitter: Mutex<Option<SeededRng>>,
    /// Every interval the runtime was asked to sleep, in order.
    sleeps: Mutex<Vec<Duration>>,
    after_sleep: Mutex<Option<AfterSleep>>,
    /// The task awaiting the next blocking work to complete panics once.
    panic_blocking: AtomicBool,
    /// The next spawned task that panics reports it only once `lost_release`
    /// is notified.
    hold_lost: AtomicBool,
    lost_release: Notify,
}

type AfterSleep = Box<dyn FnMut() + Send>;
impl GrainSource for Content {
    fn has(&self, id: &GrainId) -> bool {
        self.objects.lock().unwrap().contains_key(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        if self.unavailable.load(Ordering::Relaxed) {
            return Err(GrainSourceError::Backend("unavailable fixture".into()));
        }
        if let Some((entered, release)) = self.pause_get.lock().unwrap().take() {
            entered.notify_one();
            let (lock, wake) = &*release;
            let ready = lock.lock().unwrap();
            let (ready, timeout) = wake
                .wait_timeout_while(ready, Duration::from_secs(3), |ready| !*ready)
                .unwrap();
            assert!(
                *ready && !timeout.timed_out(),
                "verifier read was never released"
            );
        }
        let call = self.gets.fetch_add(1, Ordering::Relaxed) + 1;
        if call == self.fail_get.load(Ordering::Relaxed) {
            return Err(GrainSourceError::Backend("unavailable fixture read".into()));
        }
        self.objects
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(GrainSourceError::Missing(*id))
    }
}
impl SyncContent for Content {
    fn payload(&self, content: GrainId) -> Result<FileGrains, CoordinationError> {
        self.payloads
            .lock()
            .unwrap()
            .get(&content)
            .map(|(_, grains)| grains.clone())
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
        let refs = crate::writable_store::capture::captured_refs(self, size, &grains).unwrap();
        let mut data = Vec::with_capacity(length);
        let mut at = 0_u64;
        let limit = offset + length as u64;
        for grain in refs {
            let end = at + u64::from(grain.unpacked_len);
            if end > offset && at < limit {
                let bytes = self.get(&grain.id).unwrap();
                let from = usize::try_from(offset.saturating_sub(at)).unwrap();
                let to = usize::try_from(limit.min(end) - at).unwrap();
                data.extend_from_slice(&bytes[from..to]);
            }
            at = end;
            if at >= limit {
                break;
            }
        }
        assert_eq!(
            GrainId::of(&manifest::node::file_payload(size, &grains).unwrap()),
            content
        );
        assert_eq!(data.len(), length);
        Ok(data)
    }
    fn put_object(&self, id: GrainId, bytes: &[u8]) -> Result<(), CoordinationError> {
        if self.put_conflict.swap(false, Ordering::Relaxed) {
            return Err(CoordinationError::Overlay(OverlayError::Conflict));
        }
        let pause = self.pause.lock().unwrap().take();
        if let Some((entered, release)) = pause {
            entered.notify_one();
            let (lock, wake) = &*release;
            let mut ready = lock.lock().unwrap();
            while !*ready {
                ready = wake.wait(ready).unwrap();
            }
        }
        assert_eq!(GrainId::of(bytes), id);
        self.objects.lock().unwrap().insert(id, bytes.to_vec());
        Ok(())
    }
    fn remember_payload(
        &self,
        content: GrainId,
        size: u64,
        grains: &FileGrains,
    ) -> Result<(), CoordinationError> {
        assert_eq!(
            GrainId::of(&manifest::node::file_payload(size, grains).unwrap()),
            content
        );
        self.payloads
            .lock()
            .unwrap()
            .insert(content, (size, grains.clone()));
        Ok(())
    }
}

#[tokio::test]
async fn cancellation_during_materialisation_preserves_live_writes_and_releases_floor() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", &vec![7; 262_144]);
    let entered = Arc::new(Notify::new());
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    *fixture.content.pause.lock().unwrap() = Some((entered.clone(), release.clone()));
    let waiter = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    entered.notified().await;
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(stage, 0, b"later").map(|_| ()))
        .unwrap();
    drop(waiter);
    *release.0.lock().unwrap() = true;
    release.1.notify_one();
    fixture.settled().await;
    assert!(fixture.remote.attempts.lock().unwrap().is_empty());
    assert_eq!(fixture.marks(), 0);
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0))
        .unwrap();
}

struct Time {
    origin: tokio::time::Instant,
    wall: AtomicU64,
    scripted_wall: Mutex<Option<crate::overlay_test_support::Time>>,
    ticks: AtomicU64,
    domain: MonotonicDomain,
    unavailable: AtomicBool,
    start_unavailable: AtomicBool,
}
impl Time {
    fn new() -> Self {
        Self {
            origin: TokioSyncRuntime.now(),
            wall: AtomicU64::new(1000),
            scripted_wall: Mutex::default(),
            ticks: AtomicU64::new(10),
            domain: MonotonicDomain::default(),
            unavailable: AtomicBool::new(false),
            start_unavailable: AtomicBool::new(false),
        }
    }
}
impl Clock for Time {
    fn now(&self) -> Timestamp {
        if let Some(clock) = self.scripted_wall.lock().unwrap().as_ref() {
            return clock.now();
        }
        let elapsed = self.origin.elapsed();
        Timestamp {
            secs: i64::try_from(self.wall.load(Ordering::Relaxed) + elapsed.as_secs()).unwrap(),
            nanos: elapsed.subsec_nanos(),
        }
    }
}
impl MonotonicClock for Time {
    fn start(&self) -> Option<MonotonicToken> {
        if self.start_unavailable.load(Ordering::Relaxed) {
            return None;
        }
        Some(
            self.domain
                .token(Duration::from_millis(self.ticks.load(Ordering::Relaxed))),
        )
    }
    fn elapsed(&self, start: &MonotonicToken) -> Option<Duration> {
        if self.unavailable.load(Ordering::Relaxed) {
            None
        } else {
            self.domain.elapsed(
                start,
                Duration::from_millis(self.ticks.load(Ordering::Relaxed)),
            )
        }
    }
}

struct Remote {
    offline: AtomicBool,
    root_reads: Arc<AtomicU64>,
    unavailable_parent_read: AtomicU64,
    corrupt_probe: AtomicU64,
    recovery_reads: AtomicU64,
    recovery_read_delay: AtomicU64,
    recovery_sends: AtomicU64,
    change_selection: AtomicBool,
    supersede_selection: AtomicBool,
    forget_selection: AtomicBool,
    readback_failure: Mutex<Option<IntentTransportError>>,
    objects: Arc<super::super::sync_objects::Remote>,
    authority: Arc<Mutex<Authority>>,
    time: Arc<Time>,
    hold_first: Arc<AtomicBool>,
    unknown: Arc<AtomicBool>,
    hold_upload: AtomicBool,
    hold_meta: AtomicBool,
    panic_register: AtomicBool,
    /// The next status read panics, or fails.
    panic_status: AtomicBool,
    fail_status: AtomicBool,
    entered: Arc<Notify>,
    release: Arc<Notify>,
    upload_entered: Notify,
    upload_release: Notify,
    attempts: Arc<Mutex<Vec<Vec<u8>>>>,
    published: Arc<Mutex<BTreeMap<u64, Vec<u8>>>>,
    publication_plan: Arc<Mutex<std::collections::VecDeque<commits::PublishPlan>>>,
    publication_sends: Arc<Mutex<Vec<Vec<u8>>>>,
    publication_operations: Arc<Mutex<Vec<Vec<u8>>>>,
    publication_observer: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Sends scripted `Hold`, held until the test releases them.
    publish_hold: crate::overlay_store::tests::publish_hold::PublishHold,
    /// Landing probes made so far, and the one, counted from one, that
    /// fails with a transport error; zero fails none.
    probes: AtomicU64,
    probe_delay: Mutex<Option<Duration>>,
    failed_probe: AtomicU64,
    listing_fault: Mutex<Option<RootStoreError>>,
    root_probe_fault: Mutex<Option<RootStoreError>>,
    post_listing_probe: PostListingProbe,
}

#[derive(Default)]
struct PostListingProbe {
    armed: AtomicBool,
    observer: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}
impl PostListingProbe {
    fn inherit(&self) -> Self {
        Self {
            armed: AtomicBool::new(false),
            observer: Mutex::new(self.observer.lock().unwrap().clone()),
        }
    }
    fn set(&self, observer: Arc<dyn Fn() + Send + Sync>) {
        *self.observer.lock().unwrap() = Some(observer);
    }
    fn arm(&self) {
        self.armed
            .store(self.observer.lock().unwrap().is_some(), Ordering::Relaxed);
    }
    fn observe(&self) {
        if self.armed.swap(false, Ordering::Relaxed)
            && let Some(observer) = self.observer.lock().unwrap().as_ref()
        {
            observer();
        }
    }
}
impl BinStore for Remote {
    async fn put_bin(&self, digest: &[u8; 32], bytes: Vec<u8>) -> Result<bool, RootStoreError> {
        if self.hold_upload.load(Ordering::Relaxed) {
            self.upload_entered.notify_one();
            self.upload_release.notified().await;
        }
        self.objects.put_bin(digest, bytes).await
    }
    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        if self.hold_meta.swap(false, Ordering::Relaxed) {
            self.upload_entered.notify_one();
            self.upload_release.notified().await;
        }
        self.objects.put_meta(volume, id, bytes).await
    }
    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        self.objects.get_meta(volume, id).await
    }
    async fn get_bin_range(
        &self,
        digest: &[u8; 32],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        self.objects.get_bin_range(digest, offset, len).await
    }
}
impl SyncRemote for Remote {
    async fn register_once(
        &self,
        request: &PendingIntent,
        trusted: &TrustedKeys,
    ) -> Result<IntentReply, IntentTransportError> {
        assert!(
            !self.panic_register.load(Ordering::Relaxed),
            "fixture registration task panics"
        );
        intent::decode_register(request.bytes(), request.volume(), |doc, prefix| {
            granary_store::crypto::check_signatures(doc, prefix, trusted).is_ok()
        })
        .unwrap();
        self.attempts.lock().unwrap().push(request.bytes().to_vec());
        let answer = self.authority.lock().unwrap().send(request);
        if self.hold_first.swap(false, Ordering::Relaxed) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.time.ticks.store(35, Ordering::Relaxed);
        if self.unknown.load(Ordering::Relaxed) {
            Err(IntentTransportError::Transport)
        } else {
            Ok(answer)
        }
    }
    async fn release_once(
        &self,
        request: &PendingIntent,
    ) -> Result<IntentReply, IntentTransportError> {
        Ok(self.authority.lock().unwrap().send(request))
    }
}

struct TrackedRuntime(Arc<Content>);
impl SyncRuntime for TrackedRuntime {
    fn random_u64(&self) -> u64 {
        if let Some(word) = *self.0.jitter_word.lock().unwrap() {
            return word;
        }
        self.0
            .jitter
            .lock()
            .unwrap()
            .get_or_insert_with(|| SeededRng::new(0))
            .next_u64()
    }
    fn now(&self) -> tokio::time::Instant {
        TokioSyncRuntime.now()
    }
    fn spawn<T: Send + 'static>(
        &self,
        work: impl std::future::Future<Output = T> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        let content = self.0.clone();
        let spawned = TokioSyncRuntime.spawn(work);
        async move {
            let result = spawned.await;
            if result.is_err() && content.hold_lost.swap(false, Ordering::AcqRel) {
                content.lost_release.notified().await;
            }
            result
        }
    }
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        let content = self.0.clone();
        let panics = self.0.clone();
        let blocking = TokioSyncRuntime.blocking(move || {
            let result = work();
            content.blocking_completed.fetch_add(1, Ordering::Release);
            content.blocking_finished.notify_one();
            result
        });
        async move {
            let result = blocking.await;
            assert!(
                !panics.panic_blocking.swap(false, Ordering::AcqRel),
                "fixture operation panics"
            );
            result
        }
    }
    fn blocking_async<T: Send + 'static, F: std::future::Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        TokioSyncRuntime.blocking_async(work)
    }
    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> + Send {
        self.0.sleeps.lock().unwrap().push(duration);
        let content = self.0.clone();
        let sleep = TokioSyncRuntime.sleep(duration);
        async move {
            sleep.await;
            if let Some(after_sleep) = content.after_sleep.lock().unwrap().as_mut() {
                after_sleep();
            }
        }
    }
    fn timeout_at<T: Send>(
        &self,
        deadline: tokio::time::Instant,
        work: impl std::future::Future<Output = T> + Send,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        TokioSyncRuntime.timeout_at(deadline, work)
    }
}

type Engine = SyncEngine<SimIo, Remote, Content, Time, Time, TrackedRuntime>;
struct Fixture {
    _scratch: Scratch,
    io: SimIo,
    store: Arc<Mutex<WritableStore<SimIo>>>,
    engine: Arc<Engine>,
    remote: Arc<Remote>,
    metrics: ClientMetrics,
    base: GrainId,
    content: Arc<Content>,
}
/// A published base and everything the engine needs to attach over it.
struct Basis {
    objects: super::super::sync_objects::Remote,
    bytes: Vec<u8>,
    trusted: TrustedKeys,
    nodes: BTreeMap<GrainId, Vec<u8>>,
    entries: Vec<OverlayEntry>,
}
impl Basis {
    async fn empty() -> Self {
        let objects = super::super::sync_objects::Remote::default();
        let (bytes, trusted) = super::super::sync_objects::base(&objects).await;
        let tree = manifest::build_dir(&[]).unwrap();
        Self {
            objects,
            bytes,
            trusted,
            nodes: tree.nodes.into_iter().collect(),
            entries: vec![],
        }
    }
}
impl Fixture {
    async fn new() -> Self {
        Self::over(Basis::empty().await)
            .await
            .unwrap_or_else(|error| panic!("fixture engine refused its base: {error}"))
    }
    async fn over(basis: Basis) -> Result<Self, CoordinationError> {
        Self::over_capped(basis, 134_217_728).await
    }
    #[expect(
        clippy::too_many_lines,
        reason = "the store, remote and initial published base are wired together"
    )]
    async fn over_capped(basis: Basis, capacity: u64) -> Result<Self, CoordinationError> {
        let Basis {
            objects,
            bytes: base,
            trusted,
            nodes,
            entries,
        } = basis;
        let scratch = Scratch::new();
        let io = SimIo::default();
        let mut settings = config(&scratch.0);
        settings.cap = capacity;
        settings.ownership_completion_reserve =
            granary_core::overlay_ownership::REPLACEMENT_RESERVE;
        let mut local = WritableStore::new(
            Store::open(&scratch.0).unwrap(),
            settings,
            io.clone(),
            &mut Entropy(10),
            crate::FaultControl::default(),
            |_, _| true,
        )
        .unwrap();
        let mut authority = Authority::default();
        acquire(&mut local, &mut authority);
        let mut h = header();
        h.writer = local.writer_uuid();
        h.base_root = GrainId::of(&base);
        local
            .open_overlay(h, entries, &mut Source::default(), io.clone())
            .unwrap();
        register(&mut local, &mut authority, 1);
        let time = Arc::new(Time::new());
        let remote = Arc::new(Remote {
            offline: AtomicBool::new(false),
            root_reads: Arc::new(AtomicU64::new(0)),
            unavailable_parent_read: AtomicU64::new(0),
            corrupt_probe: AtomicU64::new(0),
            recovery_reads: AtomicU64::new(0),
            recovery_read_delay: AtomicU64::new(0),
            recovery_sends: AtomicU64::new(0),
            change_selection: AtomicBool::new(false),
            supersede_selection: AtomicBool::new(false),
            forget_selection: AtomicBool::new(false),
            readback_failure: Mutex::new(None),
            publication_plan: Arc::default(),
            publication_sends: Arc::default(),
            publication_operations: Arc::default(),
            publication_observer: Mutex::default(),
            publish_hold: crate::overlay_store::tests::publish_hold::PublishHold::default(),
            probes: AtomicU64::new(0),
            probe_delay: Mutex::new(None),
            failed_probe: AtomicU64::new(0),
            listing_fault: Mutex::new(None),
            root_probe_fault: Mutex::new(None),
            post_listing_probe: PostListingProbe::default(),
            published: Arc::new(Mutex::new([(1, base.clone())].into_iter().collect())),
            objects: Arc::new(objects),
            authority: Arc::new(Mutex::new(authority)),
            time: time.clone(),
            hold_first: Arc::new(AtomicBool::new(false)),
            unknown: Arc::new(AtomicBool::new(false)),
            hold_upload: AtomicBool::new(false),
            hold_meta: AtomicBool::new(false),
            panic_register: AtomicBool::new(false),
            panic_status: AtomicBool::new(false),
            fail_status: AtomicBool::new(false),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            upload_entered: Notify::new(),
            upload_release: Notify::new(),
            attempts: Arc::new(Mutex::new(Vec::new())),
        });
        let metrics = ClientMetrics::new(&mut Entropy(91));
        let content = Arc::new(Content::default());
        content.objects.lock().unwrap().extend(nodes);
        let store = Arc::new(Mutex::new(local));
        let engine = SyncEngine::with_runtime(
            store.clone(),
            remote.clone(),
            content.clone(),
            time.clone(),
            time,
            SigningKey::from_seed(&[39; 32]).unwrap(),
            trusted,
            base.clone(),
            metrics.clone(),
            Arc::new(TrackedRuntime(content.clone())),
        )
        .await?;
        Ok(Self {
            _scratch: scratch,
            io,
            store,
            engine,
            remote,
            metrics,
            base: GrainId::of(&base),
            content,
        })
    }
    fn create(&self, path: &str, bytes: &[u8]) -> u64 {
        self.store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                let stage =
                    t.create_file(crate::overlay_store::tests::incremental::loc(path), false)?;
                for (index, chunk) in bytes.chunks(65_536).enumerate() {
                    t.write(stage, (index * 65_536) as u64, chunk)?;
                }
                Ok(stage)
            })
            .unwrap()
    }
    fn metrics(&self) -> String {
        self.metrics
            .snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap()
    }
    fn registered(&self) -> RootDoc {
        granary_core::root::decode_root(&self.remote.authority.lock().unwrap().root).unwrap()
    }
    fn pending_registrations(&self) -> Vec<granary_core::overlay_ownership::Pending> {
        self.store
            .lock()
            .unwrap()
            .snapshot()
            .pending
            .iter()
            .filter(|p| p.operation == Operation::Register && !p.terminal)
            .cloned()
            .collect()
    }
    fn marks(&self) -> usize {
        let model = self.io.0.lock().unwrap();
        let (_, id) = model
            .names
            .iter()
            .find(|(path, _)| path.file_name().unwrap() == "journal")
            .unwrap();
        let bytes = &model.files[id].1;
        let mut marks = 0;
        granary_core::overlay_journal::scan_journal_with(bytes, |_, record| {
            if matches!(record, Record::FileSynced { .. }) {
                marks += 1;
            }
        })
        .unwrap();
        marks
    }
    async fn settled(&self) {
        for _ in 0..2000 {
            let settled = {
                let mut local = self.store.lock().unwrap();
                local
                    .snapshot()
                    .pending
                    .iter()
                    .all(|p| p.context.is_empty())
                    && local
                        .overlay_transaction(|t| Ok(t.summary().captured_bytes))
                        .unwrap()
                        < 8192
                    && self.engine.workspace_held_for_test() == 0
            };
            if settled {
                return;
            }
            TokioSyncRuntime.sleep(Duration::from_millis(1)).await;
        }
        panic!("supervisor did not release exact capture floors");
    }
}

impl granary_core::rootstore::RootStore for Remote {
    async fn put_root(&self, _: &str, _: u64, _: Vec<u8>) -> Result<(), RootStoreError> {
        panic!("sync attempted publication")
    }
    async fn get_root(&self, _: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.root_reads.fetch_add(1, Ordering::Relaxed);
        if seq == 1
            && self
                .unavailable_parent_read
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok_and(|n| n == 1)
        {
            return Err(RootStoreError::Backend("unavailable root fixture".into()));
        }
        if self.offline.load(Ordering::Relaxed) {
            return Err(RootStoreError::Backend("offline fixture".into()));
        }
        Ok(self.published.lock().unwrap().get(&seq).cloned())
    }
    async fn max_seq(&self, _: &str) -> Result<Option<u64>, RootStoreError> {
        if let Some(error) = self.listing_fault.lock().unwrap().take() {
            return Err(error);
        }
        self.post_listing_probe.arm();
        Ok(self.published.lock().unwrap().keys().copied().max())
    }
    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
    async fn read_hint(
        &self,
        _: &str,
        _: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
        Ok(granary_core::rootstore::HintRead::Missing)
    }
    async fn write_hint(&self, _: &str, _: u64) -> Result<(), RootStoreError> {
        panic!("sync advanced hint")
    }
}

fn fixture_submission(
    fixture: &Fixture,
    bytes: Vec<u8>,
) -> granary_core::retained_submission::Submission {
    let (scope, writer) = {
        let local = fixture.store.lock().unwrap();
        (local.snapshot().scope.clone(), local.writer_uuid())
    };
    submission(scope, writer, bytes)
}

async fn fired(faults: &FaultControl, name: &str, phase: &str) {
    // Contended durable syncs can delay arrival at the seam on macOS.
    let deadline = TokioSyncRuntime.now() + Duration::from_secs(10);
    while faults.sync_fired().is_empty() && TokioSyncRuntime.now() < deadline {
        TokioSyncRuntime.sleep(Duration::from_millis(1)).await;
    }
    let events = faults.sync_fired();
    let expected = (name, phase, 1);
    if !matches!(events.as_slice(), [event] if (event.name, event.phase, event.occurrence) == expected)
    {
        faults.resume();
        panic!("expected engine seam {expected:?}, observed {events:?}");
    }
}

#[tokio::test(start_paused = true)]
#[should_panic(expected = "expected engine seam (\"sync.commit\", \"captured\", 1), observed []")]
async fn fired_requires_the_armed_seam_to_fire() {
    let faults = FaultControl::default();
    faults.arm("sync.commit", "captured", 1, FaultAction::Block);
    fired(&faults, "sync.commit", "captured").await;
}

/// Poll `driving` until the armed seam fires and hold it there. A drive that
/// finishes before the seam, or a seam that never fires, fails the test.
async fn hold_at_seam<F: Future + Unpin>(
    driving: &mut F,
    faults: &FaultControl,
    name: &str,
    phase: &str,
) {
    let mut entered = Box::pin(fired(faults, name, phase));
    std::future::poll_fn(|cx| {
        assert!(
            std::pin::Pin::new(&mut *driving).poll(cx).is_pending(),
            "drive finished before its {name} {phase} seam"
        );
        entered.as_mut().poll(cx)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered arm observes sealed candidate, writer progress, admission wait, held refresh and the adopted parent together"
)]
async fn fsync_waits_for_inflight_commit() {
    use granary_core::retained_submission::{Completion, Phase};
    let fixture = Fixture::new().await;
    // An empty candidate sealed before w. No sync can register on its old base.
    fixture
        .engine
        .sync(SyncTarget::Directory(None), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let bytes = fixture.remote.authority.lock().unwrap().root.clone();
    let capture = fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .unwrap();
    let record = fixture_submission(&fixture, bytes.clone());
    let lane = Arc::new(
        fixture
            .engine
            .retain_commit(capture, &record)
            .await
            .unwrap(),
    );
    let stage = fixture.create("later", b"acknowledged after commit");
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.commit_wait", "before", 1, FaultAction::Block);
    let waiter = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    fired(&faults, "sync.commit_wait", "before").await;
    assert_eq!(
        fixture.remote.attempts.lock().unwrap().len(),
        1,
        "sync registered on old base while commit could land"
    );
    assert_eq!(faults.sync_fired().len(), 1, "commit wait seam missing");
    assert_eq!(fixture.marks(), 0);
    faults.resume();
    let mut done = record;
    done.phase = Phase::Complete(Completion {
        seq: 2,
        id: GrainId::of(&bytes),
        root: bytes.clone(),
        receipt: None,
    });
    done.current = None;
    done.generation += 1;
    fixture
        .store
        .lock()
        .unwrap()
        .publication_transaction(|j| j.replace(1, &done))
        .unwrap();
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(2, bytes.clone());
    faults.arm("sync.commit", "landed_refresh", 1, FaultAction::Block);
    let engine = fixture.engine.clone();
    let finishing = lane.clone();
    let root = GrainId::of(&bytes);
    let mut refresh = Box::pin(engine.finish_landed_commit(
        &finishing,
        LandedProof {
            boundary_seq: finishing.boundary_seq(),
            landed_root: root,
            landed_seq: 2,
            captured_entries: vec![],
            entries: vec![],
        },
        SyncOptions::default(),
    ));
    hold_at_seam(&mut refresh, &faults, "sync.commit", "landed_refresh").await;
    assert_eq!(
        fixture.remote.attempts.lock().unwrap().len(),
        1,
        "sync passed unfinished landed refresh"
    );
    assert_eq!(faults.sync_fired().len(), 1, "landed refresh seam missing");
    assert_eq!(fixture.marks(), 0);
    faults.resume();
    refresh.await.unwrap();
    waiter.wait().await.unwrap();
    let prepared = fixture.registered();
    assert_eq!(
        (prepared.seq, prepared.parent),
        (3, Some(root)),
        "sync did not adopt landed base"
    );
    assert_eq!(fixture.marks(), 1);
    assert_eq!(fixture.remote.published.lock().unwrap().len(), 2);
    let manifest = fixture.content.get(&prepared.manifest_root).unwrap();
    let (_, cursor) = granary_core::encoding::open_envelope(&manifest).unwrap();
    let entries = manifest::decode_dir_leaf(cursor).unwrap();
    assert_eq!(entries.len(), 1, "post-seal write was lost at replacement");
    let EntryKind::File {
        grains: FileGrains::Inline(refs),
        size,
        ..
    } = &entries[0].kind
    else {
        panic!("wrong recovered leaf")
    };
    assert_eq!(*size, b"acknowledged after commit".len() as u64);
    assert_eq!(
        fixture.content.get(&refs[0].id).unwrap(),
        b"acknowledged after commit"
    );
}

#[tokio::test]
async fn commit_unknown_timeout_and_later_rate_limit_never_reopen_admission() {
    use granary_core::retained_submission::LastResponse;
    let fixture = Fixture::new().await;
    fixture
        .engine
        .sync(SyncTarget::Directory(None), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let bytes = fixture.remote.authority.lock().unwrap().root.clone();
    let capture = fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .unwrap();
    let mut record = fixture_submission(&fixture, bytes);
    let lane = fixture
        .engine
        .retain_commit(capture, &record)
        .await
        .unwrap();
    for (status, token, decided, no_write) in [
        (202, "", true, false),
        (500, "internal", false, false),
        (429, "rate-limited", false, true),
        (400, "invalid-candidate", false, true),
    ] {
        let (scope, volume) = {
            let local = fixture.store.lock().unwrap();
            (
                local.snapshot().scope.clone(),
                local.snapshot().volume.clone(),
            )
        };
        record = fixture
            .store
            .lock()
            .unwrap()
            .publication_transaction(|j| j.load(&scope, &volume))
            .unwrap()
            .unwrap();
        let evidence = &mut record.candidates[0].evidence;
        let attempt = evidence.start().unwrap();
        evidence.answer(attempt, no_write, decided).unwrap();
        record.last_response = Some(LastResponse {
            candidate: 1,
            attempt,
            status,
            token: token.as_bytes().to_vec(),
            answer: vec![],
        });
        let old = record.generation;
        record.generation += 1;
        fixture
            .store
            .lock()
            .unwrap()
            .publication_transaction(|j| j.replace(old, &record))
            .unwrap();
        assert!(
            matches!(
                fixture.engine.finish_rejected_commit(&lane),
                Err(CoordinationError::Refused("SyncCommitUnresolved"))
            ),
            "later refusal reopened an earlier possible landing"
        );
    }
    let stage = fixture.create("later", b"must wait");
    assert!(matches!(
        fixture
            .engine
            .sync(
                SyncTarget::Stage(stage),
                SyncOptions {
                    resolution_bound: Duration::from_millis(1),
                    ..SyncOptions::default()
                }
            )
            .wait()
            .await,
        Err(CoordinationError::Refused(
            "SyncDeadline" | "SyncCommitUnresolved"
        ))
    ));
    assert_eq!(fixture.marks(), 0);
}

#[tokio::test]
async fn sync_fault_matrix() {
    for (name, phase, marks) in [
        ("sync.capture", "after", 0),
        ("sync.upload", "before", 0),
        ("sync.upload", "accepted", 0),
        ("sync.node_upload", "before", 0),
        ("sync.node_upload", "accepted", 0),
        ("sync.registration", "before_dispatch", 0),
        ("sync.registration", "after_response", 0),
        ("sync.reply", "before", 1),
    ] {
        let fixture = Fixture::new().await;
        let stage = fixture.create("file", b"captured bytes");
        let faults = fixture.store.lock().unwrap().fault_control();
        faults.arm(name, phase, 1, FaultAction::Fail);
        assert!(
            fixture
                .engine
                .sync(SyncTarget::Stage(stage), SyncOptions::default())
                .wait()
                .await
                .is_err(),
            "fault acknowledged caller"
        );
        let events = faults.sync_fired();
        assert_eq!(events.len(), 1, "missing engine fault tuple");
        let event = &events[0];
        assert_eq!(
            (event.name, event.phase, event.occurrence),
            (name, phase, 1)
        );
        if name == "sync.registration" || name == "sync.reply" {
            assert!(event.request.is_some(), "unbound registration/reply fault");
        } else {
            assert!(event.capture > 0, "unbound captured-object fault");
        }
        if name == "sync.node_upload" {
            assert!(matches!(
                event.object_kind,
                "manifest" | "grain_list" | "binmap" | "sheaf"
            ));
        }
        assert_eq!(fixture.marks(), marks);
        assert!(
            fixture
                .metrics()
                .contains("granary_client_syncs_total{outcome=\"ok\"} 0\n")
        );
        assert!(
            fixture
                .metrics()
                .contains("granary_client_syncs_total{outcome=\"failed\"} 1\n")
        );
        let control = Fixture::new().await;
        let stage = control.create("file", b"captured bytes");
        control
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default())
            .wait()
            .await
            .unwrap();
        assert_eq!(control.marks(), 1);
        assert!(
            control
                .store
                .lock()
                .unwrap()
                .fault_control()
                .sync_fired()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn upload_counters_count_accepted_novel_objects_only() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"one novel grain");
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let first = fixture.metrics();
    assert!(
        first.contains("granary_client_sync_grains_uploaded_total 1\n"),
        "successful novel grain was not counted"
    );
    let bin = first
        .lines()
        .find(|line| line.starts_with("granary_client_sync_uploaded_bytes_total{object=\"bin\"}"))
        .unwrap();
    assert!(
        !bin.ends_with(" 0"),
        "accepted encoded bin bytes were not counted"
    );
    let meta = first
        .lines()
        .find(|line| line.starts_with("granary_client_sync_uploaded_bytes_total{object=\"meta\"}"))
        .unwrap();
    assert!(
        !meta.ends_with(" 0"),
        "accepted encoded metadata bytes were not counted"
    );
    // All bytes and the timestamp are unchanged: every upload deduplicates.
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let second = fixture.metrics();
    assert!(
        second.contains("granary_client_sync_grains_uploaded_total 1\n"),
        "deduplicated grain incremented novelty"
    );
    assert!(
        second.lines().any(|line| line == bin),
        "deduplicated bin incremented bytes"
    );
    // A new timestamp may make a novel sheaf; grain/bin novelty stays unchanged.
    let failed = Fixture::new().await;
    let stage = failed.create("file", b"unaccepted grain");
    failed
        .store
        .lock()
        .unwrap()
        .fault_control()
        .arm("sync.upload", "before", 1, FaultAction::Fail);
    assert!(
        failed
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default())
            .wait()
            .await
            .is_err()
    );
    assert!(
        failed
            .metrics()
            .contains("granary_client_sync_grains_uploaded_total 0\n")
    );
}

#[tokio::test]
async fn novel_bins_count_carried_grains_from_unselected_files() {
    let fixture = Fixture::new().await;
    let first = fixture.create("first", b"first grain");
    fixture
        .engine
        .sync(SyncTarget::Stage(first), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let second = fixture.create("second", b"second grain");
    fixture
        .engine
        .sync(SyncTarget::Stage(second), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    assert!(
        fixture
            .metrics()
            .contains("granary_client_sync_grains_uploaded_total 3\n"),
        "carried grain in novel bin was omitted or treated as metadata"
    );
    let doc = fixture.registered();
    let bytes = fixture.content.get(&doc.manifest_root).unwrap();
    let (_, cursor) = granary_core::encoding::open_envelope(&bytes).unwrap();
    assert_eq!(manifest::decode_dir_leaf(cursor).unwrap().len(), 2);
}

#[tokio::test]
async fn sync_before_commit_is_required_in_the_sealed_candidate() {
    let fixture = Fixture::new().await;
    fixture
        .engine
        .sync(SyncTarget::Directory(None), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let empty = fixture.remote.authority.lock().unwrap().root.clone();
    let stage = fixture.create("file", b"acknowledged prefix");
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let bytes = fixture.remote.authority.lock().unwrap().root.clone();
    let capture = fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .unwrap();
    let record = fixture_submission(&fixture, bytes);
    let lane = fixture
        .engine
        .retain_commit(capture, &record)
        .await
        .unwrap();
    assert!(lane.boundary_seq() > 0);
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"acknowledged prefix");
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let capture = fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .unwrap();
    assert!(
        matches!(
            fixture
                .engine
                .retain_commit(capture, &fixture_submission(&fixture, empty))
                .await,
            Err(CoordinationError::Refused("SyncCommitNamespace"))
        ),
        "commit omitted acknowledged prefix"
    );
}

#[tokio::test]
async fn a_second_commit_construction_is_refused_while_one_holds_the_lane() {
    let fixture = Fixture::new().await;
    let first = fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .unwrap();
    assert!(
        matches!(
            fixture.engine.begin_commit(SyncOptions::default()).await,
            Err(CoordinationError::Refused("SyncCommitInFlight"))
        ),
        "an overlapping construction displaced the held lane"
    );
    fixture.engine.discard_commit(first).unwrap();
    fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .map(|capture| fixture.engine.discard_commit(capture).unwrap())
        .unwrap();
}

#[tokio::test]
async fn proven_non_landing_requires_every_submission_and_a_decision_table_refusal() {
    use granary_core::retained_submission::LastResponse;
    let fixture = Fixture::new().await;
    fixture
        .engine
        .sync(SyncTarget::Directory(None), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let bytes = fixture.remote.authority.lock().unwrap().root.clone();
    let capture = fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .unwrap();
    let mut record = fixture_submission(&fixture, bytes);
    let lane = fixture
        .engine
        .retain_commit(capture, &record)
        .await
        .unwrap();
    let attempt = record.candidates[0].evidence.start().unwrap();
    record.candidates[0]
        .evidence
        .answer(attempt, true, false)
        .unwrap();
    record.last_response = Some(LastResponse {
        candidate: 1,
        attempt,
        status: 400,
        token: b"invalid-candidate".to_vec(),
        answer: vec![],
    });
    record.generation += 1;
    fixture
        .store
        .lock()
        .unwrap()
        .publication_transaction(|j| j.replace(1, &record))
        .unwrap();
    fixture.engine.finish_rejected_commit(&lane).unwrap();
    let result = fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.create_file(at("file"), false));
    assert!(
        matches!(result, Err(CoordinationError::Fenced { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn sync_registers_signed_store_writer_and_completes_without_mount() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let doc = fixture.registered();
    assert_eq!(
        doc.writer_uuid,
        fixture.store.lock().unwrap().writer_uuid(),
        "prepared writer differs from store W"
    );
    assert_eq!(doc.parent, Some(fixture.base));
    assert_eq!(doc.seq, 2);
    assert!(
        fixture
            .metrics()
            .contains("granary_client_syncs_total{outcome=\"ok\"} 1\n")
    );
    assert!(
        fixture.metrics().contains(
            "granary_client_intent_registration_duration_seconds_sum{result=\"ok\"} 0.025000\n"
        ),
        "duration did not use exact monotonic ticks"
    );
    assert_eq!(fixture.pending_registrations().len(), 0);
    assert_eq!(
        fixture.marks(),
        1,
        "receipt did not precede durable file mark"
    );
    // Checkpoint lookup must select the synced payload even after the live file
    // changes size, then the second call retains the original prefix.
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(stage, 8, b"later").map(|_| ()))
        .unwrap();
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    assert!(
        fixture
            .metrics()
            .contains("granary_client_syncs_total{outcome=\"ok\"} 2\n")
    );
}

#[tokio::test]
async fn pipelined_reverse_receipts_reject_equal_size_loser_and_preserve_winner() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"old");
    fixture.remote.hold_first.store(true, Ordering::Relaxed);
    let older = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    fixture.remote.entered.notified().await;
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(stage, 0, b"new").map(|_| ()))
        .unwrap();
    let newer = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    newer.wait().await.unwrap();
    assert!(
        matches!(
            older.wait().await,
            Err(CoordinationError::Overlay(
                OverlayError::CaptureCoverageLost
            ))
        ),
        "equal-size older caller acknowledged winner's bytes"
    );
    fixture.remote.release.notify_one();
    fixture.settled().await;
    assert!(
        fixture
            .metrics()
            .contains("granary_client_syncs_total{outcome=\"failed\"} 1\n")
    );
    assert!(
        fixture
            .metrics()
            .contains("granary_client_syncs_total{outcome=\"ok\"} 1\n")
    );
}

#[tokio::test]
async fn cancellation_during_upload_and_admission_releases_floors_without_send() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    fixture.remote.hold_upload.store(true, Ordering::Relaxed);
    let first = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    fixture.remote.upload_entered.notified().await;
    let waiting = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    drop(waiting);
    drop(first);
    fixture.settled().await;
    assert!(
        fixture.remote.attempts.lock().unwrap().is_empty(),
        "cancelled upload dispatched registration"
    );
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0))
        .unwrap();
    assert!(
        fixture
            .metrics()
            .contains("granary_client_syncs_total{outcome=\"cancelled\"} 2\n")
    );
}

#[tokio::test]
async fn cancellation_after_send_completes_marks_and_suppresses_success() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    fixture.remote.hold_first.store(true, Ordering::Relaxed);
    let waiter = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    fixture.remote.entered.notified().await;
    drop(waiter);
    assert!(matches!(
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.truncate(stage, 0)),
        Err(CoordinationError::Overlay(OverlayError::PendingShrink))
    ));
    fixture.remote.release.notify_one();
    fixture.settled().await;
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0))
        .unwrap();
    assert!(
        fixture
            .metrics()
            .contains("granary_client_syncs_total{outcome=\"cancelled\"} 1\n")
    );
    assert!(
        fixture
            .metrics()
            .contains("granary_client_syncs_total{outcome=\"ok\"} 0\n")
    );
    assert!(fixture.pending_registrations().is_empty());
}

#[tokio::test]
async fn unknown_registration_exhaustion_persists_failure_and_releases_exact_floor() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    fixture.remote.hold_first.store(true, Ordering::Relaxed);
    fixture.remote.unknown.store(true, Ordering::Relaxed);
    let waiter = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    fixture.remote.entered.notified().await;
    tokio::time::pause();
    fixture.remote.release.notify_one();
    assert!(matches!(
        waiter.wait().await,
        Err(CoordinationError::Refused("IntentStartupAttemptsExhausted"))
    ));
    let attempts = fixture.remote.attempts.lock().unwrap();
    assert_eq!(
        attempts.len(),
        8,
        "reconciliation exceeded remaining attempt budget"
    );
    assert!(
        attempts.iter().all(|request| request == &attempts[0]),
        "retry rebuilt prepared bytes"
    );
    drop(attempts);
    let retained = fixture.pending_registrations();
    assert_eq!(retained.len(), 1);
    assert!(
        retained[0].context.is_empty(),
        "local caller disposition was not durable"
    );
    assert!(!retained[0].terminal, "silence retired network evidence");
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0))
        .unwrap();
    assert!(
        fixture
            .metrics()
            .contains("granary_client_intent_registrations_total{result=\"unknown\"} 8\n")
    );
}

/// Reconciliation can start with one real exchange whose answer was lost.
fn registration_with_lost_reply(fixture: &Fixture, at: u64) -> PendingIntent {
    let mut local = fixture.store.lock().unwrap();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let mut doc = fixture.registered();
    doc.sigs = vec![RootSig {
        key_id: key.key_id(),
        sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    }];
    let bytes = granary_core::root::encode_root(&doc).unwrap();
    let request = local
        .prepare_registration(&bytes, vec![], &Tick(at), |_, _| true)
        .unwrap();
    local.dispatch(&request, &Tick(at)).unwrap();
    let answer = fixture.remote.authority.lock().unwrap().send(&request);
    assert_eq!(answer.status, 200, "the first exchange landed: {answer:?}");
    let lost = local.complete(
        &request,
        Err(IntentTransportError::Transport),
        &Tick(at),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert!(
        matches!(lost, Ok(crate::IntentCompletion::Unknown)),
        "{lost:?}"
    );
    request
}

/// Rejects ending at the first early admission, charging an attempt per wait,
/// or emitting a failure for any early admission. A 1 ms residual freezes at
/// the same tick across several checks, exposing a retry loop with no 10 ms floor.
#[tokio::test]
async fn reconciliation_rewaits_after_wall_step_back_and_recovers() {
    use std::task::Poll;

    let fixture = Fixture::new().await;
    let request = registration_with_lost_reply(&fixture, 20_000_000);
    let eligible = fixture.pending_registrations()[0].eligible;
    let wall = Arc::new(Mutex::new(crate::overlay_test_support::AuthorityState {
        tick: eligible - 1000,
        ..Default::default()
    }));
    *fixture.remote.time.scripted_wall.lock().unwrap() =
        Some(crate::overlay_test_support::Time(wall.clone()));
    let mut sleeps = 0;
    *fixture.content.after_sleep.lock().unwrap() = Some(Box::new(move || {
        sleeps += 1;
        let mut clock = wall.lock().unwrap();
        if sleeps == 1 {
            clock.tick -= 1;
        } else if sleeps == 3 {
            clock.tick = eligible - 1000;
            clock.tick_per_read = 1;
        }
    }));
    fixture.remote.hold_first.store(true, Ordering::Relaxed);
    let log = LogCapture::default();
    let history = crate::observe::BundleHistory::default();
    let subscriber = crate::observe::closed_subscriber_with_paths(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
        crate::observe::LogPaths::Redacted,
        history.clone(),
    );
    tokio::time::pause();
    let deadline = TokioSyncRuntime.now() + Duration::from_millis(100);
    let mut settling = Box::pin(
        fixture
            .engine
            .settle_registration(&request, deadline)
            .with_subscriber(subscriber),
    );
    let mut entered = Box::pin(fixture.remote.entered.notified());
    let early = std::future::poll_fn(|cx| {
        if let Poll::Ready(result) = settling.as_mut().poll(cx) {
            return Poll::Ready(Some(result));
        }
        entered.as_mut().poll(cx).map(|()| None)
    })
    .await;
    let (result, persisted_attempts) = if let Some(result) = early {
        (result, None)
    } else {
        let persisted = {
            let model = fixture.io.0.lock().unwrap();
            let (_, id) = model
                .names
                .iter()
                .find(|(path, _)| path.ends_with("ownership"))
                .unwrap();
            granary_core::overlay_ownership::decode(&model.files[id].1).unwrap()
        };
        let attempts = persisted
            .pending
            .iter()
            .find(|pending| pending.body == request.bytes())
            .map(|pending| pending.attempts);
        fixture.remote.release.notify_one();
        (settling.await, attempts)
    };
    let log = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let exchanges = fixture.remote.authority.lock().unwrap().sends.clone();
    assert_eq!(
        (
            result.map_err(|error| error.to_string()),
            persisted_attempts,
            exchanges
                .iter()
                .filter(|body| body.as_slice() == request.bytes())
                .count(),
            fixture.content.sleeps.lock().unwrap().clone(),
            (
                log.lines()
                    .filter(|line| line.contains("op.failed"))
                    .count(),
                history.try_failure_snapshot().unwrap().entries.len(),
            ),
        ),
        (
            Ok(()),
            Some(2),
            2,
            [0, 10, 10].map(Duration::from_millis).to_vec(),
            (0, 0)
        ),
        "{log}"
    );
}

/// Rejects an unbounded spin or resetting the monotonic deadline on each
/// re-wait. A forward step at expiry or one tick beyond must forbid a send.
#[tokio::test]
async fn reconciliation_wall_steps_keep_the_original_deadline_and_expiry() {
    let mut observed = Vec::new();
    for (name, back, expiry_offset) in [
        ("frozen", 0, None),
        ("hours back", 10_800_000, None),
        ("at expiry", 0, Some(0)),
        ("past expiry", 0, Some(1)),
    ] {
        let fixture = Fixture::new().await;
        let request = registration_with_lost_reply(&fixture, 20_000_000);
        let pending = &fixture.pending_registrations()[0];
        let wall = Arc::new(Mutex::new(crate::overlay_test_support::AuthorityState {
            tick: pending.eligible - 1001,
            ..Default::default()
        }));
        *fixture.remote.time.scripted_wall.lock().unwrap() =
            Some(crate::overlay_test_support::Time(wall.clone()));
        let stepped_tick = expiry_offset.map_or(pending.eligible - 1001 - back, |offset| {
            pending.expires - 1000 + offset
        });
        *fixture.content.after_sleep.lock().unwrap() =
            Some(Box::new(move || wall.lock().unwrap().tick = stepped_tick));
        tokio::time::pause();
        let started = TokioSyncRuntime.now();
        let deadline = started + Duration::from_millis(45);
        let result = fixture.engine.settle_registration(&request, deadline).await;
        let elapsed = TokioSyncRuntime.now() - started;
        tokio::time::resume();
        let bound = deadline - started;
        observed.push((
            name,
            result.map_err(|error| error.to_string()),
            (bound..=bound + Duration::from_millis(1)).contains(&elapsed),
            fixture.remote.attempts.lock().unwrap().len(),
            fixture.pending_registrations()[0].attempts,
        ));
    }
    assert_eq!(
        observed,
        [
            ("frozen", "SyncDeadline", true),
            ("hours back", "SyncDeadline", true),
            ("at expiry", "IntentRetryDeadline", false),
            ("past expiry", "IntentRetryDeadline", false),
        ]
        .map(|(name, reason, at_bound)| (
            name,
            Err(format!("intent refused: {reason}")),
            at_bound,
            0,
            1
        ))
    );
}

/// Rejects admitting the first registration after its waiter cancelled during
/// the re-wait. The wall is eligible again when that wait wakes.
#[tokio::test]
async fn reconciliation_rechecks_the_first_waiter_after_rewaiting() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    let wall = Arc::new(Mutex::new(crate::overlay_test_support::AuthorityState {
        tick: 20_000_000,
        ..Default::default()
    }));
    *fixture.remote.time.scripted_wall.lock().unwrap() =
        Some(crate::overlay_test_support::Time(wall.clone()));
    let first_sleep = Arc::new(Notify::new());
    let waiter = Arc::new(Mutex::new(None::<crate::SyncWaiter>));
    let mut sleeps = 0;
    *fixture.content.after_sleep.lock().unwrap() = Some(Box::new({
        let first_sleep = first_sleep.clone();
        let waiter = waiter.clone();
        move || {
            sleeps += 1;
            if sleeps == 1 {
                wall.lock().unwrap().tick -= 1;
                first_sleep.notify_one();
            } else if sleeps == 2 {
                wall.lock().unwrap().tick += 1;
                waiter.lock().unwrap().as_ref().unwrap().cancel();
            }
        }
    }));
    tokio::time::pause();
    *waiter.lock().unwrap() = Some(
        fixture
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default()),
    );
    first_sleep.notified().await;
    fixture.settled().await;
    let waiter = waiter.lock().unwrap().take().unwrap();
    assert_eq!(
        (
            waiter.wait().await.map_err(|error| error.to_string()),
            fixture.remote.attempts.lock().unwrap().len(),
            fixture.content.sleeps.lock().unwrap().clone(),
        ),
        (
            Err("intent refused: SyncCancelled".to_owned()),
            0,
            [0, 10].map(Duration::from_millis).to_vec()
        ),
    );
}

/// Rejects checking cancellation only after the first dispatch was deferred.
#[tokio::test]
async fn reconciliation_rechecks_the_first_waiter_after_the_first_backoff() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    let tick = 20_000_000;
    let wall = Arc::new(Mutex::new(crate::overlay_test_support::AuthorityState {
        tick,
        ..Default::default()
    }));
    *fixture.remote.time.scripted_wall.lock().unwrap() =
        Some(crate::overlay_test_support::Time(wall.clone()));
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("intent.pending", "after_rename", 1, FaultAction::Block);
    let waiter = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    let bound = TokioSyncRuntime.now() + Duration::from_secs(2);
    while faults.fired().is_empty() && TokioSyncRuntime.now() < bound {
        TokioSyncRuntime.sleep(Duration::from_millis(1)).await;
    }
    let fired = faults.fired();
    tokio::time::pause();
    wall.lock().unwrap().tick -= 5_000;
    faults.resume();
    assert_eq!(
        fired.len(),
        1,
        "registration did not reach persistence: {fired:?}"
    );
    let started = TokioSyncRuntime.now();
    let delay = loop {
        if let Some(delay) = fixture.content.sleeps.lock().unwrap().first().copied() {
            break delay;
        }
        assert!(
            TokioSyncRuntime.now() - started < Duration::from_secs(2),
            "registration never started its first backoff"
        );
        TokioSyncRuntime.sleep(Duration::from_millis(1)).await;
    };
    assert_eq!(delay, Duration::from_secs(5));
    assert!(TokioSyncRuntime.now() - started < delay);
    waiter.cancel();
    wall.lock().unwrap().tick = tick;
    let result = waiter.wait().await;
    tokio::time::advance(delay).await;
    fixture.settled().await;
    assert_eq!(
        (
            result.map_err(|error| error.to_string()),
            fixture.remote.attempts.lock().unwrap().len(),
            fixture
                .pending_registrations()
                .first()
                .map(|pending| pending.attempts),
        ),
        (Err("intent refused: SyncCancelled".to_owned()), 0, Some(0)),
    );
}

/// Rejects checking terminal evidence only before the first backoff.
#[tokio::test]
async fn reconciliation_drains_an_answer_persisted_during_rewait() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    let wall = Arc::new(Mutex::new(crate::overlay_test_support::AuthorityState {
        tick: 20_000_000,
        ..Default::default()
    }));
    *fixture.remote.time.scripted_wall.lock().unwrap() =
        Some(crate::overlay_test_support::Time(wall));
    fixture.remote.unknown.store(true, Ordering::Relaxed);
    let store = fixture.store.clone();
    let remote = fixture.remote.clone();
    let mut sleeps = 0;
    *fixture.content.after_sleep.lock().unwrap() = Some(Box::new(move || {
        sleeps += 1;
        if sleeps == 3 {
            let mut local = store.lock().unwrap();
            let request = local.retained_requests().pop().unwrap();
            let answer = remote.authority.lock().unwrap().recorded(200, None);
            let completed = local.complete(
                &request,
                Ok(&answer),
                remote.time.as_ref(),
                &mut SeededRng::new(1),
                0,
                None,
            );
            assert!(
                matches!(completed, Ok(crate::IntentCompletion::Accepted(_))),
                "{completed:?}"
            );
        }
    }));
    tokio::time::pause();
    let result = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await;
    let delays = fixture.content.sleeps.lock().unwrap();
    assert_eq!(
        (
            result.map_err(|error| error.to_string()),
            fixture.remote.attempts.lock().unwrap().len(),
            fixture.marks(),
            delays.len(),
        ),
        (Ok(()), 1, 1, 3),
        "backoff sleeps: {delays:?}",
    );
}

#[tokio::test]
async fn caller_deadline_clamps_unknown_send_and_retains_exact_network_evidence() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    fixture.remote.hold_first.store(true, Ordering::Relaxed);
    // Asserting against the deadline itself, not a start time read before
    // the clock is paused, keeps real setup time under load out of the bound.
    let deadline = TokioSyncRuntime.now() + Duration::from_secs(1);
    let waiter = fixture.engine.sync(
        SyncTarget::Stage(stage),
        SyncOptions {
            deadline: Some(deadline),
            ..SyncOptions::default()
        },
    );
    fixture.remote.entered.notified().await;
    tokio::time::pause();
    assert!(matches!(
        waiter.wait().await,
        Err(CoordinationError::Refused("SyncDeadline"))
    ));
    assert!(
        TokioSyncRuntime.now() <= deadline + Duration::from_millis(10),
        "enclosing caller deadline was reset or ignored"
    );
    let pending = fixture.pending_registrations();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].attempts, 1);
    assert!(pending[0].context.is_empty());
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0))
        .unwrap();
}

#[derive(Clone, Default)]
struct TimingLog(Arc<Mutex<Vec<u8>>>);
impl io::Write for TimingLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TimingLog {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

#[tokio::test]
async fn unavailable_monotonic_sample_counts_exchange_without_zero_duration() {
    let fixture = Fixture::new().await;
    fixture
        .remote
        .time
        .unavailable
        .store(true, Ordering::Relaxed);
    let stage = fixture.create("file", b"captured");
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let report: Vec<_> = text
        .lines()
        .filter(|line| {
            line.contains("\"event\":\"client.sync.registration.timing.sample.unavailable\"")
        })
        .collect();
    assert_eq!(report.len(), 1, "timing report missing or repeated: {text}");
    assert!(report[0].contains("\"level\":\"DEBUG\""));
    assert!(
        !text.contains("\"event\":\"op.failed\""),
        "a missing timing sample reported a failed operation: {text}"
    );
    assert!(
        fixture
            .metrics()
            .contains("granary_client_intent_registrations_total{result=\"ok\"} 1\n")
    );
    assert!(
        fixture.metrics().contains(
            "granary_client_intent_registration_duration_seconds_count{result=\"ok\"} 0\n"
        )
    );
}

#[tokio::test]
async fn workspace_refusal_is_non_poisoning_and_precedes_capture() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    assert!(
        matches!(
            fixture
                .engine
                .sync(
                    SyncTarget::Stage(stage),
                    SyncOptions {
                        workspace_bytes: 0,
                        ..SyncOptions::default()
                    }
                )
                .wait()
                .await,
            Err(CoordinationError::Refused("SyncWorkspaceExhausted"))
        ),
        "workspace cap was bypassed"
    );
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0))
        .unwrap();
    assert!(fixture.remote.attempts.lock().unwrap().is_empty());
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_at_local_barriers_finishes_pairs_and_withholds_reply() {
    for (name, phase, occurrence, expected_marks) in [
        ("overlay.stage.sync", "after", 1, 0),
        ("intent.pending", "after_rename", 1, 0),
        ("intent.evidence", "before", 1, 1),
        ("overlay.mark.sync", "after", 1, 1),
        ("intent.pending", "after_dir_sync", 4, 1),
    ] {
        let fixture = Fixture::new().await;
        let stage = fixture.create("file", b"captured");
        let faults = fixture.store.lock().unwrap().fault_control();
        faults.arm(name, phase, occurrence, FaultAction::Block);
        let waiter = fixture
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default());
        let bound = TokioSyncRuntime.now() + Duration::from_secs(2);
        while faults.fired().is_empty() && TokioSyncRuntime.now() < bound {
            TokioSyncRuntime.sleep(Duration::from_millis(1)).await;
        }
        let fired = faults.fired();
        if fired.is_empty() {
            faults.resume();
        }
        assert_eq!(fired.len(), 1, "local cancellation seam did not fire");
        assert_eq!(
            (fired[0].name, fired[0].phase, fired[0].occurrence),
            (name, phase, occurrence)
        );
        drop(waiter);
        faults.resume();
        fixture.settled().await;
        assert_eq!(
            fixture.marks(),
            expected_marks,
            "cancelled transaction abandoned its barrier pair"
        );
        assert!(
            fixture
                .metrics()
                .contains("granary_client_syncs_total{outcome=\"cancelled\"} 1\n")
        );
        assert!(
            fixture
                .metrics()
                .contains("granary_client_syncs_total{outcome=\"ok\"} 0\n")
        );
        if expected_marks == 0 {
            assert!(fixture.remote.attempts.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn cancellation_during_metadata_upload_has_no_registration_or_mark() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    fixture.remote.hold_meta.store(true, Ordering::Relaxed);
    let waiter = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    fixture.remote.upload_entered.notified().await;
    drop(waiter);
    fixture.settled().await;
    assert!(fixture.remote.attempts.lock().unwrap().is_empty());
    assert_eq!(fixture.marks(), 0);
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0))
        .unwrap();
}

#[tokio::test]
async fn supervisor_panic_persists_local_failure_and_releases_floor() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    fixture.remote.panic_register.store(true, Ordering::Relaxed);
    assert!(
        matches!(
            fixture
                .engine
                .sync(SyncTarget::Stage(stage), SyncOptions::default())
                .wait()
                .await,
            Err(CoordinationError::Refused("SyncSupervisorLost"))
        ),
        "supervisor loss hung caller or fabricated success"
    );
    let pending = fixture.pending_registrations();
    assert_eq!(pending.len(), 1);
    assert!(pending[0].context.is_empty());
    assert_eq!(pending[0].attempts, 1);
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0))
        .unwrap();
    assert_eq!(fixture.marks(), 0);
}

#[tokio::test]
async fn wall_clock_changes_do_not_change_measured_registration_ticks() {
    for wall in [1, 1_000_000] {
        let fixture = Fixture::new().await;
        let stage = fixture.create("file", b"captured");
        fixture.remote.hold_first.store(true, Ordering::Relaxed);
        let waiter = fixture
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default());
        fixture.remote.entered.notified().await;
        fixture.remote.time.wall.store(wall, Ordering::Relaxed);
        fixture.remote.release.notify_one();
        waiter.wait().await.unwrap();
        assert!(
            fixture.metrics().contains(
                "granary_client_intent_registration_duration_seconds_sum{result=\"ok\"} 0.025000\n"
            ),
            "wall-clock change altered exchange latency"
        );
    }
}

#[tokio::test]
async fn clean_empty_directory_and_tree_sync_select_exact_payloads() {
    let fixture = Fixture::new().await;
    let empty = fixture.create("empty", b"");
    fixture
        .engine
        .sync(SyncTarget::Stage(empty), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let first_marks = fixture.marks();
    fixture
        .engine
        .sync(SyncTarget::Stage(empty), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    assert_eq!(
        fixture.marks(),
        first_marks,
        "clean sync fabricated a stage mark"
    );
    fixture.create("unsynced", b"later");
    fixture
        .engine
        .sync(SyncTarget::Directory(None), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let doc = fixture.registered();
    let bytes = fixture.content.get(&doc.manifest_root).unwrap();
    let (_, cursor) = granary_core::encoding::open_envelope(&bytes).unwrap();
    let entries = manifest::decode_dir_leaf(cursor).unwrap();
    assert_eq!(
        entries.len(),
        1,
        "directory sync admitted never-synced file bytes"
    );
    fixture
        .engine
        .sync(SyncTarget::Tree, SyncOptions::default())
        .wait()
        .await
        .unwrap();
    assert_eq!(fixture.marks(), first_marks + 1);
}

#[tokio::test]
async fn prepared_root_is_refused_as_base_even_when_cached_and_wrong_writer_refuses() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let bytes = fixture.remote.authority.lock().unwrap().root.clone();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let trusted = TrustedKeys::new([*key.public_key()]).unwrap();
    // Even a cache hit cannot change the mediator's verified base lane.
    fixture
        .content
        .put_object(GrainId::of(&bytes), &bytes)
        .unwrap();
    let result = SyncEngine::new(
        fixture.store.clone(),
        fixture.remote.clone(),
        fixture.content.clone(),
        fixture.remote.time.clone(),
        fixture.remote.time.clone(),
        key,
        trusted,
        bytes.clone(),
        fixture.metrics.clone(),
    )
    .await;
    assert!(
        matches!(result, Err(CoordinationError::Refused("SyncBaseBinding"))),
        "prepared cache hit became a published base"
    );
    let mut doc = granary_core::root::decode_root(&bytes).unwrap();
    doc.writer_uuid = [91; 16];
    doc.sigs.clear();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let prefix = granary_core::root::signing_prefix_of(&doc).unwrap();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&prefix),
    });
    let bytes = granary_core::root::encode_root(&doc).unwrap();
    let trusted = TrustedKeys::new([*key.public_key()]).unwrap();
    let result = fixture.store.lock().unwrap().prepare_registration(
        &bytes,
        vec![],
        fixture.remote.time.as_ref(),
        |doc, prefix| granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok(),
    );
    assert!(
        matches!(
            result,
            Err(CoordinationError::Refused("IntentPreparedWriter"))
        ),
        "wrong W was retained for registration"
    );
}

#[tokio::test]
async fn disposition_persistence_failure_poison_fails_shrink_with_io() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("intent.pending", "build", 18, FaultAction::Fail);
    fixture.remote.hold_first.store(true, Ordering::Relaxed);
    fixture.remote.unknown.store(true, Ordering::Relaxed);
    let waiter = fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    fixture.remote.entered.notified().await;
    tokio::time::pause();
    fixture.remote.release.notify_one();
    assert!(
        waiter.wait().await.is_err(),
        "uncertain caller disposition acknowledged"
    );
    assert_eq!(faults.fired().len(), 1, "durable failure seam did not fire");
    assert_eq!(fixture.remote.attempts.lock().unwrap().len(), 8);
    let result = fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0));
    assert!(
        matches!(
            result,
            Err(CoordinationError::Refused("IntentPersistencePoisoned"))
        ),
        "poisoned disposition let shrink proceed"
    );
    assert_eq!(fixture.marks(), 0);
}

#[tokio::test]
async fn late_receipt_after_deadline_cannot_mark_changed_staging() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"captured");
    fixture.remote.hold_first.store(true, Ordering::Relaxed);
    let waiter = fixture.engine.sync(
        SyncTarget::Stage(stage),
        SyncOptions {
            deadline: Some(TokioSyncRuntime.now() + Duration::from_secs(1)),
            ..SyncOptions::default()
        },
    );
    fixture.remote.entered.notified().await;
    tokio::time::pause();
    assert!(waiter.wait().await.is_err());
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0))
        .unwrap();
    let mut local = fixture.store.lock().unwrap();
    let request = local
        .retained_requests()
        .into_iter()
        .find(|request| request.operation() == Operation::Register)
        .unwrap();
    let answer = fixture.remote.authority.lock().unwrap().send(&request);
    local
        .complete(
            &request,
            Ok(&answer),
            fixture.remote.time.as_ref(),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert!(local.capture_completion_work().unwrap().is_none());
    drop(local);
    assert_eq!(
        fixture.marks(),
        0,
        "late answer fabricated a file mark against changed staging"
    );
}

#[tokio::test]
async fn fence_at_deadline_preserves_conflict_during_verification() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", &vec![7; 131_072]);
    let entered = Arc::new(Notify::new());
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    *fixture.content.pause_get.lock().unwrap() = Some((entered.clone(), release.clone()));
    let deadline = TokioSyncRuntime.now() + Duration::from_secs(1);
    let waiter = fixture.engine.sync(
        SyncTarget::Stage(stage),
        SyncOptions {
            deadline: Some(deadline),
            ..SyncOptions::default()
        },
    );
    entered.notified().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(1)).await;
    fixture
        .store
        .lock()
        .unwrap()
        .phase_for_test(Phase::Fenced)
        .unwrap();
    let (lock, wake) = &*release;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    let answer = waiter.wait().await;
    assert_eq!(
        (
            TokioSyncRuntime.now() >= deadline,
            matches!(answer, Err(CoordinationError::Fenced { .. }))
        ),
        (true, true),
        "fencing after verifier read must retain ESTALE at the deadline: {answer:?}"
    );
}

#[tokio::test]
async fn stage_floor_wait_keeps_wakeup_between_check_and_await() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"retained");
    let boundary = fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|overlay| overlay.seal_sync(SyncTarget::Stage(stage)))
        .unwrap();
    let pending = fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|overlay| overlay.truncate(stage, 0));
    assert!(
        matches!(
            pending,
            Err(CoordinationError::Overlay(OverlayError::PendingShrink))
        ),
        "retained floor premise: {pending:?}"
    );
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.floor", "checked", 1, FaultAction::Block);
    let engine = fixture.engine.clone();
    let wait = TokioSyncRuntime.spawn(async move {
        engine
            .wait_stage_floor(stage, 0, TokioSyncRuntime.now() + Duration::from_secs(3))
            .await
    });
    fired(&faults, "sync.floor", "checked").await;
    let events = faults.sync_fired();
    assert_eq!(
        events.len(),
        1,
        "floor wait never reached the checked boundary: {events:?}"
    );
    fixture
        .store
        .lock()
        .unwrap()
        .release_sync_boundary(&boundary)
        .unwrap();
    faults.resume();
    let result = wait.await.unwrap();
    assert!(
        result.is_ok(),
        "floor wakeup lost between check and await: {result:?}"
    );
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|overlay| overlay.truncate(stage, 0))
        .unwrap();
}

#[tokio::test]
async fn stage_floor_wait_refuses_expired_bound_even_when_floor_is_clear() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("file", b"ready");
    let result = fixture
        .engine
        .wait_stage_floor(stage, 0, TokioSyncRuntime.now() - Duration::from_secs(1))
        .await;
    assert!(
        matches!(result, Err(CoordinationError::Refused("SyncDeadline"))),
        "expired wait succeeded on a clear floor: {result:?}"
    );
}
