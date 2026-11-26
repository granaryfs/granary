// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Mounted syscall replies paired with the supervised engine and prepared bytes.

#![cfg(test)]

use super::super::commit_lane::{
    construct_commit, construct_commit_with, disjoint_head, drive_commit, foreign_head, landed,
    remote_seq, resume_commit,
};
use super::super::observed::{bounded_output, wait_owned_child};
use super::*;
use crate::SyncRuntime as _;
use granary_fuse::{Callback, CallbackOutcome};
use std::sync::{PoisonError, mpsc};
use tracing_subscriber::fmt::writer::MakeWriterExt as _;

mod endings;
mod fault_route;
mod profile;
mod published;
mod recovery;
mod remote;
mod view;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hook {
    None,
    Bound,
    Probed,
}

#[derive(Clone, Copy)]
enum MountedRuntime {
    Accelerated,
    Unscaled,
}

impl crate::SyncRuntime for MountedRuntime {
    fn now(&self) -> tokio::time::Instant {
        crate::TokioSyncRuntime.now()
    }
    fn spawn<T: Send + 'static>(
        &self,
        work: impl std::future::Future<Output = T> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        crate::TokioSyncRuntime.spawn(work)
    }
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        crate::TokioSyncRuntime.blocking(work)
    }
    fn blocking_async<T: Send + 'static, F: std::future::Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        crate::TokioSyncRuntime.blocking_async(work)
    }
    fn sleep(&self, duration: std::time::Duration) -> impl std::future::Future<Output = ()> + Send {
        let runtime = *self;
        async move {
            match runtime {
                Self::Accelerated => FastWaitRuntime.sleep(duration).await,
                Self::Unscaled => crate::TokioSyncRuntime.sleep(duration).await,
            }
        }
    }
    fn timeout_at<T: Send>(
        &self,
        deadline: tokio::time::Instant,
        work: impl std::future::Future<Output = T> + Send,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        crate::TokioSyncRuntime.timeout_at(deadline, work)
    }
}

type MountedCommitEngine = crate::SyncEngine<
    OverlayDisk,
    Authority,
    crate::MountSyncContent<Authority>,
    Time,
    crate::InstantClock,
    MountedRuntime,
>;
const TIMELINE_EVENT_LIMIT: usize = 64;
const AUTHORITY_REQUEST_LIMIT: usize = 16;

#[derive(Clone, Default)]
struct EventTimeline(Arc<Mutex<EventTimelineState>>);

#[derive(Default)]
struct EventTimelineState {
    events: std::collections::VecDeque<(std::time::Instant, String)>,
    commit_begins: u64,
    close: Option<std::time::Instant>,
}

impl std::io::Write for EventTimeline {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let record = String::from_utf8_lossy(bytes);
        if record.contains("\"target\":\"granary_client::event\"") {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if record.contains("\"event\":\"op.begin\"") && record.contains("\"kind\":\"commit\"") {
                state.commit_begins += 1;
            }
            state
                .events
                .push_back((std::time::Instant::now(), record.trim_end().to_owned()));
            if state.events.len() > TIMELINE_EVENT_LIMIT {
                state.events.pop_front();
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl EventTimeline {
    fn subscriber(&self) -> Box<dyn tracing::Subscriber + Send + Sync> {
        let timeline = self.clone();
        crate::subscriber(
            crate::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            move || timeline.clone(),
        )
    }

    fn records(&self) -> Vec<String> {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .events
            .iter()
            .map(|(_, record)| record.clone())
            .collect()
    }

    fn mark_close(&self) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        state.close = Some(std::time::Instant::now());
    }

    fn render(&self, wait_started: std::time::Instant) -> String {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        Self::render_state(&state, wait_started)
    }

    fn render_state(state: &EventTimelineState, wait_started: std::time::Instant) -> String {
        let (origin, label) = state
            .close
            .map_or((wait_started, "wait start"), |close| (close, "close"));
        let mut rendered = format!(
            "client events relative to {label} (last {}):",
            state.events.len()
        );
        for (at, event) in &state.events {
            use std::fmt::Write as _;
            let (sign, elapsed) = if *at >= origin {
                ('+', at.duration_since(origin))
            } else {
                ('-', origin.duration_since(*at))
            };
            let _ = write!(rendered, "\n  {sign}{:.3}s {event}", elapsed.as_secs_f64());
        }
        rendered
    }

    fn assert_saw_commit(&self) {
        let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let close = state.close.expect("the timeline must have a close marker");
        let commit_begins = state.commit_begins;
        let rendered = Self::render_state(&state, close);
        drop(state);
        assert!(
            commit_begins > 0,
            "the mounted fixture's shared dispatcher did not capture the engine's commit \
             event\n{rendered}",
        );
    }
}

struct SyncMount {
    // Unmount before stopping the runtime, and remove scratch directories last.
    mount: SessionGuard,
    runtime: tokio::runtime::Runtime,
    engine: Arc<MountedCommitEngine>,
    observer: Arc<indexed::WorkerObserver>,
    state: Arc<Mutex<AuthorityState>>,
    admitted_sends: usize,
    content: Arc<crate::MountSyncContent<Authority>>,
    mediator: crate::SharedWritableStore,
    metrics: crate::ClientMetrics,
    faults: crate::FaultControl,
    tree: Arc<PublishedTree>,
    /// For a probed bind, whether the session answered a request at it.
    served_at_bind: Option<bool>,
    /// The engine's shutdown, which the mount's `destroy` also runs.
    shutdown: crate::ShutdownHandle,
    timeline: EventTimeline,
    dispatch: tracing::Dispatch,
    paths: Arc<Paths>,
}

/// The cache's mount-private floor, read by the cache's own parser. A cache
/// a mount still serves opens degraded, which reads but never writes.
fn mount_floor(paths: &Paths, tree: &PublishedTree) -> Option<u64> {
    let start = input(tree, paths);
    let cache = crate::Cache::open(&paths.cache, start.cache_quota, &start.cache_origin).unwrap();
    let floor = cache.read_mount_anchor(&tree.volume);
    crate::Cache::close(cache).unwrap();
    floor
}

/// The shared anchor's bytes, if the cache holds one.
fn shared_anchor(paths: &Paths, tree: &PublishedTree) -> Option<Vec<u8>> {
    std::fs::read(paths.cache.join("anchors").join(tree.volume.as_str())).ok()
}

/// The mount's sync engine, attached on its own two-worker runtime.
fn attach_engine(
    ready: &mut crate::WritableReadiness<Authority, OverlayDisk>,
    remote: Arc<Authority>,
    content: &Arc<crate::MountSyncContent<Authority>>,
    state: &Arc<Mutex<AuthorityState>>,
    live: Option<crate::SyncOptions>,
    runtime_kind: MountedRuntime,
) -> (
    tokio::runtime::Runtime,
    crate::ClientMetrics,
    Arc<MountedCommitEngine>,
) {
    if let Some(options) = live {
        ready.backend_for_test().set_live_driver_for_test(options);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let metrics = crate::ClientMetrics::new(&mut Entropy(35));
    let engine = runtime
        .block_on(ready.backend_for_test().attach_sync_with_runtime(
            remote,
            content.clone(),
            Arc::new(Time(state.clone())),
            Arc::new(crate::InstantClock::default()),
            metrics.clone(),
            Arc::new(runtime_kind),
            Entropy(36),
        ))
        .unwrap();
    (runtime, metrics, engine)
}

impl SyncMount {
    /// A mount whose engine installs each landing as the served view.
    fn new(deadline: tokio::time::Instant) -> Self {
        Self::with_hook(deadline, Hook::Bound)
    }
    /// [`Self::new`], with `--view strict`.
    fn strict(deadline: tokio::time::Instant) -> Self {
        Self::with_options(
            deadline,
            Hook::Bound,
            crate::SyncProfile::default(),
            crate::ViewMode::Strict,
            None,
            false,
            None,
            MountedRuntime::Accelerated,
            None,
            Arc::new(Paths::new()),
            Arc::new(mounted_operation_tree()),
        )
        .unwrap()
    }
    /// A mount served through the plain session, with no view hook bound:
    /// a landing leaves the old view, which answers `EIO`.
    fn hookless(deadline: tokio::time::Instant) -> Self {
        Self::with_hook(deadline, Hook::None)
    }
    fn with_hook(deadline: tokio::time::Instant, hook: Hook) -> Self {
        Self::with_profile(deadline, hook, crate::SyncProfile::default())
    }
    /// [`Self::with_hook`], its syncs answering as `profile` says.
    fn with_profile(
        deadline: tokio::time::Instant,
        hook: Hook,
        profile: crate::SyncProfile,
    ) -> Self {
        Self::with_options(
            deadline,
            hook,
            profile,
            crate::ViewMode::Default,
            None,
            false,
            None,
            MountedRuntime::Accelerated,
            None,
            Arc::new(Paths::new()),
            Arc::new(mounted_operation_tree()),
        )
        .unwrap()
    }
    /// [`Self::new`], inside a harness that bounds it more tightly than its
    /// shutdown (a fault route, a strace arm): its cleanup aborts the session
    /// at [`session_guard::ENGINE_JOIN_FLOOR`], inside that harness's bound.
    /// The unmount's shutdown is bounded at 2 s (2.5 s with its margin), under
    /// that floor, so a slow shutdown commit cannot outlast the harness.
    fn harnessed(deadline: tokio::time::Instant) -> Self {
        Self::with_options(
            deadline,
            Hook::Bound,
            crate::SyncProfile::default(),
            crate::ViewMode::Default,
            Some(std::time::Duration::from_secs(2)),
            true,
            None,
            MountedRuntime::Accelerated,
            None,
            Arc::new(Paths::new()),
            Arc::new(mounted_operation_tree()),
        )
        .unwrap()
    }
    /// [`Self::new`], its unmount's shutdown run under `shutdown_bound` when
    /// one is given.
    fn bounded(
        deadline: tokio::time::Instant,
        shutdown_bound: Option<std::time::Duration>,
    ) -> Self {
        Self::with_options(
            deadline,
            Hook::Bound,
            crate::SyncProfile::default(),
            crate::ViewMode::Default,
            shutdown_bound,
            false,
            None,
            MountedRuntime::Accelerated,
            None,
            Arc::new(Paths::new()),
            Arc::new(mounted_operation_tree()),
        )
        .unwrap()
    }
    /// A mounted fixture whose binding starts the live commit loop.
    fn live(deadline: tokio::time::Instant, options: crate::SyncOptions) -> Self {
        Self::with_options(
            deadline,
            Hook::Bound,
            crate::SyncProfile::default(),
            crate::ViewMode::Default,
            None,
            false,
            Some(options),
            MountedRuntime::Accelerated,
            None,
            Arc::new(Paths::new()),
            Arc::new(mounted_operation_tree()),
        )
        .unwrap()
    }
    /// [`Self::live`], with waits measured on the fixture clock's real scale.
    fn live_unscaled(deadline: tokio::time::Instant, options: crate::SyncOptions) -> Self {
        Self::with_options(
            deadline,
            Hook::Bound,
            crate::SyncProfile::default(),
            crate::ViewMode::Default,
            None,
            false,
            Some(options),
            MountedRuntime::Unscaled,
            None,
            Arc::new(Paths::new()),
            Arc::new(mounted_operation_tree()),
        )
        .unwrap()
    }
    /// [`Self::live`], with `--view strict`.
    fn live_strict(deadline: tokio::time::Instant, options: crate::SyncOptions) -> Self {
        Self::with_options(
            deadline,
            Hook::Bound,
            crate::SyncProfile::default(),
            crate::ViewMode::Strict,
            None,
            false,
            Some(options),
            MountedRuntime::Accelerated,
            None,
            Arc::new(Paths::new()),
            Arc::new(mounted_operation_tree()),
        )
        .unwrap()
    }
    /// A mount using caller-selected fixture paths and publication state.
    fn shared_cache(
        deadline: tokio::time::Instant,
        profile: crate::SyncProfile,
        paths: Arc<Paths>,
        tree: Arc<PublishedTree>,
    ) -> Result<Self, String> {
        Self::shared_cache_over(deadline, profile, None, paths, tree)
    }
    /// A restarted mount whose authority keeps the first instance's persistent state.
    fn shared_cache_with_authority(
        deadline: tokio::time::Instant,
        profile: crate::SyncProfile,
        authority_state: AuthorityState,
        paths: Arc<Paths>,
        tree: Arc<PublishedTree>,
    ) -> Result<Self, String> {
        Self::shared_cache_over(deadline, profile, Some(authority_state), paths, tree)
    }
    fn shared_cache_over(
        deadline: tokio::time::Instant,
        profile: crate::SyncProfile,
        authority_state: Option<AuthorityState>,
        paths: Arc<Paths>,
        tree: Arc<PublishedTree>,
    ) -> Result<Self, String> {
        Self::with_options(
            deadline,
            Hook::Bound,
            profile,
            crate::ViewMode::Default,
            None,
            false,
            None,
            MountedRuntime::Accelerated,
            authority_state,
            paths,
            tree,
        )
    }
    /// A mount in `view` mode, its unmount's shutdown run under
    /// `shutdown_bound` when one is given.
    #[expect(
        clippy::too_many_arguments,
        reason = "the builder exposes the same independent fixture controls as with_options"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "the engine attachment, its probe and its mount stay in one fixture assembly"
    )]
    fn with_options(
        deadline: tokio::time::Instant,
        hook: Hook,
        profile: crate::SyncProfile,
        view: crate::ViewMode,
        shutdown_bound: Option<std::time::Duration>,
        harnessed: bool,
        live: Option<crate::SyncOptions>,
        runtime_kind: MountedRuntime,
        authority_state: Option<AuthorityState>,
        paths: Arc<Paths>,
        tree: Arc<PublishedTree>,
    ) -> Result<Self, String> {
        let timeline = EventTimeline::default();
        let events = super::super::Events::default();
        let dispatch = tracing::Dispatch::new(timeline.subscriber());
        let _capture = tracing::dispatcher::set_default(&dispatch);
        let parts = writable_fixture_core(
            profile,
            view,
            shutdown_bound,
            false,
            authority_state,
            &paths,
            &tree,
            |mut ready, tree, state, bound| {
                let remote = Arc::new(Authority::new(tree, state).with_publication());
                let content = Arc::new(
                    ready
                        .backend_for_test()
                        .sync_content(remote.clone())
                        .map_err(|error| error.to_string())?,
                );
                let (runtime, metrics, engine) =
                    attach_engine(&mut ready, remote, &content, state, live, runtime_kind);
                let bounded = ready
                    .backend_for_test()
                    .shutdown_for_test()
                    .ok_or_else(|| "an attached engine's shutdown is missing".to_owned())?;
                if let Some(bound) = bound {
                    bounded.bound_for_test(bound);
                }
                let attachment = ready.attach();
                let shutdown = attachment
                    .shutdown_handle()
                    .ok_or_else(|| "an attached engine's shutdown handle is missing".to_owned())?;
                Ok((attachment, (runtime, metrics, engine, content), shutdown))
            },
        )?;
        let WritableFixtureCore {
            mut attachment,
            sync_runtime: (runtime, metrics, engine, content),
            control,
            shutdown,
        } = parts;
        let state = Arc::clone(control.state());
        let mediator = control.mediator().clone();
        let faults = control.faults().clone();
        let binding = attachment.backend.take_view_binding().unwrap();
        // The tightly bounded harness rows keep the observer's original
        // single writer; syscall tracing magnifies tee and timeline-lock work there.
        let callback_capture = if harnessed {
            None
        } else {
            let callback_timeline = timeline.clone();
            let writer = events.clone().and(move || callback_timeline.clone());
            let subscriber = crate::subscriber(
                crate::LogFormat::Json,
                tracing_subscriber::EnvFilter::new("trace"),
                writer,
            );
            Some((events, tracing::Dispatch::new(subscriber)))
        };
        let (backend, observer) = indexed::observed(attachment.backend, callback_capture);
        observer.capture_events();
        let mut served_at_bind = None;
        let session = if hook == Hook::None {
            granary_fuse::spawn_session(
                attachment.snapshot,
                backend,
                1,
                granary_fuse::MountWritability::Writable,
                &paths.mountpoint,
                &granary_fuse::writable_session_config(),
            )
            .map_err(|error| format!("{error:?}: {error}"))?
        } else {
            let mountpoint = paths.mountpoint.clone();
            granary_fuse::spawn_writable_session(
                attachment.snapshot,
                backend,
                1,
                &paths.mountpoint,
                &granary_fuse::writable_session_config(),
                |view| {
                    if hook == Hook::Probed {
                        // A request blocks until a worker serves the
                        // kernel's INIT, so one answered here means the
                        // session was already serving.
                        let (answered, answer) = mpsc::channel();
                        std::thread::spawn(move || {
                            let _ = answered.send(std::fs::metadata(&mountpoint).is_ok());
                        });
                        served_at_bind = Some(
                            answer
                                .recv_timeout(std::time::Duration::from_millis(300))
                                .is_ok(),
                        );
                    }
                    binding
                        .bind(view, indexed::Measured::backend)
                        .map_err(|error| std::io::Error::other(error.to_string()))
                },
            )
            .map_err(|error| format!("{error:?}: {error}"))?
        };
        let recovery = faults.clone();
        // A test's earlier fixtures may each wait out their shutdown at
        // teardown, so an instant shared across fixtures never leaves this one
        // less than its own bound.
        let deadline = deadline.max(sync_deadline());
        let mount = SessionGuard::with_recovery(
            session,
            &paths.mountpoint,
            deadline.saturating_duration_since(crate::TokioSyncRuntime.now()),
            if harnessed {
                session_guard::ENGINE_JOIN_FLOOR
            } else {
                session_guard::engine_join_bound(shutdown_bound)
            },
            move || recovery.resume(),
        );
        assert!(
            abort::require_available(mount.abort_available, "mounted sync watchdog"),
            "mounted sync test requires its own connection abort descriptor"
        );
        let admitted_sends = state.lock().unwrap().sends.len();
        Ok(Self {
            mount,
            runtime,
            engine,
            observer,
            state,
            admitted_sends,
            content,
            mediator,
            metrics,
            faults,
            tree,
            served_at_bind,
            shutdown,
            timeline,
            dispatch,
            paths,
        })
    }
    fn with_capture<T>(&self, work: impl FnOnce() -> T) -> T {
        tracing::dispatcher::with_default(&self.dispatch, work)
    }
    fn file(&self) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.paths.mountpoint.join("f.txt"))
            .unwrap()
    }
    fn faults(&self) -> crate::FaultControl {
        self.faults.clone()
    }
    fn bytes(&self, name: &[u8]) -> Vec<u8> {
        prepared_bytes(
            &self.state,
            &*self.content,
            &self.tree.volume,
            name,
            &self.runtime,
        )
    }
    fn registrations(&self) -> usize {
        self.state.lock().unwrap().sends.len() - self.admitted_sends
    }
    fn sync_outcomes(&self) -> (u64, u64) {
        let rendered = self
            .metrics
            .snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap();
        super::super::observed::sync_metric_counts(&rendered)
    }
    fn synced_marks(&self) -> usize {
        let cfg = input(&self.tree, &self.paths);
        super::super::observed::file_synced_marks(&captured_records(&self.paths, &cfg).1)
    }
    fn published_head(&self) -> (GrainId, u64) {
        let (base_id, _) = self.mediator.with(|store| store.mount_base()).unwrap();
        let seq = self
            .runtime
            .block_on(remote_handle(&self.tree.mem).max_seq(self.tree.volume.as_str()))
            .unwrap()
            .unwrap();
        (base_id, seq)
    }
    /// The view the mount serves, as bound by its start or its last install.
    /// Read without the store's check, so it answers after a fence too; the
    /// overlay's sync base is [`remote::pin_seq`]'s.
    fn served_pin(&self) -> (GrainId, u64) {
        let pin = self
            .mediator
            .with(|store| Ok(store.mount_pin()))
            .unwrap()
            .expect("a mounted fixture binds its view at start");
        (pin.base_id, pin.base_seq)
    }
    fn mount_floor(&self) -> Option<u64> {
        mount_floor(&self.paths, &self.tree)
    }
    fn shared_anchor(&self) -> Option<Vec<u8>> {
        shared_anchor(&self.paths, &self.tree)
    }
    fn construct_commit(
        &self,
        entropy: u8,
    ) -> Result<crate::RetainedCommit, crate::CoordinationError> {
        self.with_capture(|| construct_commit(&self.engine, &self.runtime, entropy))
    }
    fn construct_commit_with(
        &self,
        options: crate::SyncOptions,
        entropy: u8,
    ) -> Result<crate::RetainedCommit, crate::CoordinationError> {
        self.with_capture(|| construct_commit_with(&self.engine, &self.runtime, options, entropy))
    }
    fn drive_commit(
        &self,
        lane: &crate::RetainedCommit,
        entropy: u8,
    ) -> Result<crate::PublicationResult, crate::CoordinationError> {
        self.with_capture(|| drive_commit(&self.engine, &self.runtime, lane, entropy))
    }
    fn resume_commit(
        &self,
        lane: &crate::RetainedCommit,
        entropy: u8,
    ) -> Result<crate::PublicationResult, crate::CoordinationError> {
        self.with_capture(|| resume_commit(&self.engine, &self.runtime, lane, entropy))
    }
    fn held_handles(&self, read: HeldRead) -> HeldHandles {
        HeldHandles::open(&self.paths.mountpoint, self.observer.clone(), read)
    }
    fn remote_seq(&self) -> u64 {
        remote_seq(&self.tree, &self.runtime)
    }
    fn publications(&self) -> usize {
        self.state.lock().unwrap().publications.len()
    }
    fn journal_records(&self) -> Vec<granary_core::overlay_journal::Record> {
        let cfg = input(&self.tree, &self.paths);
        captured_records(&self.paths, &cfg).1
    }
    fn staging(&self) -> BTreeMap<String, Vec<u8>> {
        captured_staging(&self.paths, &input(&self.tree, &self.paths))
    }
    /// Whether a submission is retained for the volume.
    fn retained(&self) -> bool {
        self.mediator
            .with(|store| {
                let scope = store.snapshot().scope.clone();
                let volume = store.snapshot().volume.clone();
                store.publication_transaction(|j| j.load(&scope, &volume))
            })
            .unwrap()
            .is_some()
    }
    /// Lookup, read and listing, each answered by the daemon: the writable mount
    /// grants the kernel no entry or attribute lifetime and no cached reads.
    fn view_probe(&self) -> [Result<(), Option<i32>>; 3] {
        let file = self.paths.mountpoint.join("f.txt");
        [
            std::fs::metadata(&file).map(drop),
            std::fs::read(&file).map(drop),
            std::fs::read_dir(&self.paths.mountpoint)
                .and_then(Iterator::collect::<Result<Vec<_>, _>>)
                .map(drop),
        ]
        .map(|result| result.map_err(|error| error.raw_os_error()))
    }
    fn mark_close(&self) {
        self.timeline.mark_close();
    }
    fn timeline_records(&self) -> Vec<String> {
        self.timeline.records()
    }
    fn assert_saw_commit(&self) {
        self.timeline.assert_saw_commit();
    }
    fn authority_requests(&self) -> String {
        let state = self.state.lock().unwrap();
        let sends = state
            .sends
            .iter()
            .skip(self.admitted_sends)
            .map(|request| GrainId::of(request))
            .collect::<Vec<_>>();
        let sends = sends
            .get(sends.len().saturating_sub(AUTHORITY_REQUEST_LIMIT)..)
            .unwrap_or_default();
        let publications = state
            .publications
            .iter()
            .map(|candidate| GrainId::of(candidate))
            .collect::<Vec<_>>();
        let publications = publications
            .get(publications.len().saturating_sub(AUTHORITY_REQUEST_LIMIT)..)
            .unwrap_or_default();
        format!(
            "authority received: sends={sends:?}; publications={publications:?}; \
             probes={}; root_reads={}; head_seq={}",
            state.probes, state.root_reads, state.head_seq
        )
    }
    fn wait(&self, label: &str, predicate: impl Fn() -> bool) {
        let started = crate::TokioSyncRuntime.now();
        let wall_started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(10);
        while !predicate() && crate::TokioSyncRuntime.now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let elapsed = crate::TokioSyncRuntime
            .now()
            .saturating_duration_since(started);
        assert!(
            predicate(),
            "mounted actor did not reach {label} after {elapsed:?}\n{}\n{}",
            self.timeline.render(wall_started),
            self.authority_requests(),
        );
    }
    fn finish(self) {
        let scratch = self.paths.scratch.clone();
        drop(self.finish_shared_cache());
        assert!(
            !scratch.exists(),
            "sync fixture scratch survived cleanup: {scratch:?}"
        );
    }
    /// Finish one owner while retaining its cache and publication for a restart.
    fn finish_shared_cache(mut self) -> (Arc<Paths>, Arc<PublishedTree>) {
        let paths = Arc::clone(&self.paths);
        let tree = Arc::clone(&self.tree);
        let result = self.mount.finish();
        // The session's `destroy` runs the engine's shutdown, so its report
        // tells a slow shutdown from a session that ended late after it.
        eprintln!(
            "sync fixture teardown: {result:?}; engine shutdown {:?}",
            self.shutdown.report()
        );
        drop(self);
        result.unwrap();
        (paths, tree)
    }
}
impl Drop for SyncMount {
    fn drop(&mut self) {
        // A failed assertion must release a blocked job before runtime teardown.
        self.faults.resume();
        if let Err(error) = self.mount.finish() {
            eprintln!("sync fixture cleanup: {error}");
        }
    }
}
struct Resume(crate::FaultControl);
impl Drop for Resume {
    fn drop(&mut self) {
        self.0.resume();
    }
}

#[derive(Clone, Copy)]
enum HeldRead {
    Buffered,
    Direct,
}

/// A file and a directory opened before a landing and used after it. Only a
/// descriptor kept open sends `read` and `readdir` for its original handle: a
/// path lookup, `read` or `read_dir` opens afresh and would fail at the open
/// whether or not the old handle still served stale bytes or entries. The
/// directory is listed by rewinding the held descriptor and calling
/// `getdents64` on it: `listdir(fd)` would duplicate the descriptor and `fstat`
/// it first, so a getattr refusal could stand in for a refused listing. The
/// buffered file is read with `pread` after `POSIX_FADV_DONTNEED` drops its
/// cached pages. Tests asserting the daemon's exact read errno use `O_DIRECT`:
/// the kernel's buffered FUSE path can return EIO for an EACCES reply.
/// The daemon's own callbacks show that each probe sent its READ or READDIR.
struct HeldHandles {
    holder: std::process::Child,
    replies: std::io::BufReader<std::process::ChildStdout>,
    observer: Arc<indexed::WorkerObserver>,
    listing: Vec<(Callback, CallbackOutcome)>,
}
impl HeldHandles {
    fn open(root: &Path, observer: Arc<indexed::WorkerObserver>, read: HeldRead) -> Self {
        use std::io::BufRead as _;
        let before = observer.callback_results().len();
        let mut holder = Command::new("python3")
            .arg("-c")
            .arg(crate::overlay_test_support::HELD_HANDLE_SCRIPT)
            .arg(root)
            .arg("both")
            .args(matches!(read, HeldRead::Direct).then_some("direct"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut replies = std::io::BufReader::new(holder.stdout.take().unwrap());
        let mut opened = String::new();
        replies.read_line(&mut opened).unwrap();
        assert_eq!(
            opened.trim(),
            "OPEN 0",
            "the directory holder must open the directory and read an entry while it is healthy"
        );
        let first_listing: Vec<_> = observer
            .callback_results()
            .split_off(before)
            .into_iter()
            .filter(|(callback, _)| matches!(callback, Callback::Readdir | Callback::Readdirplus))
            .collect();
        assert_eq!(
            first_listing.first().map(|(_, outcome)| *outcome),
            Some(CallbackOutcome::Ok),
            "the daemon must have served the holder's healthy listing: {first_listing:?}"
        );
        Self {
            holder,
            replies,
            observer,
            listing: Vec::new(),
        }
    }
    /// What the last listing's own callbacks say: `None` unless it sent only
    /// READDIRs (so no getattr or reopen could have answered for it), else
    /// whether the daemon refused any of them.
    fn listing_refused(&self) -> Option<bool> {
        let readdirs = self
            .listing
            .iter()
            .map(|(callback, outcome)| {
                matches!(callback, Callback::Readdir | Callback::Readdirplus).then_some(*outcome)
            })
            .collect::<Option<Vec<_>>>()?;
        (!readdirs.is_empty()).then(|| {
            readdirs.iter().any(|outcome| {
                matches!(
                    outcome,
                    CallbackOutcome::Refused | CallbackOutcome::Failed(_)
                )
            })
        })
    }
    /// Sends one request to the holder and returns its answer with the daemon
    /// callbacks the request caused.
    fn ask(&mut self, request: &[u8]) -> (i32, Vec<(Callback, CallbackOutcome)>) {
        use std::io::BufRead as _;
        let before = self.observer.callback_results().len();
        self.holder
            .stdin
            .as_mut()
            .unwrap()
            .write_all(request)
            .unwrap();
        let mut reply = String::new();
        self.replies.read_line(&mut reply).unwrap();
        let answer = reply
            .trim()
            .parse::<i32>()
            .unwrap_or_else(|error| panic!("handle holder answered {reply:?}: {error}"));
        (answer, self.observer.callback_results().split_off(before))
    }
    /// A read through the held file handle, then a listing through the held
    /// directory handle. The read must reach the daemon as a READ, so a page
    /// the kernel kept cannot answer for it. `POSIX_FADV_DONTNEED` may leave a
    /// page it could not drop at that moment, so the read is retried a bounded
    /// number of times and only an answer that reached the daemon counts.
    fn probe(&mut self) -> [Result<(), Option<i32>>; 2] {
        let mut attempts = Vec::new();
        let answer = loop {
            let (answer, read) = self.ask(b"READ\n");
            if read
                .iter()
                .any(|(callback, _)| matches!(callback, Callback::Read))
            {
                break answer;
            }
            attempts.push(read);
            assert!(
                attempts.len() < 10,
                "the held file read never sent the daemon a READ: {attempts:?}"
            );
        };
        let read = match answer {
            0 => Ok(()),
            errno => Err(Some(errno)),
        };
        let (answer, listing) = self.ask(b"LIST\n");
        self.listing = listing;
        let listing = match answer {
            0 => Ok(()),
            -1 => panic!("the held directory listed no entry, not even a failure"),
            errno => Err(Some(errno)),
        };
        [read, listing]
    }
}
impl Drop for HeldHandles {
    fn drop(&mut self) {
        drop(self.holder.stdin.take());
        if matches!(self.holder.try_wait(), Ok(None)) {
            let _ = self.holder.kill();
        }
        let _ = self.holder.wait();
    }
}

fn venue(name: &str) -> bool {
    if Path::new("/dev/fuse").exists() {
        assert!(
            session_guard::require_control_fs(name),
            "mounted sync test requires fusectl for its watchdog"
        );
        true
    } else {
        eprintln!("SKIPPED-NO-DEV-FUSE {name}");
        false
    }
}

fn sync_deadline() -> tokio::time::Instant {
    crate::TokioSyncRuntime.now() + session_guard::TEST_BOUND
}

#[test]
fn writable_linux_sync_table_rows() {
    if !venue("writable_linux_sync_table_rows") {
        return;
    }
    let deadline = sync_deadline();
    let mut cases = 0;
    for datasync in [false, true] {
        for kind in ["clean", "empty", "dirty", "orphan", "failure"] {
            let fixture = SyncMount::new(deadline);
            let file = if kind == "empty" {
                std::fs::File::create_new(fixture.paths.mountpoint.join("new-empty.txt")).unwrap()
            } else {
                fixture.file()
            };
            if matches!(kind, "dirty" | "orphan" | "failure") {
                file.write_at(b"sync", 0).unwrap();
            }
            if kind == "orphan" {
                std::fs::remove_file(fixture.paths.mountpoint.join("f.txt")).unwrap();
            }
            let faults = fixture.faults();
            if kind == "failure" {
                faults.arm("sync.capture", "after", 1, crate::FaultAction::Fail);
            }
            let (expected, registrations, outcome, fired) = if kind == "failure" {
                (
                    Err(Some(5)),
                    0,
                    CallbackOutcome::Failed(granary_fuse::MountError::Io),
                    vec![("sync.capture", "after", 1)],
                )
            } else {
                (Ok(()), 1, CallbackOutcome::Ok, vec![])
            };
            let before = fixture.registrations();
            let result = if datasync {
                file.sync_data()
            } else {
                file.sync_all()
            };
            assert_eq!(
                (
                    result.map_err(|error| error.raw_os_error()),
                    fixture.registrations() - before,
                    fixture.observer.sync_results(),
                    fixture.observer.sync_requests(),
                    faults
                        .sync_fired()
                        .iter()
                        .map(|event| (event.name, event.phase, event.occurrence))
                        .collect::<Vec<_>>()
                ),
                (
                    expected,
                    registrations,
                    vec![(Callback::Fsync, outcome)],
                    vec![(false, datasync)],
                    fired
                ),
                "kind={kind}, datasync={datasync}"
            );
            drop(file);
            let directory = std::fs::File::open(fixture.paths.mountpoint.as_path()).unwrap();
            directory.sync_all().unwrap();
            assert_eq!(
                fixture.observer.sync_results().last(),
                Some(&(Callback::Fsyncdir, CallbackOutcome::Ok))
            );
            drop(directory);
            fixture.finish();
            cases += 1;
        }
    }
    assert_eq!(cases, 10);
}

#[test]
fn writable_linux_sync_covers_other_handle() {
    if !venue("writable_linux_sync_covers_other_handle") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let writer = fixture.file();
    let reader = std::fs::File::open(fixture.paths.mountpoint.join("f.txt")).unwrap();
    writer.write_at(b"other", 0).unwrap();
    reader.sync_data().unwrap();
    let mut expected = FILE_CONTENT.to_vec();
    expected[..5].copy_from_slice(b"other");
    assert_eq!(
        (
            fixture.bytes(b"f.txt"),
            fixture.registrations(),
            fixture.observer.sync_results()
        ),
        (expected, 1, vec![(Callback::Fsync, CallbackOutcome::Ok)])
    );
    drop((reader, writer));
    fixture.finish();
}

#[test]
fn writable_linux_write_after_capture_survives() {
    if !venue("writable_linux_write_after_capture_survives") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let file = fixture.file();
    file.write_at(b"first", 0).unwrap();
    let actor_file = file.try_clone().unwrap();
    let writer_file = file.try_clone().unwrap();
    let faults = fixture.faults();
    faults.arm("sync.capture", "after", 1, crate::FaultAction::Block);
    std::thread::scope(|threads| {
        let _resume = Resume(faults.clone());
        let (sender, reply) = mpsc::channel();
        let actor = threads.spawn(move || {
            let result = actor_file.sync_all();
            sender.send(result).unwrap();
        });
        fixture.wait("sync.capture/after fault", || {
            !faults.sync_fired().is_empty()
        });
        let (started, writing) = mpsc::channel();
        let (written, write_reply) = mpsc::channel();
        let observer = fixture.observer.clone();
        let writer = threads.spawn(move || {
            started.send(()).unwrap();
            let result = writer_file.write_at(b"later", 0);
            // Sample terminal callbacks at syscall completion, independent of
            // actor scheduling.
            written.send((result, observer.sync_results())).unwrap();
        });
        writing
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        let write_pending = write_reply.recv_timeout(std::time::Duration::from_millis(100));
        let pending = reply.try_recv();
        assert!(
            matches!(
                (&pending, &write_pending),
                (
                    Err(mpsc::TryRecvError::Empty),
                    Err(mpsc::RecvTimeoutError::Timeout)
                )
            ),
            "sync/write before resume: {:?}",
            (pending, write_pending)
        );
        faults.resume();
        reply
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .unwrap();
        actor.join().unwrap();
        let (write_result, sync_before_write) = write_reply
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        writer.join().unwrap();
        assert_eq!(
            (
                write_result.map_err(|error| error.raw_os_error()),
                sync_before_write
            ),
            (Ok(5), vec![(Callback::Fsync, CallbackOutcome::Ok)]),
            "write must complete after the successful fsync reply"
        );
        let mut expected = FILE_CONTENT.to_vec();
        expected[..5].copy_from_slice(b"first");
        assert_eq!(fixture.bytes(b"f.txt"), expected);
        file.sync_all().unwrap();
        expected[..5].copy_from_slice(b"later");
        assert_eq!(
            (fixture.bytes(b"f.txt"), fixture.observer.sync_results()),
            (expected, vec![(Callback::Fsync, CallbackOutcome::Ok); 2])
        );
    });
    drop(file);
    fixture.finish();
}

#[test]
fn writable_linux_shrink_waits_without_blocking_sync() {
    if !venue("writable_linux_shrink_waits_without_blocking_sync") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let file = fixture.file();
    file.write_at(b"saved", 0).unwrap();
    let sync_file = file.try_clone().unwrap();
    let shrink_file = file.try_clone().unwrap();
    let faults = fixture.faults();
    faults.arm("sync.capture", "after", 1, crate::FaultAction::Block);
    std::thread::scope(|threads| {
        let _resume = Resume(faults.clone());
        let (synced, sync_reply) = mpsc::channel();
        let sync = threads.spawn(move || {
            synced.send(sync_file.sync_all()).unwrap();
        });
        fixture.wait("sync.capture/after fault", || {
            !faults.sync_fired().is_empty()
        });
        let (started, shrinking) = mpsc::channel();
        let (sender, reply) = mpsc::channel();
        let observer = fixture.observer.clone();
        let shrink = threads.spawn(move || {
            started.send(()).unwrap();
            let result = shrink_file.set_len(0);
            sender.send((result, observer.sync_results())).unwrap();
        });
        shrinking
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        let pending = reply.recv_timeout(std::time::Duration::from_millis(100));
        let sync_pending = sync_reply.try_recv();
        let captured = fixture.observer.captured_setattr();
        assert!(
            matches!(
                (&sync_pending, &pending, captured),
                (
                    Err(mpsc::TryRecvError::Empty),
                    Err(mpsc::RecvTimeoutError::Timeout),
                    false
                )
            ),
            "sync/shrink/capture before resume: {:?}",
            (sync_pending, pending, captured)
        );
        let other = std::fs::OpenOptions::new()
            .write(true)
            .open(fixture.paths.mountpoint.join("sub/g.txt"))
            .unwrap();
        other.write_at(b"free", 0).unwrap();
        faults.resume();
        sync_reply
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .unwrap();
        sync.join().unwrap();
        let (shrink_result, sync_before_shrink) = reply
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        shrink.join().unwrap();
        assert_eq!(
            (
                shrink_result.map_err(|error| error.raw_os_error()),
                sync_before_shrink
            ),
            (Ok(()), vec![(Callback::Fsync, CallbackOutcome::Ok)]),
            "shrink must complete after the successful fsync reply"
        );
        let mut expected = FILE_CONTENT.to_vec();
        expected[..5].copy_from_slice(b"saved");
        assert_eq!(
            (fixture.bytes(b"f.txt"), file.metadata().unwrap().len()),
            (expected, 0)
        );
        file.sync_all().unwrap();
        assert_eq!(
            (fixture.bytes(b"f.txt"), fixture.observer.sync_results()),
            (
                b"".to_vec(),
                vec![(Callback::Fsync, CallbackOutcome::Ok); 2]
            )
        );
        drop(other);
    });
    drop(file);
    fixture.finish();
}

#[test]
fn writable_linux_rename_directory_fault_fires() {
    if !venue("writable_linux_rename_directory_fault_fires") {
        return;
    }
    let deadline = sync_deadline();
    let mut cases = 0;
    for initial_sync in [false, true] {
        let fixture = SyncMount::new(deadline);
        let target = std::fs::File::create(fixture.paths.mountpoint.join("target")).unwrap();
        target.sync_all().unwrap();
        drop(target);
        let file = fixture.file();
        file.write_at(b"ready", 0).unwrap();
        if initial_sync {
            file.sync_all().unwrap();
        }
        let before = fixture.registrations();
        std::fs::rename(
            fixture.paths.mountpoint.join("f.txt"),
            fixture.paths.mountpoint.join("target"),
        )
        .unwrap();
        assert_eq!(
            fixture.registrations(),
            before,
            "rename registered without explicit sync"
        );
        let cursor = fixture
            .mediator
            .overlay_transaction(|overlay| overlay.journal_cursor())
            .unwrap();
        let faults = fixture.faults();
        faults.arm(
            "fuse.sync.rename_directory",
            "before",
            1,
            crate::FaultAction::Fail,
        );
        let directory = std::fs::File::open(fixture.paths.mountpoint.as_path()).unwrap();
        let failed = directory
            .sync_all()
            .err()
            .and_then(|error| error.raw_os_error());
        let events = faults.sync_fired();
        assert_eq!(
            (
                failed,
                fixture.registrations() - before,
                events
                    .iter()
                    .map(|event| (
                        event.name,
                        event.phase,
                        event.occurrence,
                        event.capture,
                        event.request,
                        event.object_kind,
                        event.rename_directory
                    ))
                    .collect::<Vec<_>>()
            ),
            (
                Some(5),
                0,
                vec![(
                    "fuse.sync.rename_directory",
                    "before",
                    1,
                    0,
                    None,
                    "directory",
                    Some(crate::RenameDirectoryFaultContext {
                        journal_cursor: cursor,
                        directory_inode: None
                    })
                )]
            )
        );
        faults.trace_sync();
        directory.sync_all().unwrap();
        let mut expected = FILE_CONTENT.to_vec();
        if initial_sync {
            expected[..5].copy_from_slice(b"ready");
        }
        assert_eq!(
            (fixture.bytes(b"target"), fixture.registrations() - before),
            (expected, 1)
        );
        drop((file, directory));
        fixture.finish();
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn writable_linux_ro_flush_release_never_register() {
    if !venue("writable_linux_ro_flush_release_never_register") {
        return;
    }
    let paths = Paths::new();
    let tree = mounted_operation_tree();
    let cfg = input(&tree, &paths);
    let journal = journal_path(&paths, &cfg);
    let (mut mount, before, state) = mount_refusal_pair(&tree, &paths, &cfg, &journal, false);
    assert!(
        abort::require_available(mount.abort_available, "RO sync watchdog"),
        "mounted sync test requires its own connection abort descriptor"
    );
    let file = std::fs::File::open(paths.mountpoint.join("f.txt")).unwrap();
    let duplicate = file.try_clone().unwrap();
    file.sync_all().unwrap();
    duplicate.sync_data().unwrap();
    std::fs::File::open(&paths.mountpoint)
        .unwrap()
        .sync_all()
        .unwrap();
    drop((file, duplicate));
    mount.finish().unwrap();
    assert_eq!(
        (before, journal.exists(), state.lock().unwrap().calls),
        (None, false, [0; 4]),
        "RO sync/flush/release constructed writable state or contacted authority"
    );
}

fn assert_sync_write_controls(deadline: tokio::time::Instant) {
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let lockfile = include_str!("../../../../../../../Cargo.lock");
    let config = granary_fuse::writable_session_config();
    let config_dbg = format!("{config:?}");
    eprintln!("kernel={kernel_release:?}; fuser=0.18.0; config={config_dbg}");
    assert!(
        !kernel_release.is_empty()
            && lockfile.contains("name = \"fuser\"\nversion = \"0.18.0\"")
            && (config.n_threads, config.clone_fd) == (Some(1), false)
            && config_dbg.contains("RW")
            && !config_dbg.contains("RO"),
        "environment/config witness: kernel={kernel_release:?}, config={config_dbg}"
    );
    let control = SyncMount::new(deadline);
    let ordinary = control.file();
    assert_eq!(ordinary.write_at(b"plain", 0).unwrap(), 5);
    let ordinary_flags = control.observer.write_flags();
    assert!(
        !ordinary_flags.is_empty()
            && ordinary_flags
                .iter()
                .all(|(req, retained)| (req | retained) & 0x0010_1000 == 0),
        "ordinary write carried synchronous flags: {ordinary_flags:?}"
    );
    assert_eq!(
        (
            control.registrations(),
            control.observer.sync_results(),
            control.observer.sync_requests(),
            control.observer.write_sync_requests()
        ),
        (0, vec![], vec![], vec![])
    );
    ordinary.sync_data().unwrap();
    assert_eq!(ordinary.write_at(b"plain-all", 0).unwrap(), 9);
    ordinary.sync_all().unwrap();
    let mut expected = FILE_CONTENT.to_vec();
    expected[..9].copy_from_slice(b"plain-all");
    assert_eq!(
        (
            control.registrations(),
            control.observer.sync_results(),
            control.observer.sync_requests(),
            control.bytes(b"f.txt")
        ),
        (
            2,
            vec![(Callback::Fsync, CallbackOutcome::Ok); 2],
            vec![(false, true), (false, false)],
            expected
        )
    );
    drop(ordinary);
    control.finish();
}

#[derive(Debug)]
struct WriteSample {
    outcomes: usize,
    flags: usize,
    jobs: usize,
    fsyncs: usize,
    fsync_bits: usize,
    opcodes: usize,
    registrations: usize,
}
impl WriteSample {
    fn new(fixture: &SyncMount) -> Self {
        Self {
            outcomes: fixture.observer.write_results().len(),
            flags: fixture.observer.write_flags().len(),
            jobs: fixture.observer.write_sync_requests().len(),
            fsyncs: fixture.observer.sync_results().len(),
            fsync_bits: fixture.observer.sync_requests().len(),
            opcodes: fixture.observer.opcodes().len(),
            registrations: fixture.registrations(),
        }
    }
    fn diagnostic(&self, fixture: &SyncMount) -> String {
        format!(
            "write_flags(request,retained)={:x?}; opcodes={:?}; write_sync_requests={:?}; write_results={:?}; sync_fired={:?}; attribution_failures={:?}; registrations={}",
            &fixture.observer.write_flags()[self.flags..],
            &fixture.observer.opcodes()[self.opcodes..],
            &fixture.observer.write_sync_requests()[self.jobs..],
            &fixture.observer.write_results()[self.outcomes..],
            fixture.faults.sync_fired(),
            fixture.observer.attribution_failures(),
            fixture.registrations() - self.registrations
        )
    }
    fn assert_completed(&self, fixture: &SyncMount, datasync: bool, count: usize) {
        let outcomes = fixture.observer.write_results();
        let flags = fixture.observer.write_flags();
        let jobs = fixture.observer.write_sync_requests();
        let fsyncs = fixture.observer.sync_results();
        let fsync_bits = fixture.observer.sync_requests();
        let opcodes = fixture.observer.opcodes();
        let mode = |flags: i32| {
            if flags & 0x0010_1000 == 0x0010_1000 {
                Some(false)
            } else if flags & 0x1000 != 0 {
                Some(true)
            } else {
                None
            }
        };
        assert_eq!(
            (
                count > 0,
                &outcomes[self.outcomes..],
                flags[self.flags..]
                    .iter()
                    .all(|(req, retained)| mode(req | retained) == Some(datasync)),
                flags.len() - self.flags,
                &jobs[self.jobs..],
                fixture.registrations() - self.registrations >= count,
                fixture.observer.attribution_failures().is_empty()
            ),
            (
                true,
                vec![CallbackOutcome::Ok; count].as_slice(),
                true,
                count,
                vec![(false, datasync); count].as_slice(),
                true,
                true
            ),
            "{}",
            self.diagnostic(fixture)
        );
        // An earlier handle's asynchronous RELEASE can land after the sample
        // starts; only a release from the sampled file's own OPEN onwards is a
        // close during the interval.
        let sampled = &opcodes[self.opcodes..];
        let from_open = sampled
            .iter()
            .position(|opcode| *opcode == Callback::Open)
            .unwrap_or(0);
        assert!(
            fsyncs[self.fsyncs..]
                .iter()
                .all(|(cb, outcome)| (*cb, *outcome) == (Callback::Fsync, CallbackOutcome::Ok))
                && fsync_bits[self.fsync_bits..].iter().all(|(dir, _)| !dir)
                && !sampled[from_open..].contains(&Callback::Release),
            "{}",
            self.diagnostic(fixture)
        );
        eprintln!(
            "measured kernel FSYNCs: {:?}; datasync bits: {:?}",
            &fsyncs[self.fsyncs..],
            &fsync_bits[self.fsync_bits..]
        );
    }
}

fn paused_sync_write<T: Send + std::fmt::Debug>(
    case: &str,
    fixture: &SyncMount,
    occurrence: usize,
    action: impl FnOnce() -> io::Result<T> + Send,
) -> T {
    let sample = WriteSample::new(fixture);
    let faults = fixture.faults();
    faults.arm(
        "sync.reply",
        "before",
        u64::try_from(occurrence).unwrap(),
        crate::FaultAction::Block,
    );
    std::thread::scope(|threads| {
        let _resume = Resume(faults.clone());
        let (sender, reply) = mpsc::channel();
        let writer = threads.spawn(move || {
            if let Err(error) = sender.send(action()) {
                eprintln!(
                    "synchronous writer receiver closed; writer result={:?}",
                    error.0
                );
            }
        });
        let deadline = crate::TokioSyncRuntime.now() + std::time::Duration::from_secs(3);
        while super::super::observed::sync_write_boundary(&faults.sync_fired(), occurrence as u64)
            .is_err()
            && crate::TokioSyncRuntime.now() < deadline
        {
            std::thread::yield_now();
        }
        let boundary =
            super::super::observed::sync_write_boundary(&faults.sync_fired(), occurrence as u64);
        let pending = reply.recv_timeout(std::time::Duration::from_millis(100));
        assert_eq!(
            (
                boundary,
                matches!(pending, Err(mpsc::RecvTimeoutError::Timeout)),
                fixture.observer.write_sync_requests().len() - sample.jobs,
                fixture.observer.write_results().len() - sample.outcomes,
                fixture.registrations() - sample.registrations >= occurrence
            ),
            (Ok(()), true, occurrence, occurrence - 1, true),
            "{case}: missing synchronous bits in fuse_write_in.flags (including RWF_DSYNC/RWF_SYNC on plain handles) cannot pass the write-path boundary; writer result={pending:?}; {}",
            sample.diagnostic(fixture)
        );
        faults.resume();
        let out = reply.recv_timeout(std::time::Duration::from_secs(5));
        assert!(
            matches!(out, Ok(Ok(_))),
            "writer result={out:?}; {}",
            sample.diagnostic(fixture)
        );
        writer.join().unwrap();
        out.unwrap().unwrap()
    })
}

fn seed_sync_write_files(fixture: &SyncMount) {
    for name in ["sync.txt", "dsync.txt"] {
        let seeded = std::fs::File::create_new(fixture.paths.mountpoint.join(name)).unwrap();
        seeded.write_at(FILE_CONTENT, 0).unwrap();
        seeded.sync_all().unwrap();
    }
    std::fs::File::open(fixture.paths.mountpoint.as_path())
        .unwrap()
        .sync_all()
        .unwrap();
}

fn sync_write_open_flag(fixture: &SyncMount, name: &str, flag: i32, datasync: bool) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(flag)
        .open(fixture.paths.mountpoint.join(name))
        .unwrap();
    let mut expected = FILE_CONTENT.to_vec();
    for (idx, payload) in [b"sync-one".as_slice(), b"sync-two".as_slice()]
        .into_iter()
        .enumerate()
    {
        let sample = WriteSample::new(fixture);
        let written = if idx == 1 {
            paused_sync_write(name, fixture, 1, || file.write_at(payload, 0))
        } else {
            file.write_at(payload, 0).unwrap()
        };
        let count = fixture.observer.write_results().len() - sample.outcomes;
        assert_eq!(written, payload.len(), "{}", sample.diagnostic(fixture));
        sample.assert_completed(fixture, datasync, count);
        let flags = fixture.observer.write_flags();
        assert!(
            flags[sample.flags..]
                .iter()
                .all(|(_, retained)| retained & flag == flag),
            "{}",
            sample.diagnostic(fixture)
        );
        expected[..payload.len()].copy_from_slice(payload);
        assert_eq!(fixture.bytes(name.as_bytes()), expected);
    }
    sync_write_failure_after_seed(fixture, &file, datasync);
}

fn sync_write_failure_after_seed(fixture: &SyncMount, file: &std::fs::File, datasync: bool) {
    let sample = WriteSample::new(fixture);
    let faults = fixture.faults();
    faults.arm("sync.capture", "after", 1, crate::FaultAction::Fail);
    let result = file
        .write_at(b"failed-write", 0)
        .map_err(|error| error.raw_os_error());
    let outcomes = fixture.observer.write_results();
    assert_eq!(
        (
            result,
            &outcomes[sample.outcomes..],
            &fixture.observer.write_sync_requests()[sample.jobs..],
            fixture.registrations() - sample.registrations
        ),
        (
            Err(Some(5)),
            [CallbackOutcome::Failed(granary_fuse::MountError::Io)].as_slice(),
            [(false, datasync)].as_slice(),
            0
        ),
        "new synchronous failure selected a seed outcome: {}",
        sample.diagnostic(fixture)
    );
    file.sync_all().unwrap();
}

fn sync_write_split_syscall(fixture: &SyncMount) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(0x0010_1000)
        .open(fixture.paths.mountpoint.join("sync.txt"))
        .unwrap();
    // fuser 0.18 offers 16,777,216 bytes per WRITE and the kernel clamps that
    // to max_pages_limit pages (256 when the sysctl is absent). One byte past
    // the smaller ceiling forces a split without filling the job's storage;
    // the premise below still requires more than one fragment.
    let pages = std::fs::read_to_string("/proc/sys/fs/fuse/max_pages_limit")
        .ok()
        .and_then(|text| text.trim().parse::<usize>().ok())
        .unwrap_or(256);
    let mut payload = vec![b'a'; (pages * 4096).min(16_777_216) + 1];
    let first = WriteSample::new(fixture);
    let written = file.write_at(&payload, 0).unwrap();
    let fragments = fixture.observer.write_results().len() - first.outcomes;
    assert_eq!(
        (written, fragments > 1),
        (payload.len(), true),
        "split-write premise: {}",
        first.diagnostic(fixture)
    );
    first.assert_completed(fixture, false, fragments);
    assert_eq!(fixture.bytes(b"sync.txt"), payload);
    payload.fill(b'b');
    let last = WriteSample::new(fixture);
    assert_eq!(
        paused_sync_write("split syscall last fragment", fixture, fragments, || file
            .write_at(&payload, 0)),
        payload.len()
    );
    last.assert_completed(fixture, false, fragments);
    assert_eq!(fixture.bytes(b"sync.txt"), payload);
}

#[test]
fn writable_linux_sync_write_wire_and_receipt() {
    if !venue("writable_linux_sync_write_wire_and_receipt") {
        return;
    }
    let deadline = sync_deadline();
    assert_sync_write_controls(deadline);
    let fixture = SyncMount::new(deadline);
    seed_sync_write_files(&fixture);
    for (name, flag, datasync) in [
        ("sync.txt", 0x0010_1000, false),
        ("dsync.txt", 0x1000, true),
    ] {
        sync_write_open_flag(&fixture, name, flag, datasync);
    }
    sync_write_rwf(&fixture);
    sync_write_split_syscall(&fixture);
    fixture.finish();
}

#[derive(Debug)]
struct RwfWriter(std::process::Child);
impl RwfWriter {
    fn start(root: &Path, flag: &str, payload: &str) -> io::Result<(usize, Self)> {
        use std::io::BufRead as _;
        let script = "import os,sys\nfd=os.open(os.path.join(sys.argv[1],'f.txt'),os.O_RDWR)\nn=os.pwritev(fd,[sys.argv[3].encode()],0,getattr(os,sys.argv[2]))\nprint(n,flush=True)\nassert sys.stdin.readline().strip()=='CLOSE'\nos.close(fd)";
        let mut actor = Self(
            Command::new("python3")
                .arg("-c")
                .arg(script)
                .arg(root)
                .arg(flag)
                .arg(payload)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?,
        );
        let mut line = String::new();
        std::io::BufReader::new(actor.0.stdout.take().unwrap()).read_line(&mut line)?;
        if line.trim().is_empty() {
            let status = actor.0.wait()?;
            let mut stderr = String::new();
            actor.0.stderr.take().unwrap().read_to_string(&mut stderr)?;
            return Err(io::Error::other(format!(
                "{flag} syscall: status={status}, stdout={line:?}, stderr={stderr}"
            )));
        }
        let count = line.trim().parse().map_err(|error| {
            io::Error::other(format!("{flag} syscall returned {line:?}: {error}"))
        })?;
        Ok((count, actor))
    }
    fn finish(&mut self) {
        self.0.stdin.take().unwrap().write_all(b"CLOSE\n").unwrap();
        let status = self.0.wait().unwrap();
        let mut stderr = String::new();
        self.0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(
            status.success(),
            "RWF syscall driver: status={status}, stderr={stderr}"
        );
    }
}
impl Drop for RwfWriter {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn sync_write_rwf(fixture: &SyncMount) {
    for (flag, datasync, payload) in [
        ("RWF_DSYNC", true, "rwf-data"),
        ("RWF_SYNC", false, "rwf-sync"),
    ] {
        let sample = WriteSample::new(fixture);
        let mountpoint = fixture.paths.mountpoint.clone();
        let (written, mut actor) = paused_sync_write(flag, fixture, 1, move || {
            RwfWriter::start(&mountpoint, flag, payload)
        });
        let flags = fixture.observer.write_flags();
        let required = if datasync { 0x1000 } else { 0x0010_1000 };
        assert_eq!(
            (
                written,
                flags[sample.flags..].iter().all(
                    |(req, retained)| retained & 0x0010_1000 == 0 && req & required == required
                )
            ),
            (8, true),
            "{flag} was not carried in fuse_write_in.flags: {}",
            sample.diagnostic(fixture)
        );
        let count = fixture.observer.write_results().len() - sample.outcomes;
        sample.assert_completed(fixture, datasync, count);
        let mut expected = FILE_CONTENT.to_vec();
        expected[..8].copy_from_slice(payload.as_bytes());
        assert_eq!(fixture.bytes(b"f.txt"), expected);
        actor.finish();
    }
}

#[test]
fn writable_linux_sync_write_error_returns_no_count() {
    use std::os::unix::fs::OpenOptionsExt as _;
    if !venue("writable_linux_sync_write_error_returns_no_count") {
        return;
    }
    let deadline = sync_deadline();
    let mut cases = 0;
    for flag in [0x0010_1000, 0x1000] {
        let fixture = SyncMount::new(deadline);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(flag)
            .open(fixture.paths.mountpoint.join("f.txt"))
            .unwrap();
        let faults = fixture.faults();
        faults.arm("sync.capture", "after", 1, crate::FaultAction::Fail);
        let before = fixture.registrations();
        let result = file
            .write_at(b"unacknowledged", 0)
            .map_err(|error| error.raw_os_error());
        let mut expected = FILE_CONTENT.to_vec();
        expected[..14].copy_from_slice(b"unacknowledged");
        assert_eq!(
            (
                result,
                fixture.registrations() - before,
                fixture.observer.write_results(),
                std::fs::read(fixture.paths.mountpoint.join("f.txt")).unwrap()
            ),
            (
                Err(Some(5)),
                0,
                vec![CallbackOutcome::Failed(granary_fuse::MountError::Io)],
                expected.clone()
            ),
            "flag={flag:#x}"
        );
        file.sync_all().unwrap();
        assert_eq!(
            (fixture.registrations() - before, fixture.bytes(b"f.txt")),
            (1, expected),
            "captured bytes must remain recoverable after failed synchronous write: flag={flag:#x}"
        );
        drop(file);
        fixture.finish();
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[derive(Default)]
struct FaultRouteProgress {
    stage: &'static str,
    faults: Option<crate::FaultControl>,
    observer: Option<Arc<indexed::WorkerObserver>>,
    stop: Option<mpsc::Sender<()>>,
    sync: Option<Result<(), Option<i32>>>,
    shrink: Option<Result<(), Option<i32>>>,
}
impl FaultRouteProgress {
    fn recover(&self, route_name: &str) -> String {
        let diagnostic = format!(
            "stage={}; fired={:?}; outcomes={:?}; floor_outcomes={:?}; sync_returned={}; sync={:?}",
            self.stage,
            self.faults.as_ref().map(crate::FaultControl::sync_fired),
            self.observer
                .as_ref()
                .map(|observer| observer.sync_results()),
            self.observer
                .as_ref()
                .map(|observer| observer.sync_floor_results()),
            self.sync.is_some(),
            self.sync,
        );
        let diagnostic = if route_name == "sync.floor" {
            format!(
                "{diagnostic}; shrink_returned={}; shrink={:?}",
                self.shrink.is_some(),
                self.shrink,
            )
        } else {
            diagnostic
        };
        let diagnostic = if self.stop.is_some() {
            diagnostic
        } else {
            // Until SyncMount::new returns the route holds no stop handle: the
            // stall is in attach or mount setup, and a session created there is
            // torn down by its SessionGuard watchdog once that guard exists.
            format!("{diagnostic}; stop=unregistered (inside mount setup)")
        };
        eprintln!("{diagnostic}");
        if let Some(faults) = &self.faults {
            faults.resume();
        }
        if let Some(stop) = &self.stop {
            let _ = stop.send(());
        }
        diagnostic
    }
}

fn mounted_floor_fault(
    fixture: &SyncMount,
    file: &std::fs::File,
    progress: &Mutex<FaultRouteProgress>,
) -> Result<(), Option<i32>> {
    // Linux holds the inode lock across FUSE fsync, excluding ftruncate on
    // that inode. Retain the capture without a pending kernel fsync request so
    // the mounted shrink reaches the engine's floor check while it is held.
    let boundary = fixture
        .mediator
        .overlay_transaction(|overlay| overlay.seal_sync(crate::SyncTarget::Tree))
        .unwrap();
    assert_eq!(
        boundary.files().len(),
        1,
        "floor premise must retain the dirty file: {boundary:?}"
    );
    fixture
        .faults
        .arm("sync.floor", "checked", 1, crate::FaultAction::Fail);
    progress.lock().unwrap().stage = "shrink with retained floor";
    let result = file.set_len(0).map_err(|error| error.raw_os_error());
    progress.lock().unwrap().shrink = Some(result);
    fixture
        .mediator
        .with(|store| store.release_sync_boundary(&boundary))
        .unwrap();
    progress.lock().unwrap().stage = "sync after failed shrink";
    let sync = file.sync_all().map_err(|error| error.raw_os_error());
    progress.lock().unwrap().sync = Some(sync);
    assert_eq!(sync, Ok(()), "sync after floor failure: {sync:?}");
    result
}

fn run_mounted_fault_route(
    deadline: tokio::time::Instant,
    route: &super::super::observed::SyncFaultRoute,
    progress: &Mutex<FaultRouteProgress>,
) {
    let fixture = SyncMount::harnessed(deadline);
    {
        let mut progress = progress.lock().unwrap();
        progress.stage = "route setup";
        progress.faults = Some(fixture.faults());
        progress.observer = Some(fixture.observer.clone());
        progress.stop = Some(fixture.mount.stop_sender());
    }
    let pinned_base = fixture.content.pinned_base().unwrap();
    let faults = fixture.faults();
    let mut expected = FILE_CONTENT.to_vec();
    let before = fixture.registrations();
    let (file, directory) = if route.directory {
        let file = fixture.file();
        drop(file);
        std::fs::rename(
            fixture.paths.mountpoint.join("f.txt"),
            fixture.paths.mountpoint.join("g.txt"),
        )
        .unwrap();
        (
            None,
            Some(std::fs::File::open(fixture.paths.mountpoint.as_path()).unwrap()),
        )
    } else {
        let file = fixture.file();
        file.write_at(b"fault-route", 0).unwrap();
        expected[..11].copy_from_slice(b"fault-route");
        (Some(file), None)
    };
    let syscall_errno = if route.name == "sync.floor" {
        mounted_floor_fault(&fixture, file.as_ref().unwrap(), progress)
    } else {
        faults.arm(route.name, route.phase, 1, crate::FaultAction::Fail);
        progress.lock().unwrap().stage = "sync with armed fault";
        let result = if let Some(dir) = &directory {
            dir.sync_all().map_err(|error| error.raw_os_error())
        } else {
            file.as_ref()
                .unwrap()
                .sync_all()
                .map_err(|error| error.raw_os_error())
        };
        progress.lock().unwrap().sync = Some(result);
        result
    };
    progress.lock().unwrap().stage = "sample route tuple";
    let sends = fixture.registrations() - before;
    let target_name: &[u8] = if route.directory && sends > 0 {
        b"g.txt"
    } else {
        b"f.txt"
    };
    let expected_bytes = if route.acknowledged.0 == 0 {
        FILE_CONTENT
    } else {
        expected.as_slice()
    };
    let prepared = fixture.bytes(target_name);
    let sample = super::super::observed::SyncFaultSample {
        syscall_errno,
        engine_outcome: fixture.sync_outcomes(),
        acknowledged: (sends, fixture.synced_marks()),
        prepared_bytes: prepared,
        published_head: fixture.published_head(),
        terminal_outcomes: if route.name == "sync.floor" {
            fixture.observer.sync_floor_results()
        } else {
            fixture.observer.sync_results()
        },
        fired: faults.sync_fired(),
    };
    assert_eq!(
        (
            super::super::observed::check_sync_fault_route(
                route,
                &sample,
                expected_bytes,
                pinned_base
            ),
            fixture.observer.sync_requests(),
        ),
        (Ok(()), vec![(route.directory, false)]),
        "route={route:?}; sample={sample:?}"
    );
    progress.lock().unwrap().stage = "route cleanup";
    drop((file, directory));
    fixture.finish();
}

#[test]
fn writable_linux_sync_fault_matrix() {
    if !venue("writable_linux_sync_fault_matrix") {
        return;
    }
    let mut executed = Vec::new();
    for route in &super::super::observed::SYNC_FAULT_MATRIX_ROUTES {
        let progress = Arc::new(Mutex::new(FaultRouteProgress {
            stage: "mount setup",
            ..FaultRouteProgress::default()
        }));
        let observed = progress.clone();
        let selected = *route;
        let result = fault_route::run(
            route.name,
            route.phase,
            std::time::Duration::from_secs(8),
            move || run_mounted_fault_route(sync_deadline(), &selected, &progress),
            || observed.lock().unwrap().recover(route.name),
        );
        assert_eq!(result, Ok(()), "route={route:?}");
        executed.push((route.name, route.phase));
    }
    assert_eq!(
        super::super::observed::check_sync_fault_matrix_coverage(&executed),
        Ok(())
    );
}

fn fired_points(faults: &crate::FaultControl) -> Vec<(&'static str, &'static str, u64)> {
    faults
        .sync_fired()
        .iter()
        .map(|event| (event.name, event.phase, event.occurrence))
        .collect()
}

/// Hold an fsync at the commit wait behind a captured commit, release the
/// commit, and require the fsync to register only then.
fn commit_wait_holds_then_releases(
    fixture: &SyncMount,
    file: &std::fs::File,
    route: &super::super::observed::CommitFaultRoute,
) {
    let mut expected = FILE_CONTENT.to_vec();
    expected[..12].copy_from_slice(b"commit-route");
    // A captured commit closes sync admission but retains no submission, so the
    // mount stays ready and the fsync reaches the engine's commit wait.
    let capture = fixture
        .runtime
        .block_on(fixture.engine.begin_commit(crate::SyncOptions::default()))
        .unwrap();
    let registered = fixture.registrations();
    let faults = fixture.faults();
    faults.arm(route.name, route.phase, 1, crate::FaultAction::Block);
    let sync_file = file.try_clone().unwrap();
    let held = std::thread::scope(|threads| {
        let _resume = Resume(faults.clone());
        let (sender, reply) = mpsc::channel();
        let waiter = threads.spawn(move || {
            sender
                .send(sync_file.sync_all().map_err(|error| error.raw_os_error()))
                .unwrap();
        });
        let label = format!("{}/{} fault", route.name, route.phase);
        fixture.wait(&label, || !faults.sync_fired().is_empty());
        let pending = reply.recv_timeout(std::time::Duration::from_millis(100));
        let waiting = (
            matches!(pending, Err(mpsc::RecvTimeoutError::Timeout)),
            fixture.registrations() - registered,
            fixture.sync_outcomes(),
            fixture.observer.sync_results(),
        );
        fixture.engine.discard_commit(capture).unwrap();
        faults.resume();
        let result = reply
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        waiter.join().unwrap();
        (waiting, result)
    });
    assert_eq!(
        (
            held,
            fired_points(&faults),
            fixture.registrations() - registered,
            fixture.sync_outcomes(),
            fixture.observer.sync_results(),
            fixture.bytes(b"f.txt"),
        ),
        (
            ((true, 0, (0, 0), vec![]), Ok(())),
            vec![(route.name, route.phase, 1)],
            1,
            (1, 0),
            vec![(Callback::Fsync, CallbackOutcome::Ok)],
            expected,
        ),
        "an fsync behind an in-flight commit must wait, then register once the commit is released"
    );
}

/// Fail an fsync at the commit wait behind a captured commit: nothing is
/// acknowledged and nothing registers beyond the one earlier fsync.
fn commit_wait_fault_fails_the_fsync(
    fixture: &SyncMount,
    file: &std::fs::File,
    route: &super::super::observed::CommitFaultRoute,
) {
    let capture = fixture
        .runtime
        .block_on(fixture.engine.begin_commit(crate::SyncOptions::default()))
        .unwrap();
    fixture
        .faults()
        .arm(route.name, route.phase, 1, crate::FaultAction::Fail);
    let injected = file.sync_all().map_err(|error| error.raw_os_error());
    assert_eq!(
        (
            injected,
            fired_points(&fixture.faults()),
            fixture.registrations(),
            fixture.sync_outcomes(),
            fixture.observer.sync_results(),
        ),
        (
            Err(Some(5)),
            vec![(route.name, route.phase, 1)],
            1,
            (1, 1),
            vec![
                (Callback::Fsync, CallbackOutcome::Ok),
                (
                    Callback::Fsync,
                    CallbackOutcome::Failed(granary_fuse::MountError::Io)
                )
            ],
        ),
        "a failed commit wait must acknowledge nothing and register nothing"
    );
    fixture.engine.discard_commit(capture).unwrap();
}

#[test]
fn writable_linux_fsync_waits_for_inflight_commit_and_commit_wait_fault() {
    if !venue("writable_linux_fsync_waits_for_inflight_commit_and_commit_wait_fault") {
        return;
    }
    let route = super::super::observed::COMMIT_FAULT_ROUTES[0];
    assert_eq!((route.name, route.phase), ("sync.commit_wait", "before"));
    let deadline = sync_deadline();
    for bound in [true, false] {
        let fixture = if bound {
            SyncMount::new(deadline)
        } else {
            SyncMount::hookless(deadline)
        };
        let file = fixture.file();
        file.write_at(b"commit-route", 0).unwrap();
        let served = fixture.view_probe();
        let mut held = fixture.held_handles(HeldRead::Buffered);
        let served_held = held.probe();
        let served_listing = held.listing_refused();
        commit_wait_holds_then_releases(&fixture, &file, &route);
        commit_wait_fault_fails_the_fsync(&fixture, &file, &route);
        let lane = fixture.construct_commit(70).unwrap();
        let result = fixture.drive_commit(&lane, 80);
        // A bound mount installs the landing as its view; a hook-less one
        // closes the old view.
        let after = if bound { Ok(()) } else { Err(Some(5)) };
        assert_eq!(
            (
                landed(&result),
                fixture.remote_seq(),
                fixture.publications(),
                served,
                fixture.view_probe(),
                (served_held, served_listing),
                (held.probe(), held.listing_refused()),
                file.sync_all().map_err(|error| error.raw_os_error()),
            ),
            (
                true,
                2,
                1,
                [Ok(()); 3],
                [after; 3],
                ([Ok(()); 2], Some(false)),
                ([after; 2], Some(!bound)),
                after
            ),
            "bound={bound}: an installed landing serves lookup, read, listing and fsync, and \
             the handles opened before it; without a hook the old view answers EIO, the held \
             listing refused by its own READDIR"
        );
        drop(held);
        drop(file);
        fixture.finish();
    }
}

#[test]
fn writable_linux_commit_captured_readback_refresh_and_replace_faults() {
    if !venue("writable_linux_commit_captured_readback_refresh_and_replace_faults") {
        return;
    }
    let deadline = sync_deadline();
    let mut executed = Vec::new();
    for route in super::super::observed::COMMIT_FAULT_ROUTES
        .iter()
        .filter(|route| route.name == "sync.commit")
    {
        // A boundary left by a cut construction holds the unmount's
        // shutdown at step 1 to its bound, which the cleanup's own bound is
        // shorter than.
        let fixture = SyncMount::bounded(
            deadline,
            (route.phase == "boundary_recorded").then_some(std::time::Duration::from_millis(500)),
        );
        let file = fixture.file();
        file.write_at(b"commit-route", 0).unwrap();
        let served = fixture.view_probe();
        let mut held = fixture.held_handles(HeldRead::Direct);
        let served_held = (held.probe(), held.listing_refused());
        let dirty_records = fixture.journal_records();
        let faults = fixture.faults();
        faults.arm(route.name, route.phase, 1, crate::FaultAction::Fail);
        let registered = fixture.registrations();
        let (error, lane) = first_commit_attempt(&fixture, route);
        // A pending landed refresh leaves the mount unready (EACCES before the
        // engine is asked); any other retained lane, its submission settled or
        // not, still holds sync admission closed, so the fsync reaches the
        // engine's commit wait and gives up (EIO). The replace point comes after the
        // landed refresh is registered, so that route has registered once.
        let (expected_fsync, expected_registered, expected_outcomes) =
            match (route.phase, route.serving) {
                ("captured", _) => (Ok(()), 1, (1, 0)),
                ("before_replace", _) => (Err(Some(5)), 1, (0, 1)),
                (_, true) => (Err(Some(5)), 0, (0, 1)),
                (_, false) => (Err(Some(13)), 0, (0, 0)),
            };
        let fsync = file.sync_all().map_err(|error| error.raw_os_error());
        assert_eq!(
            (
                error.is_some_and(|error| error.to_string().contains("SyncInjectedFault")),
                fired_points(&faults),
                fixture.remote_seq(),
                fsync,
                fixture.registrations() - registered,
                fixture.sync_outcomes(),
            ),
            (
                true,
                vec![(route.name, route.phase, 1)],
                route.remote_seq,
                expected_fsync,
                expected_registered,
                expected_outcomes,
            ),
            "route={route:?}"
        );
        assert_eq!(
            fixture.journal_records().iter().any(|record| matches!(
                record,
                granary_core::overlay_journal::Record::LandedCommit { .. }
            )),
            matches!(
                route.phase,
                "landed_readback" | "landed_refresh" | "before_replace"
            ),
            "route={route:?}: a landing must be journaled from the readback point on, and not before"
        );
        if route.phase == "boundary_recorded" {
            boundary_fault_keeps_the_crash_state(&fixture, &dirty_records);
        } else {
            let lane = lane.unwrap_or_else(|| fixture.construct_commit(71).unwrap());
            retry_lands_and_installs_the_view(
                &fixture,
                route,
                &lane,
                &file,
                &mut held,
                served,
                served_held,
            );
        }
        drop(held);
        drop(file);
        fixture.finish();
        executed.push((route.name, route.phase));
    }
    assert_eq!(
        executed,
        [
            ("sync.commit", "captured"),
            ("sync.commit", "boundary_recorded"),
            ("sync.commit", "before_submit"),
            ("sync.commit", "before_rebase"),
            ("sync.commit", "after_rebase"),
            ("sync.commit", "landed_readback"),
            ("sync.commit", "landed_refresh"),
            ("sync.commit", "before_replace"),
        ]
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "paired transport cuts keep their persisted authority premise and mounted restart tuple together"
)]
fn writable_linux_refresh_transport_restart_replays_accepted_lost_and_never_received() {
    if !venue("writable_linux_refresh_transport_restart_replays_accepted_lost_and_never_received") {
        return;
    }
    let mut cases = 0;
    for accepted_lost in [true, false] {
        let paths = Arc::new(Paths::new());
        let tree = Arc::new(mounted_operation_tree());
        let fixture = SyncMount::with_options(
            sync_deadline(),
            Hook::Bound,
            crate::SyncProfile::default(),
            crate::ViewMode::Default,
            Some(std::time::Duration::from_millis(1)),
            false,
            None,
            MountedRuntime::Accelerated,
            None,
            paths,
            tree,
        )
        .unwrap();
        let file = fixture.file();
        file.write_at(b"refresh-restart", 0).unwrap();
        let accepted_before = {
            let mut state = fixture.state.lock().unwrap();
            state.lose_registration_replies = accepted_lost;
            state.registrations_served = (!accepted_lost).then_some(0);
            state.registration_requests.len()
        };
        fixture.faults.arm(
            "sync.registration",
            "after_response",
            1,
            crate::FaultAction::Fail,
        );
        let lane = fixture.construct_commit(70).unwrap();
        let first = fixture.drive_commit(&lane, 80);
        let (refresh, first_publications, accepted_after, authority_state) = {
            let state = fixture.state.lock().unwrap();
            let refresh = state
                .sends
                .iter()
                .rev()
                .find(|request| {
                    granary_core::intent::decode_register(request, &fixture.tree.volume, |_, _| {
                        true
                    })
                    .is_ok()
                })
                .cloned()
                .expect("the cut must have sent its retained refresh");
            (
                refresh,
                state.publications.len(),
                state.registration_requests.len(),
                // The authority outlives a client restart, but its fixture
                // observations and one-shot faults do not.
                AuthorityState {
                    cursor: state.cursor,
                    row: state.row,
                    root: state.root.clone(),
                    head_seq: state.head_seq,
                    ..AuthorityState::default()
                },
            )
        };
        assert_eq!(
            (
                first
                    .as_ref()
                    .err()
                    .is_some_and(|error| error.to_string().contains("SyncInjectedFault")),
                accepted_after - accepted_before,
            ),
            (true, usize::from(accepted_lost)),
            "accepted_lost={accepted_lost}: the cut must retain R and differ only in whether the authority applied it: {first:?}"
        );
        drop(file);
        let (paths, tree) = fixture.finish_shared_cache();
        let restarted = SyncMount::shared_cache_with_authority(
            sync_deadline(),
            crate::SyncProfile::default(),
            authority_state,
            paths,
            tree,
        )
        .unwrap();
        let bytes = std::fs::read(restarted.paths.mountpoint.join("f.txt")).unwrap();
        let state = restarted.state.lock().unwrap();
        let restart_sends = &state.sends;
        let register_positions: Vec<_> = restart_sends
            .iter()
            .enumerate()
            .filter(|(_, request)| {
                granary_core::intent::decode_register(request, &restarted.tree.volume, |_, _| true)
                    .is_ok()
            })
            .collect();
        let takeover = restart_sends.iter().position(|request| {
            granary_core::intent::decode_ownership(request).is_ok_and(|request| {
                matches!(
                    request.mode,
                    granary_core::intent::OwnershipMode::Takeover { .. }
                )
            })
        });
        assert_eq!(
            (
                bytes.starts_with(b"refresh-restart"),
                (first_publications, state.publications.len()),
                // Before takeover: only the exact replay of R. After it: the
                // new owner's ordinary start registration, never R again.
                register_positions
                    .iter()
                    .filter(|(index, _)| Some(*index) < takeover)
                    .map(|(_, request)| request.as_slice())
                    .collect::<Vec<_>>(),
                register_positions
                    .iter()
                    .filter(|(index, _)| Some(*index) > takeover)
                    .map(|(_, request)| request.as_slice() == refresh.as_slice())
                    .collect::<Vec<_>>(),
                takeover.is_some(),
            ),
            (true, (1, 0), vec![refresh.as_slice()], vec![false], true,),
            "accepted_lost={accepted_lost}: mounted restart must replay the exact refresh before takeover and expose its landing"
        );
        drop(state);
        restarted.finish();
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// The first attempt of a route: the error its fault gave and the lane it
/// retained, if any. A rebasing route's authority head advances first, on a
/// path the commit does not touch.
fn first_commit_attempt(
    fixture: &SyncMount,
    route: &super::super::observed::CommitFaultRoute,
) -> (
    Option<crate::CoordinationError>,
    Option<crate::RetainedCommit>,
) {
    if matches!(route.phase, "captured" | "boundary_recorded") {
        return (fixture.construct_commit(70).err(), None);
    }
    let lane = fixture.construct_commit(70).unwrap();
    if route.rebases {
        disjoint_head(&fixture.tree, &fixture.runtime);
    }
    (fixture.drive_commit(&lane, 80).err(), Some(lane))
}

/// A fault right after the boundary is durable leaves what a crash there
/// leaves: the boundary is journaled after the dirty records, no submission is
/// retained, nothing is published, and this process cannot start another commit.
fn boundary_fault_keeps_the_crash_state(
    fixture: &SyncMount,
    dirty_records: &[granary_core::overlay_journal::Record],
) {
    let records = fixture.journal_records();
    let refused = fixture
        .construct_commit(71)
        .err()
        .is_some_and(|error| error.to_string().contains("SyncCommitInFlight"));
    assert_eq!(
        (
            records.starts_with(dirty_records),
            matches!(
                records[dirty_records.len()..],
                [granary_core::overlay_journal::Record::CommitBoundary { .. }]
            ),
            fixture.retained(),
            fixture.publications(),
            refused,
        ),
        (true, true, false, 0, true),
        "a boundary fault must leave the journaled boundary, no submission and no landing"
    );
}

/// Drive the lane the fault stopped again: it lands once and installs as the
/// served view, so lookup, read, listing, fsync and handles opened before it
/// keep working; a refresh left pending keeps the mount unready instead.
fn retry_lands_and_installs_the_view(
    fixture: &SyncMount,
    route: &super::super::observed::CommitFaultRoute,
    lane: &crate::RetainedCommit,
    file: &std::fs::File,
    held: &mut HeldHandles,
    served: [Result<(), Option<i32>>; 3],
    served_held: ([Result<(), Option<i32>>; 2], Option<bool>),
) {
    let result = if route.rebases {
        fixture.resume_commit(lane, 81)
    } else {
        fixture.drive_commit(lane, 81)
    };
    let (after, expected_landed) = if route.retry_lands {
        (Ok(()), true)
    } else {
        (Err(Some(13)), false)
    };
    assert_eq!(
        (
            landed(&result),
            fixture.remote_seq(),
            fixture.publications(),
            served,
            fixture.view_probe(),
            served_held,
            (held.probe(), held.listing_refused()),
            file.sync_all().map_err(|error| error.raw_os_error()),
        ),
        (
            expected_landed,
            2 + u64::from(route.rebases),
            1,
            [Ok(()); 3],
            [after; 3],
            ([Ok(()); 2], Some(false)),
            ([after; 2], Some(!expected_landed)),
            after
        ),
        "route={route:?}: a landing installs as the served view, and a refresh left pending keeps the mount unready; \
         a refused held listing is refused by its own READDIR, not by a getattr or reopen"
    );
}

#[test]
fn writable_linux_commit_conflict_returns_estale_and_preserves_dirty_staging() {
    if !venue("writable_linux_commit_conflict_returns_estale_and_preserves_dirty_staging") {
        return;
    }
    let fixture = SyncMount::new(sync_deadline());
    let file = fixture.file();
    file.write_at(b"commit-route", 0).unwrap();
    let dirty_records = fixture.journal_records();
    let staged = fixture.staging();
    let lane = fixture.construct_commit(70).unwrap();
    let view_before = (fixture.served_pin(), fixture.mount_floor());
    foreign_head(&fixture.tree, &fixture.runtime);
    let result = fixture.drive_commit(&lane, 80);
    let stale = Err(Some(116));
    assert_eq!(
        (
            matches!(result, Err(crate::CoordinationError::Fenced { .. })),
            fixture.remote_seq(),
            fixture.publications(),
            file.write_at(b"later", 0)
                .map(drop)
                .map_err(|error| error.raw_os_error()),
            file.sync_all().map_err(|error| error.raw_os_error()),
            std::fs::File::create_new(fixture.paths.mountpoint.join("new.txt"))
                .map(drop)
                .map_err(|error| error.raw_os_error()),
            std::fs::read(fixture.paths.mountpoint.join("f.txt"))
                .map(drop)
                .map_err(|error| error.raw_os_error()),
            fixture.journal_records().starts_with(&dirty_records),
            !staged.is_empty() && fixture.staging() == staged,
            (view_before.1, (fixture.served_pin(), fixture.mount_floor())),
        ),
        (
            true,
            2,
            0,
            stale,
            stale,
            stale,
            stale,
            true,
            true,
            (Some(1), view_before),
        ),
        "a same-path conflict must answer ESTALE, publish nothing, keep the dirty records and \
         staged bytes, and leave the pinned base and private floor unchanged"
    );
    drop(file);
    fixture.finish();
}

/// A fault while a dirty file shrinks fails the truncate with EIO and closes the
/// overlay, so no later write or commit builds on a half-shrunk stage; the
/// staged bytes are the point's side of the resize, untouched before it and cut
/// after it.
#[test]
fn writable_linux_stage_truncate_fault_fails_the_shrink_and_closes_the_overlay() {
    if !venue("writable_linux_stage_truncate_fault_fails_the_shrink_and_closes_the_overlay") {
        return;
    }
    let deadline = sync_deadline();
    let mut cases = 0;
    for (phase, cut) in [("before", false), ("after", true)] {
        let fixture = SyncMount::new(deadline);
        let file = fixture.file();
        file.write_at(b"commit-route", 0).unwrap();
        let staged = fixture.staging();
        let faults = fixture.faults();
        faults.arm("overlay.stage.truncate", phase, 1, crate::FaultAction::Fail);
        let shrink = file.set_len(4).map_err(|error| error.raw_os_error());
        let write = file
            .write_at(b"later", 0)
            .map(drop)
            .map_err(|error| error.raw_os_error());
        let fired: Vec<_> = faults
            .fired()
            .iter()
            .map(|event| (event.name, event.phase, event.occurrence))
            .collect();
        let construct = fixture
            .construct_commit(70)
            .err()
            .map(|error| error.to_string());
        // The stage header is 160 bytes; the shrink cuts the data to 4.
        assert_eq!(
            (
                shrink,
                write,
                fired,
                staged_lengths(&fixture.staging()),
                construct
            ),
            (
                Err(Some(5)),
                Err(Some(5)),
                vec![("overlay.stage.truncate", phase, 1)],
                if cut {
                    vec![164]
                } else {
                    staged_lengths(&staged)
                },
                Some("intent refused: IntentPersistencePoisoned".to_owned()),
            ),
            "phase={phase}: a failed shrink must close the overlay and cut staged bytes only after the resize"
        );
        drop(file);
        fixture.finish();
        cases += 1;
    }
    assert_eq!(cases, 2);
}

fn wire_command(trace: &Path, fds: &[u32], interrupt: bool, error: i32) -> Command {
    let mut command = Command::new("python3");
    command
        .arg("-c")
        .arg(include_str!(
            "../../../../../../../scripts/check-fuse-sync-wire.py"
        ))
        .arg("--trace")
        .arg(trace)
        .args(["--expect-opcode", "FSYNC"])
        .arg(if interrupt {
            "--expect-interrupt"
        } else {
            "--forbid-interrupt"
        })
        .arg("--expect-original-error")
        .arg(error.to_string());
    for fd in fds {
        command.arg("--fd").arg(fd.to_string());
    }
    command
}

struct StraceSupervisor {
    trace_path: std::path::PathBuf,
    fuse_fds: Vec<u32>,
}
impl StraceSupervisor {
    fn attach(fixture: &SyncMount) -> Self {
        let pid = test_process_id();
        let fuse_fds: Vec<u32> = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .expect("read /proc/<pid>/fd")
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let target = std::fs::read_link(entry.path()).ok()?;
                (target == Path::new("/dev/fuse"))
                    .then(|| entry.file_name().to_str()?.parse::<u32>().ok())
                    .flatten()
            })
            .collect();
        assert!(
            !fuse_fds.is_empty(),
            "missing venue evidence: no /dev/fuse descriptor"
        );
        let ready = std::path::PathBuf::from(
            std::env::var_os("GRANARY_INTERRUPT_READY").expect("missing interrupt handshake path"),
        );
        let trace_path = std::path::PathBuf::from(
            std::env::var_os("GRANARY_INTERRUPT_TRACE").expect("missing interrupt trace path"),
        );
        std::fs::write(
            ready,
            fuse_fds
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
        .unwrap();
        let _ = std::fs::metadata(fixture.paths.mountpoint.join("f.txt"));
        Self {
            trace_path,
            fuse_fds,
        }
    }

    fn wait_for_interrupt_enosys(&self) {
        let deadline = crate::TokioSyncRuntime.now() + std::time::Duration::from_secs(3);
        let scratch = self.trace_path.parent().unwrap();
        let mut diagnostic = String::new();
        while crate::TokioSyncRuntime.now() < deadline {
            let mut command = wire_command(&self.trace_path, &self.fuse_fds, true, 0);
            command.args(["--poll-interrupts", "1"]);
            let output =
                bounded_output(command, scratch, "poll", std::time::Duration::from_secs(1))
                    .expect("bounded wire parser poll");
            if output.status.success() && output.stdout == b"{\"ok\":true}\n" {
                return;
            }
            diagnostic = String::from_utf8_lossy(&output.stderr).into_owned();
        }
        panic!("missing venue evidence: pending FUSE_INTERRUPT ENOSYS reply absent: {diagnostic}");
    }
}

struct InterruptActor {
    child: std::process::Child,
    lines: mpsc::Receiver<String>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl InterruptActor {
    fn start(root: &Path, payload: &str) -> Self {
        use std::io::BufRead as _;
        let script = concat!(
            "import ctypes,os,signal,sys\n",
            "libc=ctypes.CDLL(None,use_errno=True)\n",
            "sigs=0\n",
            "def on_usr1(s,f):\n global sigs\n sigs+=1\n",
            "signal.signal(signal.SIGUSR1,on_usr1)\n",
            "class Sigaction(ctypes.Structure):\n _fields_=[('handler',ctypes.c_void_p),('mask',ctypes.c_ulong*16),('flags',ctypes.c_int),('restorer',ctypes.c_void_p)]\n",
            "action=Sigaction()\n",
            "if libc.sigaction(signal.SIGUSR1,None,ctypes.byref(action))!=0: raise OSError(ctypes.get_errno(),'get sigaction')\n",
            "action.flags &= ~0x10000000\n",
            "if libc.sigaction(signal.SIGUSR1,ctypes.byref(action),None)!=0: raise OSError(ctypes.get_errno(),'set sigaction')\n",
            "fd=os.open(os.path.join(sys.argv[1],'f.txt'),os.O_RDWR)\n",
            "os.pwrite(fd,sys.argv[2].encode(),0)\n",
            "print('READY',flush=True)\n",
            "while True:\n",
            " try:\n  raw=sys.stdin.readline()\n except InterruptedError:\n  continue\n",
            " if not raw:\n  break\n",
            " cmd=raw.strip()\n",
            " if cmd=='PING':\n  print(f'PONG:{sigs}',flush=True)\n",
            " elif cmd=='GO':\n",
            "  ctypes.set_errno(0)\n",
            "  rc=libc.fsync(fd)\n",
            "  print('OUTCOME:OK' if rc==0 else f'OUTCOME:ERR:{ctypes.get_errno()}',flush=True)\n",
            " elif cmd=='CLOSE':\n  os.close(fd)\n  break\n",
        );
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg(root)
            .arg(payload)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn InterruptActor");
        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let actor = Self {
            child,
            lines,
            reader: Some(reader),
        };
        let ready = actor
            .lines
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("InterruptActor ready line");
        assert_eq!(ready.trim(), "READY");
        actor
    }

    fn signal(&self) {
        let mut signal = Command::new("kill")
            .args(["-s", "USR1", &self.child.id().to_string()])
            .spawn()
            .expect("send SIGUSR1 to InterruptActor");
        let status = wait_owned_child(&mut signal, std::time::Duration::from_secs(1)).unwrap();
        assert!(status.success(), "kill -s USR1 failed: {status}");
    }

    fn go(&mut self) {
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"GO\n")
            .unwrap();
    }

    fn ping(&mut self) -> usize {
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"PING\n")
            .unwrap();
        let line = self
            .lines
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("InterruptActor PONG");
        line.trim()
            .strip_prefix("PONG:")
            .and_then(|count| count.parse::<usize>().ok())
            .unwrap_or_else(|| panic!("unexpected PONG line: {line:?}"))
    }

    fn parse_outcome(line: &str) -> Result<(), i32> {
        let trimmed = line.trim();
        if trimmed == "OUTCOME:OK" {
            Ok(())
        } else if let Some(rest) = trimmed.strip_prefix("OUTCOME:ERR:") {
            Err(rest.parse::<i32>().expect("errno integer"))
        } else {
            panic!("unexpected InterruptActor outcome line: {line:?}");
        }
    }

    fn try_outcome(&mut self) -> Option<Result<(), i32>> {
        self.lines
            .try_recv()
            .ok()
            .map(|line| Self::parse_outcome(&line))
    }

    fn wait_outcome(&mut self) -> Result<(), i32> {
        let line = self
            .lines
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("InterruptActor outcome");
        Self::parse_outcome(&line)
    }

    fn finish(mut self) {
        if let Some(mut stdin) = self.child.stdin.take() {
            let _ = stdin.write_all(b"CLOSE\n");
        }
        let status = wait_owned_child(&mut self.child, std::time::Duration::from_secs(1)).unwrap();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let mut stderr = String::new();
        if let Some(mut err) = self.child.stderr.take() {
            let _ = err.read_to_string(&mut stderr);
        }
        assert!(
            status.success(),
            "InterruptActor exit failed: status={status}, stderr={stderr}"
        );
    }
}
impl Drop for InterruptActor {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = wait_owned_child(&mut self.child, std::time::Duration::from_secs(1));
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn run_interrupted_sync_arm(
    deadline: tokio::time::Instant,
    seam: &'static str,
    phase: &'static str,
    fail_engine: bool,
    duplicate_and_late: bool,
) {
    let fixture = SyncMount::harnessed(deadline);
    let payload = "interrupted-sync";
    let mut actor = InterruptActor::start(&fixture.paths.mountpoint, payload);
    let wire = StraceSupervisor::attach(&fixture);
    let faults = fixture.faults();
    faults.arm(seam, phase, 1, crate::FaultAction::Block);
    let _resume = Resume(faults.clone());
    actor.go();
    let label = format!("{seam}/{phase} fault");
    fixture.wait(&label, || !faults.sync_fired().is_empty());
    let before_signal = actor.try_outcome();
    let terminal_before_signal = fixture.observer.sync_results();
    let pending_at_signal = terminal_before_signal.is_empty() && before_signal.is_none();
    assert_eq!(
        (before_signal, terminal_before_signal),
        (None, vec![]),
        "original request returned before the blocked seam was signalled"
    );
    actor.signal();
    wire.wait_for_interrupt_enosys();
    if duplicate_and_late {
        actor.signal();
    }
    let early_caller = actor.try_outcome();
    let early_settled =
        early_caller.map(|_| super::super::observed::at_caller_return(&fixture.metrics, || ()).0);
    let pending_after_interrupt_enosys =
        fixture.observer.sync_results().is_empty() && !matches!(early_caller, Some(Ok(())));
    if fail_engine {
        faults.arm("sync.reply", "before", 1, crate::FaultAction::Fail);
    }
    faults.resume();
    let caller_outcome = early_caller.unwrap_or_else(|| actor.wait_outcome());
    let caller_errno = caller_outcome.err();
    let (settled, engine_outcome) =
        super::super::observed::at_caller_return(&fixture.metrics, || {
            fixture.wait("engine settlement", || {
                fixture.observer.sync_results().len() == 1
            });
            fixture.sync_outcomes()
        });
    let engine_settled_at_caller_return = early_settled.unwrap_or(settled);
    if duplicate_and_late {
        actor.signal();
        assert!(actor.ping() >= 2, "duplicate/late signal was not delivered");
    }
    let settlement = super::super::observed::InterruptSettlement {
        pending_at_signal,
        pending_after_interrupt_enosys,
        caller_errno,
        engine_settled_at_caller_return,
        engine_outcome,
        terminal_outcomes: fixture.observer.sync_results(),
    };
    assert_eq!(
        super::super::observed::check_interrupt_settlement(&settlement, !fail_engine),
        Ok(()),
        "seam=({seam}, {phase}), fail_engine={fail_engine}, settlement={settlement:?}"
    );
    drop(wire);
    if !fail_engine {
        let mut expected = FILE_CONTENT.to_vec();
        expected[..payload.len()].copy_from_slice(payload.as_bytes());
        assert_eq!(fixture.bytes(b"f.txt"), expected);
    }
    actor.finish();
    fixture.finish();
}

fn run_pre_dispatch_signal_arm(deadline: tokio::time::Instant) {
    let fixture = SyncMount::harnessed(deadline);
    let payload = "pre-dispatch";
    let mut actor = InterruptActor::start(&fixture.paths.mountpoint, payload);
    let wire = StraceSupervisor::attach(&fixture);
    actor.signal();
    let wait_deadline = crate::TokioSyncRuntime.now() + std::time::Duration::from_secs(3);
    while actor.ping() == 0 && crate::TokioSyncRuntime.now() < wait_deadline {
        std::thread::yield_now();
    }
    assert!(actor.ping() >= 1, "pre-dispatch signal was not delivered");
    actor.go();
    assert_eq!(actor.wait_outcome(), Ok(()));
    assert_eq!(
        (fixture.sync_outcomes(), fixture.observer.sync_results()),
        ((1, 0), vec![(Callback::Fsync, CallbackOutcome::Ok)])
    );
    drop(wire);
    let mut expected = FILE_CONTENT.to_vec();
    expected[..payload.len()].copy_from_slice(payload.as_bytes());
    assert_eq!(fixture.bytes(b"f.txt"), expected);
    actor.finish();
    fixture.finish();
}

fn run_arm_with_strace_parent(arm: &str) {
    let paths = Paths::new();
    let scratch = &paths.scratch;
    let ready = scratch.join("strace-ready.txt");
    let trace = scratch.join("fuse-wire.strace");
    let executable = scratch.join("interrupt-test");
    let current = std::env::current_exe().expect("current test executable");
    if std::fs::hard_link(&current, &executable).is_err() {
        std::fs::copy(&current, &executable).unwrap();
    }
    let mut help = Command::new("strace");
    help.arg("--help");
    let help = bounded_output(
        help,
        scratch,
        "strace-help",
        std::time::Duration::from_secs(1),
    )
    .expect("missing venue evidence: strace unavailable");
    assert!(
        help.status.success(),
        "missing venue evidence: strace help failed"
    );
    let mut command = Command::new("strace");
    command
        .args([
            "-f",
            "--kill-on-exit",
            "-s",
            "48",
            "-xx",
            "-y",
            "-e",
            "trace=read,readv,write,writev",
        ])
        .arg("-o")
        .arg(&trace);
    // Path filtering avoids retaining other descriptors' bytes; older strace
    // still annotates descriptors so the parser can discard non-FUSE calls.
    if String::from_utf8_lossy(&help.stdout).contains("--trace-path") {
        command.args(["-P", "/dev/fuse"]);
    }
    command
        .arg(executable)
        .args([
            "--exact",
            "mount::tests::writable::mounted::sync::writable_linux_interrupt_during_sync",
            "--nocapture",
        ])
        .env("GRANARY_INTERRUPT_ARM", arm)
        .env("GRANARY_INTERRUPT_READY", &ready)
        .env("GRANARY_INTERRUPT_TRACE", &trace);
    // strace owns and waits for the re-exec'd test. EXITKILL also terminates
    // its tracees if this outer deadline kills the harness-owned tracer.
    let output = bounded_output(
        command,
        scratch,
        "strace-arm",
        std::time::Duration::from_secs(7),
    )
    .expect("missing venue evidence: traced child exceeded its bound");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.lines().any(|line| line == "INTERRUPT_ARM_OK"),
        "missing venue evidence: interrupt arm {arm} failed: status={}, stdout={stdout}, stderr={stderr}",
        output.status
    );
    let fds: Vec<u32> = std::fs::read_to_string(ready)
        .unwrap()
        .split(',')
        .map(|fd| fd.parse().unwrap())
        .collect();
    let command = wire_command(
        &trace,
        &fds,
        arm != "pre_dispatch",
        if arm == "reg_fail" { -5 } else { 0 },
    );
    let verdict = bounded_output(
        command,
        scratch,
        "verdict",
        std::time::Duration::from_secs(1),
    )
    .expect("bounded final wire verification");
    assert!(
        verdict.status.success() && verdict.stdout == b"{\"ok\":true}\n",
        "missing venue evidence: wire verification failed: status={}, stdout={}, stderr={}",
        verdict.status,
        String::from_utf8_lossy(&verdict.stdout),
        String::from_utf8_lossy(&verdict.stderr)
    );
}

#[test]
fn writable_linux_interrupt_during_sync() {
    if std::env::var_os("GRANARY_SYNC_WIRE_VENUE").is_none() {
        eprintln!(
            "SKIPPED-VENUE writable_linux_interrupt_during_sync: GRANARY_SYNC_WIRE_VENUE is not set"
        );
        return;
    }
    assert!(
        venue("writable_linux_interrupt_during_sync"),
        "missing venue evidence: /dev/fuse unavailable"
    );
    if let Ok(arm) = std::env::var("GRANARY_INTERRUPT_ARM") {
        let deadline = sync_deadline();
        match arm.as_str() {
            "reg_ok" => {
                run_interrupted_sync_arm(
                    deadline,
                    "sync.registration",
                    "before_dispatch",
                    false,
                    true,
                );
            }
            "reg_fail" => {
                run_interrupted_sync_arm(
                    deadline,
                    "sync.registration",
                    "before_dispatch",
                    true,
                    false,
                );
            }
            "reply_ok" => {
                run_interrupted_sync_arm(deadline, "sync.reply", "before", false, false);
            }
            "pre_dispatch" => run_pre_dispatch_signal_arm(deadline),
            other => panic!("unknown GRANARY_INTERRUPT_ARM={other:?}"),
        }
        println!("\nINTERRUPT_ARM_OK");
        return;
    }
    for arm in ["reg_ok", "reg_fail", "reply_ok", "pre_dispatch"] {
        run_arm_with_strace_parent(arm);
    }
}
