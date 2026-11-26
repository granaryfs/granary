// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A landing installed as the mount's view, through a test hook that stands
//! in for the adapter: it rebuilds and checks the view, runs the install on
//! the blocking seam under the mount's lock, records each view change, and
//! records whether engine admission was free when a revocation was sent.

// @file-disposition: STAYS — view-install controls share the private mount fixture and its lane-state observations.

use super::*;
use crate::SyncRuntime as _;
use crate::sync::{Adopted, AdoptionCommit, LandedCommit, MountViewHook, Revocation, ViewInstall};
use crate::writable_start::{ViewInstallError, adoption_verdict, rebuild_verdict};
use std::sync::Condvar;
use std::sync::atomic::AtomicBool;

type Mount = crate::WritableMount<Authority, OverlayDisk>;

const DEEP_CONTENT: &[u8] = b"a file the head adds three directories deep\n";

mod binding;

/// A point the hook stops at, once armed, until the test releases it.
#[derive(Default)]
struct Latch {
    armed: AtomicBool,
    /// (entered, released)
    state: Mutex<(bool, bool)>,
    wake: Condvar,
}
impl Latch {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
    fn hold(&self) {
        if !self.armed.load(Ordering::SeqCst) {
            return;
        }
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.wake.notify_all();
        while !state.1 {
            state = self.wake.wait(state).unwrap();
        }
    }
    fn is_entered(&self) -> bool {
        self.state.lock().unwrap().0
    }
    #[must_use]
    fn entered(&self) -> bool {
        let (state, _) = self
            .wake
            .wait_timeout_while(
                self.state.lock().unwrap(),
                std::time::Duration::from_secs(10),
                |state| !state.0,
            )
            .unwrap();
        state.0
    }
    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.wake.notify_all();
    }
}

/// Resumes every blocked fault point, so a failing row never leaves one held.
struct ResumeOnDrop<'a>(&'a crate::FaultControl);
impl Drop for ResumeOnDrop<'_> {
    fn drop(&mut self) {
        self.0.resume();
    }
}

/// Releases a latch, so a failing row never leaves the hook waiting.
struct ReleaseOnDrop<'a>(&'a Latch);
impl Drop for ReleaseOnDrop<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct PausedClock {
    frozen: AtomicBool,
    notify: tokio::sync::Notify,
}

struct AdvanceClock<F> {
    inner: std::pin::Pin<Box<F>>,
    control: Arc<PausedClock>,
    released: bool,
}

impl<F> AdvanceClock<F> {
    fn new(inner: F, control: Arc<PausedClock>) -> Self {
        Self {
            inner: Box::pin(inner),
            control,
            released: false,
        }
    }
}

impl<F: std::future::Future> std::future::Future for AdvanceClock<F> {
    type Output = F::Output;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let polled = self.inner.as_mut().poll(context);
        if !std::mem::replace(&mut self.released, true) {
            self.control.frozen.store(false, Ordering::SeqCst);
        }
        polled
    }
}

impl<F> Drop for AdvanceClock<F> {
    fn drop(&mut self) {
        self.control.frozen.store(true, Ordering::SeqCst);
        self.control.notify.notify_one();
    }
}

/// A live loop on the same paused, current-thread runtime shape as the mount's
/// boundary driver. Its result is observed on the test thread with a wall bound.
struct RunningLoop {
    handle: tokio::runtime::Handle,
    origin: tokio::time::Instant,
    control: Arc<PausedClock>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    outcome: std::sync::mpsc::Receiver<Option<crate::LiveEnd>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RunningLoop {
    fn start(
        engine: Arc<CommitEngine>,
        options: crate::SyncOptions,
        entropy: u8,
        events: Events,
    ) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        let origin = {
            let _entered = handle.enter();
            crate::TokioSyncRuntime.now()
        };
        let control = Arc::new(PausedClock {
            frozen: AtomicBool::new(true),
            notify: tokio::sync::Notify::new(),
        });
        let keeper = control.clone();
        let entered = handle.enter();
        drop(crate::TokioSyncRuntime.spawn(async move {
            loop {
                if keeper.frozen.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                } else {
                    keeper.notify.notified().await;
                }
            }
        }));
        drop(entered);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (send, outcome) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = tracing::subscriber::with_default(events.subscriber(), || {
                runtime.block_on(async move {
                    let mut drive = std::pin::pin!(engine.drive_live(options, Entropy(entropy)));
                    let mut stopped = std::pin::pin!(stopped);
                    std::future::poll_fn(|context| {
                        if let std::task::Poll::Ready(end) =
                            std::future::Future::poll(drive.as_mut(), context)
                        {
                            return std::task::Poll::Ready(Some(end));
                        }
                        if std::future::Future::poll(stopped.as_mut(), context).is_ready() {
                            return std::task::Poll::Ready(None);
                        }
                        std::task::Poll::Pending
                    })
                    .await
                })
            });
            let _ = send.send(result);
        });
        Self {
            handle,
            origin,
            control,
            stop: Some(stop),
            outcome,
            thread: Some(thread),
        }
    }

    fn begin_advance(&self, duration: std::time::Duration) -> std::sync::mpsc::Receiver<()> {
        let (send, receive) = std::sync::mpsc::channel();
        let control = self.control.clone();
        {
            let _entered = self.handle.enter();
            drop(crate::TokioSyncRuntime.spawn(AdvanceClock::new(
                async move {
                    crate::TokioSyncRuntime.sleep(duration).await;
                    let _ = send.send(());
                },
                control,
            )));
        }
        receive
    }

    fn advance(&self, duration: std::time::Duration) {
        self.begin_advance(duration)
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the live loop's paused clock advanced within five seconds");
    }

    fn advance_or_ended(&self, duration: std::time::Duration) {
        let (send, receive) = std::sync::mpsc::channel();
        let control = self.control.clone();
        {
            let _entered = self.handle.enter();
            drop(crate::TokioSyncRuntime.spawn(AdvanceClock::new(
                async move {
                    crate::TokioSyncRuntime.sleep(duration).await;
                    let _ = send.send(());
                },
                control,
            )));
        }
        match receive.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("the live loop neither advanced nor ended within five seconds")
            }
        }
    }

    fn elapsed(&self) -> std::time::Duration {
        let _entered = self.handle.enter();
        crate::TokioSyncRuntime.now().duration_since(self.origin)
    }

    fn turn(&self) {
        let (send, receive) = std::sync::mpsc::channel();
        {
            let _entered = self.handle.enter();
            drop(crate::TokioSyncRuntime.spawn(async move {
                tokio::task::yield_now().await;
                let _ = send.send(());
            }));
        }
        receive
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the paused runtime completed another turn within five seconds");
    }

    fn assert_running(&self, context: &str) {
        assert!(
            matches!(
                self.outcome.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "{context}"
        );
    }

    fn finish(&mut self, expected: crate::LiveEnd) {
        let observed = self
            .outcome
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the live loop returned within five seconds");
        assert_eq!(observed, Some(expected));
        self.stop = None;
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }

    fn wait_end(&mut self, context: &str) -> crate::LiveEnd {
        let observed = self
            .outcome
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("{context}"));
        let end = observed.unwrap_or_else(|| panic!("{context}"));
        self.stop = None;
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        end
    }
}

impl Drop for RunningLoop {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if self
            .outcome
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_ok()
            && let Some(thread) = self.thread.take()
        {
            let _ = thread.join();
        }
    }
}

/// What the test hook was told to do and what it saw.
#[derive(Default)]
struct Hooked {
    before_rebuild: Latch,
    before_install: Latch,
    /// Fail the commit after it returns `Ok`, standing in for a failure
    /// once the overlay switched: the engine's release of its graph, or a
    /// poisoned base lock.
    fail_after_commit: AtomicBool,
    /// Run once the real commit returns `Ok`, before the install reads
    /// the switched view.
    after_commit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    changes: Mutex<Vec<crate::ViewChange>>,
    /// Whether engine admission was free when each revocation was sent.
    revocations: Mutex<Vec<bool>>,
    /// The refusal each verdict carried, if any.
    verdicts: Mutex<Vec<Option<String>>>,
}

struct TestHook {
    mount: Arc<Mutex<Mount>>,
    content: crate::MountSyncContent<Authority>,
    runtime: Arc<FastWaitRuntime>,
    engine: std::sync::Weak<CommitEngine>,
    hooked: Arc<Hooked>,
}

impl TestHook {
    fn revocation(&self) -> Revocation {
        let engine = self.engine.clone();
        let hooked = self.hooked.clone();
        Revocation::new(move || {
            let free = engine
                .upgrade()
                .is_some_and(|engine| engine.admission_free_for_test());
            hooked.revocations.lock().unwrap().push(free);
        })
    }
}

impl MountViewHook for TestHook {
    fn install(
        &self,
        root: crate::sync::PublishedRoot,
        deadline: tokio::time::Instant,
        commit: LandedCommit,
    ) -> ViewInstall<'_> {
        Box::pin(async move {
            let lost = || {
                (
                    Err(crate::sync::refused("SyncLocalTransactionLost")),
                    Revocation::none(),
                )
            };
            let hooked = self.hooked.clone();
            if self
                .runtime
                .blocking(move || hooked.before_rebuild.hold())
                .await
                .is_err()
            {
                return lost();
            }
            let content = self.content.with_deadline(self.runtime.clone(), deadline);
            let verdict = match rebuild_verdict(&root, &content).await {
                Ok(verdict) => verdict,
                Err(error) => return (Err(error), Revocation::none()),
            };
            self.hooked
                .verdicts
                .lock()
                .unwrap()
                .push(verdict.as_ref().err().map(ToString::to_string));
            let after = self.hooked.after_commit.lock().unwrap().take();
            let fail = self.hooked.fail_after_commit.load(Ordering::SeqCst);
            let commit: LandedCommit = Box::new(move |pin| {
                let change = commit(pin)?;
                if let Some(after) = after {
                    after();
                }
                if fail {
                    return Err(crate::sync::refused("SyncBasePoisoned"));
                }
                Ok(change)
            });
            let (mount, hooked) = (self.mount.clone(), self.hooked.clone());
            let installed = self
                .runtime
                .blocking(move || {
                    hooked.before_install.hold();
                    mount.lock().unwrap().install_view(&root, verdict, commit)
                })
                .await;
            match installed {
                Ok(Ok(change)) => {
                    self.hooked.changes.lock().unwrap().push(change);
                    (Ok(()), Revocation::none())
                }
                Ok(Err(
                    ViewInstallError::KeptOpen(error) | ViewInstallError::HeadRefused(error),
                )) => (Err(error), Revocation::none()),
                Ok(Err(ViewInstallError::Deferred)) => (
                    Err(crate::sync::refused("SyncLocalTransactionLost")),
                    Revocation::none(),
                ),
                Ok(Err(ViewInstallError::Closed(error))) => (Err(error), self.revocation()),
                Ok(Err(ViewInstallError::ClosedAfterLanding)) => (Ok(()), self.revocation()),
                Err(_) => lost(),
            }
        })
    }

    fn install_unattended(
        &self,
        root: crate::sync::PublishedRoot,
        deadline: tokio::time::Instant,
        commit: LandedCommit,
    ) -> ViewInstall<'_> {
        self.install(root, deadline, commit)
    }

    /// The mount's own adoption decision, with the adapter's writer test
    /// answering no, each switched view recorded.
    fn adopt(
        &self,
        root: crate::sync::PublishedRoot,
        deadline: tokio::time::Instant,
        adoption: AdoptionCommit,
    ) -> ViewInstall<'_, Adopted> {
        Box::pin(async move {
            let content = self.content.with_deadline(self.runtime.clone(), deadline);
            let verdict = match adoption_verdict(&root, &content).await {
                Ok(verdict) => verdict,
                Err(error) => return (Err(error), Revocation::none()),
            };
            let (mount, hooked) = (self.mount.clone(), self.hooked.clone());
            let adopted = self
                .runtime
                .blocking(move || {
                    hooked.before_install.hold();
                    mount
                        .lock()
                        .unwrap()
                        .adopt_view(&root, verdict, adoption, false)
                })
                .await;
            match adopted {
                Ok(Ok(change)) => {
                    self.hooked.changes.lock().unwrap().push(change);
                    (Ok(Adopted::Installed), Revocation::none())
                }
                Ok(Err(ViewInstallError::Deferred)) => (Ok(Adopted::Deferred), Revocation::none()),
                Ok(Err(ViewInstallError::HeadRefused(error))) => {
                    (Ok(Adopted::Refused { cause: error }), Revocation::none())
                }
                Ok(Err(ViewInstallError::KeptOpen(error))) => (Err(error), Revocation::none()),
                Ok(Err(ViewInstallError::Closed(_) | ViewInstallError::ClosedAfterLanding)) => {
                    (Ok(Adopted::Closed), self.revocation())
                }
                Err(_) => (
                    Err(crate::sync::refused("SyncLocalTransactionLost")),
                    Revocation::none(),
                ),
            }
        })
    }

    fn close(&self, _: crate::CoordinationError, _: tokio::time::Instant) -> ViewInstall<'_> {
        Box::pin(async {
            (
                Err(crate::sync::refused("ViewAdapterLost")),
                Revocation::none(),
            )
        })
    }
}

/// [`EngineMount`] with its backend moved behind a lock the test hook
/// installs through.
struct HookedMount {
    mount: Arc<Mutex<Mount>>,
    engine: Arc<CommitEngine>,
    runtime: tokio::runtime::Runtime,
    faults: crate::FaultControl,
    state: Arc<Mutex<AuthorityState>>,
    tree: PublishedTree,
    paths: Paths,
    hooked: Arc<Hooked>,
}

type Base = (GrainId, u64);

impl HookedMount {
    fn new() -> Self {
        Self::with_tree(Paths::new(), mounted_operation_tree())
    }
    /// The hooked mount over `tree`, published under `paths`.
    fn with_tree(paths: Paths, tree: PublishedTree) -> Self {
        let EngineMount {
            ready,
            engine,
            runtime,
            faults,
            state,
            metrics: _,
            tree,
            paths,
        } = EngineMount::with_tree(paths, tree);
        let mount = ready.attach().backend;
        let content = mount
            .sync_content(Arc::new(Authority::new(&tree, &state).with_publication()))
            .unwrap();
        let mount = Arc::new(Mutex::new(mount));
        let hooked = Arc::new(Hooked::default());
        engine
            .set_view_hook(Arc::new(TestHook {
                mount: mount.clone(),
                content,
                runtime: engine.runtime_for_mount(),
                engine: Arc::downgrade(&engine),
                hooked: hooked.clone(),
            }))
            .unwrap();
        Self {
            mount,
            engine,
            runtime,
            faults,
            state,
            tree,
            paths,
            hooked,
        }
    }
    fn mount(&self) -> std::sync::MutexGuard<'_, Mount> {
        self.mount.lock().unwrap()
    }
    fn construct(&self, entropy: u8) -> Result<crate::RetainedCommit, crate::CoordinationError> {
        construct_commit(&self.engine, &self.runtime, entropy)
    }
    fn construct_latched(
        &self,
        entropy: u8,
    ) -> Result<crate::RetainedCommit, crate::CoordinationError> {
        self.runtime.block_on(async {
            self.engine
                .construct_latched(crate::SyncOptions::default(), &mut Entropy(entropy))
                .await
        })
    }
    fn take_over_latched(&self, entropy: u8) -> crate::sync::Resumed {
        let runtime = self.engine.runtime_for_mount();
        let deadline = runtime
            .now()
            .checked_add(crate::DEFAULT_RESOLUTION_BOUND)
            .unwrap();
        self.runtime
            .block_on(self.engine.take_over_latched(
                crate::SyncOptions::default(),
                deadline,
                &mut Entropy(entropy),
            ))
            .unwrap()
    }
    fn latch(&self) {
        self.mount()
            .shared_mediator()
            .with(|local| {
                local.close_mutations();
                Ok(())
            })
            .unwrap();
    }
    fn latch_live(&self) {
        self.latch();
        self.engine.floor_changed_for_test().notify_waiters();
    }
    fn shut_down(&self) -> crate::sync::Outcome {
        use crate::sync::Trigger;
        let shutdown = self
            .mount()
            .shutdown_for_test()
            .expect("an attached engine's shutdown");
        shutdown.begin(Trigger::SessionEnd).outcome
    }
    fn drive(
        &self,
        lane: &crate::RetainedCommit,
        entropy: u8,
    ) -> Result<crate::PublicationResult, crate::CoordinationError> {
        drive_commit(&self.engine, &self.runtime, lane, entropy)
    }
    /// Write `f.txt` through a handle the test keeps open.
    fn dirty(&self) -> u64 {
        self.dirty_with(b"commit-route")
    }
    fn dirty_with(&self, bytes: &[u8]) -> u64 {
        use granary_fuse::{MountBackend as _, OverlayMutation as M};
        let mut mount = self.mount();
        let object = mount
            .overlay_open(&handler_path(b"f.txt"))
            .unwrap()
            .unwrap();
        mount.prepare_object(object).unwrap();
        for (index, chunk) in bytes.chunks(1024 * 1024).enumerate() {
            mount
                .overlay_mutate(M::BoundWrite {
                    object,
                    offset: u64::try_from(index * 1024 * 1024).unwrap(),
                    bytes: chunk,
                    append: false,
                })
                .unwrap();
        }
        object
    }
    /// Open `path` and read it whole, preparing it first as the adapter does.
    fn read_path(&self, path: &[u8]) -> Result<Vec<u8>, granary_fuse::WriteError> {
        use granary_fuse::MountBackend as _;
        let mut mount = self.mount();
        let object = mount
            .overlay_open(&path_names(path))?
            .ok_or(granary_fuse::WriteError::Missing)?;
        let read = mount
            .prepare_object(object)
            .and_then(|()| mount.read_object(object, 0, 65_536));
        mount.overlay_close(object)?;
        read
    }
    fn close(&self, object: u64) {
        use granary_fuse::MountBackend as _;
        self.mount().overlay_close(object).unwrap();
    }
    fn pin(&self) -> Base {
        self.mount().pinned_base_for_test()
    }
    fn pin_bytes(&self) -> Vec<u8> {
        self.mount()
            .shared_mediator()
            .with(|local| Ok(local.mount_pin().unwrap().base_bytes.clone()))
            .unwrap()
    }
    /// The mediator's admitted base, as the install reads it after a failed commit.
    fn base(&self) -> Result<Base, crate::CoordinationError> {
        self.mount()
            .shared_mediator()
            .with(|local| local.mount_base())
    }
    /// The overlay's base, past the poison and fence checks.
    fn overlay_base(&self) -> Option<Base> {
        self.mount()
            .shared_mediator()
            .with(|local| Ok(local.overlay_base_for_test()))
            .unwrap()
    }
    fn view_pending(&self) -> bool {
        self.mount().view_pending_for_test()
    }
    /// The retained submission, if the engine still holds a commit lane.
    fn submission(&self) -> Option<granary_core::retained_submission::Submission> {
        let loaded = self.mount().shared_mediator().with(|store| {
            let scope = store.snapshot().scope.clone();
            let volume = store.snapshot().volume.clone();
            store.publication_transaction(|j| j.load(&scope, &volume))
        });
        match loaded {
            Err(crate::CoordinationError::Refused("SyncCommitLaneRequired")) => None,
            loaded => loaded.unwrap(),
        }
    }
    fn retained(&self) -> bool {
        self.submission().is_some()
    }
    fn wait_for_live_clean(&self, context: &str) {
        use crate::writable_store::sync_engine::LiveState;

        let runtime = self.engine.runtime_for_mount();
        let read = || {
            self.mount()
                .shared_mediator()
                .with(|local| local.live_state(&crate::SyncOptions::default(), runtime.now()))
        };
        let clean = eventually(|| matches!(read(), Ok(LiveState::Clean)));
        assert!(clean, "{context}: live state={:?}", read());
    }
    fn finish_non_landing(&self) {
        self.engine.forget_commit_for_test();
        self.mount()
            .shared_mediator()
            .with(|local| {
                let scope = local.snapshot().scope.clone();
                let volume = local.snapshot().volume.clone();
                let mut submission = local
                    .publication_transaction(|journal| journal.load(&scope, &volume))?
                    .expect("a retained submission");
                let candidate = submission
                    .candidates
                    .first_mut()
                    .expect("the retained submission's candidate");
                let attempt = candidate.evidence.start().expect("an unused attempt slot");
                candidate
                    .evidence
                    .answer(attempt, true, false)
                    .expect("the terminal refusal answer");
                let generation = submission.generation;
                submission.generation += 1;
                local
                    .publication_transaction(|journal| journal.replace(generation, &submission))?;
                let (serial, boundary, _, _, recovered) = local.recovered_commit()?;
                local.overlay_transaction(|overlay| {
                    overlay.record_commit_attempt(boundary, recovered.publication_id, 1)
                })?;
                local.finish_non_landing(serial, boundary, recovered.publication_id)
            })
            .unwrap();
        self.engine.floor_changed_for_test().notify_waiters();
    }
    fn set_coalescing_journal_length(&self, length: u64) {
        self.mount()
            .shared_mediator()
            .overlay_transaction(|overlay| overlay.set_coalescing_journal_length_for_test(length))
            .unwrap();
    }
    /// Drive `lane` on a helper thread, run `during` once the hook holds at
    /// its `latch`, then release it.
    fn drive_holding(
        &self,
        lane: &crate::RetainedCommit,
        entropy: u8,
        latch: impl Fn(&Hooked) -> &Latch,
        during: impl FnOnce(),
    ) -> Result<crate::PublicationResult, crate::CoordinationError> {
        let latch = latch(&self.hooked);
        latch.arm();
        std::thread::scope(|threads| {
            let _release = ReleaseOnDrop(latch);
            let driver = threads.spawn(|| self.drive(lane, entropy));
            assert!(latch.entered(), "premise: the hook reached its latch");
            during();
            latch.release();
            driver.join().unwrap()
        })
    }
    /// Drive `lane` and drop the caller's future once the hook holds its
    /// install section; whether the drive had already finished by then.
    fn drive_then_cancel(&self, lane: &crate::RetainedCommit, entropy: u8) -> bool {
        use std::future::Future as _;
        let latch = &self.hooked.before_install;
        self.runtime.block_on(async {
            let (mut secure, mut delay) = (Entropy(entropy), NoDelay);
            let mut drive = Box::pin(self.engine.drive_commit(
                lane,
                &mut secure,
                &mut delay,
                RecoveryIntent::Continue,
                crate::SyncOptions::default(),
            ));
            loop {
                let finished = std::future::poll_fn(|context| {
                    std::task::Poll::Ready(drive.as_mut().poll(context).is_ready())
                })
                .await;
                if finished || latch.is_entered() {
                    return finished;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
    }
    fn changes(&self) -> Vec<crate::ViewChange> {
        self.hooked.changes.lock().unwrap().clone()
    }
    fn revocations(&self) -> Vec<bool> {
        self.hooked.revocations.lock().unwrap().clone()
    }
    fn ranges(&self) -> usize {
        self.state.lock().unwrap().ranges.len()
    }
    fn fired(&self) -> Vec<(&'static str, &'static str, u64)> {
        self.faults
            .sync_fired()
            .iter()
            .map(|event| (event.name, event.phase, event.occurrence))
            .collect()
    }
    fn anchor(&self) -> std::path::PathBuf {
        self.paths
            .cache
            .join("anchors")
            .join(format!("{}.mount", self.tree.volume.as_str()))
    }
    /// The mount-private floor, as the anchor file states it.
    fn floor(&self) -> Option<u64> {
        let text = std::fs::read_to_string(self.anchor()).ok()?;
        text.strip_prefix("seq ")?.trim_end().parse().ok()
    }
    fn cached_root_path(&self, seq: u64) -> std::path::PathBuf {
        self.paths
            .cache
            .join("roots")
            .join(self.tree.volume.as_str())
            .join(format!("{seq:020}"))
    }
    /// Every root the mount's cache holds.
    fn cached_roots(&self) -> Vec<Vec<u8>> {
        let directory = self
            .paths
            .cache
            .join("roots")
            .join(self.tree.volume.as_str());
        let mut roots: Vec<_> = std::fs::read_dir(directory)
            .map(|entries| {
                entries
                    .map(|entry| std::fs::read(entry.unwrap().path()).unwrap())
                    .collect()
            })
            .unwrap_or_default();
        roots.sort();
        roots
    }
    fn store_root(&self, seq: u64) -> Vec<u8> {
        self.runtime
            .block_on(remote_handle(&self.tree.mem).get_root(self.tree.volume.as_str(), seq))
            .unwrap()
            .unwrap()
    }
    /// Plant a root at `seq`, validly signed by the volume's key, in the
    /// mount's cache, so a landing there is an equivocation.
    fn plant_equivocation(&self, seq: u64) -> std::path::PathBuf {
        let forged = super::super::super::sign_root(
            &self.tree,
            &self.tree.key,
            &self.tree.volume,
            seq,
            1,
            [0xAA; 16],
        );
        let path = self.cached_root_path(seq);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, forged).unwrap();
        path
    }
    /// Add a symlink at the root of the overlay with a `len`-byte target,
    /// past the backend's own servability refusal.
    fn link(&self, len: usize) {
        use granary_core::overlay_journal::{CreateKind, Location, Parent, Record};
        self.mount()
            .shared_mediator()
            .overlay_transaction(|overlay| {
                overlay.namespace_record(Record::Create {
                    at: Location {
                        name: granary_core::manifest::Name::new(b"long-link".to_vec()).unwrap(),
                        parent: Parent::new(vec![]).unwrap(),
                    },
                    kind: CreateKind::Symlink {
                        target: granary_core::manifest::SymlinkTarget::new(vec![b't'; len])
                            .unwrap(),
                    },
                })
            })
            .unwrap();
    }
}

/// A transient install refusal keeps its lane live, follows the growing fast
/// schedule, and lands once the floor can be persisted.
#[test]
fn live_driver_resumes_a_transient_install_refusal() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    fixture.close(object);
    let anchor = fixture.anchor();
    std::fs::remove_file(&anchor).unwrap();
    std::fs::create_dir(&anchor).unwrap();
    let before = fixture.pin();
    std::thread::scope(|threads| {
        let engine = fixture.engine.clone();
        let driver = threads.spawn(|| {
            fixture
                .runtime
                .block_on(engine.drive_live(crate::SyncOptions::default(), Entropy(90)))
        });
        assert!(
            eventually(|| fixture.engine.live_pauses_for_test().len() >= 3),
            "the retained landing did not reach three refused pauses"
        );
        let pauses = fixture.engine.live_pauses_for_test();
        assert_eq!(
            pauses
                .iter()
                .take(3)
                .map(|(base, _)| base.as_millis())
                .collect::<Vec<_>>(),
            vec![40, 80, 160],
            "the first three refused-pause ceilings"
        );
        assert_eq!(
            (fixture.retained(), fixture.pin()),
            (true, before),
            "the refused install retains its lane and served pin"
        );
        std::fs::remove_dir(&anchor).unwrap();
        assert!(
            eventually(|| !fixture.changes().is_empty()),
            "the live driver did not resume the retained landing"
        );
        fixture.latch_live();
        assert_eq!(driver.join().unwrap(), crate::LiveEnd::Latched);
    });
    assert_eq!(
        (fixture.pin().1, fixture.retained(), fixture.changes().len()),
        (2, false, 1),
        "(installed sequence, retained lane, installed views)"
    );
}

fn drive_to_eighth_refusal(
    fixture: &HookedMount,
    driver: &RunningLoop,
) -> Vec<(std::time::Duration, std::time::Duration)> {
    assert!(
        within_five_seconds(|| !fixture.engine.live_pauses_for_test().is_empty()),
        "the first refused drive entered its retry pause within five seconds"
    );
    while fixture.engine.live_pauses_for_test().len() < 8 {
        let pauses = fixture.engine.live_pauses_for_test();
        let count = pauses.len();
        let drawn = pauses.last().unwrap().1;
        if !drawn.is_zero() {
            driver.advance(drawn);
        }
        assert!(
            within_five_seconds(|| fixture.engine.live_pauses_for_test().len() > count),
            "refused pass {} began after its drawn pause within five seconds",
            count + 1
        );
    }
    let pauses = fixture.engine.live_pauses_for_test();
    assert_eq!(
        pauses
            .iter()
            .take(8)
            .map(|(base, _)| base.as_millis())
            .collect::<Vec<_>>(),
        vec![40, 80, 160, 320, 640, 1_280, 2_560, 600_000],
        "seven fast pauses and the eighth pass's slow pause"
    );
    assert_eq!(
        pauses.len(),
        8,
        "the eighth refusal leaves the loop alive in its pause"
    );
    pauses
}

/// The eighth refusal enters a slow pause that incidental wakes cannot end,
/// then the running loop drives and lands a later pass.
#[test]
fn live_driver_slows_after_eight_refusals_and_keeps_driving() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    fixture.close(object);
    let anchor = fixture.anchor();
    std::fs::remove_file(&anchor).unwrap();
    std::fs::create_dir(&anchor).unwrap();
    let events = Events::default();
    let mut driver = RunningLoop::start(
        fixture.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::ZERO,
            max_coalesce_delay: std::time::Duration::ZERO,
            ..crate::SyncOptions::default()
        },
        104,
        events.clone(),
    );
    let pauses = drive_to_eighth_refusal(&fixture, &driver);
    driver.assert_running("the loop stopped when its eighth refusal entered");

    let slow_started = driver.elapsed();
    let slow_drawn = pauses[7].1;
    <Arc<CommitEngine> as crate::sync::HeadAdopter>::answered(&fixture.engine);
    assert!(
        !within_five_seconds(|| fixture.engine.live_pauses_for_test().len() > 8),
        "an authority answer ended the slow stall pause"
    );
    fixture.engine.floor_changed_for_test().notify_waiters();
    driver.turn();
    let held = fixture.dirty();
    driver.turn();
    fixture.close(held);
    driver.turn();
    assert_eq!(
        (
            fixture.engine.live_pauses_for_test().len(),
            driver.elapsed(),
        ),
        (8, slow_started),
        "an authority answer, floor wake, dirty write and handle close start no pass during the slow pause"
    );

    let before_deadline = slow_drawn
        .checked_sub(std::time::Duration::from_secs(1))
        .unwrap();
    driver.advance(before_deadline);
    assert_eq!(
        (
            fixture.engine.live_pauses_for_test().len(),
            driver.elapsed(),
        ),
        (8, slow_started + before_deadline),
        "no pass begins before the drawn slow-pause deadline"
    );
    driver.advance(std::time::Duration::from_secs(1));
    driver.turn();
    assert!(
        within_five_seconds(|| fixture.engine.live_pauses_for_test().len() >= 9),
        "the ninth refusal was driven after the slow pause elapsed"
    );
    assert!(
        driver.elapsed() >= slow_started + slow_drawn,
        "the ninth pass began before the paused clock elapsed the drawn pause"
    );
    driver.assert_running("the loop stopped instead of driving the ninth refusal");
    std::fs::remove_dir(&anchor).unwrap();
    let final_pause = fixture.engine.live_pauses_for_test()[8].1;
    driver.advance(final_pause);
    assert!(
        within_five_seconds(|| !fixture.changes().is_empty()),
        "the loop did not land after the stall plant was removed"
    );
    fixture.wait_for_live_clean("the loop did not land both dirty records before shutdown");
    assert!(
        eventually(|| backoff_count(&events, "stall", "recovered") == 1),
        "the landed pass did not record stall recovery before shutdown: recovered={}",
        backoff_count(&events, "stall", "recovered")
    );
    fixture.latch_live();
    driver.finish(crate::LiveEnd::Latched);
    assert_eq!(
        (
            fixture.pin().1,
            backoff_count(&events, "stall", "entered"),
            backoff_count(&events, "stall", "recovered"),
        ),
        (3, 1, 1),
        "(installed sequence after one landing per dirty record, stall entered, stall recovered)"
    );
}

fn outage_draw_is_within_twenty_percent(
    base: std::time::Duration,
    drawn: std::time::Duration,
) -> bool {
    let base_ms = base.as_millis();
    ((base_ms * 800 / 1_000)..=(base_ms * 1_200 / 1_000)).contains(&drawn.as_millis())
}

#[test]
fn outage_draw_bounds_follow_millisecond_flooring() {
    let base = std::time::Duration::from_millis(6_554);
    let draws = [800, 1_200].map(|factor| std::time::Duration::from_millis(6_554 * factor / 1_000));
    let exact_duration_bounds = (base * 8 / 10)..=(base * 12 / 10);
    assert_eq!(
        draws.map(|drawn| exact_duration_bounds.contains(&drawn)),
        [false, true],
        "premise: exact-duration bounds do not admit both millisecond-floored endpoints: \
         bounds={exact_duration_bounds:?}, draws={draws:?}"
    );
    assert_eq!(
        draws.map(|drawn| outage_draw_is_within_twenty_percent(base, drawn)),
        [true, true],
        "whole-millisecond bounds admit factors 800 and 1200: base={base:?}, draws={draws:?}"
    );
}

/// Outage retries grow and cap under the running loop; an authority answer
/// resets the next step but cannot start another pass before one second.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one running-loop row covers growth, the cap, answer timing and recovery"
)]
fn live_driver_backs_off_through_an_outage_and_resets_when_the_authority_answers() {
    use granary_core::rootstore::RootStoreError;

    let fixture = HookedMount::new();
    let object = fixture.dirty();
    fixture.close(object);
    fixture.state.lock().unwrap().root_fault.insert(
        fixture.tree.seq + 1,
        RootStoreError::Unavailable {
            operation: "GET root",
            status: 503,
        },
    );
    let events = Events::default();
    let mut driver = RunningLoop::start(
        fixture.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::ZERO,
            max_coalesce_delay: std::time::Duration::ZERO,
            ..crate::SyncOptions::default()
        },
        109,
        events.clone(),
    );
    assert!(
        within_five_seconds(|| !fixture.engine.live_pauses_for_test().is_empty()),
        "the first unavailable drive entered its outage pause within five seconds"
    );
    while fixture.engine.live_pauses_for_test().len() < 13 {
        let pauses = fixture.engine.live_pauses_for_test();
        let count = pauses.len();
        driver.advance(pauses.last().unwrap().1);
        assert!(
            within_five_seconds(|| fixture.engine.live_pauses_for_test().len() > count),
            "outage pass {} began after its drawn pause within five seconds",
            count + 1
        );
    }
    let expected = [
        1_000, 1_600, 2_560, 4_096, 6_554, 10_486, 16_777, 26_844, 42_950, 68_719, 109_951,
        120_000, 120_000,
    ];
    let pauses = fixture.engine.live_pauses_for_test();
    assert_eq!(
        pauses
            .iter()
            .map(|(base, _)| base.as_millis())
            .collect::<Vec<_>>(),
        expected,
        "the running loop's thirteen outage bases grow by 1.6 and cap at 120000 ms"
    );
    for (base, drawn) in &pauses {
        assert!(
            outage_draw_is_within_twenty_percent(*base, *drawn),
            "outage draw {drawn:?} for base {base:?} is outside ±20%"
        );
    }

    let answered_at = driver.elapsed();
    <Arc<CommitEngine> as crate::sync::HeadAdopter>::answered(&fixture.engine);
    driver.turn();
    assert_eq!(
        (
            fixture.engine.live_pauses_for_test().len(),
            driver.elapsed()
        ),
        (13, answered_at),
        "an answer does not retry an outage immediately"
    );
    driver.advance(std::time::Duration::from_millis(999));
    assert_eq!(
        fixture.engine.live_pauses_for_test().len(),
        13,
        "an answer starts no outage pass before one second"
    );
    driver.advance(std::time::Duration::from_millis(1));
    assert!(
        within_five_seconds(|| fixture.engine.live_pauses_for_test().len() == 14),
        "the answered outage retried at one second"
    );
    assert_eq!(
        (
            fixture.engine.live_pauses_for_test()[13].0,
            driver.elapsed(),
            backoff_count(&events, "outage", "entered"),
        ),
        (
            std::time::Duration::from_secs(1),
            answered_at + std::time::Duration::from_secs(1),
            1,
        ),
        "(reset outage base, retry instant, entered transitions)"
    );

    fixture.state.lock().unwrap().root_fault.clear();
    driver.advance(fixture.engine.live_pauses_for_test()[13].1);
    assert!(
        within_five_seconds(|| !fixture.changes().is_empty()),
        "the live loop did not install the landing after the outage cleared"
    );
    fixture.wait_for_live_clean("the outage landing did not finish before shutdown");
    assert!(
        eventually(|| backoff_count(&events, "outage", "recovered") == 1),
        "the landed pass did not record outage recovery before shutdown: recovered={}",
        backoff_count(&events, "outage", "recovered")
    );
    fixture.latch_live();
    driver.finish(crate::LiveEnd::Latched);
    assert_eq!(
        (
            fixture.pin().1,
            backoff_count(&events, "outage", "entered"),
            backoff_count(&events, "outage", "recovered"),
        ),
        (2, 1, 1),
        "(installed sequence, outage entered, outage recovered)"
    );
}

/// A landing by another driver ends a retry that first observed open
/// admission and resets the refused cadence for the next failure.
#[test]
fn live_driver_counts_progress_as_landings() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    fixture.close(object);
    let mut driver = RunningLoop::start(
        fixture.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::ZERO,
            max_coalesce_delay: std::time::Duration::ZERO,
            workspace_bytes: 0,
            ..crate::SyncOptions::default()
        },
        110,
        Events::default(),
    );
    assert!(
        within_five_seconds(|| !fixture.engine.live_pauses_for_test().is_empty()),
        "the first refused construction entered its pause within five seconds"
    );
    while fixture.engine.live_pauses_for_test().len() < 4 {
        let count = fixture.engine.live_pauses_for_test().len();
        driver.advance(std::time::Duration::from_secs(601));
        assert!(
            within_five_seconds(|| fixture.engine.live_pauses_for_test().len() > count),
            "refused pass {} began after its drawn pause within five seconds",
            count + 1
        );
    }
    let retry_read = Arc::new(Latch::default());
    retry_read.arm();
    fixture.engine.after_live_retry_read_for_test({
        let retry_read = retry_read.clone();
        move || retry_read.hold()
    });
    {
        let _release = ReleaseOnDrop(&retry_read);
        let advanced = driver.begin_advance(std::time::Duration::from_mins(10));
        assert!(
            retry_read.entered(),
            "premise: the retry wait first observed open admission"
        );
        assert_eq!(
            fixture.engine.live_pauses_for_test().len(),
            5,
            "the fifth refused construction entered its pause"
        );
        let lane = fixture.construct(111).unwrap();
        let later = fixture.dirty_with(b"after-progress-landing");
        fixture.close(later);
        let landing = fixture.drive(&lane, 112).unwrap();
        assert!(
            matches!(landing.outcome, crate::PublicationOutcome::Landed(_)),
            "premise: the other driver landed the lane, got {:?}",
            landing.outcome
        );
        retry_read.release();
        advanced
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the paused clock advance completed after the retry read resumed");
    }
    driver.advance(std::time::Duration::from_secs(601));
    assert!(
        within_five_seconds(|| fixture.engine.live_pauses_for_test().len() >= 6),
        "the first refusal after the other driver's landing did not enter its pause: pauses={:?}, constructions={}, retained={}, changes={}, elapsed={:?}",
        fixture.engine.live_pauses_for_test(),
        fixture.engine.live_constructions_for_test(),
        fixture.retained(),
        fixture.changes().len(),
        driver.elapsed(),
    );
    assert_eq!(
        fixture.engine.live_pauses_for_test()[5].0,
        std::time::Duration::from_millis(40),
        "the other driver's landing resets the next refused pause"
    );
    fixture.latch_live();
    driver.finish(crate::LiveEnd::Latched);
}

/// Losing the lane's driver after construction costs one pass and no retry
/// pause; takeover waits for the winning driver to finish.
#[test]
fn live_driver_waits_when_another_driver_wins_after_construction() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    fixture.close(object);
    let before_drive = Arc::new(Latch::default());
    before_drive.arm();
    fixture.engine.before_live_commit_drive_for_test({
        let before_drive = before_drive.clone();
        move || before_drive.hold()
    });
    let mut driver = RunningLoop::start(
        fixture.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::ZERO,
            max_coalesce_delay: std::time::Duration::ZERO,
            ..crate::SyncOptions::default()
        },
        113,
        Events::default(),
    );
    assert!(
        before_drive.entered(),
        "premise: the live loop constructed before its drive"
    );
    let lane = fixture
        .engine
        .recover_commit(crate::SyncOptions::default())
        .unwrap();
    fixture.hooked.before_install.arm();
    std::thread::scope(|threads| {
        let _release_drive = ReleaseOnDrop(&before_drive);
        let _release_install = ReleaseOnDrop(&fixture.hooked.before_install);
        let winner = threads.spawn(|| fixture.drive(&lane, 114));
        assert!(
            fixture.hooked.before_install.entered(),
            "premise: the other driver won and held the lane"
        );
        before_drive.release();
        driver.turn();
        assert_eq!(
            fixture.engine.live_pauses_for_test().len(),
            0,
            "drive-side SyncCommitInFlight starts no retry pause"
        );
        fixture.hooked.before_install.release();
        let result = winner.join().unwrap().unwrap();
        assert!(
            matches!(result.outcome, crate::PublicationOutcome::Landed(_)),
            "premise: the winning driver landed, got {:?}",
            result.outcome
        );
    });
    assert!(
        within_five_seconds(|| !fixture.changes().is_empty()),
        "the live loop did not observe the other driver's landing"
    );
    fixture.wait_for_live_clean("the other driver's landing did not settle before shutdown");
    fixture.latch_live();
    driver.finish(crate::LiveEnd::Latched);
}

/// An answer received after the pass starts but before construction is older
/// than the drive and cannot shorten that drive's outage pause.
#[test]
fn live_driver_clears_an_answer_immediately_before_a_constructed_drive() {
    use granary_core::rootstore::RootStoreError;

    let fixture = HookedMount::new();
    fixture.state.lock().unwrap().root_fault.insert(
        fixture.tree.seq + 1,
        RootStoreError::Unavailable {
            operation: "GET root",
            status: 503,
        },
    );
    let object = fixture.dirty();
    fixture.close(object);
    let before_pass = Arc::new(Latch::default());
    before_pass.arm();
    fixture.engine.before_live_drive_for_test({
        let before_pass = before_pass.clone();
        move || before_pass.hold()
    });
    let (mark, observed_mark) = std::sync::mpsc::channel();
    fixture.engine.before_live_commit_drive_for_test({
        let engine = Arc::downgrade(&fixture.engine);
        move || {
            let engine = engine.upgrade().expect("the fixture still owns its engine");
            mark.send(engine.take_answered()).unwrap();
        }
    });
    let mut driver = RunningLoop::start(
        fixture.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::ZERO,
            max_coalesce_delay: std::time::Duration::ZERO,
            ..crate::SyncOptions::default()
        },
        115,
        Events::default(),
    );
    assert!(
        before_pass.entered(),
        "premise: the pass cleared its old answer before the drive"
    );
    <Arc<CommitEngine> as crate::sync::HeadAdopter>::answered(&fixture.engine);
    before_pass.release();
    assert!(
        !observed_mark
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the constructed drive reached its pre-drive hook"),
        "the constructed drive left an older answer mark set"
    );
    assert!(
        within_five_seconds(|| !fixture.engine.live_pauses_for_test().is_empty()),
        "the drive after the pre-construction answer entered its outage pause: pauses={:?}, constructions={}, retained={}, changes={}, root_reads={}",
        fixture.engine.live_pauses_for_test(),
        fixture.engine.live_constructions_for_test(),
        fixture.retained(),
        fixture.changes().len(),
        fixture.state.lock().unwrap().root_reads,
    );
    driver.turn();
    assert_eq!(
        (
            fixture.engine.live_pauses_for_test().len(),
            driver.elapsed()
        ),
        (1, std::time::Duration::ZERO),
        "the answer from before construction does not wake the retry"
    );
    driver.advance(std::time::Duration::from_secs(1));
    driver.turn();
    assert_ne!(
        fixture
            .engine
            .live_pauses_for_test()
            .get(1)
            .map(|(base, _)| *base),
        Some(std::time::Duration::from_secs(1)),
        "a stale answer reset the outage step after the constructed drive"
    );
    fixture.latch_live();
    driver.finish(crate::LiveEnd::Latched);
}

/// An answer received after the pass starts but before takeover is older than
/// the resumed drive and cannot shorten that drive's outage pause.
#[test]
fn live_driver_clears_an_answer_immediately_before_a_resumed_drive() {
    use granary_core::rootstore::RootStoreError;

    let fixture = HookedMount::new();
    let object = fixture.dirty();
    fixture.close(object);
    let _lane = fixture.construct(118).unwrap();
    fixture.state.lock().unwrap().root_fault.insert(
        fixture.tree.seq + 1,
        RootStoreError::Unavailable {
            operation: "GET root",
            status: 503,
        },
    );
    let before_pass = Arc::new(Latch::default());
    before_pass.arm();
    fixture.engine.before_live_drive_for_test({
        let before_pass = before_pass.clone();
        move || before_pass.hold()
    });
    let (mark, observed_mark) = std::sync::mpsc::channel();
    fixture.engine.before_live_commit_drive_for_test({
        let engine = Arc::downgrade(&fixture.engine);
        move || {
            let engine = engine.upgrade().expect("the fixture still owns its engine");
            mark.send(engine.take_answered()).unwrap();
        }
    });
    let mut driver = RunningLoop::start(
        fixture.engine.clone(),
        crate::SyncOptions::default(),
        119,
        Events::default(),
    );
    assert!(
        before_pass.entered(),
        "premise: the pass began before takeover resumed the lane"
    );
    <Arc<CommitEngine> as crate::sync::HeadAdopter>::answered(&fixture.engine);
    before_pass.release();
    assert!(
        !observed_mark
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the resumed drive reached its pre-drive hook"),
        "the resumed drive left an older answer mark set"
    );
    assert!(
        within_five_seconds(|| !fixture.engine.live_pauses_for_test().is_empty()),
        "the resumed drive entered its outage pause"
    );
    driver.turn();
    assert_eq!(
        (
            fixture.engine.live_pauses_for_test().len(),
            driver.elapsed()
        ),
        (1, std::time::Duration::ZERO),
        "the answer from before takeover does not wake the resumed drive's retry"
    );
    driver.advance(std::time::Duration::from_secs(1));
    assert_ne!(
        fixture
            .engine
            .live_pauses_for_test()
            .get(1)
            .map(|(base, _)| *base),
        Some(std::time::Duration::from_secs(1)),
        "a stale answer reset the outage step after the resumed drive"
    );
    fixture.latch_live();
    driver.finish(crate::LiveEnd::Latched);
}

/// Ending a lane without a landing during a slow retry neither recovers the
/// stall episode nor returns its next construction refusal to the fast cadence.
#[test]
fn live_driver_keeps_a_stall_episode_across_a_non_landing_lane_end() {
    let lane_end = HookedMount::new();
    let object = lane_end.dirty();
    lane_end.close(object);
    let lane_events = Events::default();
    let mut driver = RunningLoop::start(
        lane_end.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::ZERO,
            max_coalesce_delay: std::time::Duration::ZERO,
            workspace_bytes: 0,
            ..crate::SyncOptions::default()
        },
        106,
        lane_events.clone(),
    );
    assert!(
        within_five_seconds(|| !lane_end.engine.live_pauses_for_test().is_empty()),
        "the first capacity-refused construction entered its pause within five seconds"
    );
    while lane_end.engine.live_pauses_for_test().len() < 8 {
        let count = lane_end.engine.live_pauses_for_test().len();
        driver.advance(std::time::Duration::from_secs(601));
        assert!(
            within_five_seconds(|| lane_end.engine.live_pauses_for_test().len() > count),
            "capacity refusal {} entered its pause within five seconds: pauses={:?}, constructions={}, retained={}",
            count + 1,
            lane_end.engine.live_pauses_for_test(),
            lane_end.engine.live_constructions_for_test(),
            lane_end.retained(),
        );
    }
    assert_eq!(
        lane_end.engine.live_pauses_for_test().len(),
        8,
        "the eighth construction refusal leaves the loop in its slow pause"
    );
    let before_lane_end = driver.elapsed();
    let _lane = lane_end.construct(107).unwrap();
    driver.turn();
    // Advance the generation after acquisition 1: an atomic finish has
    // already ended the lane, while the old split helper still has to replace.
    let mediator = lane_end.mount().shared_mediator().clone();
    crate::writable_store::track_acquisitions_for_test(Some((
        1,
        Box::new(move || {
            let advanced = mediator.with(|local| {
                let scope = local.snapshot().scope.clone();
                let volume = local.snapshot().volume.clone();
                let Some(mut submission) =
                    local.publication_transaction(|journal| journal.load(&scope, &volume))?
                else {
                    return Ok(());
                };
                let generation = submission.generation;
                submission.generation += 1;
                local.publication_transaction(|journal| journal.replace(generation, &submission))
            });
            if !matches!(
                &advanced,
                Err(crate::CoordinationError::Refused("SyncCommitLaneRequired"))
            ) {
                advanced.unwrap();
            }
        }),
    )));
    lane_end.finish_non_landing();
    crate::writable_store::track_acquisitions_for_test(None);
    driver.advance(std::time::Duration::from_secs(601));
    assert!(
        within_five_seconds(|| lane_end.engine.live_pauses_for_test().len() >= 9),
        "the loop did not continue after the non-landing lane end"
    );
    assert_eq!(
        (
            lane_end.engine.live_pauses_for_test()[8].0,
            driver.elapsed(),
            backoff_count(&lane_events, "stall", "entered"),
            backoff_count(&lane_events, "stall", "recovered"),
        ),
        (
            std::time::Duration::from_mins(10),
            before_lane_end + std::time::Duration::from_secs(601),
            1,
            0,
        ),
        "(next pause, clock, entered, recovered) after a non-landing lane end"
    );
    lane_end.latch_live();
    driver.finish(crate::LiveEnd::Latched);
    assert_eq!(
        (
            backoff_count(&lane_events, "stall", "entered"),
            backoff_count(&lane_events, "stall", "recovered"),
        ),
        (1, 0),
        "the non-landing end neither recovers nor re-enters the open stall episode"
    );
}

/// A lane already retained when the loop starts is resumed before the
/// coalescer is allowed to construct anything.
#[test]
fn live_driver_starts_with_a_retained_lane() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    fixture.close(object);
    let _lane = fixture.construct(70).unwrap();
    assert!(fixture.retained(), "premise: a lane is retained");
    let mut driver = RunningLoop::start(
        fixture.engine.clone(),
        crate::SyncOptions::default(),
        91,
        Events::default(),
    );
    assert!(
        within_five_seconds(|| !fixture.changes().is_empty()),
        "the initial retained lane was not resumed within five seconds"
    );
    assert_eq!(
        fixture.engine.live_constructions_for_test(),
        0,
        "the resume-first pass must not construct"
    );
    fixture.wait_for_live_clean("the resumed lane did not finish before shutdown");
    fixture.latch_live();
    driver.finish(crate::LiveEnd::Latched);
}

/// Every live wait observes the shutdown latch and returns without beginning
/// another drive. Case count 4.
#[test]
fn live_driver_ends_at_the_latch_from_every_wait() {
    let mut cases = 0;
    let fixture = HookedMount::new();
    let (started, observed) = std::sync::mpsc::channel();
    fixture
        .engine
        .before_live_drive_for_test(move || started.send(()).unwrap());
    std::thread::scope(|threads| {
        let engine = fixture.engine.clone();
        let driver = threads.spawn(|| {
            fixture
                .runtime
                .block_on(engine.drive_live(crate::SyncOptions::default(), Entropy(92)))
        });
        observed
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        fixture.latch_live();
        assert_eq!(driver.join().unwrap(), crate::LiveEnd::Latched);
    });
    assert_eq!(fixture.engine.live_constructions_for_test(), 0);
    cases += 1;

    let timer = HookedMount::new();
    let object = timer.dirty();
    let (started, observed) = std::sync::mpsc::channel();
    timer
        .engine
        .before_live_drive_for_test(move || started.send(()).unwrap());
    std::thread::scope(|threads| {
        let engine = timer.engine.clone();
        let driver = threads.spawn(|| {
            timer
                .runtime
                .block_on(engine.drive_live(crate::SyncOptions::default(), Entropy(98)))
        });
        observed
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        timer.latch_live();
        assert_eq!(driver.join().unwrap(), crate::LiveEnd::Latched);
    });
    timer.close(object);
    assert_eq!(timer.engine.live_constructions_for_test(), 0);
    cases += 1;

    let retry = HookedMount::new();
    let object = retry.dirty();
    retry.close(object);
    let anchor = retry.anchor();
    std::fs::remove_file(&anchor).unwrap();
    std::fs::create_dir(&anchor).unwrap();
    std::thread::scope(|threads| {
        let engine = retry.engine.clone();
        let driver = threads.spawn(|| {
            retry
                .runtime
                .block_on(engine.drive_live(crate::SyncOptions::default(), Entropy(99)))
        });
        assert!(
            eventually(|| !retry.engine.live_pauses_for_test().is_empty()),
            "premise: the loop entered its refused retry wait"
        );
        retry.latch_live();
        assert_eq!(driver.join().unwrap(), crate::LiveEnd::Latched);
    });
    std::fs::remove_dir(&anchor).unwrap();
    cases += 1;

    let resume = HookedMount::new();
    let object = resume.dirty();
    resume.close(object);
    let lane = resume.construct(70).unwrap();
    resume
        .faults
        .arm("sync.commit", "before_submit", 1, crate::FaultAction::Block);
    let _release = ResumeOnDrop(&resume.faults);
    std::thread::scope(|threads| {
        let external = threads.spawn(|| resume.drive(&lane, 71));
        assert!(
            eventually(|| {
                resume
                    .fired()
                    .contains(&("sync.commit", "before_submit", 1))
            }),
            "premise: another driver holds the lane"
        );
        let engine = resume.engine.clone();
        let driver = threads.spawn(|| {
            resume
                .runtime
                .block_on(engine.drive_live(crate::SyncOptions::default(), Entropy(100)))
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        resume.latch_live();
        assert_eq!(driver.join().unwrap(), crate::LiveEnd::Latched);
        resume.faults.resume();
        let _ = external.join().unwrap();
    });
    cases += 1;
    assert_eq!(cases, 4);
}

/// A cancelled drive leaves a retained lane that wakes the parked live loop,
/// which resumes it without another write.
#[test]
fn live_driver_drives_a_lane_a_cancelled_fsync_left() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    fixture.close(object);
    let lane = fixture.construct(70).unwrap();
    fixture.state.lock().unwrap().publish_delay = Some(std::time::Duration::from_millis(500));
    let cancelled = fixture.runtime.block_on(async {
        let mut secure = Entropy(71);
        let mut delay = NoDelay;
        Box::pin(tokio::time::timeout(
            std::time::Duration::from_millis(50),
            fixture.engine.drive_commit(
                &lane,
                &mut secure,
                &mut delay,
                RecoveryIntent::Continue,
                crate::SyncOptions::default(),
            ),
        ))
        .await
        .is_err()
    });
    assert_eq!(
        (cancelled, fixture.retained(), fixture.changes().len()),
        (true, true, 0),
        "premise: the caller was cancelled with a retained, uninstalled lane"
    );
    std::thread::scope(|threads| {
        let engine = fixture.engine.clone();
        let driver = threads.spawn(|| {
            fixture
                .runtime
                .block_on(engine.drive_live(crate::SyncOptions::default(), Entropy(72)))
        });
        assert!(
            eventually(|| fixture.pin().1 == 2 && !fixture.retained()),
            "the live wait did not wake and resume the cancelled caller's lane"
        );
        fixture.latch_live();
        assert_eq!(driver.join().unwrap(), crate::LiveEnd::Latched);
    });
}

/// A live loop waits for the current lane's driver, then coalesces work that
/// arrived behind it without surfacing an in-flight construction.
#[test]
fn live_driver_waits_for_another_driver_then_coalesces() {
    let fixture = HookedMount::new();
    let first = fixture.dirty();
    fixture.close(first);
    let lane = fixture.construct(70).unwrap();
    fixture
        .faults
        .arm("sync.commit", "before_submit", 1, crate::FaultAction::Block);
    let _release = ResumeOnDrop(&fixture.faults);
    std::thread::scope(|threads| {
        let external = threads.spawn(|| fixture.drive(&lane, 71));
        assert!(
            eventually(|| {
                fixture
                    .fired()
                    .contains(&("sync.commit", "before_submit", 1))
            }),
            "premise: the explicit driver holds the retained lane"
        );
        let second = fixture.dirty();
        fixture.close(second);
        let engine = fixture.engine.clone();
        let driver = threads.spawn(|| {
            fixture
                .runtime
                .block_on(engine.drive_live(crate::SyncOptions::default(), Entropy(73)))
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(
            fixture.engine.live_constructions_for_test(),
            0,
            "the live wait constructed while another driver held the lane"
        );
        fixture.faults.resume();
        assert!(external.join().unwrap().is_ok());
        assert!(
            eventually(|| fixture.pin().1 == 3),
            "the loop did not coalesce and land the work behind the first lane"
        );
        fixture.latch_live();
        assert_eq!(driver.join().unwrap(), crate::LiveEnd::Latched);
    });
    assert_eq!(fixture.engine.live_constructions_for_test(), 1);
}

/// Shutdown takes over a lane after the live driver's deadline cut and retry
/// pause; the live loop holds no driver guard across that pause.
#[test]
fn shutdown_drains_a_live_drivers_lane() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    fixture.close(object);
    fixture.state.lock().unwrap().publish_delay = Some(std::time::Duration::from_millis(500));
    let options = crate::SyncOptions {
        resolution_bound: std::time::Duration::from_millis(50),
        quiesce_delay: std::time::Duration::ZERO,
        max_coalesce_delay: std::time::Duration::ZERO,
        ..crate::SyncOptions::default()
    };
    std::thread::scope(|threads| {
        let engine = fixture.engine.clone();
        let driver = threads.spawn(|| {
            fixture
                .runtime
                .block_on(engine.drive_live(options, Entropy(74)))
        });
        assert!(
            eventually(|| !fixture.engine.live_pauses_for_test().is_empty()),
            "premise: the live drive was cut and entered its outage pause"
        );
        let outcome = fixture.shut_down();
        assert_eq!(outcome, crate::sync::Outcome::Committed(2));
        assert_eq!(driver.join().unwrap(), crate::LiveEnd::Latched);
    });
}

/// A refused construction enters the retry policy instead of spinning or
/// ending the loop. Case count 2.
#[test]
fn live_driver_pauses_after_a_refused_construction() {
    let capacity = HookedMount::new();
    let object = capacity.dirty();
    capacity.close(object);
    let options = crate::SyncOptions {
        workspace_bytes: 0,
        quiesce_delay: std::time::Duration::ZERO,
        max_coalesce_delay: std::time::Duration::ZERO,
        ..crate::SyncOptions::default()
    };
    std::thread::scope(|threads| {
        let engine = capacity.engine.clone();
        let driver = threads.spawn(|| {
            capacity
                .runtime
                .block_on(engine.drive_live(options, Entropy(75)))
        });
        assert!(
            eventually(|| capacity.engine.live_constructions_for_test() == 1),
            "the capacity-refused construction was not attempted"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(
            capacity.engine.live_constructions_for_test(),
            1,
            "a capacity refusal spun into another construction without its long wait"
        );
        capacity.latch_live();
        assert_eq!(driver.join().unwrap(), crate::LiveEnd::Latched);
    });

    let other = HookedMount::new();
    let object = other.dirty();
    other.close(object);
    other
        .faults
        .arm("sync.commit", "captured", 1, crate::FaultAction::Fail);
    let mut driver = RunningLoop::start(
        other.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::ZERO,
            max_coalesce_delay: std::time::Duration::ZERO,
            ..crate::SyncOptions::default()
        },
        76,
        Events::default(),
    );
    assert!(
        within_five_seconds(|| !other.engine.live_pauses_for_test().is_empty()),
        "the injected construction failure did not enter a retry pause within five seconds"
    );
    assert_eq!(
        other.engine.live_pauses_for_test()[0].0,
        std::time::Duration::from_millis(40),
        "the first non-capacity construction refusal uses the 40 ms fast ceiling"
    );
    other.latch_live();
    driver.finish(crate::LiveEnd::Latched);
}

/// The coalescer constructs and installs without an explicit drive once the
/// dirty handle is closed.
#[test]
fn live_driver_lands_within_the_coalesce_delay_and_installs() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    fixture.close(object);
    std::thread::scope(|threads| {
        let engine = fixture.engine.clone();
        let driver = threads.spawn(|| {
            fixture
                .runtime
                .block_on(engine.drive_live(crate::SyncOptions::default(), Entropy(93)))
        });
        assert!(
            eventually(|| !fixture.changes().is_empty()),
            "the coalescer did not install its landing"
        );
        fixture.latch_live();
        assert_eq!(driver.join().unwrap(), crate::LiveEnd::Latched);
    });
    assert_eq!(
        (
            fixture.engine.live_constructions_for_test(),
            fixture.pin().1,
            fixture.changes().len(),
        ),
        (1, 2, 1),
        "(live constructions, served sequence, installed views)"
    );

    let held = HookedMount::new();
    let object = held.dirty();
    std::thread::scope(|threads| {
        let engine = held.engine.clone();
        let driver = threads.spawn(|| {
            held.runtime.block_on(engine.drive_live(
                crate::SyncOptions {
                    quiesce_delay: std::time::Duration::from_secs(10),
                    max_coalesce_delay: std::time::Duration::from_millis(40),
                    ..crate::SyncOptions::default()
                },
                Entropy(103),
            ))
        });
        assert!(
            eventually(|| held.pin().1 == 2),
            "a held writer did not land at the maximum coalescing delay"
        );
        held.close(object);
        held.latch_live();
        assert_eq!(driver.join().unwrap(), crate::LiveEnd::Latched);
    });

    assert_eq!(
        (
            fixture.engine.live_constructions_for_test(),
            held.engine.live_constructions_for_test(),
        ),
        (1, 1),
        "the quiescent and held-writer cases each construct once"
    );

    let pressure = HookedMount::new();
    let object = pressure.dirty();
    pressure.set_coalescing_journal_length(50_331_648);
    let mut driver = RunningLoop::start(
        pressure.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::from_secs(10),
            max_coalesce_delay: std::time::Duration::from_secs(10),
            ..crate::SyncOptions::default()
        },
        105,
        Events::default(),
    );
    assert!(
        within_five_seconds(|| !pressure.changes().is_empty()),
        "journal pressure did not land without advancing the paused clock"
    );
    assert_eq!(
        (
            driver.elapsed(),
            pressure.engine.live_constructions_for_test(),
            pressure.pin().1,
            pressure.changes().len(),
        ),
        (std::time::Duration::ZERO, 1, 2, 1),
        "(paused time, constructions, served sequence, installed views) under journal pressure"
    );
    pressure.close(object);
    pressure.wait_for_live_clean("the pressure landing did not finish before shutdown");
    pressure.latch_live();
    driver.finish(crate::LiveEnd::Latched);
    assert_eq!(
        (
            fixture.engine.live_constructions_for_test(),
            held.engine.live_constructions_for_test(),
            pressure.engine.live_constructions_for_test(),
        ),
        (1, 1, 1),
        "the quiescent, held-writer and pressure cases each construct once"
    );
}

/// Fences, poison and a closed view end the loop instead of entering a retry
/// cadence. Case count 4.
#[test]
fn live_driver_stops_on_a_fence_on_poison_and_on_a_closed_view() {
    use granary_fuse::{MountBackend as _, OverlayMutation as M};

    let fenced = HookedMount::new();
    let object = fenced.dirty();
    fenced.close(object);
    foreign_head(&fenced.tree, &fenced.runtime);
    let mut driver = RunningLoop::start(
        fenced.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::ZERO,
            max_coalesce_delay: std::time::Duration::ZERO,
            ..crate::SyncOptions::default()
        },
        94,
        Events::default(),
    );
    let end = driver.wait_end("the conflicted live loop did not stop within five seconds");

    let closed = HookedMount::new();
    let object = closed.dirty();
    closed.close(object);
    closed.plant_equivocation(2);
    let mut driver = RunningLoop::start(
        closed.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::ZERO,
            max_coalesce_delay: std::time::Duration::ZERO,
            ..crate::SyncOptions::default()
        },
        95,
        Events::default(),
    );
    driver.advance_or_ended(std::time::Duration::from_secs(10));
    let closed_end = driver.wait_end("the closed-view live loop did not stop within five seconds");

    let exhausted = HookedMount::new();
    exhausted.state.lock().unwrap().publish_refusals = 8;
    let object = exhausted.dirty();
    exhausted.close(object);
    let mut driver = RunningLoop::start(
        exhausted.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::ZERO,
            max_coalesce_delay: std::time::Duration::ZERO,
            ..crate::SyncOptions::default()
        },
        101,
        Events::default(),
    );
    driver.advance_or_ended(std::time::Duration::from_hours(1));
    let exhausted_end = driver.wait_end("the exhausted live loop did not stop within five seconds");

    let poisoned = HookedMount::new();
    let object = poisoned.dirty();
    poisoned.faults.arm(
        "overlay.stage.truncate",
        "before",
        1,
        crate::FaultAction::Fail,
    );
    let shrink = poisoned.mount().overlay_mutate(M::BoundSetattr {
        object,
        size: Some(4),
        exec: None,
    });
    assert!(
        shrink.is_err(),
        "premise: the truncate route poisons the overlay"
    );
    let mut driver = RunningLoop::start(
        poisoned.engine.clone(),
        crate::SyncOptions {
            quiesce_delay: std::time::Duration::ZERO,
            max_coalesce_delay: std::time::Duration::ZERO,
            ..crate::SyncOptions::default()
        },
        102,
        Events::default(),
    );
    let poisoned_end = driver.wait_end("the poisoned live loop did not stop within five seconds");
    assert_eq!(
        (
            end,
            exhausted_end,
            poisoned_end,
            closed_end,
            closed.view_pending()
        ),
        (
            crate::LiveEnd::Fenced,
            crate::LiveEnd::Fenced,
            crate::LiveEnd::Fenced,
            crate::LiveEnd::Closed,
            true,
        ),
        "(conflict, exhaustion, poison, equivocation endings; closed view)"
    );
}

/// A terminal live loop reports one event and one local line for a fence,
/// poison or closed view, unless shutdown closed mutations before reporting.
/// Exact counts catch reporting on every pass; exact causes catch mapping both
/// endings alike; the three latch cases catch reporting shutdown races. Case count 6.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "six terminal-state rows share one isolated local-report recipient"
)]
fn live_driver_reports_each_non_shutdown_end_once() {
    use granary_fuse::{MountBackend as _, OverlayMutation as M};

    let full_identity = concat!(
        module_path!(),
        "::",
        stringify!(live_driver_reports_each_non_shutdown_end_once)
    );
    let identity = full_identity
        .strip_prefix(concat!(env!("CARGO_CRATE_NAME"), "::"))
        .unwrap_or(full_identity);
    if std::env::var("GRANARY_LIVE_REPORT_TEST_CHILD")
        .ok()
        .as_deref()
        != Some(identity)
    {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", identity, "--nocapture"])
            .env("GRANARY_LIVE_REPORT_TEST_CHILD", identity)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "isolated live report control failed:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(
            stdout.matches("test result: ok. 1 passed;").count(),
            1,
            "the isolated child must run exactly one passing test:\n{stdout}"
        );
        return;
    }

    let reports = crate::local_report::local_capture();
    let options = crate::SyncOptions {
        quiesce_delay: std::time::Duration::ZERO,
        max_coalesce_delay: std::time::Duration::ZERO,
        ..crate::SyncOptions::default()
    };
    let report = |engine: &Arc<CommitEngine>, events: &Events, end| {
        tracing::subscriber::with_default(events.subscriber(), || {
            engine.report_live_end(end);
        });
    };
    let stopped_since = |baseline| {
        reports
            .since(baseline)
            .into_iter()
            .filter(|line| line.contains("COMMIT STOPPED"))
            .collect::<Vec<_>>()
    };

    let fenced = HookedMount::new();
    let object = fenced.dirty();
    fenced.close(object);
    foreign_head(&fenced.tree, &fenced.runtime);
    let events = Events::default();
    let mut driver = RunningLoop::start(fenced.engine.clone(), options, 103, events.clone());
    let end = driver.wait_end("the fenced live loop did not stop within five seconds");
    let baseline = reports.len();
    report(&fenced.engine, &events, end);
    let stopped = events.commit_stopped();
    let local = stopped_since(baseline);
    assert_eq!(
        (
            end,
            stopped.len(),
            stopped.first().is_some_and(|line| {
                line.contains("\"level\":\"ERROR\"")
                    && line.contains("\"cause\":\"fenced\"")
            }),
            local,
        ),
        (
            crate::LiveEnd::Fenced,
            1,
            true,
            vec!["gran mount: error: COMMIT STOPPED (fenced): new writes are refused; pending changes are kept in the store, but nothing more is committed while this mount runs; volume=v\n".to_owned()],
        ),
        "a fenced loop reports once with the fenced cause, rather than on every pass or with the closed cause"
    );

    let closed = HookedMount::new();
    let object = closed.dirty();
    closed.close(object);
    closed.plant_equivocation(2);
    let events = Events::default();
    let mut driver = RunningLoop::start(closed.engine.clone(), options, 104, events.clone());
    driver.advance_or_ended(std::time::Duration::from_secs(10));
    let end = driver.wait_end("the closed-view live loop did not stop within five seconds");
    let baseline = reports.len();
    report(&closed.engine, &events, end);
    let stopped = events.commit_stopped();
    let local = stopped_since(baseline);
    assert_eq!(
        (
            end,
            stopped.len(),
            stopped.first().is_some_and(|line| {
                line.contains("\"level\":\"ERROR\"")
                    && line.contains("\"cause\":\"closed\"")
            }),
            local,
        ),
        (
            crate::LiveEnd::Closed,
            1,
            true,
            vec!["gran mount: error: COMMIT STOPPED (closed): the served view is closed or its session has ended; pending changes are kept in the store, but nothing more is committed while this mount runs; volume=v\n".to_owned()],
        ),
        "a closed-view loop reports once with the closed cause, rather than the fenced cause"
    );

    let latched = HookedMount::new();
    let events = Events::default();
    let mut driver = RunningLoop::start(latched.engine.clone(), options, 105, events.clone());
    latched.latch_live();
    let end = driver.wait_end("the latched live loop did not stop within five seconds");
    let baseline = reports.len();
    report(&latched.engine, &events, end);
    assert_eq!(
        (
            end,
            events.commit_stopped().len(),
            stopped_since(baseline).len(),
        ),
        (crate::LiveEnd::Latched, 0, 0),
        "a shutdown latch reports neither commit.stopped nor a local line"
    );

    let latched_adapter = HookedMount::new();
    latched_adapter.latch();
    let events = Events::default();
    let baseline = reports.len();
    report(&latched_adapter.engine, &events, crate::LiveEnd::Closed);
    assert_eq!(
        (events.commit_stopped().len(), stopped_since(baseline).len()),
        (0, 0),
        "an adapter-lost end observed after shutdown latched reports nothing"
    );

    let latched_fence = HookedMount::new();
    latched_fence.latch();
    let events = Events::default();
    let baseline = reports.len();
    report(&latched_fence.engine, &events, crate::LiveEnd::Fenced);
    assert_eq!(
        (events.commit_stopped().len(), stopped_since(baseline).len()),
        (0, 0),
        "a fence end observed after shutdown latched reports nothing"
    );

    let poisoned = HookedMount::new();
    let object = poisoned.dirty();
    poisoned.faults.arm(
        "overlay.stage.truncate",
        "before",
        1,
        crate::FaultAction::Fail,
    );
    let shrink = poisoned.mount().overlay_mutate(M::BoundSetattr {
        object,
        size: Some(4),
        exec: None,
    });
    assert!(
        shrink.is_err(),
        "premise: the truncate route poisons the overlay"
    );
    let events = Events::default();
    let mut driver = RunningLoop::start(poisoned.engine.clone(), options, 106, events.clone());
    let end = driver.wait_end("the poisoned live loop did not stop within five seconds");
    let baseline = reports.len();
    report(&poisoned.engine, &events, end);
    let stopped = events.commit_stopped();
    let local = stopped_since(baseline);
    assert_eq!(
        (
            end,
            stopped.len(),
            stopped.first().is_some_and(|line| {
                line.contains("\"level\":\"ERROR\"")
                    && line.contains("\"cause\":\"fenced\"")
            }),
            local,
        ),
        (
            crate::LiveEnd::Fenced,
            1,
            true,
            vec!["gran mount: error: COMMIT STOPPED (fenced): new writes are refused; pending changes are kept in the store, but nothing more is committed while this mount runs; volume=v\n".to_owned()],
        ),
        "a poisoned loop reports once with the fenced cause"
    );
}

/// The production start enables the live binding, while the explicit harness
/// attachment leaves both the mount and binding non-live.
#[test]
fn start_sync_enables_the_live_driver() {
    let paths = Paths::new();
    let tree = mounted_operation_tree();
    let (ready, state, _) = attempt(&input(&tree, &paths), &tree, "valid", &Events::default());
    let mut attachment = ready.unwrap().attach();
    assert!(!attachment.backend.live_driver_for_test());
    let runtime = attachment
        .start_sync(Arc::new(Time(state.clone())))
        .unwrap();
    let production_enabled = attachment.backend.live_driver_for_test();
    let production_binding = attachment
        .backend
        .take_view_binding()
        .unwrap()
        .live_for_test();
    drop(runtime);

    let paths = Paths::new();
    let tree = mounted_operation_tree();
    let (ready, state, _) = attempt(&input(&tree, &paths), &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let remote = Arc::new(Authority::new(&tree, &state).with_publication());
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(remote.clone())
            .unwrap(),
    );
    let test_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    test_runtime
        .block_on(ready.backend_for_test().attach_sync_with_runtime(
            remote,
            content,
            Arc::new(Time(state)),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(96)),
            Arc::new(FastWaitRuntime),
            Entropy(97),
        ))
        .unwrap();
    let harness_enabled = ready.backend_for_test().live_driver_for_test();
    let harness_binding = ready
        .backend_for_test()
        .take_view_binding()
        .unwrap()
        .live_for_test();
    ready
        .backend_for_test()
        .set_live_driver_for_test(crate::SyncOptions::default());
    let setter_enabled = ready.backend_for_test().live_driver_for_test();
    assert_eq!(
        (
            production_enabled,
            production_binding,
            harness_enabled,
            harness_binding,
            setter_enabled,
        ),
        (true, (true, true), false, (false, false), true),
        "(production mount, production binding, harness mount, harness binding, test setter)"
    );
}

/// A failed production start leaves the backend's live-driver state off.
#[test]
fn failed_start_sync_does_not_enable_the_live_driver() {
    let paths = Paths::new();
    let tree = mounted_operation_tree();
    let (ready, state, _) = attempt(&input(&tree, &paths), &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let remote = Arc::new(Authority::new(&tree, &state).with_publication());
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(remote.clone())
            .unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(ready.backend_for_test().attach_sync_with_runtime(
            remote,
            content,
            Arc::new(Time(state.clone())),
            Arc::new(crate::InstantClock::default()),
            crate::ClientMetrics::new(&mut Entropy(116)),
            Arc::new(FastWaitRuntime),
            Entropy(117),
        ))
        .unwrap();
    let mut attachment = ready.attach();
    let failed = attachment.start_sync(Arc::new(Time(state))).is_err();
    assert_eq!(
        (failed, attachment.backend.live_driver_for_test()),
        (true, false),
        "(second engine attachment refused, live driver enabled)"
    );
}

/// A live construction closes no lane after shutdown latches while it is
/// between the engine state lock and the mediator closure. The unlatched
/// construction remains the shutdown path's control.
#[test]
fn live_driver_stops_constructing_at_the_shutdown_latch() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    let latch = Arc::new(Latch::default());
    latch.arm();
    let held = latch.clone();
    fixture
        .engine
        .before_close_for_construction_for_test(move || held.hold());
    let events = Events::default();
    let result = std::thread::scope(|threads| {
        let observed = events.clone();
        let constructing_fixture = &fixture;
        let constructing = threads.spawn(move || {
            tracing::subscriber::with_default(observed.subscriber(), || {
                constructing_fixture.construct_latched(70)
            })
        });
        assert!(
            latch.entered(),
            "premise: construction reached the fused closure"
        );
        fixture.latch();
        latch.release();
        constructing.join().unwrap()
    });
    assert_eq!(
        (
            result.as_ref().err().map(ToString::to_string),
            fixture.engine.commit_lane_for_test(),
            fixture.retained(),
            String::from_utf8(events.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .filter(|line| {
                    line.contains("\"event\":\"op.failed\"") && line.contains("\"kind\":\"commit\"")
                })
                .count(),
        ),
        (
            Some("overlay closed to mutations (EROFS)".to_owned()),
            (false, false),
            false,
            0,
        ),
        "(refusal, construction/lane state, retained submission, commit failures)"
    );
    fixture.close(object);

    let control = HookedMount::new();
    let object = control.dirty();
    let result = control.construct_latched(71);
    assert_eq!(
        (result.is_ok(), control.retained()),
        (true, true),
        "the unlatched control constructs and retains its lane"
    );
    control.close(object);
}

/// A retained lane is left for shutdown once the mutations latch is set; the
/// latch-aware takeover does not begin a drive.
#[test]
fn take_over_latched_refuses_a_retained_lane_after_the_latch() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    let _lane = fixture.construct(70).unwrap();
    let before = fixture.pin();
    assert!(
        fixture.retained(),
        "premise: construction retained the lane"
    );
    fixture.latch();
    let resumed = fixture.take_over_latched(80);
    assert_eq!(
        (resumed, fixture.retained(), fixture.pin()),
        (crate::sync::Resumed::Latched, true, before,),
        "(takeover answer, retained lane, served pin)"
    );
    fixture.close(object);
}

/// Closing admission through the latch-aware primitive distinguishes a live
/// store from one shutdown already owns, even when that store is fenced. Case count 3.
#[test]
fn close_sync_admission_unless_latched_closes_only_an_unlatched_store() {
    let open = HookedMount::new();
    let serial = open
        .mount()
        .shared_mediator()
        .with(crate::WritableStore::close_sync_admission_unless_latched)
        .unwrap();
    let closed = open
        .mount()
        .shared_mediator()
        .with(|local| local.sync_admission_open())
        .unwrap();
    open.mount()
        .shared_mediator()
        .with(|local| local.cancel_unsent_commit(serial, None, 0))
        .unwrap();

    let latched = HookedMount::new();
    latched.latch();
    let refusal = latched
        .mount()
        .shared_mediator()
        .with(crate::WritableStore::close_sync_admission_unless_latched)
        .unwrap_err()
        .to_string();
    let still_open = latched
        .mount()
        .shared_mediator()
        .with(|local| local.sync_admission_open())
        .unwrap();
    let fenced = HookedMount::new();
    fenced.latch();
    fenced
        .mount()
        .shared_mediator()
        .with(|local| Err::<(), _>(local.fence_commit_conflict()))
        .unwrap_err();
    let latch_first = fenced
        .mount()
        .shared_mediator()
        .with(crate::WritableStore::close_sync_admission_unless_latched)
        .unwrap_err()
        .to_string();
    assert_eq!(
        ((closed, serial > 0), (refusal, still_open), latch_first),
        (
            (false, true),
            ("overlay closed to mutations (EROFS)".to_owned(), true),
            "overlay closed to mutations (EROFS)".to_owned(),
        ),
        "((unlatched admission open, serial assigned), (latched refusal, admission open), fenced-and-latched refusal)"
    );
}

/// The live state read gives shutdown priority over a retained lane, and a
/// retained lane priority over the clean coalescer state. Case count 3.
#[test]
fn live_state_reads_the_lane_and_latch_together() {
    use crate::writable_store::sync_engine::LiveState;
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    let _lane = fixture.construct(70).unwrap();
    let runtime = fixture.engine.runtime_for_mount();
    let read = || {
        fixture
            .mount()
            .shared_mediator()
            .with(|local| local.live_state(&crate::SyncOptions::default(), runtime.now()))
    };
    let retained = read().unwrap();
    fixture.latch();
    let latched = read().unwrap();

    let clean = HookedMount::new();
    let clean_runtime = clean.engine.runtime_for_mount();
    let clean_state = clean
        .mount()
        .shared_mediator()
        .with(|local| local.live_state(&crate::SyncOptions::default(), clean_runtime.now()))
        .unwrap();
    assert_eq!(
        (retained, latched, clean_state),
        (LiveState::LaneHeld, LiveState::Latched, LiveState::Clean),
        "(retained lane, retained lane after latch, clean control)"
    );
    fixture.close(object);
}

/// An observed authority sequence marks the engine and wakes the floor wait.
#[test]
fn an_answer_marks_the_engine_and_wakes_floor_changed() {
    let fixture = HookedMount::new();
    let floor = fixture.engine.floor_changed_for_test();
    let mut notified = Box::pin(floor.notified());
    notified.as_mut().enable();
    <Arc<CommitEngine> as crate::sync::HeadAdopter>::answered(&fixture.engine);
    let floor_woke = fixture.runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(1), notified)
            .await
            .is_ok()
    });
    assert_eq!(
        (fixture.engine.take_answered(), floor_woke),
        (true, true),
        "(answer mark, floor wake)"
    );
}

/// Wait up to ten seconds for `done`.
fn eventually(done: impl Fn() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !done() {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    true
}

/// Wait at most two real seconds for work running on a separate paused runtime.
#[expect(
    clippy::disallowed_methods,
    reason = "a test-thread wall bound catches parked and spinning live-loop mutants"
)]
fn within_five_seconds(done: impl Fn() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !done() {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    true
}

fn backoff_count(events: &Events, cause: &str, outcome: &str) -> usize {
    String::from_utf8(events.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| {
            line.contains("\"event\":\"commit.backoff\"")
                && line.contains(&format!("\"cause\":\"{cause}\""))
                && line.contains(&format!("\"outcome\":\"{outcome}\""))
        })
        .count()
}

fn path_names(path: &[u8]) -> Vec<granary_core::manifest::Name> {
    path.split(|byte| *byte == b'/')
        .map(|name| granary_core::manifest::Name::new(name.to_vec()).unwrap())
        .collect()
}

fn names(path: &[granary_core::manifest::Name]) -> String {
    path.iter()
        .map(|name| String::from_utf8_lossy(name.as_bytes()).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn refusal(result: &Result<crate::PublicationResult, crate::CoordinationError>) -> String {
    result
        .as_ref()
        .err()
        .map_or_else(|| "landed".to_owned(), ToString::to_string)
}

/// The same-size rewrite of a file that held the base's `FILE_CONTENT`.
fn rewritten() -> Vec<u8> {
    let mut rewritten = FILE_CONTENT.to_vec();
    rewritten[..4].copy_from_slice(b"head");
    rewritten
}

/// A head that rewrites `sub/g.txt` at the same size and adds a file three
/// directories deep, published over the base while a commit is in flight.
fn rebasing_head(fixture: &HookedMount) {
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("sub/g.txt"), rewritten()).unwrap();
        std::fs::create_dir_all(source.join("a/b/c")).unwrap();
        std::fs::write(source.join("a/b/c/deep.txt"), DEEP_CONTENT).unwrap();
    });
}

/// A rebased landing pins the root the store holds at the landed seq: not
/// the candidate the commit first sent, nor the head it rebased onto. The
/// consumer of the engine's install gets the view change the overlay
/// computed, and a file the head contributed reads through the new pin's
/// binmap, which the session never opened with.
#[test]
fn repin_after_rebase_pins_the_store_bytes_not_a_candidate() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    let lane = fixture.construct(70).unwrap();
    let candidate = fixture.submission().unwrap().frozen.initial_root;
    rebasing_head(&fixture);
    let ranges = fixture.ranges();
    let result = fixture.drive(&lane, 80);
    let landing_ranges = fixture.ranges() - ranges;
    let seq = remote_seq(&fixture.tree, &fixture.runtime);
    let (head, landed_root) = (fixture.store_root(2), fixture.store_root(seq));
    // The premise: a forced rebase, three different roots.
    assert_eq!(
        (
            landed(&result),
            seq,
            candidate != head,
            landed_root != candidate,
            landed_root != head
        ),
        (true, 3, true, true, true),
        "premise: a rebased landing; got {}",
        refusal(&result)
    );
    let cached = fixture.cached_roots();
    let changes = fixture.changes();
    let paths: Vec<_> = changes
        .first()
        .map(|change| {
            change
                .paths
                .iter()
                .map(|path| (names(&path.path), path.old.is_some(), path.new.is_some()))
                .collect()
        })
        .unwrap_or_default();
    let retired = changes.first().is_some_and(|change| {
        change
            .paths
            .iter()
            .filter_map(|path| path.old)
            .all(|old| change.retired.contains_key(&old))
    });
    assert_eq!(
        (
            fixture.pin(),
            fixture.pin_bytes() == landed_root,
            cached.contains(&candidate) || cached.contains(&head),
            fixture.floor(),
            fixture.mount().observe_engine_view().is_ok(),
            changes.len(),
            paths,
            retired,
            fixture.revocations(),
        ),
        (
            (GrainId::of(&landed_root), 3),
            true,
            false,
            Some(3),
            true,
            1,
            vec![
                ("a".to_owned(), false, true),
                ("a/b".to_owned(), false, true),
                ("a/b/c".to_owned(), false, true),
                ("a/b/c/deep.txt".to_owned(), false, true),
                ("sub/g.txt".to_owned(), true, true),
            ],
            true,
            vec![],
        )
    );
    // The rebase stored the head's grains: evict the deep file's, so its
    // read has to fetch them through the pin.
    let digest = GrainId::of(DEEP_CONTENT).digest_hex();
    let stored = fixture
        .paths
        .store
        .join("objects")
        .join(&digest[..2])
        .join(&digest);
    let _ = std::fs::remove_file(&stored);
    assert!(!stored.exists(), "premise: the deep file's grain is absent");
    let ranges = fixture.ranges();
    let read = fixture.read_path(b"a/b/c/deep.txt");
    assert_eq!(
        (read, fixture.ranges() - ranges),
        (Ok(DEEP_CONTENT.to_vec()), 1)
    );
    eprintln!("bin range reads during the rebased landing: {landing_ranges}");
    fixture.close(object);
    let _ = fixture.mount().observe_engine_view();
}

/// A held clean file whose path a landing gave another identity keeps the
/// bytes it opened, read by their content id from its own material, which
/// it shares with every held object of that content; its changes refuse as
/// stale and its fsync owes nothing. A fresh open of the path reads the
/// head's bytes.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one row per case keeps each tuple beside the setup it asserts"
)]
fn held_object_on_a_replaced_path_keeps_its_opened_content() {
    use granary_fuse::{MountBackend as _, MountSyncRequest, OverlayMutation as M};
    let g = path_names(b"sub/g.txt");
    let old = String::from_utf8_lossy(FILE_CONTENT).into_owned();
    let mut cases = 0;
    for warm in [true, false] {
        let fixture = HookedMount::new();
        fixture.link(8);
        let open = |path: &[granary_core::manifest::Name]| {
            fixture.mount().overlay_open(path).unwrap().unwrap()
        };
        let read = |object| {
            let mut mount = fixture.mount();
            mount
                .prepare_object(object)
                .and_then(|()| mount.read_object(object, 0, 65_536))
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        };
        let held = open(&g);
        let (writer, other) = if warm {
            assert_eq!(read(held), Ok(old.clone()));
            (Some(open(&g)), Some(open(&path_names(b"f.txt"))))
        } else {
            (None, None)
        };
        let lane = fixture.construct(70).unwrap();
        let previous = fixture
            .mount()
            .shared_mediator()
            .with(|local| Ok(local.mount_pin().unwrap()))
            .unwrap();
        publish_head(&fixture.tree, &fixture.runtime, &rewritten(), |source| {
            std::fs::write(source.join("sub/g.txt"), rewritten()).unwrap();
        });
        let result = fixture.drive(&lane, 80);
        assert!(
            landed(&result) && fixture.changes().len() == 1,
            "premise: a rebased landing installed; got {}",
            refusal(&result)
        );
        if !warm {
            let digest = GrainId::of(FILE_CONTENT).digest_hex();
            let stored = fixture
                .paths
                .store
                .join("objects")
                .join(&digest[..2])
                .join(&digest);
            let _ = std::fs::remove_file(&stored);
            assert!(!stored.exists(), "premise: the opened grain is absent");
            let ranges = fixture.ranges();
            assert_eq!(
                (read(held), fixture.ranges() - ranges),
                (Ok(old.clone()), 1)
            );
            fixture.close(held);
            cases += 1;
            continue;
        }
        let (writer, other) = (writer.unwrap(), other.unwrap());
        let registrations = fixture.mount().sync_job_counter_for_test();
        let ranges = fixture.ranges();
        let first = read(held);
        let fetched = fixture.ranges() - ranges;
        let mutate = |mutation| fixture.mount().overlay_mutate(mutation);
        let write = mutate(M::BoundWrite {
            object: writer,
            offset: 0,
            bytes: b"stale",
            append: false,
        });
        let truncate = mutate(M::BoundSetattr {
            object: writer,
            size: Some(0),
            exec: None,
        });
        let exec = mutate(M::BoundSetattr {
            object: writer,
            size: None,
            exec: Some(true),
        });
        let shrink = fixture
            .mount()
            .prepare_shrink_retry(granary_fuse::MountShrinkRequest {
                inode: held,
                object: Some(held),
                path: g.clone(),
                size: 0,
                exec: None,
            })
            .map(|_| ());
        let (sent, completed) = std::sync::mpsc::channel();
        let job = fixture.mount().prepare_sync(MountSyncRequest::File {
            object: held,
            datasync: false,
        });
        let synced = job.map(|job| {
            job.start(Box::new(move |result| {
                let _ = sent.send(result);
            }));
            completed
                .recv_timeout(std::time::Duration::from_secs(10))
                .ok()
        });
        let fresh = open(&g);
        let fresh_read = read(fresh);
        let again = read(held);
        let stale = Err(granary_fuse::WriteError::Backend(
            granary_fuse::MountError::Stale,
        ));
        assert_eq!(
            (
                first,
                fetched,
                write,
                truncate,
                exec,
                shrink,
                synced.ok(),
                registrations.load(Ordering::Relaxed),
                fresh != held,
                fresh_read,
                again,
            ),
            (
                Ok(old.clone()),
                0,
                stale,
                stale,
                stale,
                Err(granary_fuse::MountSyncError::Backend(
                    granary_fuse::MountError::Stale
                )),
                Some(Some(Ok(()))),
                0,
                true,
                Ok(String::from_utf8_lossy(&rewritten()).into_owned()),
                Ok(old.clone()),
            )
        );
        let (mount, other_mount) = {
            let mount = fixture.mount();
            (
                mount.replaced_for_test(held),
                mount.replaced_for_test(other),
            )
        };
        let shared = mount
            .as_ref()
            .zip(other_mount.as_ref())
            .is_some_and(|(held, other)| Arc::ptr_eq(held, other));
        let bins = mount
            .as_ref()
            .is_some_and(|material| Arc::ptr_eq(&material.bins, &previous.bins));
        assert_eq!((shared, bins), (true, true));
        for object in [fresh, other, writer, held] {
            fixture.close(object);
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// An fsync on a held clean file, queued behind a commit, is still waiting
/// when the commit lands with a head that gives the file another identity.
/// The landing replaces the object, so the fsync owes nothing and succeeds,
/// as one started after the landing does; it does not refuse the inode the
/// landing retired. The same holds when the descriptor closed before the
/// landing: the fsync's own hold outlives the open object.
#[test]
fn a_queued_fsync_on_an_object_a_landing_replaces_succeeds() {
    use granary_fuse::{MountBackend as _, MountSyncRequest};
    let sync = |fixture: &HookedMount, held| {
        let (sent, completed) = std::sync::mpsc::channel();
        fixture
            .mount()
            .prepare_sync(MountSyncRequest::File {
                object: held,
                datasync: false,
            })
            .unwrap()
            .start(Box::new(move |result| {
                let _ = sent.send(result);
            }));
        completed
    };
    let mut cases = 0;
    for closed in [false, true] {
        let fixture = HookedMount::new();
        let object = fixture.dirty();
        let held = fixture
            .mount()
            .overlay_open(&path_names(b"sub/g.txt"))
            .unwrap()
            .unwrap();
        // A captured commit closes sync admission while the mount stays
        // ready, so an fsync started there waits for the commit; a retained
        // lane would refuse it before the engine is asked. The commit is
        // held after its capture by the authority's lock, which its upload
        // needs, and the fsync inside its commit wait until the landing has
        // installed.
        fixture
            .faults
            .arm("sync.commit_wait", "before", 1, crate::FaultAction::Block);
        let _resume = ResumeOnDrop(&fixture.faults);
        let (lane, completed) = std::thread::scope(|threads| {
            let authority = fixture.state.lock().unwrap();
            let constructing = threads.spawn(|| fixture.construct(70));
            let admission_closed = || {
                fixture
                    .mount()
                    .shared_mediator()
                    .with(|local| local.sync_admission_open())
                    .is_ok_and(|open| !open)
            };
            assert!(eventually(admission_closed), "premise: the commit captured");
            let completed = sync(&fixture, held);
            drop(authority);
            (constructing.join().unwrap().unwrap(), completed)
        });
        assert!(
            eventually(|| !fixture.faults.sync_fired().is_empty()),
            "premise: the fsync waits for the commit"
        );
        if closed {
            fixture.close(held);
        }
        publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
            std::fs::write(source.join("sub/g.txt"), rewritten()).unwrap();
        });
        let result = fixture.drive(&lane, 80);
        // A closed object is gone from the mount; an open one is replaced.
        let replaced = fixture.mount().replaced_for_test(held).is_some();
        let waiting = completed.try_recv().is_err();
        let sends = fixture.state.lock().unwrap().sends.len();
        fixture.faults.resume();
        let queued = completed
            .recv_timeout(std::time::Duration::from_secs(10))
            .ok();
        let registered = fixture.state.lock().unwrap().sends.len() - sends;
        let again = (!closed).then(|| {
            sync(&fixture, held)
                .recv_timeout(std::time::Duration::from_secs(10))
                .ok()
        });
        assert_eq!(
            (
                waiting,
                landed(&result) && fixture.changes().len() == 1,
                replaced,
                queued,
                registered,
                again
            ),
            (
                true,
                true,
                !closed,
                Some(Ok(())),
                0,
                (!closed).then_some(Some(Ok(())))
            ),
            "closed={closed}: (premise: the fsync waited behind the commit; premise: a \
             rebased landing installed; the held object was replaced; the queued fsync; \
             its registrations; a later fsync)"
        );
        if !closed {
            fixture.close(held);
        }
        fixture.close(object);
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A written file whose fsync sealed a boundary that is not yet registered
/// is never replaced while that data is not durable. No commit captures
/// past the pending boundary: the fsync holds admission until its
/// registration is recorded, and a capture either waits for every recorded
/// one or refuses as unresolved, after which a second capture follows the
/// registered fsync. Once it is
/// registered, a head that changes the same path conflicts and fences the
/// lane rather than replacing the object, and the object's own landing
/// carries its stage's content and keeps its identity. Neither answers a
/// later fsync `Ok` for data the store does not hold.
#[test]
fn a_written_object_with_a_pending_boundary_is_never_replaced() {
    use granary_fuse::{MountBackend as _, MountSyncRequest};
    let sync = |fixture: &HookedMount, object| {
        let (sent, completed) = std::sync::mpsc::channel();
        fixture
            .mount()
            .prepare_sync(MountSyncRequest::File {
                object,
                datasync: false,
            })
            .map(|job| {
                job.start(Box::new(move |result| {
                    let _ = sent.send(result);
                }));
                completed
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .ok()
            })
    };
    let mut cases = 0;
    for foreign in [true, false] {
        let fixture = HookedMount::new();
        let object = fixture.dirty();
        // The fsync is held inside its preparation, after its seal and
        // holding engine admission, until a commit has tried to capture.
        fixture
            .faults
            .arm("sync.upload", "before", 1, crate::FaultAction::Block);
        let _resume = ResumeOnDrop(&fixture.faults);
        let (pending, captured, synced, lane) = std::thread::scope(|threads| {
            let syncing = threads.spawn(|| sync(&fixture, object));
            let pending = eventually(|| !fixture.faults.sync_fired().is_empty());
            let constructing = threads.spawn(|| fixture.construct(70));
            std::thread::sleep(std::time::Duration::from_millis(300));
            let captured = constructing.is_finished();
            fixture.faults.resume();
            let synced = syncing.join().unwrap();
            (pending, captured, synced, constructing.join().unwrap())
        });
        let registered = fixture.state.lock().unwrap().sends.len();
        // A commit drains admitted fsyncs in a bounded number of backoff
        // polls, and this fixture's runtime shortens those waits. A
        // construct that took admission before the released fsync's
        // registration drained refuses as unresolved, the specified
        // transient outcome. That fsync has completed now, so a second
        // construct captures past its registered boundary. On that path the
        // run shows the ordering (no capture while the fsync is held) but not
        // the drain of a registration still in flight.
        let lane = match lane {
            Err(crate::CoordinationError::Refused("SyncCommitUnresolved")) => fixture.construct(71),
            lane => lane,
        };
        let lane = lane.unwrap();
        if foreign {
            publish_head(&fixture.tree, &fixture.runtime, FOREIGN_CONTENT, |_| ());
        }
        let result = fixture.drive(&lane, 80);
        let replaced = fixture.mount().replaced_for_test(object).is_some();
        let again = sync(&fixture, object);
        let again_ok = matches!(again, Ok(Some(Ok(()))));
        let expected = if foreign {
            // A conflict fences: every later sync refuses.
            (
                "intent fenced (ESTALE), recorded generation None".to_owned(),
                false,
                false,
            )
        } else {
            ("landed".to_owned(), false, true)
        };
        let outcome = refusal(&result);
        assert_eq!(
            (
                pending,
                captured,
                synced,
                registered > 0,
                (outcome, replaced, again_ok)
            ),
            (true, false, Ok(Some(Ok(()))), true, expected),
            "foreign={foreign}: (premise: the fsync was held after its seal; a commit captured \
             past it; the fsync; it registered; (the landing, the object replaced, a later \
             fsync answered Ok)); later fsync {again:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A held clean file larger than one content read, inline or spilled,
/// reads whole in one call once a landing replaced its path: the read is
/// chunked, and a spilled file's material carries its grain-list node.
#[test]
fn held_large_object_on_a_replaced_path_reads_whole_in_one_call() {
    use granary_fuse::MountBackend as _;
    let mut cases = 0;
    for spill in [false, true] {
        let paths = Paths::new();
        let clean = super::super::queries::clean::clean_tree(&paths, spill);
        let fixture = HookedMount::with_tree(paths, clean.tree);
        fixture.link(8);
        let held = fixture
            .mount()
            .overlay_open(&path_names(b"f.txt"))
            .unwrap()
            .unwrap();
        let lane = fixture.construct(70).unwrap();
        publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |_| ());
        let result = fixture.drive(&lane, 80);
        let retired = fixture
            .changes()
            .first()
            .is_some_and(|change| change.retired.contains_key(&held));
        assert!(
            landed(&result) && retired,
            "premise: a landing retired the held file; got {}",
            refusal(&result)
        );
        let read = {
            let mut mount = fixture.mount();
            mount
                .prepare_object(held)
                .and_then(|()| mount.read_object(held, 0, 262_144))
        };
        let nodes = fixture
            .mount()
            .replaced_for_test(held)
            .map(|material| material.pin_nodes.len());
        assert_eq!(
            (
                clean.bytes.len() > 65_536,
                read.as_ref().map(Vec::len),
                read.as_ref().is_ok_and(|bytes| *bytes == clean.bytes),
                nodes,
            ),
            (true, Ok(clean.bytes.len()), true, Some(usize::from(spill)),),
            "spill={spill}"
        );
        fixture.close(held);
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A private floor that cannot be persisted refuses the install as
/// transient: nothing moves, nothing is revoked, and the open view keeps
/// serving reads and local writes. Once the floor can be written again, the
/// resumed landing installs.
#[test]
fn repin_refuses_when_the_private_floor_cannot_be_persisted() {
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    let lane = fixture.construct(70).unwrap();
    let (pin, base) = (fixture.pin(), fixture.base().unwrap());
    let anchor = fixture.anchor();
    std::fs::remove_file(&anchor).unwrap();
    std::fs::create_dir(&anchor).unwrap();
    let result = fixture.drive(&lane, 80);
    let write = fixture.mount().overlay_mutate(M::BoundWrite {
        object,
        offset: 0,
        bytes: b"still",
        append: false,
    });
    assert_eq!(
        (
            refusal(&result),
            fixture.pin(),
            fixture.base().ok(),
            fixture.retained(),
            fixture.view_pending(),
            fixture.revocations(),
            fixture.read_path(b"sub/g.txt"),
            write,
        ),
        (
            "intent refused: ViewRootNotAccepted".to_owned(),
            pin,
            Some(base),
            true,
            false,
            vec![],
            Ok(FILE_CONTENT.to_vec()),
            Ok(()),
        )
    );
    std::fs::remove_dir(&anchor).unwrap();
    let resumed = fixture.drive(&lane, 81);
    assert_eq!(
        (
            refusal(&resumed),
            fixture.pin().1,
            fixture.floor(),
            fixture.changes().len(),
            fixture.view_pending(),
        ),
        ("landed".to_owned(), 2, Some(2), 1, false)
    );
    fixture.close(object);
}

/// An equivocating cached root closes the view and revokes it once
/// admission is released. A later landing on the closed view refuses before
/// it moves the pin, the base or the private floor, and revokes again.
#[test]
fn install_never_reopens_a_closed_view() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    let lane = fixture.construct(70).unwrap();
    let (pin, base, floor) = (fixture.pin(), fixture.base().unwrap(), fixture.floor());
    let planted = fixture.plant_equivocation(2);
    let result = fixture.drive(&lane, 80);
    assert_eq!(
        (
            refusal(&result),
            fixture.view_pending(),
            fixture.pin(),
            fixture.base().ok(),
            fixture.revocations(),
        ),
        (
            "intent refused: ViewRootEquivocation".to_owned(),
            true,
            pin,
            Some(base),
            vec![true],
        ),
        "phase 1: an equivocating root closes the view"
    );
    std::fs::remove_file(planted).unwrap();
    let resumed = fixture.drive(&lane, 81);
    assert_eq!(
        (
            refusal(&resumed),
            fixture.view_pending(),
            fixture.pin(),
            fixture.base().ok(),
            fixture.floor(),
            fixture.revocations(),
        ),
        (
            "intent refused: ViewPending".to_owned(),
            true,
            pin,
            Some(base),
            floor,
            vec![true, true],
        ),
        "phase 2: a closed view is never reopened"
    );
    fixture.close(object);
}

/// A landing whose view holds a symlink target the mount cannot return
/// closes the view before anything moves; one at the limit installs.
#[test]
fn install_closes_a_view_the_mount_cannot_serve() {
    let mut cases = 0;
    for (len, servable) in [(4096, false), (4095, true)] {
        let fixture = HookedMount::new();
        fixture.link(len);
        let lane = fixture.construct(70).unwrap();
        let (pin, base, cached) = (
            fixture.pin(),
            fixture.base().unwrap(),
            fixture.cached_roots(),
        );
        let result = fixture.drive(&lane, 80);
        let expected = if servable {
            ("landed".to_owned(), false, 2, false, false, vec![], 1)
        } else {
            (
                "intent refused: ViewUnservable".to_owned(),
                true,
                pin.1,
                true,
                true,
                vec![true],
                0,
            )
        };
        assert_eq!(
            (
                refusal(&result),
                fixture.view_pending(),
                fixture.pin().1,
                fixture.base().ok() == Some(base) && fixture.cached_roots() == cached,
                fixture.retained(),
                fixture.revocations(),
                fixture.changes().len(),
            ),
            expected,
            "target of {len} bytes"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A replacement that refuses on the suffix fences the store, and the
/// install closes the view over it: the fence refuses every daemon call.
#[test]
fn install_conflict_fences_and_closes_the_view() {
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    let lane = fixture.construct(70).unwrap();
    let pin = fixture.pin();
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("sub/g.txt"), FOREIGN_CONTENT).unwrap();
    });
    let mut local = None;
    // The landing is complete at the authority while the hook holds, so the
    // mount serves local writes again; this one lands after the boundary.
    let result = fixture.drive_holding(
        &lane,
        80,
        |hooked| &hooked.before_rebuild,
        || {
            let mut mount = fixture.mount();
            let object = mount
                .overlay_open(&path_names(b"sub/g.txt"))
                .unwrap()
                .unwrap();
            mount.prepare_object(object).unwrap();
            mount
                .overlay_mutate(M::BoundWrite {
                    object,
                    offset: 0,
                    bytes: b"local",
                    append: false,
                })
                .unwrap();
            local = Some(object);
        },
    );
    let admission = fixture
        .mount()
        .shared_mediator()
        .with(|local| local.sync_admission_open());
    assert_eq!(
        (
            matches!(result, Err(crate::CoordinationError::Fenced { .. })),
            matches!(admission, Err(crate::CoordinationError::Fenced { .. })),
            fixture.view_pending(),
            fixture.overlay_base(),
            fixture.revocations(),
        ),
        (true, true, true, Some(pin), vec![true]),
        "result={}, admission={admission:?}",
        refusal(&result)
    );
    fixture.close(local.unwrap());
    fixture.close(object);
}

/// The install belongs to the sync runtime, not to the caller that drives
/// the landing: a caller dropped while the install holds its section loses
/// only its wait. The install still closes and revokes, and keeps the commit
/// driver, so no second driver starts a refresh under it.
#[test]
fn install_survives_a_cancelled_caller() {
    let mut cases = 0;
    for equivocation in [true, false] {
        let fixture = HookedMount::new();
        let object = fixture.dirty();
        let lane = fixture.construct(70).unwrap();
        if equivocation {
            fixture.plant_equivocation(2);
        }
        let latch = &fixture.hooked.before_install;
        latch.arm();
        std::thread::scope(|threads| {
            let _release = ReleaseOnDrop(latch);
            assert!(
                !fixture.drive_then_cancel(&lane, 80),
                "premise: the caller is dropped while the install holds"
            );
            if equivocation {
                latch.release();
                let ended = eventually(|| !fixture.revocations().is_empty());
                assert_eq!(
                    (
                        ended,
                        fixture.revocations(),
                        fixture.view_pending(),
                        eventually(|| fixture.engine.admission_free_for_test()),
                    ),
                    (true, vec![true], true, true),
                    "case 1: the closing install runs to its revocation"
                );
            } else {
                fixture.faults.arm(
                    "sync.commit",
                    "landed_refresh",
                    1,
                    crate::FaultAction::Block,
                );
                let second = threads.spawn(|| fixture.drive(&lane, 81));
                let settled = eventually(|| second.is_finished() || !fixture.fired().is_empty());
                let refreshing = fixture
                    .fired()
                    .contains(&("sync.commit", "landed_refresh", 1));
                latch.release();
                let ended =
                    eventually(|| fixture.changes().len() + fixture.revocations().len() == 1);
                fixture.faults.resume();
                let second = second.join().unwrap();
                assert_eq!(
                    (
                        settled && ended,
                        refusal(&second),
                        refreshing,
                        fixture.changes().len(),
                        fixture.revocations(),
                        fixture.view_pending(),
                    ),
                    (
                        true,
                        "intent refused: SyncCommitInFlight".to_owned(),
                        false,
                        1,
                        vec![],
                        false
                    ),
                    "case 2: the install keeps the driver until it ends"
                );
            }
        });
        fixture.close(object);
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A caller waits for its install no longer than its deadline: it returns
/// then, while the held install keeps the driver, and the install, once
/// released, still switches the view and frees admission.
#[test]
fn install_wait_ends_at_the_caller_deadline() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    let lane = fixture.construct(70).unwrap();
    let latch = &fixture.hooked.before_install;
    latch.arm();
    std::thread::scope(|threads| {
        let _release = ReleaseOnDrop(latch);
        let caller = threads.spawn(|| {
            fixture
                .runtime
                .block_on(Box::pin(fixture.engine.drive_commit(
                    &lane,
                    &mut Entropy(80),
                    &mut NoDelay,
                    RecoveryIntent::Continue,
                    crate::SyncOptions {
                        resolution_bound: std::time::Duration::from_secs(8),
                        ..crate::SyncOptions::default()
                    },
                )))
        });
        if !latch.entered() {
            latch.release();
            panic!(
                "premise: the hook reached its latch: {}",
                refusal(&caller.join().unwrap())
            );
        }
        let returned = eventually(|| caller.is_finished());
        let second = fixture.drive(&lane, 81);
        latch.release();
        let installed = eventually(|| fixture.changes().len() == 1);
        let first = caller.join().unwrap();
        assert_eq!(
            (
                returned,
                refusal(&first),
                refusal(&second),
                installed,
                eventually(|| fixture.engine.admission_free_for_test()),
            ),
            (
                true,
                "intent refused: SyncDeadline".to_owned(),
                "intent refused: SyncCommitInFlight".to_owned(),
                true,
                true
            ),
            "the caller stops at its deadline; the install keeps the driver and finishes"
        );
    });
    fixture.close(object);
}

/// A rebuild that fails on a store that refuses its own base is terminal:
/// the install closes and revokes. One that fails on a store still serving
/// its base is transient: nothing moves and nothing is revoked.
#[test]
fn install_classifies_a_rebuild_failure_by_the_mediator() {
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    let mut cases = 0;
    for poisoned in [true, false] {
        let fixture = HookedMount::new();
        let object = fixture.dirty();
        let lane = fixture.construct(70).unwrap();
        let (pin, base) = (fixture.pin(), fixture.overlay_base());
        let result = fixture.drive_holding(
            &lane,
            80,
            |hooked| &hooked.before_rebuild,
            || {
                if poisoned {
                    fixture.faults.arm(
                        "overlay.stage.truncate",
                        "before",
                        1,
                        crate::FaultAction::Fail,
                    );
                    let shrink = fixture.mount().overlay_mutate(M::BoundSetattr {
                        object,
                        size: Some(4),
                        exec: None,
                    });
                    assert!(shrink.is_err(), "premise: the shrink poisons the overlay");
                } else {
                    fixture.state.lock().unwrap().fail_next_read = true;
                }
            },
        );
        let verdicts = fixture.hooked.verdicts.lock().unwrap().clone();
        // The premise: the rebuild failed. A poisoned store's refusal is the
        // verdict only through the rebuild's failure arm; a transient
        // failure returns before any verdict is recorded.
        eprintln!("poisoned={poisoned}: verdicts {verdicts:?}");
        let expected = if poisoned {
            (
                "intent refused: IntentPersistencePoisoned".to_owned(),
                vec![Some("intent refused: IntentPersistencePoisoned".to_owned())],
                true,
                true,
                vec![true],
            )
        } else {
            (refusal(&result), vec![], false, true, vec![])
        };
        assert_eq!(
            (
                refusal(&result),
                verdicts,
                fixture.view_pending(),
                (fixture.pin(), fixture.overlay_base()) == (pin, base)
                    && (poisoned || fixture.retained()),
                fixture.revocations(),
            ),
            expected,
            "poisoned={poisoned}"
        );
        if !poisoned {
            assert!(
                matches!(
                    result,
                    Err(crate::CoordinationError::Recovery(
                        crate::RecoveryError::Preparation(crate::PublishError::Remote(
                            RootStoreError::Unavailable { status: 503, .. }
                        ))
                    ))
                ),
                "the transient landing refuses with the read's own cause: {}",
                refusal(&result)
            );
            fixture.close(object);
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A failure before the switch, or a commit that failed with the store
/// still on the pin's base, leaves the view open; one after the switch, or
/// a commit that left the store poisoned or on another base, closes it.
#[test]
fn install_fault_points_split_transient_from_terminal() {
    let mut cases = 0;
    for (name, phase) in [
        ("fuse.view.install", "before_switch"),
        ("sync.commit", "before_replace"),
        ("fuse.view.install", "after_switch"),
        ("overlay.replace.switched", "after"),
        ("commit", "wrapped"),
    ] {
        let fixture = HookedMount::new();
        let object = fixture.dirty();
        let lane = fixture.construct(70).unwrap();
        let (pin, base) = (fixture.pin(), fixture.base().unwrap());
        if name == "commit" {
            fixture
                .hooked
                .fail_after_commit
                .store(true, Ordering::SeqCst);
        } else {
            fixture.faults.arm(name, phase, 1, crate::FaultAction::Fail);
        }
        let result = fixture.drive(&lane, 80);
        // Step 7's own read of the base, after the landing.
        let after = fixture.base();
        let observed = (
            refusal(&result),
            fixture.pin() == pin,
            after.as_ref().ok() == Some(&base),
            fixture.view_pending(),
            after.is_ok() && fixture.retained(),
            fixture.revocations(),
        );
        let open = |refused: &str| (refused.to_owned(), true, true, false, true, vec![]);
        match (name, phase) {
            ("fuse.view.install", "before_switch") | ("sync.commit", "before_replace") => {
                assert_eq!(
                    observed,
                    open("intent refused: SyncInjectedFault"),
                    "{name}/{phase}"
                );
            }
            ("fuse.view.install", "after_switch") => assert_eq!(
                (observed.0, observed.3, observed.5),
                ("landed".to_owned(), true, vec![true]),
                "{name}/{phase}"
            ),
            ("overlay.replace.switched", _) => assert_eq!(
                (
                    result.is_err(),
                    after.err().map(|error| error.to_string()),
                    observed.3,
                    observed.5
                ),
                (
                    true,
                    Some("intent refused: IntentPersistencePoisoned".to_owned()),
                    true,
                    vec![true]
                ),
                "{name}/{phase}: premise, the install's post-commit base read refuses; got {}",
                observed.0
            ),
            _ => assert_eq!(
                (
                    observed.0.as_str(),
                    after.as_ref().is_ok_and(|after| *after != pin),
                    observed.3,
                    observed.5
                ),
                ("intent refused: SyncBasePoisoned", true, true, vec![true]),
                "{name}/{phase}: premise, the install's post-commit base read succeeds on another base: {after:?}"
            ),
        }
        if !observed.3 {
            fixture.close(object);
        }
        cases += 1;
    }
    assert_eq!(cases, 5);
}

/// A mediator that refuses before the switch refuses every later read and
/// write as well, so the install closes the view and revokes it rather than
/// leaving it open over a store it can no longer read.
#[test]
fn install_closes_on_a_mediator_that_refuses_before_the_switch() {
    let fixture = HookedMount::new();
    let _object = fixture.dirty();
    let lane = fixture.construct(70).unwrap();
    let result = fixture.drive_holding(
        &lane,
        80,
        |hooked| &hooked.before_install,
        || {
            let mediator = fixture.mount().shared_mediator().clone();
            let poisoned = std::thread::spawn(move || {
                mediator.with(|_| -> Result<(), crate::CoordinationError> {
                    panic!("a holder of the mediator panics")
                })
            })
            .join();
            assert!(poisoned.is_err(), "premise: the mediator lock is poisoned");
        },
    );
    assert_eq!(
        (
            refusal(&result),
            fixture.view_pending(),
            fixture.revocations(),
            fixture.changes().len(),
        ),
        (
            "intent refused: SyncMediatorPoisoned".to_owned(),
            true,
            vec![true],
            0
        )
    );
}

/// A store that refuses its switched view after the commit completed
/// closes the view: the landing stands, the view is revoked, and the close
/// reports one `op.failed` of kind `view`.
#[test]
fn install_closes_when_the_switched_view_cannot_be_read() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    let lane = fixture.construct(70).unwrap();
    let mediator = fixture.mount().shared_mediator().clone();
    let crate::overlay_store::OverlayQuery::Found(found) = mediator
        .overlay_transaction(|overlay| overlay.query_path(&handler_path(b"f.txt")))
        .unwrap()
    else {
        panic!("premise: f.txt is in the view")
    };
    let stage = found.entry.and_then(|entry| entry.stage_id).unwrap();
    let faults = fixture.faults.clone();
    *fixture.hooked.after_commit.lock().unwrap() = Some(Box::new(move || {
        faults.arm(
            "overlay.stage.truncate",
            "before",
            1,
            crate::FaultAction::Fail,
        );
        let shrink = mediator.overlay_transaction(|overlay| overlay.truncate(stage, 4));
        assert!(shrink.is_err(), "premise: the shrink poisons the store");
    }));
    let events = Events::default();
    let result =
        tracing::subscriber::with_default(events.subscriber(), || fixture.drive(&lane, 80));
    let view_failures = String::from_utf8(events.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| {
            line.contains("\"event\":\"op.failed\"") && line.contains("\"kind\":\"view\"")
        })
        .count();
    assert_eq!(
        (
            refusal(&result),
            fixture.view_pending(),
            fixture.revocations(),
            view_failures,
        ),
        ("landed".to_owned(), true, vec![true], 1)
    );
    let _ = object;
}
