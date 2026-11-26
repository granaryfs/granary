// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! An explicit commit trigger over the writable fixture: the authority the
//! engine's commit lane publishes through, a foreign head to conflict with, and
//! the engine-level routes the mounted commit rows also take through a real mount.

mod carry_forward;
pub(super) mod finish;
mod refresh;
mod shutdown;
mod view_install;
use super::*;
use crate::{PublicationOutcome, RecoveryDelay, RecoveryIntent};
use granary_core::{
    grainsource::GrainSourceError,
    manifest::{self, DirEntry, EntryKind, FileGrains},
};
use std::{collections::BTreeSet, future::Future, pin::Pin};

const FOREIGN_CONTENT: &[u8] = b"foreign head file content\n";

pub(super) struct NoDelay;
impl RecoveryDelay for NoDelay {
    fn jitter(&mut self, _: std::time::Duration) -> std::time::Duration {
        std::time::Duration::ZERO
    }
    fn wait(&mut self, _: std::time::Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

pub(super) type CommitEngine<E = FastWaitRuntime> = crate::SyncEngine<
    OverlayDisk,
    Authority,
    crate::MountSyncContent<Authority>,
    Time,
    crate::InstantClock,
    E,
>;

pub(super) fn construct_commit<E: crate::SyncRuntime + 'static>(
    engine: &Arc<CommitEngine<E>>,
    runtime: &tokio::runtime::Runtime,
    entropy: u8,
) -> Result<crate::RetainedCommit, crate::CoordinationError> {
    construct_commit_with(engine, runtime, crate::SyncOptions::default(), entropy)
}

pub(super) fn construct_commit_with<E: crate::SyncRuntime + 'static>(
    engine: &Arc<CommitEngine<E>>,
    runtime: &tokio::runtime::Runtime,
    options: crate::SyncOptions,
    entropy: u8,
) -> Result<crate::RetainedCommit, crate::CoordinationError> {
    runtime.block_on(engine.construct_commit(options, &mut Entropy(entropy)))
}

pub(super) fn drive_commit<E: crate::SyncRuntime + 'static>(
    engine: &Arc<CommitEngine<E>>,
    runtime: &tokio::runtime::Runtime,
    lane: &crate::RetainedCommit,
    entropy: u8,
) -> Result<crate::PublicationResult, crate::CoordinationError> {
    drive_commit_as(engine, runtime, lane, entropy, RecoveryIntent::Continue)
}

/// Drive a lane left in a rebase by an earlier attempt: only an explicit
/// recovery authorizes the fresh read cycle that merges onto the new head.
pub(super) fn resume_commit<E: crate::SyncRuntime + 'static>(
    engine: &Arc<CommitEngine<E>>,
    runtime: &tokio::runtime::Runtime,
    lane: &crate::RetainedCommit,
    entropy: u8,
) -> Result<crate::PublicationResult, crate::CoordinationError> {
    drive_commit_as(
        engine,
        runtime,
        lane,
        entropy,
        RecoveryIntent::ExplicitRecovery,
    )
}

fn drive_commit_as<E: crate::SyncRuntime + 'static>(
    engine: &Arc<CommitEngine<E>>,
    runtime: &tokio::runtime::Runtime,
    lane: &crate::RetainedCommit,
    entropy: u8,
    intent: RecoveryIntent,
) -> Result<crate::PublicationResult, crate::CoordinationError> {
    runtime.block_on(Box::pin(engine.drive_commit(
        lane,
        &mut Entropy(entropy),
        &mut NoDelay,
        intent,
        crate::SyncOptions::default(),
    )))
}

pub(super) fn landed(result: &Result<crate::PublicationResult, crate::CoordinationError>) -> bool {
    result
        .as_ref()
        .is_ok_and(|result| matches!(result.outcome, PublicationOutcome::Landed(_)))
}

/// Publish a second head whose `f.txt` differs from the base, so the commit's
/// sealed `f.txt` and the authority's head change the same path.
pub(super) fn foreign_head(tree: &PublishedTree, runtime: &tokio::runtime::Runtime) {
    publish_head(tree, runtime, FOREIGN_CONTENT, |_| ());
}

/// Publish a second head that only adds `remote.txt`, so a commit sealed over
/// the base rebases onto it without touching the same path.
pub(super) fn disjoint_head(tree: &PublishedTree, runtime: &tokio::runtime::Runtime) {
    publish_head(tree, runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("remote.txt"), FOREIGN_CONTENT).unwrap();
    });
}

/// Publish the next head as a foreign writer: the base tree with `f.txt`
/// holding `file`, then edited by `edit`.
pub(super) fn publish_head(
    tree: &PublishedTree,
    runtime: &tokio::runtime::Runtime,
    file: &[u8],
    edit: impl FnOnce(&Path),
) {
    let scratch = ScratchDir::new();
    let store = Store::open(&scratch.0.join("publication")).unwrap();
    publish_head_from(tree, runtime, &store, file, edit);
}

/// [`publish_head`], publishing from `store`, which keeps every object the
/// head was built from.
pub(super) fn publish_head_from(
    tree: &PublishedTree,
    runtime: &tokio::runtime::Runtime,
    store: &Store,
    file: &[u8],
    edit: impl FnOnce(&Path),
) {
    let scratch = ScratchDir::new();
    let source = scratch.0.join("foreign");
    write_operation_source(&source, file);
    edit(&source);
    let summary = runtime
        .block_on(publish(
            &tree.remote,
            store,
            &source,
            &tree.volume,
            &tree.key,
            &WriterIdentity::from_bytes(*b"foreign-writer!!"),
            stamp(),
            Policy::default(),
        ))
        .unwrap();
    assert_eq!(summary.seq, tree.seq + 1);
}

pub(super) fn remote_seq(tree: &PublishedTree, runtime: &tokio::runtime::Runtime) -> u64 {
    runtime
        .block_on(remote_handle(&tree.mem).max_seq(tree.volume.as_str()))
        .unwrap()
        .unwrap()
}

struct EngineMount {
    ready: crate::WritableReadiness<Authority, OverlayDisk>,
    engine: Arc<CommitEngine>,
    runtime: tokio::runtime::Runtime,
    faults: crate::FaultControl,
    state: Arc<Mutex<AuthorityState>>,
    metrics: crate::ClientMetrics,
    tree: PublishedTree,
    paths: Paths,
}

#[test]
fn live_driver_observes_configured_workspace() {
    use granary_fuse::MountBackend as _;
    for bound in [8_388_608, 1_073_741_824] {
        let reports = crate::local_report::local_capture();
        let paths = Paths::new();
        let tree = mounted_operation_tree();
        let cfg = WritableStart {
            construction_workspace_bytes: bound,
            ..input(&tree, &paths)
        };
        let (ready, state, _) = attempt(&cfg, &tree, "sync_publish", &Events::default());
        let mut ready = ready.unwrap();
        shutdown::create(
            ready.backend_for_test(),
            "live-workspace",
            &vec![7; 2_097_152],
        );
        let mut attachment = ready.attach();
        let worker = attachment
            .start_sync(Arc::new(Time(state.clone())))
            .unwrap();
        let object = attachment
            .backend
            .overlay_open(&handler_path(b"live-workspace"))
            .unwrap()
            .unwrap();
        attachment.backend.prepare_object(object).unwrap();
        let job = attachment
            .backend
            .prepare_sync(granary_fuse::MountSyncRequest::File {
                object,
                datasync: false,
            })
            .unwrap();
        let result = start_job(job).blocking_recv().unwrap();
        assert_eq!(
            result,
            if bound == 8_388_608 {
                Err(granary_fuse::MountSyncError::Backend(
                    granary_fuse::MountError::NoSpace,
                ))
            } else {
                Ok(())
            },
            "sync job bound={bound}"
        );
        attachment.backend.overlay_close(object).unwrap();
        let baseline = reports.len();
        let shutdown = attachment.shutdown_handle().unwrap();
        let binding = attachment.backend.take_view_binding().unwrap();
        let fs = granary_fuse::GranaryFs::new(
            attachment.snapshot,
            attachment.backend,
            1,
            granary_fuse::MountWritability::Writable,
        )
        .unwrap();
        binding.bind(fs.view_handle(), |mount| mount).unwrap();
        shutdown::wait_until("the live attempt reports capacity or publishes", || {
            reports
                .since(baseline)
                .iter()
                .any(|r| r.contains("SyncWorkspaceExhausted"))
                || !state.lock().unwrap().publications.is_empty()
        });
        let refused = reports
            .since(baseline)
            .iter()
            .any(|r| r.contains("SyncWorkspaceExhausted"));
        assert_eq!(
            (refused, state.lock().unwrap().publications.is_empty()),
            (bound == 8_388_608, bound == 8_388_608),
            "bound={bound}"
        );
        let _ = shutdown.begin(crate::sync::Trigger::SessionEnd);
        drop(fs);
        drop(worker);
    }
}
impl EngineMount {
    fn new() -> Self {
        Self::with_tree(Paths::new(), mounted_operation_tree())
    }
    /// The engine mount over `tree`, published under `paths`.
    fn with_tree(paths: Paths, tree: PublishedTree) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        Self::with_runtime(paths, tree, runtime)
    }
    /// The engine mount over `tree`, its engine driven by `runtime`.
    fn with_runtime(paths: Paths, tree: PublishedTree, runtime: tokio::runtime::Runtime) -> Self {
        Self::with_profile(paths, tree, runtime, crate::SyncProfile::default())
    }
    /// [`Self::with_runtime`], its mount's syncs answering as `profile` says.
    fn with_profile(
        paths: Paths,
        tree: PublishedTree,
        runtime: tokio::runtime::Runtime,
        profile: crate::SyncProfile,
    ) -> Self {
        Self::with_profile_and_live(paths, tree, runtime, profile, None)
    }
    /// [`Self::with_runtime`], with a live loop waiting for the production binding.
    fn with_live(
        paths: Paths,
        tree: PublishedTree,
        runtime: tokio::runtime::Runtime,
        options: crate::SyncOptions,
    ) -> Self {
        Self::with_profile_and_live(
            paths,
            tree,
            runtime,
            crate::SyncProfile::default(),
            Some(options),
        )
    }
    fn with_profile_and_live(
        paths: Paths,
        tree: PublishedTree,
        runtime: tokio::runtime::Runtime,
        profile: crate::SyncProfile,
        live: Option<crate::SyncOptions>,
    ) -> Self {
        let cfg = WritableStart {
            sync_profile: profile,
            ..input(&tree, &paths)
        };
        let (ready, state, _) = attempt(&cfg, &tree, "valid", &Events::default());
        let mut ready = ready.unwrap();
        if let Some(options) = live {
            ready.backend_for_test().set_live_driver_for_test(options);
        }
        let remote = Arc::new(Authority::new(&tree, &state).with_publication());
        let content = Arc::new(
            ready
                .backend_for_test()
                .sync_content(remote.clone())
                .unwrap(),
        );
        let metrics = crate::ClientMetrics::new(&mut Entropy(35));
        let engine = runtime
            .block_on(ready.backend_for_test().attach_sync_with_runtime(
                remote,
                content,
                Arc::new(Time(state.clone())),
                Arc::new(crate::InstantClock::default()),
                metrics.clone(),
                Arc::new(FastWaitRuntime),
                Entropy(36),
            ))
            .unwrap();
        let faults = ready
            .backend_for_test()
            .shared_mediator()
            .with(|store| Ok(store.fault_control()))
            .unwrap();
        Self {
            ready,
            engine,
            runtime,
            faults,
            state,
            metrics,
            tree,
            paths,
        }
    }
    fn construct(&self, entropy: u8) -> Result<crate::RetainedCommit, crate::CoordinationError> {
        construct_commit(&self.engine, &self.runtime, entropy)
    }
    fn drive(
        &self,
        lane: &crate::RetainedCommit,
        entropy: u8,
    ) -> Result<crate::PublicationResult, crate::CoordinationError> {
        drive_commit(&self.engine, &self.runtime, lane, entropy)
    }
    fn resume(
        &self,
        lane: &crate::RetainedCommit,
        entropy: u8,
    ) -> Result<crate::PublicationResult, crate::CoordinationError> {
        resume_commit(&self.engine, &self.runtime, lane, entropy)
    }
    fn fired(&self) -> Vec<(&'static str, &'static str, u64)> {
        self.faults
            .sync_fired()
            .iter()
            .map(|event| (event.name, event.phase, event.occurrence))
            .collect()
    }
    fn publications(&self) -> usize {
        self.state.lock().unwrap().publications.len()
    }
    fn registrations(&self) -> usize {
        self.state.lock().unwrap().sends.len()
    }
    fn records(&self) -> Vec<granary_core::overlay_journal::Record> {
        captured_records(&self.paths, &input(&self.tree, &self.paths)).1
    }
    fn staging(&self) -> BTreeMap<String, Vec<u8>> {
        captured_staging(&self.paths, &input(&self.tree, &self.paths))
    }
    /// Whether a submission is retained for the volume.
    fn retained(&mut self) -> bool {
        self.ready
            .backend_for_test()
            .shared_mediator()
            .with(|store| {
                let scope = store.snapshot().scope.clone();
                let volume = store.snapshot().volume.clone();
                store.publication_transaction(|j| j.load(&scope, &volume))
            })
            .unwrap()
            .is_some()
    }
    fn sync_outcomes(&self) -> (u64, u64) {
        let rendered = self
            .metrics
            .snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap();
        super::observed::sync_metric_counts(&rendered)
    }
    fn sync_tree(&self) -> Result<(), crate::CoordinationError> {
        sync_tree(&self.engine, &self.runtime)
    }
}

fn sync_tree(
    engine: &Arc<CommitEngine>,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), crate::CoordinationError> {
    runtime.block_on(async {
        engine
            .sync(crate::SyncTarget::Tree, crate::SyncOptions::default())
            .wait()
            .await
    })
}

fn dirty_bytes() -> Vec<u8> {
    let mut expected = FILE_CONTENT.to_vec();
    expected[..12].copy_from_slice(b"commit-route");
    expected
}

fn dirty(fixture: &mut EngineMount) -> u64 {
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    let backend = fixture.ready.backend_for_test();
    let object = backend
        .overlay_open(&handler_path(b"f.txt"))
        .unwrap()
        .unwrap();
    backend.prepare_object(object).unwrap();
    backend
        .overlay_mutate(M::BoundWrite {
            object,
            offset: 0,
            bytes: b"commit-route",
            append: false,
        })
        .unwrap();
    object
}

type View = (bool, Result<Vec<u8>, granary_fuse::WriteError>);

fn serving(fixture: &mut EngineMount, object: u64) -> View {
    use granary_fuse::MountBackend as _;
    let backend = fixture.ready.backend_for_test();
    (
        backend.observe_engine_view().is_ok(),
        backend.read_object(object, 0, 65_536),
    )
}

/// The first attempt of a route that retains a lane: the error the fault gave,
/// the view it left, and the lane to drive again.
fn first_attempt(
    fixture: &mut EngineMount,
    route: &super::observed::CommitFaultRoute,
    object: u64,
) -> (
    Option<crate::CoordinationError>,
    View,
    crate::RetainedCommit,
) {
    if route.phase == "captured" {
        let error = fixture.construct(70).err();
        let view = serving(fixture, object);
        // A failed capture released admission: a sync registers, and the
        // commit can still be constructed afterwards.
        assert_eq!(
            (fixture.sync_tree().is_ok(), fixture.sync_outcomes()),
            (true, (1, 0)),
            "route={route:?}"
        );
        (error, view, fixture.construct(71).unwrap())
    } else {
        let lane = fixture.construct(70).unwrap();
        if route.rebases {
            disjoint_head(&fixture.tree, &fixture.runtime);
        }
        let error = fixture.drive(&lane, 80).err();
        (error, serving(fixture, object), lane)
    }
}

/// Each commit-lane fault stops the first attempt; the retry lands once and
/// only then does the old view close, except after a refresh fault, where the
/// pending refresh keeps the lane from landing in this process. A fault before
/// or after a rebase retries on an explicit recovery and lands the merge.
#[test]
fn commit_lane_fault_routes_fail_once_then_land_and_close_the_view() {
    use granary_fuse::{MountBackend as _, MountError, WriteError};
    let mut cases = 0;
    for route in super::observed::COMMIT_FAULT_ROUTES
        .iter()
        .filter(|route| route.name == "sync.commit" && route.phase != "boundary_recorded")
    {
        let mut fixture = EngineMount::new();
        let object = dirty(&mut fixture);
        fixture
            .faults
            .arm(route.name, route.phase, 1, crate::FaultAction::Fail);
        let (error, view, lane) = first_attempt(&mut fixture, route, object);
        assert_eq!(
            (
                error.is_some_and(|error| error.to_string().contains("SyncInjectedFault")),
                fixture.fired(),
                remote_seq(&fixture.tree, &fixture.runtime),
                view.0,
                view.1 == Ok(dirty_bytes()),
            ),
            (
                true,
                vec![(route.name, route.phase, 1)],
                route.remote_seq,
                route.serving,
                route.serving
            ),
            "route={route:?}, view={view:?}"
        );
        if route.serving && route.phase != "captured" {
            // The retained lane, its submission settled or not, still holds
            // admission closed: a sync behind it waits out its attempts and fails.
            let unresolved = fixture.sync_tree().err().map(|error| error.to_string());
            assert_eq!(
                (
                    unresolved.is_some_and(|text| text.contains("SyncCommitUnresolved")),
                    fixture.sync_outcomes()
                ),
                (true, (0, 1)),
                "route={route:?}"
            );
        }
        let result = if route.rebases {
            fixture.resume(&lane, 81)
        } else {
            fixture.drive(&lane, 81)
        };
        let closed = (false, Err(WriteError::Backend(MountError::Io)));
        let unready = (false, Err(WriteError::Backend(MountError::Access)));
        assert_eq!(
            (
                landed(&result),
                remote_seq(&fixture.tree, &fixture.runtime),
                fixture.publications(),
                serving(&mut fixture, object)
            ),
            (
                route.retry_lands,
                2 + u64::from(route.rebases),
                1,
                if route.retry_lands { closed } else { unready }
            ),
            "route={route:?}, retry={:?}",
            result.as_ref().err().map(ToString::to_string)
        );
        fixture
            .ready
            .backend_for_test()
            .overlay_close(object)
            .unwrap();
        cases += 1;
    }
    assert_eq!(cases, 7);
}

/// A failed caller's retained Register keeps the mount serving and is still
/// owed an answer: the shutdown settles it before it releases, and closes
/// the cache. Without the failed caller, the shutdown releases at once.
#[test]
fn writable_shutdown_settles_a_failed_callers_registration_then_releases() {
    let mut cases = 0;
    for failed in [false, true] {
        let mut fixture = EngineMount::new();
        if failed {
            fixture.faults.arm(
                "sync.registration",
                "before_dispatch",
                1,
                crate::FaultAction::Fail,
            );
            assert!(fixture.sync_tree().is_err(), "premise: the caller fails");
        }
        let (pending, serving) = fixture
            .ready
            .backend_for_test()
            .shared_mediator()
            .with(|store| {
                let pending = store
                    .snapshot()
                    .pending
                    .iter()
                    .filter(|pending| !pending.terminal)
                    .count();
                Ok((pending, store.check_readiness().is_ok()))
            })
            .unwrap();
        let shutdown = granary_fuse::MountBackend::shutdown(fixture.ready.backend_for_test());
        let (pending_after, phase) = fixture
            .ready
            .backend_for_test()
            .shared_mediator()
            .with(|store| {
                let snapshot = store.snapshot();
                Ok((
                    snapshot
                        .pending
                        .iter()
                        .filter(|pending| {
                            !pending.terminal
                                && pending.operation
                                    == granary_core::overlay_ownership::Operation::Register
                        })
                        .count(),
                    snapshot.phase,
                ))
            })
            .unwrap();
        let cfg = input(&fixture.tree, &fixture.paths);
        let cache = Cache::open(&fixture.paths.cache, cfg.cache_quota, &cfg.cache_origin).unwrap();
        assert_eq!(
            (
                pending,
                serving,
                shutdown.clone(),
                pending_after,
                phase,
                cache.is_read_only_degraded(),
            ),
            (
                usize::from(failed),
                true,
                Ok(()),
                0,
                granary_core::overlay_ownership::Phase::Released,
                false
            ),
            "failed={failed}: shutdown={shutdown:?}"
        );
        Cache::close(cache).unwrap();
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A fault right after the boundary is durable leaves what a crash there
/// leaves: the boundary is journaled, no submission is retained and nothing is
/// published, while this process's lane stays closed until a restart.
#[test]
fn commit_boundary_fault_keeps_the_boundary_and_the_lane_closed() {
    use granary_fuse::MountBackend as _;
    let route = super::observed::COMMIT_FAULT_ROUTES
        .iter()
        .find(|route| route.phase == "boundary_recorded")
        .unwrap();
    let mut fixture = EngineMount::new();
    let object = dirty(&mut fixture);
    let before = fixture.records();
    fixture
        .faults
        .arm(route.name, route.phase, 1, crate::FaultAction::Fail);
    let error = fixture.construct(70).err();
    let view = serving(&mut fixture, object);
    let again = fixture.construct(71).err();
    let waiting = fixture.sync_tree().err();
    let refused = |error: Option<crate::CoordinationError>, name: &str| {
        error.is_some_and(|error| error.to_string().contains(name))
    };
    let records = fixture.records();
    assert_eq!(
        (
            refused(error, "SyncInjectedFault"),
            fixture.fired(),
            remote_seq(&fixture.tree, &fixture.runtime),
            fixture.publications(),
            fixture.retained(),
            matches!(
                records[before.len()..],
                [granary_core::overlay_journal::Record::CommitBoundary { .. }]
            ),
            view == (route.serving, Ok(dirty_bytes())),
            refused(again, "SyncCommitInFlight"),
            refused(waiting, "SyncCommitUnresolved"),
        ),
        (
            true,
            vec![(route.name, route.phase, 1)],
            route.remote_seq,
            0,
            false,
            true,
            true,
            true,
            true
        ),
        "route={route:?}, view={view:?}"
    );
    fixture
        .ready
        .backend_for_test()
        .overlay_close(object)
        .unwrap();
}

struct ResumeOnDrop(crate::FaultControl);
impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        self.0.resume();
    }
}

/// A sync behind a captured, unretained commit registers nothing while it waits:
/// held at the wait fault it proceeds once the commit's admission closure is
/// released, and failed there it never registers. The mount stays ready while
/// only a capture is in flight, unlike a retained submission.
#[test]
fn commit_wait_holds_a_sync_until_the_commit_is_released_or_the_fault_fails_it() {
    use granary_fuse::MountBackend as _;
    let mut fixture = EngineMount::new();
    let object = dirty(&mut fixture);
    let options = crate::SyncOptions::default();
    let capture = fixture
        .runtime
        .block_on(fixture.engine.begin_commit(options))
        .unwrap();
    assert_eq!(
        serving(&mut fixture, object),
        (true, Ok(dirty_bytes())),
        "a captured commit must leave the mount view ready"
    );
    let registered = fixture.registrations();
    fixture
        .faults
        .arm("sync.commit_wait", "before", 1, crate::FaultAction::Block);
    let held = std::thread::scope(|threads| {
        let _resume = ResumeOnDrop(fixture.faults.clone());
        let waiter = threads.spawn(|| sync_tree(&fixture.engine, &fixture.runtime));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while fixture.fired().is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        let waiting = (
            waiter.is_finished(),
            fixture.fired(),
            fixture.registrations() - registered,
            fixture.sync_outcomes(),
        );
        fixture.engine.discard_commit(capture).unwrap();
        fixture.faults.resume();
        (waiting, waiter.join().unwrap().is_ok())
    });
    assert_eq!(
        (
            held,
            fixture.registrations() - registered,
            fixture.sync_outcomes()
        ),
        (
            (
                (false, vec![("sync.commit_wait", "before", 1)], 0, (0, 0)),
                true
            ),
            1,
            (1, 0)
        ),
        "a sync must wait behind the commit and register only after it is released"
    );
    let capture = fixture
        .runtime
        .block_on(fixture.engine.begin_commit(options))
        .unwrap();
    fixture
        .faults
        .arm("sync.commit_wait", "before", 1, crate::FaultAction::Fail);
    let injected = fixture.sync_tree().err().map(|error| error.to_string());
    assert_eq!(
        (
            injected.is_some_and(|text| text.contains("SyncInjectedFault")),
            fixture.fired(),
            fixture.registrations() - registered,
            fixture.sync_outcomes()
        ),
        (true, vec![("sync.commit_wait", "before", 1)], 1, (1, 1)),
        "a failed wait must register nothing"
    );
    fixture.engine.discard_commit(capture).unwrap();
    // After the released captures and the earlier sync, the commit still lands.
    let lane = fixture.construct(70).unwrap();
    let result = fixture.drive(&lane, 80);
    assert_eq!(
        (landed(&result), remote_seq(&fixture.tree, &fixture.runtime)),
        (true, 2)
    );
    fixture
        .ready
        .backend_for_test()
        .overlay_close(object)
        .unwrap();
}

/// A fault while a dirty file shrinks fails the truncate and poisons the
/// overlay, so no later write or commit builds on a half-shrunk stage; the
/// staged bytes are the point's side of the resize, untouched before it and cut
/// after it.
#[test]
fn stage_truncate_fault_fails_the_shrink_and_closes_the_overlay() {
    use granary_fuse::{MountBackend as _, MountError, OverlayMutation as M, WriteError};
    let mut cases = 0;
    for (phase, cut) in [("before", false), ("after", true)] {
        let mut fixture = EngineMount::new();
        let object = dirty(&mut fixture);
        let staged = fixture.staging();
        fixture
            .faults
            .arm("overlay.stage.truncate", phase, 1, crate::FaultAction::Fail);
        let backend = fixture.ready.backend_for_test();
        let shrink = backend.overlay_mutate(M::BoundSetattr {
            object,
            size: Some(4),
            exec: None,
        });
        let write = backend.overlay_mutate(M::BoundWrite {
            object,
            offset: 0,
            bytes: b"later",
            append: false,
        });
        let fired: Vec<_> = fixture
            .faults
            .fired()
            .iter()
            .map(|event| (event.name, event.phase, event.occurrence))
            .collect();
        let io = Err(WriteError::Backend(MountError::Io));
        let construct = fixture.construct(70).err().map(|error| error.to_string());
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
                io,
                io,
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
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn same_path_conflict_fences_and_keeps_the_dirty_staging() {
    use granary_fuse::{MountBackend as _, MountError, OverlayMutation as M, WriteError};
    let mut fixture = EngineMount::new();
    let object = dirty(&mut fixture);
    let before = fixture.records();
    let staged = fixture.staging();
    let lane = fixture.construct(70).unwrap();
    foreign_head(&fixture.tree, &fixture.runtime);
    let result = fixture.drive(&lane, 80);
    let view = serving(&mut fixture, object);
    let backend = fixture.ready.backend_for_test();
    let write = backend.overlay_mutate(M::BoundWrite {
        object,
        offset: 0,
        bytes: b"later",
        append: false,
    });
    let create = backend.overlay_mutate(M::Create {
        path: &handler_path(b"new.txt"),
        kind: granary_vfs::NodeKind::File,
        exec: false,
    });
    let stale = WriteError::Backend(MountError::Stale);
    assert_eq!(
        (
            matches!(result, Err(crate::CoordinationError::Fenced { .. })),
            view,
            write.err(),
            create.err(),
            matches!(
                fixture.sync_tree(),
                Err(crate::CoordinationError::Fenced { .. })
            ),
            fixture.publications(),
            remote_seq(&fixture.tree, &fixture.runtime),
            fixture.records().starts_with(&before),
            !staged.is_empty() && fixture.staging() == staged,
        ),
        (
            true,
            (false, Err(stale)),
            Some(stale),
            Some(stale),
            true,
            0,
            2,
            true,
            true
        ),
        "a same-path conflict must fence every mutation, publish nothing and keep the dirty records and staged bytes"
    );
}

type ViewContext = crate::writable_store::ViewContext;
type RebuildContent = crate::MountSyncContent<Authority, OverlayDisk, FastWaitRuntime>;

const DEEP_CONTENT: &[u8] = b"a file three directories deep\n";

fn error_text(error: &crate::CoordinationError) -> String {
    format!("{error:?}")
}

impl EngineMount {
    /// The pin the start bound, read from the mediator.
    fn start_pin(&mut self) -> Arc<ViewContext> {
        self.ready
            .backend_for_test()
            .shared_mediator()
            .with(|local| Ok(local.mount_pin()))
            .unwrap()
            .expect("the start binds a pin")
    }
    fn mediator(&mut self) -> crate::SharedWritableStore<OverlayDisk> {
        self.ready.backend_for_test().shared_mediator().clone()
    }
    /// A content bridge bound to a deadline, built while the mediator still
    /// serves the start base; its range reads land in this fixture's log.
    fn view_content(&mut self) -> RebuildContent {
        let deadline =
            crate::SyncRuntime::now(&FastWaitRuntime) + std::time::Duration::from_mins(1);
        self.ready
            .backend_for_test()
            .sync_content(Arc::new(Authority::new(&self.tree, &self.state)))
            .unwrap()
            .with_deadline(Arc::new(FastWaitRuntime), deadline)
    }
    fn published(&self, seq: u64) -> crate::sync::PublishedRoot {
        self.runtime
            .block_on(crate::sync::PublishedRoot::read(
                &self.tree.remote,
                &self.tree.volume,
                seq,
                None,
                &trusted(&self.tree),
            ))
            .unwrap_or_else(|error| {
                panic!("fixture precondition: the root at {seq} reads: {error}")
            })
    }
    fn rebuild(
        &self,
        previous: Arc<ViewContext>,
        published: &crate::sync::PublishedRoot,
        content: &RebuildContent,
    ) -> Result<ViewContext, String> {
        self.runtime
            .block_on(crate::writable_start::rebuild_view(
                previous, published, content,
            ))
            .map_err(|error| error_text(&error))
    }
    /// Drain the bin-range log: every `(digest, offset, length)` read since
    /// the last drain.
    fn take_ranges(&self) -> Vec<([u8; DIGEST_LEN], u64, u32)> {
        std::mem::take(&mut self.state.lock().unwrap().ranges)
    }
    /// Land the dirty `f.txt` through the engine and return the landed seq.
    fn land(&mut self) -> u64 {
        dirty(self);
        self.sync_tree().unwrap();
        let lane = self.construct(60).unwrap();
        assert!(
            landed(&self.drive(&lane, 61)),
            "fixture precondition: B lands"
        );
        remote_seq(&self.tree, &self.runtime)
    }
}

/// Publish the head `build` writes into a fresh source directory, under the
/// tree's key, and return its seq.
pub(super) fn publish_source(
    tree: &PublishedTree,
    runtime: &tokio::runtime::Runtime,
    build: impl FnOnce(&Path),
) -> u64 {
    let scratch = ScratchDir::new();
    let source = scratch.0.join("source");
    build(&source);
    let store = Store::open(&scratch.0.join("publication")).unwrap();
    runtime
        .block_on(publish(
            &tree.remote,
            &store,
            &source,
            &tree.volume,
            &tree.key,
            &WriterIdentity::from_bytes(*b"foreign-writer!!"),
            stamp(),
            Policy::default(),
        ))
        .unwrap()
        .seq
}

/// The landed tree's dirty `f.txt`, the unchanged `sub/g.txt` subtree, and one
/// distinct file three directories deep.
fn deep_source(source: &Path) {
    write_operation_source(source, &dirty_bytes());
    std::fs::create_dir_all(source.join("deep/a/b")).unwrap();
    std::fs::write(source.join("deep/a/b/leaf.txt"), DEEP_CONTENT).unwrap();
}

/// Every manifest structure node of the root at `seq`, by id.
fn structure_nodes(
    tree: &PublishedTree,
    runtime: &tokio::runtime::Runtime,
    seq: u64,
) -> BTreeMap<GrainId, Vec<u8>> {
    use granary_core::encoding::{ObjectType, open_envelope};
    let (_, objects) = runtime
        .block_on(crate::resolve::resolve_at_collecting(
            &tree.remote,
            tree.volume.as_str(),
            seq,
        ))
        .unwrap();
    objects
        .into_iter()
        .filter(|(_, bytes)| {
            matches!(
                open_envelope(bytes).map(|(kind, _)| kind),
                Ok(ObjectType::DirLeaf
                    | ObjectType::DirInterior
                    | ObjectType::GrainListLeaf
                    | ObjectType::GrainListIndex)
            )
        })
        .collect()
}

/// Every file the leaves among `nodes` name, as the view pins them.
fn files_of(nodes: &BTreeMap<GrainId, Vec<u8>>) -> BTreeMap<GrainId, (u64, FileGrains)> {
    use granary_core::encoding::{ObjectType, open_envelope};
    let mut files = BTreeMap::new();
    for bytes in nodes.values() {
        let (kind, cursor) = open_envelope(bytes).unwrap();
        if kind != ObjectType::DirLeaf {
            continue;
        }
        for entry in manifest::decode_dir_leaf(cursor).unwrap() {
            if let EntryKind::File { size, grains, .. } = entry.kind {
                let payload = manifest::node::file_payload(size, &grains).unwrap();
                files.insert(GrainId::of(&payload), (size, grains));
            }
        }
    }
    files
}

/// The content grain of the deep file among `nodes`' leaves.
fn deep_grain(nodes: &BTreeMap<GrainId, Vec<u8>>) -> GrainId {
    use granary_core::encoding::{ObjectType, open_envelope};
    nodes
        .values()
        .find_map(|bytes| {
            let (kind, cursor) = open_envelope(bytes).ok()?;
            if kind != ObjectType::DirLeaf {
                return None;
            }
            manifest::decode_dir_leaf(cursor)
                .ok()?
                .into_iter()
                .find_map(|entry| {
                    let DirEntry { name, kind } = entry;
                    match kind {
                        EntryKind::File {
                            grains: FileGrains::Inline(refs),
                            ..
                        } if name.as_bytes() == b"leaf.txt" => refs.first().map(|r| r.id),
                        _ => None,
                    }
                })
        })
        .expect("the deep file is an inline-grain file in one leaf")
}

/// The id behind each range read logged since the last drain, in read order
/// and with repeats, resolved through the binmap they were read with.
fn ids_read(
    fixture: &EngineMount,
    known: &BTreeMap<GrainId, granary_core::binmap::ShardEntry>,
    bins: &[[u8; DIGEST_LEN]],
) -> Vec<GrainId> {
    let by_extent: BTreeMap<_, _> = known
        .values()
        .map(|entry| {
            let digest = bins[usize::try_from(entry.bin_ordinal).unwrap()];
            ((digest, entry.offset, entry.comp_len), entry.id)
        })
        .collect();
    fixture
        .take_ranges()
        .into_iter()
        .map(|extent| {
            by_extent
                .get(&extent)
                .copied()
                .unwrap_or_else(|| panic!("a range read outside the binmap: {extent:?}"))
        })
        .collect()
}

/// The tree's root at `seq`: its id and decoded document.
fn root_doc(
    tree: &PublishedTree,
    runtime: &tokio::runtime::Runtime,
    seq: u64,
) -> (GrainId, RootDoc) {
    let bytes = runtime
        .block_on(remote_handle(&tree.mem).get_root(tree.volume.as_str(), seq))
        .unwrap()
        .unwrap();
    (GrainId::of(&bytes), root::decode_root(&bytes).unwrap())
}

/// Sign `doc` under the tree's key, put it at its seq, and return that seq.
fn sign_and_put(tree: &PublishedTree, runtime: &tokio::runtime::Runtime, mut doc: RootDoc) -> u64 {
    doc.sigs.clear();
    doc.sigs.push(RootSig {
        key_id: tree.key.key_id(),
        sig: tree.key.sign(&root::signing_prefix_of(&doc).unwrap()),
    });
    runtime
        .block_on(remote_handle(&tree.mem).put_root(
            tree.volume.as_str(),
            doc.seq,
            root::encode_root(&doc).unwrap(),
        ))
        .unwrap();
    doc.seq
}

/// Publish, at the next seq, the root at `seq` with `omitted` removed from
/// every shard of its binmap, re-signed under the tree's key.
fn publish_without(
    tree: &PublishedTree,
    runtime: &tokio::runtime::Runtime,
    seq: u64,
    omitted: GrainId,
) -> u64 {
    use granary_core::binmap;
    let remote = remote_handle(&tree.mem);
    let volume = tree.volume.as_str();
    let (parent, mut doc) = root_doc(tree, runtime, seq);
    runtime.block_on(async {
        let index =
            binmap::decode_binmap_index(&remote.get_meta(volume, &doc.binmap_index).await.unwrap())
                .unwrap();
        let mut shard_ids = Vec::new();
        for id in &index.shards {
            let mut entries =
                binmap::decode_shard(&remote.get_meta(volume, id).await.unwrap()).unwrap();
            entries.retain(|entry| entry.id != omitted);
            let shard = binmap::encode_shard(&entries).unwrap();
            let id = GrainId::of(&shard);
            remote.put_meta(volume, &id, shard).await.unwrap();
            shard_ids.push(id);
        }
        let index_bytes =
            binmap::encode_binmap_index(index.prefix_bits, index.bin_table, &shard_ids).unwrap();
        doc.binmap_index = GrainId::of(&index_bytes);
        remote
            .put_meta(volume, &doc.binmap_index, index_bytes)
            .await
            .unwrap();
    });
    doc.parent = Some(parent);
    doc.seq = seq + 1;
    sign_and_put(tree, runtime, doc)
}

/// The rebuild takes a node from the view it replaces, then from the mount's
/// store, and reads from the remote only what neither holds. Control, before
/// any landing and with every start node evicted from the store: rebuilding
/// the start root from the start view reads no range and reproduces the
/// start context field for field. Main case, after B lands and C is
/// published over it while the pin still holds A: the rebuild of C reads
/// each C node absent from both local sources exactly once and no other
/// range, keeps every C node
/// and file, carries C's binmap, and pins C's id, seq and bytes.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture carries the zero-read control and the measured rebuild"
)]
fn view_context_rebuild_fetches_only_new_nodes() {
    let mut fixture = EngineMount::new();
    let start = fixture.start_pin();
    let content = fixture.view_content();
    // Attach warmed the start's structure nodes into the store; evict them so
    // the control's zero can only come from the previous context.
    for id in start.pin_nodes.keys() {
        let hex = id.digest_hex();
        let object = fixture
            .paths
            .store
            .join("objects")
            .join(&hex[..2])
            .join(&hex);
        std::fs::remove_file(&object)
            .unwrap_or_else(|error| panic!("evicting {}: {error}", object.display()));
    }
    let absent: Vec<_> = start
        .pin_nodes
        .keys()
        .map(|id| {
            (
                *id,
                matches!(
                    crate::SyncContent::get_local(&content, id),
                    Err(GrainSourceError::Missing(missing)) if missing == *id
                ),
            )
        })
        .collect();
    assert!(
        !absent.is_empty() && absent.iter().all(|(_, missing)| *missing),
        "control premise: every start node is absent from the store: {absent:?}"
    );
    let base_root = fixture.published(fixture.tree.seq);
    fixture.take_ranges();
    let control = fixture.rebuild(start.clone(), &base_root, &content);
    let ranges = fixture.take_ranges();
    assert_eq!(
        (ranges.len(), control.map(|context| context == *start)),
        (0, Ok(true)),
        "control: ranges={ranges:?}"
    );

    let landed_seq = fixture.land();
    let head_seq = publish_source(&fixture.tree, &fixture.runtime, deep_source);
    assert_eq!(head_seq, landed_seq + 1);
    let head_nodes = structure_nodes(&fixture.tree, &fixture.runtime, head_seq);
    let head = fixture.published(head_seq);
    let manifest_root = head.doc().manifest_root;
    let mediator = fixture.mediator();
    let stored = |id: &GrainId| {
        mediator
            .with(|local| Ok(local.immutable_content()?.has(id)))
            .unwrap()
    };
    let new_nodes: Vec<GrainId> = head_nodes
        .keys()
        .filter(|id| !start.pin_nodes.contains_key(id) && !stored(id))
        .copied()
        .collect();
    let retained: Vec<GrainId> = head_nodes
        .keys()
        .filter(|id| **id != manifest_root && start.pin_nodes.contains_key(id))
        .copied()
        .collect();
    let seeded: Vec<GrainId> = std::iter::once(manifest_root)
        .chain(
            new_nodes
                .iter()
                .copied()
                .filter(|id| *id != manifest_root)
                .take(1),
        )
        .collect();
    for id in &seeded {
        mediator.put_immutable(*id, &head_nodes[id]).unwrap();
    }
    let remote_only: BTreeSet<GrainId> = new_nodes
        .iter()
        .copied()
        .filter(|id| !seeded.contains(id))
        .collect();
    let base = mediator.with(|local| local.mount_base()).unwrap();
    let pin = mediator
        .with(|local| Ok(local.mount_pin()))
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            base.1,
            (pin.base_id, pin.base_seq),
            new_nodes.contains(&manifest_root),
            seeded
                .iter()
                .all(|id| stored(id) && !start.pin_nodes.contains_key(id)),
            remote_only
                .iter()
                .all(|id| !stored(id) && !start.pin_nodes.contains_key(id)),
            retained.is_empty(),
            seeded.len(),
            remote_only.len(),
        ),
        (
            landed_seq,
            (start.base_id, start.base_seq),
            true,
            true,
            true,
            false,
            2,
            2
        ),
        "main-case premises: seeded={seeded:?} remote_only={remote_only:?} retained={retained:?}"
    );
    let binmap = fixture
        .runtime
        .block_on(crate::publish::state_from_published(
            &fixture.tree.remote,
            &head,
        ))
        .unwrap();
    fixture.take_ranges();
    let rebuilt = fixture
        .rebuild(start.clone(), &head, &content)
        .unwrap_or_else(|error| panic!("the rebuild of C: {error}"));
    let read = ids_read(&fixture, &binmap.known, &binmap.bins);
    assert_eq!(
        (
            read.len(),
            read.iter().copied().collect::<BTreeSet<_>>(),
            rebuilt.pin_nodes.keys().copied().collect::<BTreeSet<_>>(),
            rebuilt.pin_files == files_of(&head_nodes),
            rebuilt.entries == binmap.known,
            *rebuilt.bins == *binmap.bins,
            (
                rebuilt.base_id,
                rebuilt.base_seq,
                rebuilt.base_bytes == head.bytes()
            ),
        ),
        (
            remote_only.len(),
            remote_only,
            head_nodes.keys().copied().collect(),
            true,
            true,
            true,
            (head.id(), head_seq, true),
        )
    );
}

/// Membership and coverage against the new root's binmap refuse a node
/// whichever source supplied it. Each case lands B, publishes C with its
/// manifest root seeded into the store, rebuilds C as the control, then
/// publishes C at the next seq with one id omitted from its binmap: the
/// manifest root (held by the store, not by the previous view), a directory
/// C keeps from A (held by the previous view), and the deep file's content
/// grain (never fetched). Case count 3.
#[test]
fn view_context_rebuild_refuses_an_uncovered_node_from_any_source() {
    let mut observations = Vec::new();
    for case in 0..3 {
        let mut fixture = EngineMount::new();
        let start = fixture.start_pin();
        let content = fixture.view_content();
        let landed_seq = fixture.land();
        let head_seq = publish_source(&fixture.tree, &fixture.runtime, deep_source);
        assert_eq!(head_seq, landed_seq + 1);
        let head_nodes = structure_nodes(&fixture.tree, &fixture.runtime, head_seq);
        let head = fixture.published(head_seq);
        let manifest_root = head.doc().manifest_root;
        let mediator = fixture.mediator();
        mediator
            .put_immutable(manifest_root, &head_nodes[&manifest_root])
            .unwrap();
        let stored = |id: &GrainId| {
            mediator
                .with(|local| Ok(local.immutable_content()?.has(id)))
                .unwrap()
        };
        let control = fixture
            .rebuild(start.clone(), &head, &content)
            .map(|context| context.base_id == head.id());
        let (omitted, premise) = match case {
            0 => (
                manifest_root,
                stored(&manifest_root) && !start.pin_nodes.contains_key(&manifest_root),
            ),
            1 => {
                let kept = head_nodes
                    .keys()
                    .copied()
                    .find(|id| *id != manifest_root && start.pin_nodes.contains_key(id))
                    .expect("C keeps a directory from A");
                (kept, start.pin_nodes.contains_key(&kept))
            }
            2 => {
                let grain = deep_grain(&head_nodes);
                (grain, !head_nodes.contains_key(&grain))
            }
            _ => unreachable!(),
        };
        let altered_seq = publish_without(&fixture.tree, &fixture.runtime, head_seq, omitted);
        let altered = fixture.published(altered_seq);
        let result = fixture
            .rebuild(start.clone(), &altered, &content)
            .map(|context| context.base_id);
        observations.push((case, control, premise, result));
    }
    assert_eq!(
        observations,
        (0..3)
            .map(|case| (
                case,
                Ok(true),
                true,
                Err("Refused(\"SyncBase\")".to_owned())
            ))
            .collect::<Vec<_>>()
    );
}

/// A read-side root reserves no successor: the rebuild accepts a head at
/// `u64::MAX - 1` and an epoch at `u64::MAX`, which the write side refuses to
/// build on. Each case rewrites A's root to a fresh seq with A as its parent,
/// keeps its manifest and binmap, signs it under A's key and reads it through
/// `PublishedRoot` only; the rebuilt context pins that root over A's
/// unchanged material. Case count 2.
#[test]
fn view_context_rebuild_accepts_read_side_counter_maxima() {
    let mut fixture = EngineMount::new();
    let start = fixture.start_pin();
    let content = fixture.view_content();
    let (base_id, base_doc) = root_doc(&fixture.tree, &fixture.runtime, fixture.tree.seq);
    let mut observations = Vec::new();
    let mut expected = Vec::new();
    for (case, seq, epoch) in [
        (0, u64::MAX - 1, base_doc.epoch),
        (1, base_doc.seq + 1, u64::MAX),
    ] {
        let mut doc = base_doc.clone();
        doc.seq = seq;
        doc.epoch = epoch;
        doc.parent = Some(base_id);
        sign_and_put(&fixture.tree, &fixture.runtime, doc);
        let root = fixture.published(seq);
        let rebuilt = fixture
            .rebuild(start.clone(), &root, &content)
            .map(|context| {
                (
                    context.base_id,
                    context.base_seq,
                    context.base_bytes == root.bytes(),
                    context.pin_nodes == start.pin_nodes,
                    context.pin_files == start.pin_files,
                    context.entries == start.entries,
                    context.bins == start.bins,
                )
            });
        observations.push((case, root.doc().epoch, rebuilt));
        expected.push((
            case,
            epoch,
            Ok((root.id(), seq, true, true, true, true, true)),
        ));
    }
    assert_eq!(observations, expected);
}

/// A store read the mediator refuses keeps the mediator's refusal: it is not
/// a cache miss and does not fall back to the remote. Each case retains a lane
/// over a dirty `f.txt`, publishes a foreign C whose manifest root the store
/// is seeded with, rebuilds C as the control, then poisons the mediator mutex
/// or drives the lane into the conflict fence and rebuilds C again: the
/// mediator's own refusal with its fields, and no range read. Case count 2.
#[test]
fn view_context_rebuild_preserves_a_mediator_refusal() {
    let mut observations = Vec::new();
    let mut expected = Vec::new();
    for case in 0..2 {
        let mut fixture = EngineMount::new();
        let start = fixture.start_pin();
        let content = fixture.view_content();
        dirty(&mut fixture);
        let lane = fixture.construct(70).unwrap();
        foreign_head(&fixture.tree, &fixture.runtime);
        let head_seq = fixture.tree.seq + 1;
        let head_nodes = structure_nodes(&fixture.tree, &fixture.runtime, head_seq);
        let head = fixture.published(head_seq);
        let manifest_root = head.doc().manifest_root;
        assert!(
            !start.pin_nodes.contains_key(&manifest_root),
            "premise: C's manifest root is new to the previous view"
        );
        let mediator = fixture.mediator();
        mediator
            .put_immutable(manifest_root, &head_nodes[&manifest_root])
            .unwrap();
        let control = fixture
            .rebuild(start.clone(), &head, &content)
            .map(|context| context.base_id == head.id());
        let refusal = match case {
            0 => {
                let mutex = mediator.as_arc();
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _guard = mutex.lock().unwrap();
                    panic!("poison the mediator");
                }));
                "Refused(\"SyncMediatorPoisoned\")".to_owned()
            }
            1 => {
                let fenced = fixture.drive(&lane, 80);
                assert!(
                    matches!(fenced, Err(crate::CoordinationError::Fenced { .. })),
                    "premise: the lane fences: {:?}",
                    fenced.as_ref().err().map(error_text)
                );
                error_text(
                    &mediator
                        .with(|local| local.immutable_content().map(|_| ()))
                        .expect_err("the fenced mediator refuses"),
                )
            }
            _ => unreachable!(),
        };
        fixture.take_ranges();
        let result = fixture
            .rebuild(start.clone(), &head, &content)
            .map(|context| context.base_id);
        let ranges = fixture.take_ranges().len();
        assert!(
            refusal.starts_with(["Refused(\"SyncMediatorPoisoned\")", "Fenced {"][case]),
            "case {case}: the mediator's refusal is {refusal}"
        );
        observations.push((case, control, result, ranges));
        expected.push((case, Ok(true), Err(refusal), 0));
    }
    assert_eq!(observations, expected);
}

/// A stored copy of a needed node that fails hash authentication is a miss,
/// not an error: the rebuild reads that node from the remote through the new
/// binmap and succeeds. The case publishes a foreign C, stores tampered bytes
/// under C's manifest root, and rebuilds C: the store answers `Corrupt` for
/// that id, the root is read from the remote once, and the rebuilt context
/// pins C with the authenticated node.
#[test]
fn view_context_rebuild_fetches_a_node_whose_stored_copy_is_corrupt() {
    let mut fixture = EngineMount::new();
    let start = fixture.start_pin();
    let content = fixture.view_content();
    foreign_head(&fixture.tree, &fixture.runtime);
    let head_seq = fixture.tree.seq + 1;
    let head_nodes = structure_nodes(&fixture.tree, &fixture.runtime, head_seq);
    let head = fixture.published(head_seq);
    let manifest_root = head.doc().manifest_root;
    fixture
        .mediator()
        .put_immutable(manifest_root, &head_nodes[&manifest_root])
        .unwrap();
    let hex = manifest_root.digest_hex();
    let object = fixture
        .paths
        .store
        .join("objects")
        .join(&hex[..2])
        .join(&hex);
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&object, b"tampered manifest root").unwrap();
    let local = crate::SyncContent::get_local(&content, &manifest_root);
    assert!(
        !start.pin_nodes.contains_key(&manifest_root)
            && matches!(local, Err(GrainSourceError::Corrupt(id)) if id == manifest_root),
        "premise: C's manifest root is new to the previous view and its stored copy is corrupt: {local:?}"
    );
    let binmap = fixture
        .runtime
        .block_on(crate::publish::state_from_published(
            &fixture.tree.remote,
            &head,
        ))
        .unwrap();
    fixture.take_ranges();
    let rebuilt = fixture.rebuild(start, &head, &content).map(|context| {
        (
            context.base_id,
            context.pin_nodes.get(&manifest_root) == head_nodes.get(&manifest_root),
        )
    });
    let root_reads = ids_read(&fixture, &binmap.known, &binmap.bins)
        .into_iter()
        .filter(|id| *id == manifest_root)
        .count();
    assert_eq!((rebuilt, root_reads), (Ok((head.id(), true)), 1));
}

/// A node read that fails at the transport keeps its own class, so the
/// rebuild's caller can tell it from a bad head: the read answers 503 once,
/// after the binmap read, and the rebuild refuses `ContentUnavailable`.
/// A node whose frame does not verify is a bad base: `SyncBase`. In both
/// cases the failing node is the head's manifest root, new to the previous
/// view and absent from the store. Case count 2.
#[test]
fn rebuild_keeps_a_node_read_transport_failure_transient() {
    let mut observations = Vec::new();
    for case in ["transport", "frame"] {
        let mut fixture = EngineMount::new();
        let start = fixture.start_pin();
        let content = fixture.view_content();
        foreign_head(&fixture.tree, &fixture.runtime);
        let head = fixture.published(fixture.tree.seq + 1);
        let manifest_root = head.doc().manifest_root;
        let stored = crate::SyncContent::get_local(&content, &manifest_root);
        eprintln!(
            "{case}: premise, the failing node is in the previous view: {}, stored: {stored:?}",
            start.pin_nodes.contains_key(&manifest_root)
        );
        assert!(
            !start.pin_nodes.contains_key(&manifest_root)
                && matches!(stored, Err(GrainSourceError::Missing(_))),
            "{case}: premise, the head's manifest root is read from the remote"
        );
        {
            let mut state = fixture.state.lock().unwrap();
            if case == "transport" {
                state.next_range_fault = Some(RangeFault::Unavailable);
            } else {
                state.next_range_fault = Some(RangeFault::Corrupt);
            }
        }
        let result = fixture
            .rebuild(start, &head, &content)
            .map(|context| context.base_id);
        observations.push((case, result));
    }
    assert_eq!(
        observations,
        vec![
            (
                "transport",
                Err(error_text(&crate::OverlayError::ContentUnavailable.into()))
            ),
            ("frame", Err("Refused(\"SyncBase\")".to_owned())),
        ]
    );
}
