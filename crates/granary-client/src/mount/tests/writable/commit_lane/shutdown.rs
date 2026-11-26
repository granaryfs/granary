// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A writable mount's shutdown over the engine fixture: the latch, the drain,
//! one sync per dirty file, one commit and the release, under one deadline,
//! and the report of what each ending leaves.

use super::*;
use crate::sync::{Cause, Cut, MountShutdown as _, Outcome, Shutdown, ShutdownReport, Trigger};
use granary_core::overlay_ownership::Phase;
use granary_fuse::{MountBackend as _, OverlayMutation as M};

/// Entropy a controller draws from, as a mount's one source.
#[derive(Clone)]
pub(super) struct SharedEntropy(Arc<Mutex<Entropy>>);
impl SharedEntropy {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(Entropy(90))))
    }
}
impl granary_core::secure_random::SecureRandom for SharedEntropy {
    fn fill(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        self.0.lock().unwrap().fill(bytes)
    }
}

/// The engine fixture's engine type, on runtime `E`.
pub(super) type Engine<E> = crate::SyncEngine<
    OverlayDisk,
    Authority,
    crate::MountSyncContent<Authority>,
    Time,
    crate::InstantClock,
    E,
>;

/// A shutdown controller over the engine fixture, on runtime `E`.
pub(super) type Controller<E = FastWaitRuntime> = Shutdown<
    OverlayDisk,
    Authority,
    crate::MountSyncContent<Authority>,
    Time,
    crate::InstantClock,
    E,
    SharedEntropy,
>;

/// A controller over `engine` and `mediator` with `bound`, starting its
/// sequence through `handle`.
pub(super) fn controller<E: crate::SyncRuntime + 'static>(
    engine: &Arc<Engine<E>>,
    mediator: crate::SharedWritableStore<OverlayDisk>,
    handle: tokio::runtime::Handle,
    bound: std::time::Duration,
) -> Controller<E> {
    Shutdown::new(
        engine.clone(),
        mediator,
        engine.runtime_for_mount(),
        SharedEntropy::new(),
        Some(handle),
        bound,
    )
}

/// What a row reads back from a fixture: the authority's record and the
/// mediator, whatever phase the store is in.
pub(super) struct Probe {
    pub(super) state: Arc<Mutex<AuthorityState>>,
    pub(super) volume: VolumeName,
    pub(super) mediator: crate::SharedWritableStore<OverlayDisk>,
}
impl Probe {
    pub(super) fn phase(&self) -> Phase {
        self.mediator
            .with(|store| Ok(store.snapshot().phase))
            .unwrap()
    }
    /// The overlay's base `(id, seq)`.
    pub(super) fn overlay_base(&self) -> (GrainId, u64) {
        self.mediator
            .with(|store| Ok(store.overlay_base_for_test()))
            .unwrap()
            .unwrap()
    }
    /// Every registration sent from the `from`th on, as its prepared root's
    /// root-level files by name and size.
    pub(super) fn registered(&self, from: usize) -> Vec<BTreeMap<Vec<u8>, u64>> {
        let sends = self.state.lock().unwrap().sends.clone();
        sends
            .iter()
            .filter_map(|bytes| intent::decode_register(bytes, &self.volume, |_, _| true).ok())
            .skip(from)
            .map(|request| {
                let manifest = granary_core::root::decode_root(request.root)
                    .unwrap()
                    .manifest_root;
                let node = self
                    .mediator
                    .with(|store| Ok(store.stored_for_test(&manifest)))
                    .unwrap()
                    .expect("a registered root's manifest is stored");
                let (_, cursor) = granary_core::encoding::open_envelope(&node).unwrap();
                granary_core::manifest::decode_dir_leaf(cursor)
                    .unwrap()
                    .into_iter()
                    .filter_map(|entry| match entry.kind {
                        granary_core::manifest::EntryKind::File { size, .. } => {
                            Some((entry.name.as_bytes().to_vec(), size))
                        }
                        _ => None,
                    })
                    .collect()
            })
            .collect()
    }
    /// How many registrations were sent.
    pub(super) fn registration_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .sends
            .iter()
            .filter(|bytes| intent::decode_register(bytes, &self.volume, |_, _| true).is_ok())
            .count()
    }
    /// How many Releases were sent.
    pub(super) fn releases(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .sends
            .iter()
            .filter(|bytes| intent::decode_release(bytes).is_ok())
            .count()
    }
}

/// Create the root-level file `name` holding `bytes`.
pub(super) fn create(
    backend: &mut crate::WritableMount<Authority, OverlayDisk>,
    name: &str,
    bytes: &[u8],
) {
    let path = handler_path(name.as_bytes());
    backend
        .overlay_mutate(M::Create {
            path: &path,
            kind: granary_vfs::NodeKind::File,
            exec: false,
        })
        .unwrap();
    backend
        .overlay_mutate(M::Write {
            path: &path,
            offset: 0,
            bytes,
            append: false,
        })
        .unwrap();
}

impl EngineMount {
    /// A shutdown controller over this fixture's engine with `bound`.
    fn controller(&mut self, bound: std::time::Duration) -> Controller {
        let mediator = self.mediator();
        controller(&self.engine, mediator, self.runtime.handle().clone(), bound)
    }
    /// The shutdown the mount's own backend runs, with its default bound.
    fn shut_down(&mut self) -> Outcome {
        self.ready
            .backend_for_test()
            .shutdown_for_test()
            .expect("an attached engine's shutdown")
            .begin(Trigger::SessionEnd)
            .outcome
    }
    fn probe(&mut self) -> Probe {
        Probe {
            state: self.state.clone(),
            volume: self.tree.volume.clone(),
            mediator: self.mediator(),
        }
    }
    fn phase(&mut self) -> Phase {
        self.probe().phase()
    }
    fn overlay_base(&mut self) -> (GrainId, u64) {
        self.probe().overlay_base()
    }
    fn registered(&mut self, from: usize) -> Vec<BTreeMap<Vec<u8>, u64>> {
        self.probe().registered(from)
    }
    fn registration_count(&mut self) -> usize {
        self.probe().registration_count()
    }
    fn releases(&mut self) -> usize {
        self.probe().releases()
    }
    fn create(&mut self, name: &str, bytes: &[u8]) {
        create(self.ready.backend_for_test(), name, bytes);
    }
    fn rename(&mut self, from: &str, to: &str) {
        self.ready
            .backend_for_test()
            .overlay_mutate(M::Rename {
                from: &handler_path(from.as_bytes()),
                to: &handler_path(to.as_bytes()),
                no_replace: false,
            })
            .unwrap();
    }
    fn mkdir(&mut self, name: &str) {
        self.ready
            .backend_for_test()
            .overlay_mutate(M::Create {
                path: &handler_path(name.as_bytes()),
                kind: granary_vfs::NodeKind::Dir,
                exec: false,
            })
            .unwrap();
    }
}

/// A writable mount whose engine runs on `E`, attached in a runtime the row
/// owns.
struct Attached<E: crate::SyncRuntime> {
    ready: crate::WritableReadiness<Authority, OverlayDisk>,
    engine: Arc<Engine<E>>,
    state: Arc<Mutex<AuthorityState>>,
    tree: PublishedTree,
    _paths: Paths,
}
impl<E: crate::SyncRuntime + 'static> Attached<E> {
    /// Attach an engine inside `runtime`, on the sync runtime `sync` makes
    /// over the authority's record.
    fn new(
        runtime: &tokio::runtime::Runtime,
        sync: impl FnOnce(&Arc<Mutex<AuthorityState>>) -> Arc<E>,
    ) -> Self {
        let tree = mounted_operation_tree();
        let paths = Paths::new();
        let cfg = input(&tree, &paths);
        let (ready, state, _) = attempt(&cfg, &tree, "valid", &Events::default());
        let sync = sync(&state);
        let mut ready = ready.unwrap();
        let remote = Arc::new(Authority::new(&tree, &state).with_publication());
        let content = Arc::new(
            ready
                .backend_for_test()
                .sync_content(remote.clone())
                .unwrap(),
        );
        let engine = runtime
            .block_on(ready.backend_for_test().attach_sync_with_runtime(
                remote,
                content,
                Arc::new(Time(state.clone())),
                Arc::new(crate::InstantClock::default()),
                crate::ClientMetrics::new(&mut Entropy(35)),
                sync,
                Entropy(36),
            ))
            .unwrap();
        Self {
            ready,
            engine,
            state,
            tree,
            _paths: paths,
        }
    }
    fn mediator(&mut self) -> crate::SharedWritableStore<OverlayDisk> {
        self.ready.backend_for_test().shared_mediator().clone()
    }
    fn probe(&mut self) -> Probe {
        Probe {
            state: self.state.clone(),
            volume: self.tree.volume.clone(),
            mediator: self.mediator(),
        }
    }
}

/// A runtime whose sleeps move the authority's wall clock as far as they
/// ask, so a retry waits out its own delay.
struct WallRuntime(Arc<Mutex<AuthorityState>>);
impl crate::SyncRuntime for WallRuntime {
    fn now(&self) -> tokio::time::Instant {
        FastWaitRuntime.now()
    }
    fn spawn<T: Send + 'static>(
        &self,
        work: impl std::future::Future<Output = T> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        FastWaitRuntime.spawn(work)
    }
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        FastWaitRuntime.blocking(work)
    }
    fn blocking_async<T: Send + 'static, F: std::future::Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        FastWaitRuntime.blocking_async(work)
    }
    fn sleep(&self, duration: std::time::Duration) -> impl std::future::Future<Output = ()> + Send {
        self.0.lock().unwrap().tick += u64::try_from(duration.as_millis()).unwrap();
        FastWaitRuntime.sleep(duration)
    }
    fn timeout_at<T: Send>(
        &self,
        deadline: tokio::time::Instant,
        work: impl std::future::Future<Output = T> + Send,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        FastWaitRuntime.timeout_at(deadline, work)
    }
}

/// A two-worker runtime, as the engine fixture drives its engine.
fn multi_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// [`Attached`] on a [`WallRuntime`], with its controller and `bound`.
fn walled(
    runtime: &tokio::runtime::Runtime,
    bound: std::time::Duration,
) -> (Attached<WallRuntime>, Controller<WallRuntime>) {
    let mut fixture = Attached::new(runtime, |state| Arc::new(WallRuntime(state.clone())));
    let mediator = fixture.mediator();
    let controller = controller(&fixture.engine, mediator, runtime.handle().clone(), bound);
    (fixture, controller)
}

/// The class of each `op.failed` of the unmount among `events`, in order.
fn unmount_failures(events: &Events) -> Vec<String> {
    String::from_utf8(events.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| {
            line.contains("\"event\":\"op.failed\"") && line.contains("\"kind\":\"unmount\"")
        })
        .map(|line| {
            line.split_once("\"class\":\"")
                .and_then(|(_, rest)| rest.split_once('"'))
                .map_or_else(String::new, |(class, _)| class.to_owned())
        })
        .collect()
}

/// The `mount.unmount` lines among `events`.
pub(super) fn unmount_lines(events: &Events) -> Vec<String> {
    String::from_utf8(events.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| line.contains("\"event\":\"mount.unmount\""))
        .map(str::to_owned)
        .collect()
}

/// Three dirty files, a rename and a directory: one registration per file
/// in stage order, one for the namespace, one publication, then the
/// release. A commit before the syncs, syncs out of stage order, a second
/// commit or a published sync per file changes the counts or the order.
#[test]
fn shutdown_syncs_each_dirty_file_then_commits_once_then_releases() {
    let mut cases = 0;
    for profile in [
        crate::SyncProfile::DurablePrepared,
        crate::SyncProfile::Published,
    ] {
        let mut fixture = EngineMount::with_profile(
            Paths::new(),
            mounted_operation_tree(),
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
            profile,
        );
        for (name, length) in [("a", 100), ("b", 200), ("c", 300)] {
            fixture.create(name, &vec![b'x'; length]);
        }
        fixture.rename("original-link", "renamed-link");
        fixture.mkdir("made");
        let before = fixture.registration_count();
        let events = Events::default();
        let outcome =
            tracing::subscriber::with_default(events.subscriber(), || fixture.shut_down());
        let landed = remote_seq(&fixture.tree, &fixture.runtime);
        let registered = fixture.registered(before);
        let sizes: Vec<Vec<Option<u64>>> = registered
            .iter()
            .map(|files| {
                ["a", "b", "c"]
                    .iter()
                    .map(|name| files.get(name.as_bytes()).copied())
                    .collect()
            })
            .collect();
        let lines = unmount_lines(&events);
        assert_eq!(
            (
                outcome,
                landed,
                fixture.publications(),
                sizes,
                fixture.phase(),
                // The journal holds only the landing's refresh, on the landed base.
                matches!(
                    fixture.records()[..],
                    [granary_core::overlay_journal::Record::IntentRegistered {
                        cause: granary_core::overlay_journal::IntentCause::LandedRefresh,
                        ..
                    }]
                ),
                fixture.overlay_base().1,
                fixture.releases(),
                lines.len(),
                lines.first().is_some_and(|line| {
                    line.contains("\"outcome\":\"committed\"")
                        && line.contains(&format!("\"seq\":{landed}"))
                }),
            ),
            (
                Outcome::Committed(2),
                2,
                1,
                vec![
                    vec![Some(100), None, None],
                    vec![Some(100), Some(200), None],
                    vec![Some(100), Some(200), Some(300)],
                    vec![Some(100), Some(200), Some(300)],
                    // The landing's refresh.
                    vec![Some(100), Some(200), Some(300)],
                ],
                Phase::Released,
                true,
                2,
                1,
                1,
                true,
            ),
            "profile={profile:?}: {lines:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn shutdown_observes_configured_workspace() {
    for bound in [8_388_608, 1_073_741_824] {
        let reports = crate::local_report::local_capture();
        let baseline = reports.len();
        let mut fixture = EngineMount::new();
        fixture
            .mediator()
            .with(|store| {
                store.construction_workspace_bytes = bound;
                Ok(())
            })
            .unwrap();
        fixture.create("shutdown-workspace", &vec![7; 2_097_152]);
        let result = fixture.shut_down();
        assert_eq!(
            (
                result,
                reports
                    .since(baseline)
                    .iter()
                    .any(|r| r.contains("SyncWorkspaceExhausted"))
            ),
            (
                if bound == 8_388_608 {
                    Outcome::Incomplete(Cause::Failed(crate::FailureClass::Refused))
                } else {
                    Outcome::Committed(fixture.tree.seq + 1)
                },
                bound == 8_388_608
            ),
            "bound={bound}"
        );
    }
}

/// A fixture in `profile`, its engine driven by two workers.
fn fixture_with(profile: crate::SyncProfile) -> EngineMount {
    EngineMount::with_profile(
        Paths::new(),
        mounted_operation_tree(),
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap(),
        profile,
    )
}

pub(super) const PROFILES: [crate::SyncProfile; 2] = [
    crate::SyncProfile::DurablePrepared,
    crate::SyncProfile::Published,
];

/// A lane its first drive left retained, cut before its submission.
fn retained_lane(fixture: &mut EngineMount) -> u64 {
    retained_lane_at(fixture, "before_submit")
}

/// A lane its first drive left retained, cut at `phase`; a cut before a
/// rebase finds another writer's head published first.
fn retained_lane_at(fixture: &mut EngineMount, phase: &'static str) -> u64 {
    let object = dirty(fixture);
    fixture
        .faults
        .arm("sync.commit", phase, 1, crate::FaultAction::Fail);
    let lane = fixture.construct(70).unwrap();
    if phase == "before_rebase" {
        disjoint_head(&fixture.tree, &fixture.runtime);
    }
    let cut = fixture.drive(&lane, 80);
    assert!(
        cut.is_err_and(|error| error.to_string().contains("SyncInjectedFault")),
        "premise: the first drive is cut"
    );
    fixture
        .ready
        .backend_for_test()
        .overlay_close(object)
        .unwrap();
    object
}

/// How long a row waits for another thread before it names the hang.
pub(super) const HANG: std::time::Duration = std::time::Duration::from_secs(20);

/// Resumes a blocked fault point, so a failing row never leaves it parked.
pub(super) struct ResumeOnDrop(pub(super) crate::FaultControl);
impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        self.0.resume();
    }
}

/// Wait until `name`/`phase` has fired, or name the hang.
pub(super) fn wait_fired(faults: &crate::FaultControl, name: &str, phase: &str) {
    let started = std::time::Instant::now();
    while !faults
        .sync_fired()
        .iter()
        .any(|event| event.name == name && event.phase == phase)
    {
        assert!(started.elapsed() < HANG, "{name}/{phase} never fired");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Wait until `ready` holds, or name the hang.
pub(super) fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while !ready() {
        assert!(started.elapsed() < HANG, "never: {what}");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Start `job`, answering on the returned channel.
pub(super) fn start(
    job: Box<dyn granary_fuse::MountSyncJob>,
) -> std::sync::mpsc::Receiver<Result<(), granary_fuse::MountSyncError>> {
    let (send, receive) = std::sync::mpsc::channel();
    job.start(Box::new(move |result| {
        let _ = send.send(result);
    }));
    receive
}

/// Begin `controller` on its own thread, as a session thread would.
pub(super) fn begin_on_thread<E: crate::SyncRuntime + 'static>(
    controller: &Arc<Controller<E>>,
) -> std::sync::mpsc::Receiver<Outcome> {
    let (send, receive) = std::sync::mpsc::channel();
    let controller = controller.clone();
    std::thread::spawn(move || {
        let _ = send.send(controller.begin(Trigger::SessionEnd).outcome);
    });
    receive
}

/// Whether `mediator`'s store has been closed to mutations.
pub(super) fn closed(mediator: &crate::SharedWritableStore<OverlayDisk>) -> bool {
    mediator.mutations_closed().unwrap()
}

const CLOSING: granary_fuse::WriteError =
    granary_fuse::WriteError::Backend(granary_fuse::MountError::Closing);

/// A clean mount registers and publishes nothing and releases. With stage
/// writes only, the files register and commit and the namespace does not.
/// A directory sync run unconditionally registers once more in each.
#[test]
fn shutdown_of_a_clean_mount_releases_only() {
    let mut cases = 0;
    for profile in PROFILES {
        for written in [false, true] {
            let mut fixture = fixture_with(profile);
            if written {
                let object = dirty(&mut fixture);
                fixture
                    .ready
                    .backend_for_test()
                    .overlay_close(object)
                    .unwrap();
            }
            let before = fixture.registration_count();
            let outcome = fixture.shut_down();
            assert_eq!(
                (
                    outcome,
                    fixture.registration_count() - before,
                    fixture.publications(),
                    fixture.phase(),
                    fixture.releases(),
                ),
                if written {
                    // The file's registration and the landing's refresh.
                    (Outcome::Committed(2), 2, 1, Phase::Released, 1)
                } else {
                    (Outcome::Clean, 0, 0, Phase::Released, 1)
                },
                "profile={profile:?}, written={written}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

/// At the bound a sync held before its registration is prepared, or one
/// whose registration never sends, leaves the journal, the staging and the
/// intent exactly as they were: the outcome names the deadline, no Release
/// is sent, and the event reports the bound.
#[test]
fn shutdown_past_the_bound_keeps_journal_staging_and_intent() {
    let bound = std::time::Duration::from_secs(2);
    let mut cases = 0;
    for profile in PROFILES {
        for (name, phase) in [
            ("sync.capture", "after"),
            ("sync.registration", "before_dispatch"),
        ] {
            let mut fixture = fixture_with(profile);
            fixture.create("a", b"bytes the bound cuts");
            let (records, staging) = (fixture.records(), fixture.staging());
            fixture
                .faults
                .arm(name, phase, 1, crate::FaultAction::Block);
            let resume = ResumeOnDrop(fixture.faults.clone());
            let controller = fixture.controller(bound);
            let events = Events::default();
            let outcome = tracing::subscriber::with_default(events.subscriber(), || {
                controller.begin(Trigger::SessionEnd).outcome
            });
            let lines = unmount_lines(&events);
            let elapsed = lines
                .first()
                .and_then(|line| line.split("\"elapsed_ms\":").nth(1))
                .and_then(|rest| rest.trim_end_matches('}').parse::<u64>().ok());
            assert_eq!(
                (
                    outcome,
                    fixture.records() == records,
                    fixture.staging() == staging,
                    fixture.phase(),
                    fixture.releases(),
                    // From `begin`: the cut, at the bound, to `begin`'s
                    // answer, by the bound and its margin.
                    elapsed.is_some_and(|elapsed| (2000..=2500).contains(&elapsed)),
                    lines
                        .first()
                        .is_some_and(|line| line.contains("\"level\":\"WARN\"")
                            && line.contains("\"outcome\":\"incomplete\"")
                            && line.contains("\"cause\":\"deadline\"")),
                ),
                (
                    Outcome::Incomplete(Cause::Deadline),
                    true,
                    true,
                    Phase::Serving,
                    0,
                    true,
                    true
                ),
                "profile={profile:?}, held at {name}/{phase}: {lines:?}"
            );
            drop(resume);
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

fn non_bookkeeping_operations(records: &[granary_core::overlay_journal::Record]) -> usize {
    use granary_core::overlay_journal::Record;

    records
        .iter()
        .filter(|record| {
            !matches!(
                record,
                Record::IntentRegistered { .. }
                    | Record::CommitBoundary { .. }
                    | Record::LandedCommit { .. }
                    | Record::CommitAttempt { .. }
                    | Record::CommitFence { .. }
                    | Record::ProjectedBoundary { .. }
            )
        })
        .count()
}

/// Five dirty files, the third registration held past the bound: the first
/// two register, and the residue is the other three, counted by their dirty
/// spans, one of them a partial write to a larger base file, with every
/// record since the base that is not bookkeeping.
#[test]
fn shutdown_graduated_residue_counts_the_unsynced_files() {
    let bound = std::time::Duration::from_secs(2);
    let mut cases = 0;
    for profile in PROFILES {
        let mut fixture = fixture_with(profile);
        fixture.create("a", &[b'a'; 100]);
        fixture.create("b", &[b'b'; 200]);
        // The third stage: twelve bytes written over the base file.
        let object = dirty(&mut fixture);
        fixture
            .ready
            .backend_for_test()
            .overlay_close(object)
            .unwrap();
        fixture.create("c", &[b'c'; 400]);
        fixture.create("d", &[b'd'; 500]);
        let before = fixture.registration_count();
        fixture.faults.arm(
            "sync.registration",
            "before_dispatch",
            3,
            crate::FaultAction::Block,
        );
        let resume = ResumeOnDrop(fixture.faults.clone());
        let controller = fixture.controller(bound);
        let events = Events::default();
        let outcome = tracing::subscriber::with_default(events.subscriber(), || {
            controller.begin(Trigger::SessionEnd).outcome
        });
        let operations = non_bookkeeping_operations(&fixture.records());
        let registered = fixture.registered(before);
        let lines = unmount_lines(&events);
        assert_eq!(
            (
                outcome,
                registered
                    .iter()
                    .map(|files| files.contains_key(b"a".as_slice())
                        && files.contains_key(b"b".as_slice()))
                    .collect::<Vec<_>>(),
                lines
                    .first()
                    .is_some_and(|line| line.contains("\"files\":3,")
                        && line.contains("\"bytes\":912,")
                        && line.contains(&format!("\"operations\":{operations},"))),
            ),
            (
                Outcome::Incomplete(Cause::Deadline),
                vec![false, true],
                true
            ),
            "profile={profile:?}, operations={operations}: {lines:?}"
        );
        drop(resume);
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// Once every file has completed its sync, a cut after the commit boundary
/// leaves operations to land but no file stage or dirty byte in the residue.
#[test]
fn shutdown_completed_file_syncs_leave_no_stage_before_commit_lands() {
    use granary_core::overlay_journal::Record;

    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    for (name, length) in [("a", 100), ("b", 200), ("c", 300)] {
        fixture.create(name, &vec![name.as_bytes()[0]; length]);
    }
    fixture.faults.arm(
        "sync.commit",
        "boundary_recorded",
        1,
        crate::FaultAction::Fail,
    );
    let events = Events::default();
    // The armed fault is the only cut this row may take. The bound is the
    // siblings' 15 s, wide enough that durable syncs under a contended
    // full-device flush (F_FULLFSYNC on Apple) cannot reach it first.
    let outcome = tracing::subscriber::with_default(events.subscriber(), || {
        fixture
            .controller(std::time::Duration::from_secs(15))
            .begin(Trigger::SessionEnd)
            .outcome
    });
    let records = fixture.records();
    let operations = non_bookkeeping_operations(&records);
    let synced = records
        .iter()
        .filter(|record| matches!(record, Record::FileSynced { .. }))
        .count();
    let faults: Vec<_> = fixture
        .faults
        .sync_fired()
        .iter()
        .map(|fault| (fault.name, fault.phase, fault.occurrence))
        .collect();
    let lines = unmount_lines(&events);
    assert!(
        matches!(outcome, Outcome::Incomplete(_)),
        "outcome={outcome:?}, faults={faults:?}, records={records:?}, lines={lines:?}"
    );
    assert_eq!(
        faults,
        vec![("sync.commit", "boundary_recorded", 1)],
        "the deterministic post-sync cut did not fire: records={records:?}, lines={lines:?}"
    );
    assert_eq!(
        synced, 3,
        "commit cut did not follow every file sync: {records:?}"
    );
    let reported_operations = lines.first().and_then(|line| {
        line.split_once("\"operations\":")
            .and_then(|(_, value)| value.split_once(','))
            .and_then(|(value, _)| value.parse::<usize>().ok())
    });
    assert!(
        lines.len() == 1
            && lines[0].contains("\"files\":0,")
            && lines[0].contains("\"bytes\":0,")
            && reported_operations == Some(operations),
        "commit-cut residue: operations={operations}, lines={lines:?}"
    );
}

/// A sync that fails before the bound stops the sequence: the next file
/// is never synced, nothing is published and nothing is released.
#[test]
fn shutdown_stops_at_a_failed_step() {
    let runtime = multi_thread();
    let (mut fixture, controller) = walled(&runtime, crate::DEFAULT_RESOLUTION_BOUND);
    for (name, bytes) in [
        ("a", "registers"),
        ("b", "never registers"),
        ("c", "never synced"),
    ] {
        create(fixture.ready.backend_for_test(), name, bytes.as_bytes());
    }
    let probe = fixture.probe();
    let before = probe.registration_count();
    fixture.state.lock().unwrap().registrations_served = Some(1);
    let started = std::time::Instant::now();
    let outcome = controller.begin(Trigger::SessionEnd).outcome;
    let registered = probe.registered(before);
    let publications = fixture.state.lock().unwrap().publications.len();
    assert_eq!(
        (
            outcome,
            started.elapsed() < crate::DEFAULT_RESOLUTION_BOUND,
            registered
                .iter()
                .filter(|files| files.contains_key(b"c".as_slice()))
                .count(),
            publications,
            probe.releases(),
            probe.phase(),
        ),
        (
            Outcome::Incomplete(Cause::Failed(crate::FailureClass::Unavailable)),
            true,
            0,
            0,
            0,
            Phase::Serving
        )
    );
}

/// A Release the authority answers as superseded or absent fences the
/// mount, whether or not a commit moved the base before it: the store is
/// fenced, the backend's shutdown closes its cache and its handle reports
/// the fence, and the event still carries the counts, read from a fenced
/// store.
#[test]
fn shutdown_release_superseded_or_absent_is_fenced() {
    let mut cases = 0;
    for profile in PROFILES {
        for answer in [ReleaseAnswer::Superseded, ReleaseAnswer::Absent] {
            for written in [false, true] {
                let mut fixture = fixture_with(profile);
                if written {
                    fixture.create("a", b"committed before the release");
                }
                fixture.state.lock().unwrap().release_answer = answer;
                let events = Events::default();
                let shutdown = tracing::subscriber::with_default(events.subscriber(), || {
                    granary_fuse::MountBackend::shutdown(fixture.ready.backend_for_test())
                });
                let lines = unmount_lines(&events);
                let report = fixture
                    .ready
                    .backend_for_test()
                    .shutdown_for_test()
                    .and_then(|shutdown| shutdown.report())
                    .map(|report| report.outcome);
                assert_eq!(
                    (
                        (shutdown, report),
                        fixture.phase(),
                        fixture.overlay_base().1,
                        lines
                            .first()
                            .is_some_and(|line| line.contains("\"level\":\"WARN\"")
                                && line.contains("\"outcome\":\"fenced\"")
                                && line.contains("\"files\":0,")
                                && line.contains("\"operations\":")),
                        unmount_failures(&events),
                    ),
                    (
                        (Ok(()), Some(Outcome::Fenced)),
                        Phase::Fenced,
                        1 + u64::from(written),
                        true,
                        vec!["conflict".to_owned()]
                    ),
                    "profile={profile:?}, written={written}: {lines:?}"
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 8);
}

/// A Release the authority refuses without a fence ends the shutdown as
/// failed, with `WritableStore::complete` emitting the one `op.failed` for
/// the unmount. A Release that fails before `complete` retires it still
/// emits its one `op.failed` through `report_outcome`.
#[test]
fn shutdown_release_refused_without_a_fence_emits_one_unmount_failure() {
    let mut cases = 0;
    for profile in PROFILES {
        for answer in [
            ReleaseAnswer::Refused(404, "unknown-target"),
            ReleaseAnswer::Refused(403, "no-principal"),
        ] {
            for written in [false, true] {
                let mut fixture = fixture_with(profile);
                if written {
                    fixture.create("a", b"committed before the refused release");
                }
                fixture.state.lock().unwrap().release_answer = answer;
                let events = Events::default();
                let shutdown = tracing::subscriber::with_default(events.subscriber(), || {
                    granary_fuse::MountBackend::shutdown(fixture.ready.backend_for_test())
                });
                let lines = unmount_lines(&events);
                let report = fixture
                    .ready
                    .backend_for_test()
                    .shutdown_for_test()
                    .and_then(|shutdown| shutdown.report())
                    .map(|report| report.outcome);
                assert_eq!(
                    (
                        (shutdown, report),
                        fixture.phase(),
                        fixture.releases(),
                        fixture.overlay_base().1,
                        lines
                            .first()
                            .is_some_and(|line| line.contains("\"level\":\"WARN\"")
                                && line.contains("\"outcome\":\"incomplete\"")
                                && line.contains("\"cause\":\"failed\"")
                                && line.contains("\"files\":0,")
                                && line.contains("\"operations\":")),
                        unmount_failures(&events),
                    ),
                    (
                        (
                            Ok(()),
                            Some(Outcome::Incomplete(Cause::Failed(
                                crate::FailureClass::Refused
                            )))
                        ),
                        Phase::Releasing,
                        1,
                        1 + u64::from(written),
                        true,
                        vec!["refused".to_owned()],
                    ),
                    "profile={profile:?}, written={written}: {lines:?}"
                );
                cases += 1;
            }
        }
    }
    for (point, sent) in [("intent.send", 0), ("intent.retire", 1)] {
        let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
        fixture.state.lock().unwrap().release_answer =
            ReleaseAnswer::Refused(404, "unknown-target");
        fixture
            .faults
            .arm(point, "before", 1, crate::FaultAction::Fail);
        let events = Events::default();
        let outcome =
            tracing::subscriber::with_default(events.subscriber(), || fixture.shut_down());
        assert_eq!(
            (
                outcome,
                fixture.phase(),
                fixture.releases(),
                unmount_failures(&events),
            ),
            (
                Outcome::Incomplete(Cause::Failed(crate::FailureClass::Io)),
                Phase::Releasing,
                sent,
                vec!["io".to_owned()],
            ),
            "point={point}"
        );
        cases += 1;
    }
    assert_eq!(cases, 10);
}

/// A commit the authority refuses outright, or rate-limits through its
/// whole dispatch budget, fences the mount before any Release is sent.
#[test]
fn shutdown_commit_rejected_or_exhausted_is_fenced() {
    let mut cases = 0;
    for profile in PROFILES {
        for rejected in [false, true] {
            let mut fixture = fixture_with(profile);
            let object = dirty(&mut fixture);
            fixture
                .ready
                .backend_for_test()
                .overlay_close(object)
                .unwrap();
            {
                let mut state = fixture.state.lock().unwrap();
                if rejected {
                    state.reject_publications = true;
                } else {
                    state.publish_refusals = 8;
                }
            }
            let events = Events::default();
            let outcome =
                tracing::subscriber::with_default(events.subscriber(), || fixture.shut_down());
            assert_eq!(
                (
                    outcome,
                    fixture.releases(),
                    remote_seq(&fixture.tree, &fixture.runtime),
                    unmount_failures(&events),
                ),
                (Outcome::Fenced, 0, 1, vec!["conflict".to_owned()]),
                "profile={profile:?}, rejected={rejected}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

/// A Release the authority never answers is retried to the bound, not
/// abandoned before it: the outcome names the deadline at the bound, the
/// Release stays retained to expire with the shutdown, and the counts are
/// read from the releasing store.
#[test]
fn shutdown_release_unknown_at_the_bound_stays_retained() {
    let bound = std::time::Duration::from_secs(2);
    let runtime = multi_thread();
    let (mut fixture, controller) = walled(&runtime, bound);
    fixture.state.lock().unwrap().release_answer = ReleaseAnswer::Unavailable;
    let probe = fixture.probe();
    let events = Events::default();
    let started = std::time::Instant::now();
    let outcome = tracing::subscriber::with_default(events.subscriber(), || {
        controller.begin(Trigger::SessionEnd).outcome
    });
    let elapsed = started.elapsed();
    let release = probe
        .mediator
        .with(|store| {
            Ok(store
                .snapshot()
                .pending
                .iter()
                .find(|pending| {
                    pending.operation == granary_core::overlay_ownership::Operation::Release
                })
                .map(|pending| {
                    (
                        pending.terminal,
                        pending.expires.saturating_sub(pending.first),
                    )
                }))
        })
        .unwrap();
    let lines = unmount_lines(&events);
    assert_eq!(
        (
            outcome,
            elapsed >= bound,
            probe.releases() > 1,
            // It expires with the shutdown: within the bound of its first try.
            release.map(|(terminal, horizon)| (terminal, horizon <= 2000)),
            probe.phase(),
            lines.first().is_some_and(
                |line| line.contains("\"cause\":\"deadline\"") && line.contains("\"files\":0,")
            ),
        ),
        (
            Outcome::Incomplete(Cause::Deadline),
            true,
            true,
            Some((false, true)),
            Phase::Releasing,
            true
        ),
        "{lines:?}"
    );
}

/// A landing recorded whose refresh never ran is not a landing the shutdown
/// can install: it answers unresolved, keeps the lane and releases nothing.
#[test]
fn shutdown_landed_but_uninstalled_lane_is_incomplete() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let object = dirty(&mut fixture);
    fixture
        .faults
        .arm("sync.commit", "landed_refresh", 1, crate::FaultAction::Fail);
    let lane = fixture.construct(70).unwrap();
    assert!(
        fixture.drive(&lane, 80).is_err(),
        "premise: the refresh is cut"
    );
    fixture
        .ready
        .backend_for_test()
        .overlay_close(object)
        .unwrap();
    let outcome = fixture.shut_down();
    assert_eq!(
        (
            matches!(outcome, Outcome::Incomplete(Cause::Failed(_))),
            fixture.retained(),
            fixture.releases(),
            fixture.phase()
        ),
        (true, true, 0, Phase::Serving),
        "{outcome:?}"
    );
}

/// After the latch, every write seam refuses past the pre-check, and
/// nothing reaches the journal or the staging: a file creation, the four
/// namespace records, a write that needs a copy-up, a write to a held
/// stage, and a truncate of a staged file.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one row holds the eight seams' mutations and their shared journal oracle"
)]
fn latch_refuses_each_write_seam() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let held = dirty(&mut fixture);
    let mediator = fixture.mediator();
    mediator
        .with(|store| {
            store.close_mutations();
            Ok(())
        })
        .unwrap();
    let (records, staging) = (fixture.records().len(), fixture.staging().len());
    let g = vec![
        granary_core::manifest::Name::new(b"sub".to_vec()).unwrap(),
        granary_core::manifest::Name::new(b"g.txt".to_vec()).unwrap(),
    ];
    let target = granary_core::manifest::SymlinkTarget::new(b"f.txt".to_vec()).unwrap();
    let [new_file, new_dir, new_link, link, empty, moved, f] = [
        "new-file",
        "new-dir",
        "new-link",
        "original-link",
        "empty",
        "moved",
        "f.txt",
    ]
    .map(|name| handler_path(name.as_bytes()));
    let mutations: Vec<(&str, M<'_>)> = vec![
        (
            "create file",
            M::Create {
                path: &new_file,
                kind: granary_vfs::NodeKind::File,
                exec: false,
            },
        ),
        (
            "create directory",
            M::Create {
                path: &new_dir,
                kind: granary_vfs::NodeKind::Dir,
                exec: false,
            },
        ),
        (
            "symlink",
            M::Symlink {
                path: &new_link,
                target: &target,
            },
        ),
        (
            "remove",
            M::Remove {
                path: &link,
                directory: false,
            },
        ),
        (
            "rename",
            M::Rename {
                from: &empty,
                to: &moved,
                no_replace: false,
            },
        ),
        (
            "write to a clean file",
            M::Write {
                path: &g,
                offset: 0,
                bytes: b"x",
                append: false,
            },
        ),
        (
            "write to a held stage",
            M::BoundWrite {
                object: held,
                offset: 0,
                bytes: b"x",
                append: false,
            },
        ),
        (
            "truncate a staged file",
            M::Setattr {
                path: &f,
                size: Some(1),
                exec: None,
            },
        ),
    ];
    let mut cases = 0;
    for (case, mutation) in mutations {
        let answer = fixture.ready.backend_for_test().overlay_mutate(mutation);
        assert_eq!(
            (answer, fixture.records().len(), fixture.staging().len()),
            (Err(CLOSING), records, staging),
            "{case}"
        );
        cases += 1;
    }
    assert_eq!(cases, 8);
}

/// The production shape: an engine on the Tokio adapter, its current-thread
/// runtime driven by its own `granary-sync` worker, and the shutdown begun
/// from a plain thread outside that runtime. The sequence starts only
/// through the handle the attach captured.
#[test]
fn shutdown_begins_from_a_thread_outside_the_runtime() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut fixture = Attached::new(&runtime, |_| Arc::new(crate::TokioSyncRuntime));
    create(
        fixture.ready.backend_for_test(),
        "a",
        b"outside the runtime",
    );
    let shutdown = fixture
        .ready
        .backend_for_test()
        .shutdown_for_test()
        .unwrap();
    let served = crate::writable_start::WritableSyncRuntime::serve(runtime).unwrap();
    let outcome = std::thread::spawn(move || shutdown.begin(Trigger::SessionEnd).outcome)
        .join()
        .unwrap();
    let probe = fixture.probe();
    assert_eq!(
        (outcome, probe.phase(), probe.releases()),
        (Outcome::Committed(2), Phase::Released, 1)
    );
    drop(served);
}

/// A runtime that, once stopped, starts nothing it is given: its spawned
/// work is kept, never polled, and its join never answers.
#[derive(Default)]
struct StopsPolling(
    AtomicBool,
    Mutex<Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>>,
);
impl crate::SyncRuntime for StopsPolling {
    fn now(&self) -> tokio::time::Instant {
        FastWaitRuntime.now()
    }
    fn spawn<T: Send + 'static>(
        &self,
        work: impl std::future::Future<Output = T> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        let join = if self.0.load(Ordering::SeqCst) {
            self.1.lock().unwrap().push(Box::pin(async move {
                work.await;
            }));
            None
        } else {
            Some(FastWaitRuntime.spawn(work))
        };
        async move {
            match join {
                Some(join) => join.await,
                None => std::future::pending().await,
            }
        }
    }
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        FastWaitRuntime.blocking(work)
    }
    fn blocking_async<T: Send + 'static, F: std::future::Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        FastWaitRuntime.blocking_async(work)
    }
    fn sleep(&self, duration: std::time::Duration) -> impl std::future::Future<Output = ()> + Send {
        FastWaitRuntime.sleep(duration)
    }
    fn timeout_at<T: Send>(
        &self,
        deadline: tokio::time::Instant,
        work: impl std::future::Future<Output = T> + Send,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        FastWaitRuntime.timeout_at(deadline, work)
    }
}

/// A runtime that never runs the sequence cannot hold the session thread:
/// `begin` answers internal once the bound and its margin pass.
#[test]
fn begin_returns_when_the_runtime_cannot_deliver() {
    let bound = std::time::Duration::from_millis(50);
    let runtime = multi_thread();
    let mut fixture = Attached::new(&runtime, |_| Arc::new(StopsPolling::default()));
    fixture
        .engine
        .runtime_for_mount()
        .0
        .store(true, Ordering::SeqCst);
    let mediator = fixture.mediator();
    let controller = Arc::new(controller(
        &fixture.engine,
        mediator,
        runtime.handle().clone(),
        bound,
    ));
    let started = std::time::Instant::now();
    let answer = begin_on_thread(&controller)
        .recv_timeout(bound + std::time::Duration::from_millis(1_500))
        .ok();
    assert_eq!(
        (
            answer,
            started.elapsed() < bound + std::time::Duration::from_millis(1_500)
        ),
        (Some(Outcome::Incomplete(Cause::Internal)), true)
    );
}

/// A sequence that panics answers internal at once, through the monitor
/// that joins it, long before its bound.
#[test]
fn sequence_panic_reports_internal_within_the_margin() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let controller = Arc::new(fixture.controller(crate::DEFAULT_RESOLUTION_BOUND));
    controller.panic_for_test();
    let started = std::time::Instant::now();
    let answer = begin_on_thread(&controller)
        .recv_timeout(std::time::Duration::from_secs(1))
        .ok();
    assert_eq!(
        (
            answer,
            started.elapsed() < std::time::Duration::from_secs(1)
        ),
        (Some(Outcome::Incomplete(Cause::Internal)), true)
    );
}

/// The sync runtime's drop returns within its slack while blocking work it
/// started is still running; that work is released afterwards.
#[test]
fn sync_runtime_drop_returns_within_its_slack() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (release, parked) = std::sync::mpsc::channel::<()>();
    let (finished, done) = std::sync::mpsc::channel();
    runtime.block_on(async move {
        drop(crate::SyncRuntime::blocking(
            &crate::TokioSyncRuntime,
            move || {
                let _ = parked.recv();
                let _ = finished.send(());
            },
        ));
    });
    let served = crate::writable_start::WritableSyncRuntime::serve(runtime).unwrap();
    let (dropped, answer) = std::sync::mpsc::channel();
    let started = std::time::Instant::now();
    std::thread::spawn(move || {
        drop(served);
        let _ = dropped.send(());
    });
    let returned = answer
        .recv_timeout(std::time::Duration::from_secs(3))
        .is_ok();
    let elapsed = started.elapsed();
    release.send(()).unwrap();
    assert_eq!(
        (
            returned,
            elapsed < std::time::Duration::from_secs(3),
            done.recv_timeout(HANG).is_ok()
        ),
        (true, true, true)
    );
}

/// A sync admitted at the adapter before the latch is counted in the same
/// acquisition that reads the latch: a shutdown begun between that
/// acquisition and the job's start waits for the job, which then completes,
/// and the shutdown goes on. Control: a sync asked for after the latch is
/// refused with nothing counted.
#[test]
fn a_sync_admitted_across_the_latch_is_counted_or_refused() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let object = dirty(&mut fixture);
    let mediator = fixture.mediator();
    let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(15)));
    let begun = Arc::new(Mutex::new(None));
    {
        let (controller, begun) = (controller.clone(), begun.clone());
        fixture.ready.backend_for_test().after_view_hook = Some(Box::new(move |mediator| {
            *begun.lock().unwrap() = Some(begin_on_thread(&controller));
            wait_until("the latch closed", || closed(mediator));
        }));
    }
    let job = fixture
        .ready
        .backend_for_test()
        .prepare_sync(granary_fuse::MountSyncRequest::File {
            object,
            datasync: false,
        })
        .unwrap();
    let outcome = begun.lock().unwrap().take().unwrap();
    // The shutdown waits for the unstarted job it counted.
    std::thread::sleep(std::time::Duration::from_secs(1));
    let waiting = (
        fixture.phase(),
        mediator.with(|store| Ok(store.admitted_syncs)).unwrap(),
        outcome.try_recv().is_err(),
    );
    let synced = start(job).recv_timeout(HANG).ok();
    let outcome = outcome.recv_timeout(HANG).ok();
    assert_eq!(
        (waiting, synced, outcome, fixture.phase()),
        (
            (Phase::Serving, 1, true),
            Some(Ok(())),
            Some(Outcome::Committed(2)),
            Phase::Released
        )
    );
    fixture
        .ready
        .backend_for_test()
        .overlay_close(object)
        .unwrap();

    let mut control = fixture_with(crate::SyncProfile::DurablePrepared);
    let object = dirty(&mut control);
    let mediator = control.mediator();
    mediator
        .with(|store| {
            store.close_mutations();
            Ok(())
        })
        .unwrap();
    let refused = control
        .ready
        .backend_for_test()
        .prepare_sync(granary_fuse::MountSyncRequest::File {
            object,
            datasync: false,
        })
        .err();
    assert_eq!(
        (
            refused,
            mediator.with(|store| Ok(store.admitted_syncs)).unwrap()
        ),
        (
            Some(granary_fuse::MountSyncError::Backend(
                granary_fuse::MountError::Closing
            )),
            0
        )
    );
}

/// A write that passed its pre-check before the latch and was held in its
/// preparation while the shutdown ran to step 3 is refused at its effect:
/// no stage is made for it and nothing of it is journaled, while reads of
/// the same file are served throughout.
#[test]
fn latch_refuses_a_mutation_between_its_check_and_its_effect() {
    use granary_core::overlay_journal::Record;
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    fixture.create("other", b"held at step 3");
    let file = handler_path(b"f.txt");
    let object = fixture
        .ready
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    let before = (fixture.records().len(), fixture.staging().len());
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let resume = ResumeOnDrop(fixture.faults.clone());
    let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(15)));
    let begun = Arc::new(Mutex::new(None));
    {
        let (controller, begun, faults) =
            (controller.clone(), begun.clone(), fixture.faults.clone());
        fixture.ready.backend_for_test().before_materialize_hook = Some(Box::new(move |_| {
            *begun.lock().unwrap() = Some(begin_on_thread(&controller));
            wait_fired(&faults, "sync.registration", "before_dispatch");
        }));
    }
    let backend = fixture.ready.backend_for_test();
    let checked = backend.mutation_readiness();
    let prepared = backend.prepare_object(object);
    let write = backend.overlay_mutate(M::BoundWrite {
        object,
        offset: 0,
        bytes: b"never lands",
        append: false,
    });
    let served = (
        backend.overlay_path(&file).is_ok(),
        backend.read_object(object, 0, FILE_CONTENT.len()),
    );
    let after = (fixture.records(), fixture.staging().len());
    drop(resume);
    let outcome = begun
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .recv_timeout(HANG)
        .ok();
    assert_eq!(
        (
            checked,
            prepared,
            write,
            served,
            after.0[before.0..].to_vec(),
            after.1 - before.1,
            outcome,
        ),
        (
            Ok(()),
            Ok(()),
            Err(CLOSING),
            (true, Ok(FILE_CONTENT.to_vec())),
            Vec::<Record>::new(),
            0,
            Some(Outcome::Committed(2)),
        )
    );
}

/// One size-and-exec change, as each of its three entries takes it.
#[derive(Clone, Copy, Debug)]
enum SizeAndExec {
    /// A path's setattr through the backend.
    Setattr,
    /// A held object's setattr.
    Bound,
    /// A path's setattr through the mutation entry.
    Mutate,
}
impl SizeAndExec {
    /// Apply size 4 and exec on the staged `f.txt`, held as `object`.
    fn apply(
        self,
        backend: &mut crate::WritableMount<Authority, OverlayDisk>,
        object: u64,
    ) -> Result<(), granary_fuse::WriteError> {
        let file = handler_path(b"f.txt");
        match self {
            Self::Setattr => backend
                .overlay_setattr(&file, Some(4), Some(true))
                .map(|_| ()),
            Self::Bound => backend.overlay_mutate(M::BoundSetattr {
                object,
                size: Some(4),
                exec: Some(true),
            }),
            Self::Mutate => backend.overlay_mutate(M::Setattr {
                path: &file,
                size: Some(4),
                exec: Some(true),
            }),
        }
    }
}

/// The records of the journal at `journal`.
fn journal_records(journal: &Path) -> Vec<granary_core::overlay_journal::Record> {
    let bytes = std::fs::read(journal).unwrap();
    let mut records = Vec::new();
    granary_core::overlay_journal::scan_journal_with(&bytes, |_, record| {
        records.push(record.clone());
    })
    .unwrap();
    records
}

/// Close `mediator` to mutations right after the first acquisition on this
/// thread that leaves a record `landed` names in the journal at `journal`.
fn latch_once_journaled(
    mediator: crate::SharedWritableStore<OverlayDisk>,
    journal: std::path::PathBuf,
    landed: Arc<dyn Fn(&granary_core::overlay_journal::Record) -> bool>,
) {
    crate::writable_store::track_acquisitions_for_test(Some((
        1,
        Box::new(move || {
            if journal_records(&journal)
                .iter()
                .any(|record| landed(record))
            {
                mediator
                    .with(|store| {
                        store.close_mutations();
                        Ok(())
                    })
                    .unwrap();
            } else {
                latch_once_journaled(mediator, journal, landed);
            }
        }),
    )));
}

impl EngineMount {
    fn journal(&self) -> std::path::PathBuf {
        overlay_area(&self.paths, &input(&self.tree, &self.paths)).join("journal")
    }
}

/// A size-and-exec change lands in one transaction: a latch set right after
/// the acquisition that journals its truncate finds the exec change already
/// recorded, and only the next mutation refuses. The acquisition is found
/// by the journal it leaves, not by a count a split would shift.
#[test]
fn a_size_and_exec_setattr_is_one_transaction() {
    use granary_core::overlay_journal::Record;
    let mut cases = 0;
    for entry in [
        SizeAndExec::Setattr,
        SizeAndExec::Bound,
        SizeAndExec::Mutate,
    ] {
        let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
        let object = dirty(&mut fixture);
        latch_once_journaled(
            fixture.mediator(),
            fixture.journal(),
            Arc::new(|record| matches!(record, Record::Truncate { new_size: 4, .. })),
        );
        let changed = entry.apply(fixture.ready.backend_for_test(), object);
        crate::writable_store::track_acquisitions_for_test(None);
        let next = fixture.ready.backend_for_test().overlay_mutate(M::Create {
            path: &handler_path(b"next"),
            kind: granary_vfs::NodeKind::File,
            exec: false,
        });
        let records = fixture.records();
        assert_eq!(
            (
                changed,
                next,
                records
                    .iter()
                    .any(|record| matches!(record, Record::Truncate { new_size: 4, .. })),
                matches!(records.last(), Some(Record::SetattrExec { exec: true, .. })),
            ),
            (Ok(()), Err(CLOSING), true, true),
            "{entry:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

/// A latch set right after a write's copy-up refuses the write itself: the
/// stage the copy-up made holds the base's bytes and nothing else, so the
/// commit carries the file as it was.
#[test]
fn a_latch_after_a_copy_up_refuses_the_write() {
    use granary_core::overlay_journal::Record;
    let file = handler_path(b"f.txt");
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    fixture
        .ready
        .backend_for_test()
        .prepare_overlay(&file)
        .unwrap();
    let staged = fixture.staging().len();
    latch_once_journaled(
        fixture.mediator(),
        fixture.journal(),
        Arc::new(|record| matches!(record, Record::StageBind { .. })),
    );
    let refused = fixture.ready.backend_for_test().overlay_mutate(M::Write {
        path: &file,
        offset: 0,
        bytes: b"refused",
        append: false,
    });
    crate::writable_store::track_acquisitions_for_test(None);
    let made = fixture.staging().len() - staged;
    let written = fixture
        .records()
        .iter()
        .any(|record| matches!(record, Record::WriteExtent { .. }));
    let before = fixture.registration_count();
    let outcome = fixture.shut_down();
    let registered = fixture.registered(before);
    assert_eq!(
        (
            refused,
            made,
            written,
            outcome,
            registered
                .last()
                .and_then(|files| files.get(b"f.txt".as_slice()).copied()),
        ),
        (
            Err(CLOSING),
            1,
            false,
            Outcome::Committed(2),
            Some(FILE_CONTENT.len() as u64)
        )
    );
}

/// A shrink waiting on a sync's floor wakes at the latch and refuses with
/// nothing truncated, and a sync asked for after the latch refuses too.
#[test]
fn latch_refuses_a_pending_shrink_and_syncs() {
    use granary_core::overlay_journal::Record;
    use granary_fuse::MountSyncRequest;
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let object = dirty(&mut fixture);
    let file = handler_path(b"f.txt");
    fixture
        .faults
        .arm("sync.capture", "after", 1, crate::FaultAction::Block);
    let resume = ResumeOnDrop(fixture.faults.clone());
    let synced = start(
        fixture
            .ready
            .backend_for_test()
            .prepare_sync(MountSyncRequest::File {
                object,
                datasync: false,
            })
            .unwrap(),
    );
    wait_fired(&fixture.faults, "sync.capture", "after");
    let pending = fixture
        .ready
        .backend_for_test()
        .overlay_mutate(M::BoundSetattr {
            object,
            size: Some(0),
            exec: None,
        });
    let shrink = start(
        fixture
            .ready
            .backend_for_test()
            .prepare_shrink_retry(granary_fuse::MountShrinkRequest {
                inode: object,
                object: Some(object),
                path: file,
                size: 0,
                exec: None,
            })
            .unwrap(),
    );
    let waiting = shrink
        .recv_timeout(std::time::Duration::from_millis(200))
        .is_err();
    let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(15)));
    let outcome = begin_on_thread(&controller);
    let answered = shrink.recv_timeout(std::time::Duration::from_secs(3)).ok();
    let truncated = fixture
        .records()
        .iter()
        .any(|record| matches!(record, Record::Truncate { new_size: 0, .. }));
    drop(resume);
    let synced = synced.recv_timeout(HANG).ok();
    let outcome = outcome.recv_timeout(HANG).ok();
    let after = fixture
        .ready
        .backend_for_test()
        .prepare_sync(MountSyncRequest::File {
            object,
            datasync: false,
        })
        .err();
    let closing = granary_fuse::MountSyncError::Backend(granary_fuse::MountError::Closing);
    assert_eq!(
        (
            pending, waiting, answered, truncated, synced, outcome, after
        ),
        (
            Err(granary_fuse::WriteError::PendingShrink),
            true,
            Some(Err(closing)),
            false,
            Some(Ok(())),
            Some(Outcome::Committed(2)),
            Some(closing),
        )
    );
}

/// After the latch, with the sequence held at its commit, every read is
/// served: a lookup, the attributes, a directory listing, a read of an open
/// file and its release. And a store closed to mutations defers an
/// adoption it would otherwise take.
#[test]
fn latch_never_gates_a_read() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    fixture.create("other", b"held at the commit");
    let file = handler_path(b"f.txt");
    let object = fixture
        .ready
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    fixture
        .ready
        .backend_for_test()
        .prepare_object(object)
        .unwrap();
    fixture
        .faults
        .arm("sync.commit", "before_submit", 1, crate::FaultAction::Block);
    let resume = ResumeOnDrop(fixture.faults.clone());
    let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(15)));
    let outcome = begin_on_thread(&controller);
    wait_fired(&fixture.faults, "sync.commit", "before_submit");
    let backend = fixture.ready.backend_for_test();
    let directory = backend.overlay_directory(&[]);
    let served = (
        backend
            .overlay_lookup(
                &[],
                &granary_core::manifest::Name::new(b"f.txt".to_vec()).unwrap(),
            )
            .is_ok(),
        backend.overlay_path(&file).is_ok(),
        directory
            .as_ref()
            .is_ok_and(|directory| backend.overlay_children(&directory.cursor).is_ok()),
        backend.read_object(object, 0, FILE_CONTENT.len()),
        backend.overlay_close(object),
    );
    drop(resume);
    let outcome = outcome.recv_timeout(HANG).ok();
    assert_eq!(
        (served, outcome),
        (
            (true, true, true, Ok(FILE_CONTENT.to_vec()), Ok(())),
            Some(Outcome::Committed(2))
        )
    );

    let mut clean = fixture_with(crate::SyncProfile::DurablePrepared);
    let mediator = clean.mediator();
    let open = clean.engine.adoption_blocked().unwrap();
    mediator
        .with(|store| {
            store.close_mutations();
            Ok(())
        })
        .unwrap();
    assert_eq!(
        (open, clean.engine.adoption_blocked().unwrap()),
        (false, true),
        "(adoption blocked before the latch, after it)"
    );
}

/// A sync admitted before the latch and held at its registration orders
/// the shutdown's own syncs after it: while it is held, no registration
/// of the shutdown's is sent. It then answers, and the shutdown goes on.
#[test]
fn drain_orders_a_held_pre_latch_sync_before_the_shutdowns_syncs() {
    use granary_fuse::MountSyncRequest;
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let object = dirty(&mut fixture);
    fixture.create("other", b"synced by the shutdown");
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let resume = ResumeOnDrop(fixture.faults.clone());
    let synced = start(
        fixture
            .ready
            .backend_for_test()
            .prepare_sync(MountSyncRequest::File {
                object,
                datasync: false,
            })
            .unwrap(),
    );
    wait_fired(&fixture.faults, "sync.registration", "before_dispatch");
    let before = fixture.registration_count();
    let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(15)));
    let outcome = begin_on_thread(&controller);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let held = fixture.registration_count() - before;
    drop(resume);
    let synced = synced.recv_timeout(HANG).ok();
    let outcome = outcome.recv_timeout(HANG).ok();
    assert_eq!(
        (held, synced, outcome),
        (0, Some(Ok(())), Some(Outcome::Committed(2)))
    );
    fixture
        .ready
        .backend_for_test()
        .overlay_close(object)
        .unwrap();
}

/// A shutdown over a poisoned mediator reads no residue: its event carries
/// no counts, never a guessed one.
#[test]
fn shutdown_over_a_poisoned_mediator_reports_no_counts() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let mediator = fixture.mediator();
    let store = mediator.as_arc();
    let _ = std::thread::spawn(move || {
        let _held = store.lock().unwrap();
        panic!("a mediator transaction panics");
    })
    .join();
    let controller = fixture.controller(std::time::Duration::from_secs(5));
    let events = Events::default();
    let outcome = tracing::subscriber::with_default(events.subscriber(), || {
        controller.begin(Trigger::SessionEnd).outcome
    });
    let lines = unmount_lines(&events);
    assert_eq!(
        (
            matches!(outcome, Outcome::Incomplete(Cause::Failed(_))),
            lines.len(),
            lines
                .first()
                .is_some_and(|line| line.contains("\"level\":\"WARN\"")
                    && line.contains("\"outcome\":\"incomplete\"")
                    && !line.contains("\"files\"")
                    && !line.contains("\"bytes\"")
                    && !line.contains("\"operations\"")),
        ),
        (true, 1, true),
        "{outcome:?}: {lines:?}"
    );
}

/// The hook-less fixture's landing takes the no-hook branch, which binds no
/// pin: a lane step 1 lands moves the base and leaves the pin on the start's,
/// so step 3's sync of a file written after the lane's capture refuses at
/// its first content call, and nothing is released. Production binds a hook
/// before it serves; this is the shape the hook-bound rows exist to avoid.
#[test]
fn a_hook_less_landing_leaves_the_pin_and_refuses_later_reads() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    retained_lane(&mut fixture);
    fixture.create("later", b"synced after the landing");
    let shutdown = granary_fuse::MountBackend::shutdown(fixture.ready.backend_for_test());
    let report = fixture
        .ready
        .backend_for_test()
        .shutdown_for_test()
        .and_then(|shutdown| shutdown.report())
        .map(|report| report.outcome);
    let (pin, left) = fixture
        .mediator()
        .with(|store| {
            Ok((
                store.mount_pin().map(|pin| pin.base_seq),
                store.shutdown_report().map(|work| work.stages.len()),
            ))
        })
        .unwrap();
    assert_eq!(
        (
            (shutdown, report),
            pin,
            fixture.overlay_base().1,
            fixture.releases(),
            fixture.phase(),
            left,
        ),
        // The later file is still owed, in the kept journal and staging.
        (
            (
                Ok(()),
                Some(Outcome::Incomplete(Cause::Failed(
                    crate::FailureClass::Refused
                )))
            ),
            Some(1),
            2,
            0,
            Phase::Serving,
            Some(1)
        )
    );
}

/// A construction cut once its boundary is durable holds its lane closed
/// for the next start: step 1 waits for it to its deadline, and the store
/// is kept as it was, intent included.
#[test]
fn a_boundary_left_by_a_cut_construction_holds_step_1_to_the_deadline() {
    let bound = std::time::Duration::from_secs(2);
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let object = dirty(&mut fixture);
    fixture.faults.arm(
        "sync.commit",
        "boundary_recorded",
        1,
        crate::FaultAction::Fail,
    );
    assert!(
        fixture.construct(70).is_err(),
        "premise: the boundary is cut"
    );
    fixture
        .ready
        .backend_for_test()
        .overlay_close(object)
        .unwrap();
    let records = fixture.records();
    let shutdown = fixture
        .ready
        .backend_for_test()
        .shutdown_for_test()
        .unwrap();
    shutdown.bound_for_test(bound);
    let started = std::time::Instant::now();
    let outcome = shutdown.begin(Trigger::SessionEnd).outcome;
    assert_eq!(
        (
            outcome,
            started.elapsed() >= bound,
            fixture.records() == records,
            fixture.releases(),
            fixture.phase(),
        ),
        (
            Outcome::Incomplete(Cause::Deadline),
            true,
            true,
            0,
            Phase::Serving
        )
    );
}

/// A runtime that, once delayed, starts what it is given only after the
/// delay, as a busy executor would.
#[derive(Default)]
struct DelaysStart(AtomicBool);
impl crate::SyncRuntime for DelaysStart {
    fn now(&self) -> tokio::time::Instant {
        FastWaitRuntime.now()
    }
    fn spawn<T: Send + 'static>(
        &self,
        work: impl std::future::Future<Output = T> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        let delayed = self.0.load(Ordering::SeqCst);
        FastWaitRuntime.spawn(async move {
            if delayed {
                crate::SyncRuntime::sleep(
                    &crate::TokioSyncRuntime,
                    std::time::Duration::from_secs(2),
                )
                .await;
            }
            work.await
        })
    }
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        FastWaitRuntime.blocking(work)
    }
    fn blocking_async<T: Send + 'static, F: std::future::Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        FastWaitRuntime.blocking_async(work)
    }
    fn sleep(&self, duration: std::time::Duration) -> impl std::future::Future<Output = ()> + Send {
        FastWaitRuntime.sleep(duration)
    }
    fn timeout_at<T: Send>(
        &self,
        deadline: tokio::time::Instant,
        work: impl std::future::Future<Output = T> + Send,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        FastWaitRuntime.timeout_at(deadline, work)
    }
}

/// A runtime that starts the sequence only after `begin` has stopped
/// waiting for it: the deadline taken at `begin` has passed by then, so the
/// late sequence changes nothing, and nothing is released behind the
/// internal outcome `begin` answered.
#[test]
fn begin_cuts_a_sequence_the_runtime_starts_late() {
    let bound = std::time::Duration::from_secs(1);
    let runtime = multi_thread();
    let mut fixture = Attached::new(&runtime, |_| Arc::new(DelaysStart::default()));
    fixture
        .engine
        .runtime_for_mount()
        .0
        .store(true, Ordering::SeqCst);
    let mediator = fixture.mediator();
    let controller = controller(&fixture.engine, mediator, runtime.handle().clone(), bound);
    let outcome = controller.begin(Trigger::SessionEnd).outcome;
    // The sequence starts four seconds after `begin`; give it time to act.
    std::thread::sleep(std::time::Duration::from_secs(6));
    let probe = fixture.probe();
    assert_eq!(
        (outcome, probe.releases(), probe.phase()),
        (Outcome::Incomplete(Cause::Internal), 0, Phase::Serving)
    );
}

/// A second `begin` while the first is held at its registration waits for
/// it and answers the same outcome.
#[test]
fn a_second_begin_waits_for_the_first_outcome() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    fixture.create("a", b"held at its registration");
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let resume = ResumeOnDrop(fixture.faults.clone());
    let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(15)));
    let first = begin_on_thread(&controller);
    wait_fired(&fixture.faults, "sync.registration", "before_dispatch");
    let second = begin_on_thread(&controller);
    let early = second
        .recv_timeout(std::time::Duration::from_millis(300))
        .ok();
    drop(resume);
    let answers = (
        early,
        first.recv_timeout(HANG).ok(),
        second.recv_timeout(HANG).ok(),
    );
    assert_eq!(
        (answers, fixture.releases()),
        (
            (
                None,
                Some(Outcome::Committed(2)),
                Some(Outcome::Committed(2))
            ),
            1
        )
    );
}

/// An engine sync no adapter admitted, so no count holds it, is still
/// drained: while it is held at its registration the shutdown sends none
/// of its own, and the sync's end wakes the drain at once.
#[test]
fn drain_waits_for_an_engine_sync_with_no_admission_count() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let object = dirty(&mut fixture);
    let stage = fixture
        .ready
        .backend_for_test()
        .overlay_object(object)
        .unwrap()
        .stage
        .unwrap();
    fixture.create("other", b"synced by the shutdown");
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let resume = ResumeOnDrop(fixture.faults.clone());
    let entered = fixture.runtime.enter();
    let waiter = fixture.engine.sync(
        crate::SyncTarget::Stage(stage),
        crate::SyncOptions::default(),
    );
    drop(entered);
    let (answered, synced) = std::sync::mpsc::channel();
    drop(fixture.runtime.spawn(async move {
        let _ = answered.send(waiter.wait().await.is_ok());
    }));
    wait_fired(&fixture.faults, "sync.registration", "before_dispatch");
    let before = fixture.registration_count();
    let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(15)));
    let outcome = begin_on_thread(&controller);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let held = fixture.registration_count() - before;
    drop(resume);
    let resumed = std::time::Instant::now();
    let synced = synced.recv_timeout(HANG).ok();
    let outcome = outcome.recv_timeout(HANG).ok();
    assert_eq!(
        (
            held,
            synced,
            outcome,
            resumed.elapsed() < std::time::Duration::from_secs(10)
        ),
        (0, Some(true), Some(Outcome::Committed(2)), true)
    );
    fixture
        .ready
        .backend_for_test()
        .overlay_close(object)
        .unwrap();
}

/// A step that fails before the deadline is a failure, though the outcome
/// is decided after the deadline has passed.
#[test]
fn a_step_error_before_the_deadline_is_failed_though_answered_late() {
    let runtime = multi_thread();
    let (mut fixture, controller) = walled(&runtime, std::time::Duration::from_secs(3));
    create(fixture.ready.backend_for_test(), "a", b"never registers");
    fixture.state.lock().unwrap().registrations_served = Some(0);
    controller.answer_late_for_test();
    let started = std::time::Instant::now();
    let outcome = controller.begin(Trigger::SessionEnd).outcome;
    assert_eq!(
        (
            outcome,
            started.elapsed() >= std::time::Duration::from_secs(3)
        ),
        (
            Outcome::Incomplete(Cause::Failed(crate::FailureClass::Unavailable)),
            true
        )
    );
}

/// A further signal cuts a sequence held at a registration one second into
/// a thirty-second bound: the outcome names the deadline and the cut the
/// signal, well before the bound, and the journal, the staging and the
/// intent are kept as they were, with no Release sent. An expiry that never
/// wakes the sequence holds it to the bound and records the bound's cut.
#[test]
fn expire_cuts_a_running_shutdown_at_once() {
    let bound = std::time::Duration::from_secs(30);
    let mut cases = 0;
    for profile in PROFILES {
        let mut fixture = fixture_with(profile);
        fixture.create("a", b"bytes a second signal cuts");
        let (records, staging) = (fixture.records(), fixture.staging());
        fixture.faults.arm(
            "sync.registration",
            "before_dispatch",
            1,
            crate::FaultAction::Block,
        );
        let resume = ResumeOnDrop(fixture.faults.clone());
        let controller = Arc::new(fixture.controller(bound));
        let expirer = {
            let (controller, faults) = (controller.clone(), fixture.faults.clone());
            std::thread::spawn(move || {
                wait_fired(&faults, "sync.registration", "before_dispatch");
                std::thread::sleep(std::time::Duration::from_secs(1));
                controller.expire();
            })
        };
        let events = Events::default();
        let report = tracing::subscriber::with_default(events.subscriber(), || {
            controller.begin(Trigger::Signal)
        });
        expirer.join().unwrap();
        let lines = unmount_lines(&events);
        assert_eq!(
            (
                report.outcome,
                report.cut,
                (1000..bound.as_millis().try_into().unwrap()).contains(&report.elapsed_ms),
                fixture.records() == records,
                fixture.staging() == staging,
                fixture.phase(),
                fixture.releases(),
                lines
                    .first()
                    .is_some_and(|line| line.contains("\"level\":\"WARN\"")
                        && line.contains("\"outcome\":\"incomplete\"")
                        && line.contains("\"cause\":\"deadline\"")),
            ),
            (
                Outcome::Incomplete(Cause::Deadline),
                Some(Cut::Signal),
                true,
                true,
                true,
                Phase::Serving,
                0,
                true
            ),
            "profile={profile:?}, elapsed_ms={}: {lines:?}",
            report.elapsed_ms
        );
        drop(resume);
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// The report records what cut the sequence where it was decided: the
/// bound's timer, or an expiry before it. An expiry after the bound has
/// already cut a sequence does not rewrite its report, and a sequence that
/// commits has no cut. Recording the bound for every cut fails the expiry
/// case; reading the cut from whether an expiry was ever asked for fails the
/// late-expiry case.
#[test]
fn cut_records_what_ended_the_sequence() {
    // (case, the begin's cut, the stored report's cut)
    type Row = (&'static str, Option<Cut>, Option<Option<Cut>>);
    let held = |bound: u64| {
        let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
        fixture.create("a", b"held at its registration");
        fixture.faults.arm(
            "sync.registration",
            "before_dispatch",
            1,
            crate::FaultAction::Block,
        );
        let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(bound)));
        (fixture, controller)
    };
    let mut rows: Vec<Row> = Vec::new();

    let (fixture, controller) = held(2);
    let resume = ResumeOnDrop(fixture.faults.clone());
    let report = controller.begin(Trigger::Signal);
    rows.push(("the bound", report.cut, Some(report.cut)));
    drop(resume);

    let (fixture, controller) = held(30);
    let resume = ResumeOnDrop(fixture.faults.clone());
    let expirer = {
        let (controller, faults) = (controller.clone(), fixture.faults.clone());
        std::thread::spawn(move || {
            wait_fired(&faults, "sync.registration", "before_dispatch");
            controller.expire();
        })
    };
    let report = controller.begin(Trigger::Signal);
    expirer.join().unwrap();
    rows.push(("an expiry", report.cut, controller.report().map(|r| r.cut)));
    drop(resume);

    let (fixture, controller) = held(2);
    let resume = ResumeOnDrop(fixture.faults.clone());
    let report = controller.begin(Trigger::Signal);
    controller.expire();
    rows.push((
        "the bound, then an expiry",
        report.cut,
        controller.report().map(|r| r.cut),
    ));
    drop(resume);

    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    fixture.create("a", b"committed");
    let controller = fixture.controller(std::time::Duration::from_secs(30));
    let report = controller.begin(Trigger::Signal);
    rows.push((
        "a commit",
        report.cut,
        Some(matches!(report.outcome, Outcome::Committed(_)).then_some(Cut::Bound)),
    ));

    assert_eq!(
        rows,
        vec![
            ("the bound", Some(Cut::Bound), Some(Some(Cut::Bound))),
            ("an expiry", Some(Cut::Signal), Some(Some(Cut::Signal))),
            (
                "the bound, then an expiry",
                Some(Cut::Bound),
                Some(Some(Cut::Bound))
            ),
            // The commit's own marker stands in for its outcome.
            ("a commit", None, Some(Some(Cut::Bound))),
        ],
        "(case, the begin's cut, the stored report's cut)"
    );
}

/// An expiry that arrives once the Release has been answered, while its
/// completion transaction is finishing, leaves a sequence that is ready in
/// the poll that observes it: that poll reports it as it ended, committed
/// and released. The expiry is made on the sequence's own one-thread
/// runtime, so that poll cannot come before the completion has returned.
/// An expiry while the steps are parked at a registration cuts them.
#[test]
fn a_sequence_ready_when_expired_reports_as_it_ended() {
    let one_thread = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let handle = one_thread.handle().clone();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let driver = std::thread::spawn(move || {
        one_thread.block_on(async {
            let _ = stopped.await;
        });
    });

    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    fixture.create("a", b"committed, then expired");
    let mediator = fixture.mediator();
    let controller = Arc::new(controller(
        &fixture.engine,
        mediator.clone(),
        handle,
        std::time::Duration::from_secs(30),
    ));
    let expiring = controller.clone();
    fixture.state.lock().unwrap().on_release = Some(Box::new(move || {
        // Queued on the sequence's runtime before the completion is
        // spawned, it holds that runtime's only thread until the completion
        // has released the store, then expires: the sequence's next poll
        // finds both the flag and its answer.
        drop(tokio::spawn(async move {
            wait_until("the Release completed", || {
                mediator
                    .with(|store| Ok(store.snapshot().phase))
                    .is_ok_and(|phase| phase == Phase::Released)
            });
            std::thread::sleep(std::time::Duration::from_millis(100));
            expiring.expire();
        }));
    }));
    let ready = controller.begin(Trigger::Signal);
    let ready = (
        ready.outcome,
        ready.cut,
        fixture.phase(),
        fixture.releases(),
    );
    let _ = stop.send(());
    driver.join().unwrap();

    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    fixture.create("a", b"cut at its registration");
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let resume = ResumeOnDrop(fixture.faults.clone());
    let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(30)));
    let expirer = {
        let (controller, faults) = (controller.clone(), fixture.faults.clone());
        std::thread::spawn(move || {
            wait_fired(&faults, "sync.registration", "before_dispatch");
            controller.expire();
        })
    };
    let parked = controller.begin(Trigger::Signal);
    expirer.join().unwrap();
    let parked = (
        parked.outcome,
        parked.cut,
        fixture.phase(),
        fixture.releases(),
    );
    drop(resume);

    assert_eq!(
        (ready, parked),
        (
            (Outcome::Committed(2), None, Phase::Released, 1),
            (
                Outcome::Incomplete(Cause::Deadline),
                Some(Cut::Signal),
                Phase::Serving,
                0
            )
        ),
        "((outcome, cut, phase, releases) expired when ready, then parked)"
    );
}

/// An expiry before the shutdown has begun is kept: the sequence still
/// latches, so a later write answers closing, and it is cut at its first
/// poll, so nothing registers and nothing is released. A wake sent with no
/// flag set reaches no waiter, and the sequence would then run to its end.
#[test]
fn expire_before_begin_latches_then_stops() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    fixture.create("a", b"never registers");
    let before = fixture.registration_count();
    let controller = fixture.controller(std::time::Duration::from_secs(30));
    controller.expire();
    let report = controller.begin(Trigger::Signal);
    let write = fixture.ready.backend_for_test().overlay_mutate(M::Create {
        path: &handler_path(b"after"),
        kind: granary_vfs::NodeKind::File,
        exec: false,
    });
    assert_eq!(
        (
            report.outcome,
            report.cut,
            write,
            fixture.registration_count() - before,
            fixture.releases(),
            fixture.phase(),
        ),
        (
            Outcome::Incomplete(Cause::Deadline),
            Some(Cut::Signal),
            Err(CLOSING),
            0,
            0,
            Phase::Serving
        ),
        "(outcome, cut, a later write, registrations, releases, phase)"
    );
}

/// The text of `field` in a JSON event line.
fn text_field(line: &str, field: &str) -> Option<String> {
    line.split_once(&format!("\"{field}\":\""))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(value, _)| value.to_owned())
}

/// The number in `field` of a JSON event line.
fn number_field(line: &str, field: &str) -> Option<u64> {
    line.split_once(&format!("\"{field}\":"))
        .map(|(_, rest)| {
            rest.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .and_then(|digits| digits.parse().ok())
}

/// What a report says in the event's own fields: its outcome and cause
/// labels, its counts, its seq for a released outcome, and its time.
type EventFields = (
    String,
    Option<String>,
    Option<[u64; 3]>,
    Option<u64>,
    Option<u64>,
);

fn report_fields(report: ShutdownReport) -> EventFields {
    let (outcome, cause, seq) = match report.outcome {
        Outcome::Committed(seq) => ("committed", None, Some(seq)),
        Outcome::Clean => ("clean", None, None),
        Outcome::Incomplete(Cause::Deadline) => ("incomplete", Some("deadline"), None),
        Outcome::Incomplete(Cause::Failed(_)) => ("incomplete", Some("failed"), None),
        Outcome::Incomplete(Cause::Internal) => ("incomplete", Some("internal"), None),
        Outcome::Fenced => ("fenced", Some("failed"), None),
    };
    (
        outcome.to_owned(),
        cause.map(str::to_owned),
        report
            .residue
            .map(|residue| [residue.files, residue.bytes, residue.operations]),
        seq,
        Some(report.elapsed_ms),
    )
}

fn line_fields(line: &str) -> EventFields {
    let counts = match (
        number_field(line, "files"),
        number_field(line, "bytes"),
        number_field(line, "operations"),
    ) {
        (Some(files), Some(bytes), Some(operations)) => Some([files, bytes, operations]),
        _ => None,
    };
    let outcome = text_field(line, "outcome").unwrap_or_default();
    let seq = (outcome == "committed")
        .then(|| number_field(line, "seq"))
        .flatten();
    (
        outcome,
        text_field(line, "cause"),
        counts,
        seq,
        number_field(line, "elapsed_ms"),
    )
}

/// The report `controller` holds before it begins, its `begin`'s report
/// under a recording subscriber with the `mount.unmount` lines it emitted,
/// and the report it holds after.
fn observed<E: crate::SyncRuntime + 'static>(
    controller: &Controller<E>,
    trigger: Trigger,
) -> (
    Option<ShutdownReport>,
    ShutdownReport,
    Option<ShutdownReport>,
    Vec<String>,
) {
    let before = controller.report();
    let events = Events::default();
    let report =
        tracing::subscriber::with_default(events.subscriber(), || controller.begin(trigger));
    (before, report, controller.report(), unmount_lines(&events))
}

/// For each way a shutdown ends, its report says what its event says: the
/// outcome, the cause, the counts, the committed seq and the time, so a
/// status line printed from the report cannot disagree with the log. No
/// report is held before the sequence has run, and the one held after is
/// the one `begin` answered.
#[test]
fn report_matches_the_event() {
    let mut rows = Vec::new();
    for (trigger, label) in [(Trigger::Signal, "signal"), (Trigger::Umount, "umount")] {
        for case in ["committed", "clean", "deadline", "fenced", "internal"] {
            let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
            let mut bound = std::time::Duration::from_secs(30);
            match case {
                "committed" => fixture.create("a", b"committed"),
                "deadline" => {
                    fixture.create("a", b"held to the bound");
                    fixture.faults.arm(
                        "sync.registration",
                        "before_dispatch",
                        1,
                        crate::FaultAction::Block,
                    );
                    bound = std::time::Duration::from_secs(2);
                }
                "fenced" => {
                    fixture.state.lock().unwrap().release_answer = ReleaseAnswer::Superseded;
                }
                // A bound past the clock's range loses the sequence before its
                // first step, which still reports.
                "internal" => bound = std::time::Duration::MAX,
                _ => (),
            }
            let resume = ResumeOnDrop(fixture.faults.clone());
            rows.push((case, label, observed(&fixture.controller(bound), trigger)));
            drop(resume);
        }
        let runtime = multi_thread();
        let (mut fixture, controller) = walled(&runtime, crate::DEFAULT_RESOLUTION_BOUND);
        create(fixture.ready.backend_for_test(), "a", b"never registers");
        fixture.state.lock().unwrap().registrations_served = Some(0);
        rows.push(("failed", label, observed(&controller, trigger)));
    }
    let mut cases = 0;
    for (case, label, (before, report, after, lines)) in rows {
        assert_eq!(
            lines
                .iter()
                .map(|line| text_field(line, "trigger"))
                .collect::<Vec<_>>(),
            vec![Some(label.to_owned())],
            "{case}: shutdown reports its initiating trigger {label}"
        );
        assert_eq!(
            (
                before,
                after,
                lines.len(),
                lines.first().map(|line| line_fields(line)),
            ),
            (None, Some(report), 1, Some(report_fields(report))),
            "{case}: (report before, report after, events, the event's fields) for {report:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 12);
}

/// An expiry before the shutdown begins cuts it before its steps are
/// polled at all: a lane retained before the shutdown is not driven, so no
/// commit fault point fires, the lane stays retained, and nothing is sent.
#[test]
fn expire_before_begin_never_polls_the_steps() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    retained_lane(&mut fixture);
    fixture
        .faults
        .arm("sync.commit", "before_submit", 1, crate::FaultAction::Block);
    let resume = ResumeOnDrop(fixture.faults.clone());
    let sends = fixture.state.lock().unwrap().sends.len();
    let controller = fixture.controller(std::time::Duration::from_secs(30));
    controller.expire();
    let report = controller.begin(Trigger::Signal);
    let fired = fixture.fired();
    drop(resume);
    assert_eq!(
        (
            report.outcome,
            report.cut,
            fired,
            fixture.retained(),
            fixture.state.lock().unwrap().sends.len() - sends,
        ),
        (
            Outcome::Incomplete(Cause::Deadline),
            Some(Cut::Signal),
            vec![],
            true,
            0
        ),
        "(outcome, cut, fault points fired, lane retained, sends)"
    );
}

/// A first caller that unwinds after claiming the run still settles it and
/// wakes the caller waiting for it: the first caller is held right after its
/// claim while a second caller begins and waits, then panics, and the second
/// answers a lost report instead of waiting forever, as `destroy` would. A
/// settle that set the state but woke no one leaves the second waiting.
#[test]
fn an_unwinding_begin_settles_its_state() {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(30)));
    let (claimed, held) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    controller.on_claimed_for_test(move || {
        let _ = claimed.send(());
        let _ = released.recv_timeout(HANG);
        panic!("simulated unwind after the claim, for the settle guard's own test");
    });
    let first = {
        let controller = controller.clone();
        std::thread::spawn(move || controller.begin(Trigger::Signal))
    };
    held.recv_timeout(HANG).unwrap();
    let (send, second) = std::sync::mpsc::channel();
    {
        let controller = controller.clone();
        std::thread::spawn(move || {
            let _ = send.send(controller.begin(Trigger::SessionEnd));
        });
    }
    // The second caller finds the run claimed and waits on it.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let waiting = second.try_recv().is_err();
    drop(release);
    let first = first.join();
    let second = second.recv_timeout(std::time::Duration::from_secs(5)).ok();
    assert_eq!(
        (waiting, first.is_err(), second, controller.report()),
        (
            true,
            true,
            Some(ShutdownReport::lost()),
            Some(ShutdownReport::lost())
        ),
        "(the second caller waited, the first caller unwound, the second caller's report, the \
         held report)"
    );
}

#[test]
fn complete_snapshot_unmount_routes_unrepresentable_scoped_sync() {
    for profile in PROFILES {
        let mut fixture = fixture_with(profile);
        fixture.create("poison", b"dead");
        fixture
            .ready
            .backend_for_test()
            .overlay_mutate(M::Remove {
                path: &handler_path(b"poison"),
                directory: false,
            })
            .unwrap();
        fixture.create("poison", b"live");
        fixture.create("later", b"later");
        let before = fixture.registration_count();
        let outcome = fixture.shut_down();
        assert!(
            matches!(outcome, Outcome::Committed(_)),
            "profile={profile:?}: {outcome:?}"
        );
        let registered = fixture.registered(before);
        assert_eq!(
            (
                registered.len(),
                registered
                    .last()
                    .and_then(|files| files.get(b"poison".as_slice()))
                    .copied(),
                registered
                    .last()
                    .and_then(|files| files.get(b"later".as_slice()))
                    .copied(),
                fixture.releases()
            ),
            (1, Some(4), Some(5), 1)
        );
    }
}
