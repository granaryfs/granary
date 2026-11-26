// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The production view hook, bound to a writable adapter through a gate
//! that forwards to the real one and can be told to answer busy, to panic,
//! or to hold a revocation's sends.

use super::*;
use crate::writable_start::{GateAction, GateOutcome, Projected, ViewGate, send_revocation};
use granary_fuse::{GranaryFs, SlotBusy, ViewHandle};
use std::collections::VecDeque;
use std::sync::atomic::AtomicUsize;

mod adoption;
mod observer;
mod profile;
mod shutdown;

/// How long a row waits for another thread before it names the hang.
const BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// An answer the gate gives in place of trying the real adapter.
enum Forced {
    Busy(SlotBusy),
    /// `Taken`, with the slot returned before the hook can start to wait.
    TakenThenReturned,
    /// The install's action panics under the real gate.
    Panic,
}

/// The real adapter's gate, with the answers a row forces and a record of
/// what the hook asked of it.
struct TestGate {
    real: Projected<Mount, Authority, OverlayDisk>,
    forced: Mutex<VecDeque<Forced>>,
    always_taken: AtomicBool,
    attempts: AtomicUsize,
    finished: AtomicUsize,
    waker: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Each send waits here once armed.
    send_hold: Latch,
    send_fails: AtomicBool,
    engine: Mutex<std::sync::Weak<CommitEngine>>,
    /// Whether engine admission was free when each send ran.
    sends: Mutex<Vec<bool>>,
    /// The writer test's answer in place of the real adapter's, once set.
    writers: Mutex<Option<bool>>,
    /// Run once, on the install's blocking thread, before its first attempt.
    before_attempt: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl ViewGate<Authority, OverlayDisk> for TestGate {
    fn on_slot_returned(&self, waker: Arc<dyn Fn() + Send + Sync>) -> bool {
        *self.waker.lock().unwrap() = Some(waker.clone());
        self.real.on_slot_returned(waker)
    }
    fn has_slot_waker(&self) -> bool {
        self.real.has_slot_waker()
    }
    fn try_install(
        &self,
        action: &mut Option<GateAction<Authority, OverlayDisk>>,
    ) -> Result<Option<GateOutcome>, SlotBusy> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let before = self.before_attempt.lock().unwrap().take();
        if let Some(before) = before {
            before();
        }
        if self.always_taken.load(Ordering::SeqCst) {
            return Err(SlotBusy::Taken);
        }
        match self.forced.lock().unwrap().pop_front() {
            Some(Forced::Busy(busy)) => Err(busy),
            Some(Forced::TakenThenReturned) => {
                if let Some(waker) = self.waker.lock().unwrap().clone() {
                    waker();
                }
                Err(SlotBusy::Taken)
            }
            Some(Forced::Panic) => {
                let spent = action.take();
                let mut panics: Option<GateAction<Authority, OverlayDisk>> =
                    Some(Box::new(move |_, _| {
                        drop(spent);
                        panic!("an install action panicked under the gate")
                    }));
                self.real.try_install(&mut panics)
            }
            None => self.real.try_install(action),
        }
    }
    fn finish_install(&self) {
        self.finished.fetch_add(1, Ordering::SeqCst);
        self.real.finish_install();
    }
    fn revoke(&self, inodes: &[u64]) -> std::io::Result<()> {
        self.send_hold.hold();
        let free = self
            .engine
            .lock()
            .unwrap()
            .upgrade()
            .is_some_and(|engine| engine.admission_free_for_test());
        self.sends.lock().unwrap().push(free);
        if self.send_fails.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("the kernel refused the send"));
        }
        self.real.revoke(inodes)
    }
    fn write_capable(&self, adapter: &granary_fuse::ViewAdapter<'_>) -> bool {
        self.writers
            .lock()
            .unwrap()
            .unwrap_or_else(|| self.real.write_capable(adapter))
    }
}

/// [`EngineMount`] served through a writable adapter, its engine's view
/// hook bound to that adapter through a [`TestGate`].
struct BoundMount {
    gate: Arc<TestGate>,
    /// The test's own way to the adapter state.
    handle: ViewHandle<Mount>,
    engine: Arc<CommitEngine>,
    faults: crate::FaultControl,
    state: Arc<Mutex<AuthorityState>>,
    metrics: crate::ClientMetrics,
    tree: PublishedTree,
    // The adapter outlives every handle the rows use, the runtime outlives
    // the adapter, and the scratch directories go last.
    _fs: GranaryFs<Mount>,
    runtime: tokio::runtime::Runtime,
    paths: Paths,
}

impl BoundMount {
    fn new() -> Self {
        Self::with_runtime(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
        )
    }
    fn with_runtime(runtime: tokio::runtime::Runtime) -> Self {
        Self::bound(runtime, granary_fuse::kernel_time)
    }
    /// The mount with its hook bound, converting root times with
    /// `kernel_time`.
    fn bound(
        runtime: tokio::runtime::Runtime,
        kernel_time: crate::writable_start::KernelTime,
    ) -> Self {
        let (fixture, binding) = Self::unbound(runtime);
        binding
            .bind_gate(fixture.gate.clone(), kernel_time)
            .unwrap();
        fixture
    }
    /// The mount with its hook bound, its syncs answering as `profile` says.
    fn with_profile(profile: crate::SyncProfile) -> Self {
        let (fixture, binding) = Self::unbound_as(multi_thread(), profile);
        binding
            .bind_gate(fixture.gate.clone(), granary_fuse::kernel_time)
            .unwrap();
        fixture
    }
    /// The mount and the binding its attach left, not yet bound.
    fn unbound(
        runtime: tokio::runtime::Runtime,
    ) -> (Self, crate::ViewBinding<Authority, OverlayDisk>) {
        Self::unbound_as(runtime, crate::SyncProfile::default())
    }
    /// The mount and live binding its test-enabled attach left, not yet bound.
    fn unbound_live(
        runtime: tokio::runtime::Runtime,
    ) -> (Self, crate::ViewBinding<Authority, OverlayDisk>) {
        let EngineMount {
            ready,
            engine,
            runtime,
            faults,
            state,
            metrics,
            tree,
            paths,
        } = EngineMount::with_live(
            Paths::new(),
            mounted_operation_tree(),
            runtime,
            crate::SyncOptions {
                quiesce_delay: std::time::Duration::ZERO,
                max_coalesce_delay: std::time::Duration::ZERO,
                ..crate::SyncOptions::default()
            },
        );
        Self::from_engine_mount(ready, engine, runtime, faults, state, metrics, tree, paths)
    }
    /// [`Self::unbound`], its syncs answering as `profile` says.
    fn unbound_as(
        runtime: tokio::runtime::Runtime,
        profile: crate::SyncProfile,
    ) -> (Self, crate::ViewBinding<Authority, OverlayDisk>) {
        let EngineMount {
            ready,
            engine,
            runtime,
            faults,
            state,
            metrics,
            tree,
            paths,
        } = EngineMount::with_profile(Paths::new(), mounted_operation_tree(), runtime, profile);
        Self::from_engine_mount(ready, engine, runtime, faults, state, metrics, tree, paths)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "the fixture keeps the attached engine's independent test seams explicit"
    )]
    fn from_engine_mount(
        ready: crate::WritableReadiness<Authority, OverlayDisk>,
        engine: Arc<CommitEngine>,
        runtime: tokio::runtime::Runtime,
        faults: crate::FaultControl,
        state: Arc<Mutex<AuthorityState>>,
        metrics: crate::ClientMetrics,
        tree: PublishedTree,
        paths: Paths,
    ) -> (Self, crate::ViewBinding<Authority, OverlayDisk>) {
        let mut attachment = ready.attach();
        let binding = attachment.backend.take_view_binding().unwrap();
        let fs = GranaryFs::new(
            attachment.snapshot,
            attachment.backend,
            1,
            granary_fuse::MountWritability::Writable,
        )
        .unwrap();
        let gate = Arc::new(TestGate {
            real: Projected {
                handle: fs.view_handle(),
                project: |mount| mount,
            },
            forced: Mutex::default(),
            always_taken: AtomicBool::new(false),
            attempts: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
            waker: Mutex::default(),
            send_hold: Latch::default(),
            send_fails: AtomicBool::new(false),
            engine: Mutex::new(Arc::downgrade(&engine)),
            sends: Mutex::default(),
            writers: Mutex::default(),
            before_attempt: Mutex::default(),
        });
        let fixture = Self {
            gate,
            handle: fs.view_handle(),
            engine,
            faults,
            state,
            metrics,
            tree,
            _fs: fs,
            runtime,
            paths,
        };
        (fixture, binding)
    }
    /// Run `action` on the mount under the adapter gate; `None` when the
    /// gate cannot be taken.
    fn with_mount<T>(&self, action: impl FnOnce(&mut Mount) -> T) -> Option<T> {
        self.handle.try_install(|mount, _| action(mount)).ok()
    }
    fn view_pending(&self) -> Option<bool> {
        self.with_mount(|mount| mount.view_pending_for_test())
    }
    fn pin_seq(&self) -> Option<u64> {
        self.with_mount(|mount| mount.pinned_base_for_test().1)
    }
    fn construct(&self, entropy: u8) -> crate::RetainedCommit {
        construct_commit(&self.engine, &self.runtime, entropy).unwrap()
    }
    fn drive(
        &self,
        lane: &crate::RetainedCommit,
        entropy: u8,
    ) -> Result<crate::PublicationResult, crate::CoordinationError> {
        drive_commit(&self.engine, &self.runtime, lane, entropy)
    }
    /// Drive `lane` with a deadline `seconds` away. The fixture runtime
    /// answers a sleep of five seconds or less at once, so a nearer
    /// deadline ends the landing before the install starts.
    fn drive_within(
        &self,
        lane: &crate::RetainedCommit,
        entropy: u8,
        seconds: u64,
    ) -> Result<crate::PublicationResult, crate::CoordinationError> {
        let deadline = crate::TokioSyncRuntime.now() + std::time::Duration::from_secs(seconds);
        self.runtime.block_on(Box::pin(self.engine.drive_commit(
            lane,
            &mut Entropy(entropy),
            &mut NoDelay,
            RecoveryIntent::Continue,
            crate::SyncOptions {
                deadline: Some(deadline),
                ..crate::SyncOptions::default()
            },
        )))
    }
    fn retained(&self) -> bool {
        self.with_mount(|mount| {
            let store = mount.shared_mediator();
            let loaded = store.with(|store| {
                let scope = store.snapshot().scope.clone();
                let volume = store.snapshot().volume.clone();
                store.publication_transaction(|j| j.load(&scope, &volume))
            });
            !matches!(
                loaded,
                Err(crate::CoordinationError::Refused("SyncCommitLaneRequired"))
            )
        })
        .unwrap_or(true)
    }
    /// Plant a root at `seq`, validly signed by the volume's key, in the
    /// mount's cache, so a landing there is an equivocation.
    fn plant_equivocation(&self, seq: u64) {
        let forged = super::super::super::super::sign_root(
            &self.tree,
            &self.tree.key,
            &self.tree.volume,
            seq,
            1,
            [0xAA; 16],
        );
        let path = self
            .paths
            .cache
            .join("roots")
            .join(self.tree.volume.as_str())
            .join(format!("{seq:020}"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, forged).unwrap();
    }
}

/// The `mount.view` events `events` holds, as (installed, refused).
fn view_events(events: &Events) -> (usize, usize) {
    let text = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
    let view = |outcome: &str| {
        text.lines()
            .filter(|line| {
                line.contains("mount.view") && line.contains(&format!("\"outcome\":\"{outcome}\""))
            })
            .count()
    };
    (view("installed"), view("refused"))
}

/// A live loop starts only when the production binding succeeds. Attaching
/// the engine and the finish path's gate binding leave it parked. Case count 3.
#[test]
#[expect(
    clippy::used_underscore_binding,
    reason = "the lifetime-holding adapter supplies the independent production view handle"
)]
fn live_driver_starts_only_from_the_production_binding() {
    let unbound = BoundMount::unbound_live(multi_thread());
    unbound.0.write_path(b"f.txt", b"unbound", false);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let before_binding = unbound.0.engine.live_constructions_for_test();

    let gate_bound = BoundMount::unbound_live(multi_thread());
    gate_bound
        .1
        .bind_gate(gate_bound.0.gate.clone(), granary_fuse::kernel_time)
        .unwrap();
    gate_bound.0.write_path(b"f.txt", b"gate-bound", false);
    std::thread::sleep(std::time::Duration::from_millis(100));
    let after_gate = gate_bound.0.engine.live_constructions_for_test();

    let (production_mount, production_binding) = BoundMount::unbound_live(multi_thread());
    production_binding
        .bind(production_mount._fs.view_handle(), |mount| mount)
        .unwrap();
    production_mount.write_path(b"f.txt", b"production", false);
    assert!(
        eventually(|| production_mount.pin_seq() == Some(2)),
        "the production binding did not start and land the live commit"
    );
    assert_eq!(
        (
            before_binding,
            after_gate,
            production_mount.engine.live_constructions_for_test(),
            production_mount.pin_seq(),
        ),
        (0, 0, 1, Some(2)),
        "(constructions after attach, after bind_gate, after bind, installed sequence)"
    );
}

/// While the install waits for a gate another holder has, the sync runtime
/// keeps running other work and the engine's state lock stays free: the
/// gate is taken on the blocking seam, and the state lock only inside it.
#[test]
fn install_waits_for_the_adapter_without_holding_the_state_lock() {
    // A current-thread runtime, as production's: a second worker would keep
    // a heartbeat going while the install blocked the first.
    let fixture = BoundMount::with_runtime(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
    );
    let lane = fixture.construct(70);
    let ticks = Arc::new(AtomicUsize::new(0));
    let beat = ticks.clone();
    drop(fixture.runtime.spawn(async move {
        loop {
            crate::TokioSyncRuntime
                .sleep(std::time::Duration::from_millis(1))
                .await;
            beat.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let (observed, result) = std::thread::scope(|threads| {
        let driver = threads.spawn(|| fixture.drive(&lane, 80));
        let observed = fixture.with_mount(|_| {
            let reached = eventually(|| fixture.gate.attempts.load(Ordering::SeqCst) > 0);
            // The install's blocking thread is now waiting for this gate.
            std::thread::sleep(std::time::Duration::from_millis(50));
            let before = ticks.load(Ordering::SeqCst);
            let ticking = eventually(|| ticks.load(Ordering::SeqCst) > before + 10);
            (reached, ticking, fixture.engine.state_free_for_test())
        });
        (observed, driver.join().unwrap())
    });
    assert_eq!(
        (observed, refusal(&result), fixture.view_pending()),
        (Some((true, true, true)), "landed".to_owned(), Some(false)),
        "(premise: the install reached the gate, the runtime kept running, the state lock was free)"
    );
}

/// A closed view's sends run on their own task once admission is released:
/// the landing's caller is answered while a send is still held, and the
/// send finds admission free. A refused send is reported once.
#[test]
fn revocation_sends_run_after_admission_is_released() {
    let fixture = BoundMount::new();
    let lane = fixture.construct(70);
    fixture.plant_equivocation(2);
    let hold = &fixture.gate.send_hold;
    hold.arm();
    let (returned, entered, free_while_held) = std::thread::scope(|threads| {
        let _release = ReleaseOnDrop(hold);
        let (done, answered) = std::sync::mpsc::channel();
        let (fixture, lane) = (&fixture, &lane);
        threads.spawn(move || {
            let _ = done.send(fixture.drive(lane, 80));
        });
        let returned = answered.recv_timeout(BOUND).ok();
        let entered = hold.entered();
        let free = fixture.engine.admission_free_for_test();
        hold.release();
        (returned, entered, free)
    });
    let sent = eventually(|| fixture.gate.sends.lock().unwrap().len() == 1);
    assert_eq!(
        (
            returned.as_ref().map(refusal),
            entered,
            free_while_held,
            sent,
            fixture.gate.sends.lock().unwrap().clone(),
            fixture.view_pending(),
        ),
        (
            Some("intent refused: ViewRootEquivocation".to_owned()),
            true,
            true,
            true,
            vec![true],
            Some(true),
        ),
        "(caller answered while the send was held, send started, admission free, sent once)"
    );
    fixture.gate.send_fails.store(true, Ordering::SeqCst);
    let events = Events::default();
    tracing::subscriber::with_default(events.subscriber(), || {
        send_revocation(&*fixture.gate, &[1, 2]);
    });
    let failures = String::from_utf8(events.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| {
            line.contains("\"event\":\"op.failed\"")
                && line.contains("\"kind\":\"view\"")
                && line.contains("\"class\":\"io\"")
        })
        .count();
    assert_eq!(failures, 1);
}

/// Every way an install can end without reaching the mount's own install
/// releases the preparations waiting on it and reports the landing as not
/// installed: a slot not returned by the deadline, an adapter gone or
/// poisoned, and an action that panics under the gate, even when the
/// caller's deadline ends its wait first. A slot returned between the
/// attempt and the wait still wakes it, and it installs.
#[test]
fn an_install_releases_waiting_preparations_and_reports_every_exit() {
    let lost = "intent refused: ViewAdapterLost";
    let mut cases = 0;
    for (case, forced) in [
        ("deadline", None),
        ("abandoned", Some(Forced::Busy(SlotBusy::Abandoned))),
        ("poisoned", Some(Forced::Busy(SlotBusy::Poisoned))),
        ("panicked", Some(Forced::Panic)),
        ("returned", Some(Forced::TakenThenReturned)),
    ] {
        let fixture = BoundMount::new();
        let lane = fixture.construct(70);
        match forced {
            Some(forced) => fixture.gate.forced.lock().unwrap().push_back(forced),
            None => fixture.gate.always_taken.store(true, Ordering::SeqCst),
        }
        let events = Events::default();
        let result = tracing::subscriber::with_default(events.subscriber(), || {
            fixture.drive_within(&lane, 80, 8)
        });
        // A caller whose deadline passes first stops waiting; the install
        // still runs to its end.
        let finished = eventually(|| {
            fixture.gate.finished.load(Ordering::SeqCst) > 0 && view_events(&events) != (0, 0)
        });
        let observed = (
            refusal(&result),
            finished,
            view_events(&events),
            fixture.view_pending(),
            fixture.retained(),
            fixture.gate.sends.lock().unwrap().len(),
        );
        let expected = match case {
            "deadline" => (
                "intent refused: SyncDeadline",
                true,
                (0, 1),
                Some(false),
                true,
                0,
            ),
            "abandoned" | "poisoned" => (lost, true, (0, 1), Some(false), true, 0),
            // The panic poisons the real gate: nothing reads the view again.
            "panicked" => (lost, true, (0, 1), None, true, 0),
            _ => ("landed", true, (1, 0), Some(false), false, 0),
        };
        assert_eq!(
            observed,
            (
                expected.0.to_owned(),
                expected.1,
                expected.2,
                expected.3,
                expected.4,
                expected.5
            ),
            "{case}: (refusal, waiting preparations released, (installed, refused) events, \
             view pending, lane retained, sends)"
        );
        if case == "returned" {
            assert_eq!(fixture.gate.attempts.load(Ordering::SeqCst), 2, "{case}");
        }
        cases += 1;
    }
    assert_eq!(cases, 5);
}

/// The mount accepts the landed root before the switch, so an install that
/// then stops short keeps the root cached and the private floor at its seq.
/// The landing's retry accepts the same root again and installs.
#[test]
fn a_retried_landing_after_a_kept_open_install_is_accepted() {
    let fixture = BoundMount::new();
    let lane = fixture.construct(70);
    fixture.faults.arm(
        "fuse.view.install",
        "before_switch",
        1,
        crate::FaultAction::Fail,
    );
    let first = fixture.drive(&lane, 80);
    let kept = (fixture.view_pending(), fixture.pin_seq());
    let resumed = fixture.drive(&lane, 81);
    assert_eq!(
        (
            refusal(&first),
            kept,
            refusal(&resumed),
            fixture.view_pending(),
            fixture.pin_seq(),
            fixture.gate.sends.lock().unwrap().len(),
        ),
        (
            "intent refused: SyncInjectedFault".to_owned(),
            (Some(false), Some(1)),
            "landed".to_owned(),
            Some(false),
            Some(2),
            0,
        )
    );
}

fn multi_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// A root whose time the kernel cannot hold can never install, so its
/// landing closes the view and revokes it rather than leaving the view open
/// and the lane waiting for an install that cannot come.
#[test]
fn a_root_time_the_kernel_cannot_hold_closes_the_view() {
    let fixture = BoundMount::bound(multi_thread(), |_| None);
    let lane = fixture.construct(70);
    let events = Events::default();
    let result =
        tracing::subscriber::with_default(events.subscriber(), || fixture.drive(&lane, 80));
    let sent = eventually(|| fixture.gate.sends.lock().unwrap().len() == 1);
    assert_eq!(
        (
            refusal(&result),
            fixture.view_pending(),
            sent,
            view_events(&events)
        ),
        (
            "intent refused: ViewTimeUnrepresentable".to_owned(),
            Some(true),
            true,
            (0, 1)
        ),
        "(refusal, view pending, revoked, (installed, refused) events)"
    );
}

/// A binding refused because its engine already has a hook leaves the
/// adapter's one slot waker unregistered, for the binding that is bound.
#[test]
fn a_refused_binding_leaves_the_slot_waker_free() {
    struct Bound;
    impl MountViewHook for Bound {
        fn install(
            &self,
            _: crate::sync::PublishedRoot,
            _: tokio::time::Instant,
            _: LandedCommit,
        ) -> ViewInstall<'_> {
            Box::pin(async { (Err(crate::sync::refused("ViewPending")), Revocation::none()) })
        }
        fn adopt(
            &self,
            _: crate::sync::PublishedRoot,
            _: tokio::time::Instant,
            _: AdoptionCommit,
        ) -> ViewInstall<'_, Adopted> {
            Box::pin(async { (Err(crate::sync::refused("ViewPending")), Revocation::none()) })
        }
        fn close(&self, _: crate::CoordinationError, _: tokio::time::Instant) -> ViewInstall<'_> {
            Box::pin(async { (Err(crate::sync::refused("ViewPending")), Revocation::none()) })
        }
    }
    let (fixture, binding) = BoundMount::unbound(multi_thread());
    fixture.engine.set_view_hook(Arc::new(Bound)).unwrap();
    let refused = binding
        .bind_gate(fixture.gate.clone(), granary_fuse::kernel_time)
        .map_err(|error| error.to_string());
    let registered = fixture.gate.waker.lock().unwrap().is_some();
    let free = fixture.handle.on_slot_returned(Arc::new(|| ()));
    assert_eq!(
        (refused, registered, free),
        (Err("intent refused: ViewHookBound".to_owned()), false, true),
        "(the binding, its waker registered, a later waker registers)"
    );
}

/// A binding onto a handle whose slot already has a waker refuses before it
/// sets anything: the engine is left with no hook, free for a binding that
/// can register its waker.
#[test]
fn a_binding_onto_a_bound_slot_leaves_the_engine_unhooked() {
    struct Spare;
    impl MountViewHook for Spare {
        fn install(
            &self,
            _: crate::sync::PublishedRoot,
            _: tokio::time::Instant,
            _: LandedCommit,
        ) -> ViewInstall<'_> {
            Box::pin(async { (Err(crate::sync::refused("ViewPending")), Revocation::none()) })
        }
        fn adopt(
            &self,
            _: crate::sync::PublishedRoot,
            _: tokio::time::Instant,
            _: AdoptionCommit,
        ) -> ViewInstall<'_, Adopted> {
            Box::pin(async { (Err(crate::sync::refused("ViewPending")), Revocation::none()) })
        }
        fn close(&self, _: crate::CoordinationError, _: tokio::time::Instant) -> ViewInstall<'_> {
            Box::pin(async { (Err(crate::sync::refused("ViewPending")), Revocation::none()) })
        }
    }
    let (fixture, binding) = BoundMount::unbound(multi_thread());
    assert!(
        fixture.handle.on_slot_returned(Arc::new(|| ())),
        "premise: another waker holds the slot"
    );
    let refused = binding
        .bind_gate(fixture.gate.clone(), granary_fuse::kernel_time)
        .map_err(|error| error.to_string());
    // The engine takes a hook only if the refused binding set none.
    let unhooked = fixture.engine.set_view_hook(Arc::new(Spare)).is_ok();
    assert_eq!(
        (refused, unhooked),
        (Err("intent refused: ViewHookBound".to_owned()), true),
        "(the binding, the engine left without a hook)"
    );
}
