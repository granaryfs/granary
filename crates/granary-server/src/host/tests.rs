// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The host's lifecycle, driven in process: the engine over the
//! simulator's decision log behind a seam that holds (blocking the
//! authority thread, as a hung flush does) or fails one call; a serve step
//! the test watches; a trigger the test fires. The host runs on a thread
//! of its own, so every wait here is bounded and a broken host fails a
//! test rather than hanging the suite.
//!
//! Out-of-line: this crate has its own binary and `tests/` directory.

use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::task::Poll;
use std::time::Duration;

use granary_core::authlog::{Append, EPOCH_LEN, EncodedEnvelope, Envelope, Epoch, encode_envelope};
use granary_core::clock::Clock;
use granary_core::decisionlog::{DecisionLog, LogIoError, MarkerRead};
use granary_core::root::VolumeName;
use granary_core::runmarker::{BootId, EncodedMarker, RunMarker, decode_marker, encode_marker};
use granary_core::sheaf::Timestamp;
use granary_core::testkit::DecisionLogFixture;
use granary_net::accept::ShutdownOutcome;
use granary_sim::decision_log::{LogFaults, SimDecisionLog};
use granary_sim::fakes::{Fault, Faults, Sim, SimStore};
use granary_sim::rng::Rng as SimRng;
use granary_sim::sched::yield_once;
use granary_sim::secure_random::SeededSecureRandom;
use granary_store::crypto::{SigningKey, TrustedKeys};
use tokio::sync::watch;

use super::*;
use crate::authority::{AuthorityHandle, AuthorityParts, Pause, VolumeConfig};
use crate::serve::{
    EXIT_DEADLINE_EXPIRED, EXIT_DRAINED, EXIT_FENCED, EXIT_SERVE_FAILED, EXIT_STARTUP_FAILED,
};

/// The shutdown budget every test runs under.
const BUDGET: Duration = Duration::from_millis(400);
/// What a host exiting "by the deadline" may take past the budget: room
/// for a loaded machine's scheduling, far below a hang.
const SLACK: Duration = Duration::from_secs(3);
/// How long a test waits for something that should happen promptly.
const BOUND: Duration = Duration::from_secs(20);
/// How long a held log call waits for its release before going on by
/// itself, so a test that failed before releasing leaves no thread held
/// for the life of the suite.
const HOLD_CAP: Duration = Duration::from_mins(1);

// ------------------------------------------------------------ the log seam

/// A held call's state: whether the call has reached the hold, and
/// whether the test has released it.
#[derive(Debug, Default)]
struct Hold {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Hold {
    /// Block this thread until released (or [`HOLD_CAP`]), noting that
    /// the call reached the hold.
    fn wait(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            let (next, waited) = self.changed.wait_timeout(state, HOLD_CAP).unwrap();
            state = next;
            if waited.timed_out() {
                break;
            }
        }
    }

    /// Whether a call reaches the hold within `bound`.
    fn reached_within(&self, bound: Duration) -> bool {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, bound, |state| !state.0)
            .unwrap();
        state.0
    }

    fn release(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

/// Releases its hold when dropped, so a failing test frees the thread it
/// held.
struct Releases(Arc<Hold>);

impl Drop for Releases {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Which log call the seam acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    /// A volume's log read: the start's classification.
    Read,
    /// A log's creation: a flush made while serving.
    Initialise,
    /// The **clean** marker write.
    Clean,
}

/// What the seam does to that call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    /// Block the authority thread until released, then make the call.
    Hold,
    /// Fail it without making it: the engine fences.
    Fail,
}

/// The simulator's log, with one call held or failed.
#[derive(Debug, Clone)]
struct SeamLog {
    log: Arc<SimDecisionLog>,
    at: Option<(Call, Act)>,
    hold: Arc<Hold>,
}

impl SeamLog {
    fn act(&self, call: Call) -> Result<(), LogIoError> {
        match self.at {
            Some((at, Act::Hold)) if at == call => {
                self.hold.wait();
                Ok(())
            }
            Some((at, Act::Fail)) if at == call => Err(LogIoError::SyncFailed),
            _ => Ok(()),
        }
    }
}

impl DecisionLog for SeamLog {
    fn read_marker(&self) -> impl Future<Output = Result<MarkerRead, LogIoError>> + Send {
        self.log.read_marker()
    }

    async fn write_marker(&self, marker: &EncodedMarker) -> Result<(), LogIoError> {
        if marker.as_bytes() == encode_marker(&RunMarker::Clean).as_bytes() {
            self.act(Call::Clean)?;
        }
        self.log.write_marker(marker).await
    }

    async fn read(&self, volume: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        self.act(Call::Read)?;
        self.log.read(volume).await
    }

    fn remove_temporary(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<bool, LogIoError>> + Send {
        self.log.remove_temporary(volume)
    }

    async fn initialise(&self, envelope: &EncodedEnvelope) -> Result<(), LogIoError> {
        self.act(Call::Initialise)?;
        self.log.initialise(envelope).await
    }

    fn complete_namespace(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.complete_namespace(volume)
    }

    fn append(&self, append: &Append) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.append(append)
    }

    fn truncate(
        &self,
        volume: &VolumeName,
        len: u64,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.truncate(volume, len)
    }

    fn resync(&self, volume: &VolumeName) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.resync(volume)
    }
}

// ------------------------------------------------------------- the engine

#[derive(Debug)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        }
    }
}

#[derive(Debug)]
struct YieldPause;

impl Pause for YieldPause {
    fn pause(&self, _duration: Duration) -> impl Future<Output = ()> + Send {
        yield_once()
    }
}

fn vol(name: &str) -> VolumeName {
    VolumeName::new(name.to_owned()).unwrap()
}

fn a() -> VolumeName {
    vol("vol-a")
}

fn boot() -> BootId {
    BootId::from_bytes([1; 16])
}

fn configs() -> Vec<VolumeConfig> {
    let key = SigningKey::from_seed(&[0x5A; 32]).unwrap();
    let keys = TrustedKeys::new([*key.public_key()]).unwrap();
    vec![VolumeConfig::new(a(), keys)]
}

/// Drive `future` to completion on the simulator's scheduler: the
/// fixture calls on the log, made from the test's thread.
fn block<T: 'static>(future: impl Future<Output = T> + 'static) -> T {
    granary_sim::scenario::run(0, Box::pin(future))
}

/// A world: the simulator's log, and the seam the engine runs over.
struct World {
    log: Arc<SimDecisionLog>,
    seam: SeamLog,
    _releases: Releases,
}

impl World {
    /// An empty state directory, with `at` held or failed.
    fn new(at: Option<(Call, Act)>) -> Self {
        let log = Arc::new(Sim::new().decision_log(0, LogFaults::none()));
        let hold = Arc::new(Hold::default());
        Self {
            seam: SeamLog {
                log: Arc::clone(&log),
                at,
                hold: Arc::clone(&hold),
            },
            log,
            _releases: Releases(hold),
        }
    }

    /// As [`Self::new`], with a clean marker and, at A's name, a log under
    /// another volume's envelope: the marker admits the start and A
    /// refuses it as damaged.
    fn refusing(at: Option<(Call, Act)>) -> Self {
        let world = Self::new(at);
        world.seed_marker(&RunMarker::Clean);
        let other = Envelope::new(vol("vol-z"), Epoch::from_bytes([7; EPOCH_LEN]));
        let bytes = encode_envelope(&other).as_bytes().to_vec();
        let log = Arc::clone(&world.log);
        block(async move { log.seed_bytes(&a(), bytes).await });
        world
    }

    fn seed_marker(&self, marker: &RunMarker) {
        let log = Arc::clone(&self.log);
        let bytes = encode_marker(marker).as_bytes().to_vec();
        block(async move { log.seed_marker_bytes(&bytes).await });
    }

    fn hold(&self) -> &Hold {
        &self.seam.hold
    }

    fn marker_says(&self) -> Option<RunMarker> {
        let log = Arc::clone(&self.log);
        match block(async move { log.read_marker().await }).unwrap() {
            MarkerRead::Present(bytes) => decode_marker(&bytes).ok(),
            MarkerRead::Missing { .. } => None,
        }
    }

    fn parts(
        &self,
    ) -> AuthorityParts<SeamLog, SimStore, FixedClock, SimRng, SeededSecureRandom, YieldPause> {
        AuthorityParts {
            admission: crate::Admission::chain_fixture(),
            log: self.seam.clone(),
            store: Sim::new().node(1, Faults::just(Fault::FailFrom(0))),
            clock: FixedClock,
            rng: SimRng::seeded(1, 0xA7),
            secure_random: SeededSecureRandom::for_incarnation(1, 1),
            pause: YieldPause,
        }
    }

    /// The engine closure: start, then as `then` says.
    fn engine(&self, then: Then) -> Engine {
        let parts = self.parts();
        let hold = Arc::clone(&self.seam.hold);
        Box::new(move |seat: AuthoritySeat| -> EngineRun {
            Box::pin(async move {
                assert!(
                    then != Then::Panic,
                    "the engine closure panics before the start"
                );
                let Some(driver) = seat.start(parts, configs()).await else {
                    return;
                };
                match then {
                    Then::Run => {
                        let _end = driver.run().await;
                    }
                    Then::DropAndHold => {
                        drop(driver);
                        hold.wait();
                    }
                    Then::DropAndReturn | Then::Panic => drop(driver),
                }
            })
        })
    }
}

type EngineRun = Pin<Box<dyn Future<Output = ()>>>;
type Engine = Box<dyn FnOnce(AuthoritySeat) -> EngineRun + Send>;

/// What the engine closure does after the start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Then {
    /// Drive the driver to its end.
    Run,
    /// Drop the driver unrun and keep the thread, until the hold is
    /// released.
    DropAndHold,
    /// Drop the driver unrun and end the thread.
    DropAndReturn,
    /// Panic before the start.
    Panic,
}

// ------------------------------------------------------------ the serving

/// What the serve step does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Serving {
    /// Bind, answer pings, and drain at once when told to shut down.
    Drains,
    /// As [`Self::Drains`], and initialise A through the handle as it
    /// begins, polling that call beside the pings.
    InitialisesThenDrains,
    /// Answer pings, and never finish draining.
    NeverDrains,
    /// The bind fails.
    BindFails,
    /// Bind, then fail at once.
    FailsAtOnce,
    /// Answer pings, and when told to shut down end with the drain's own
    /// deadline expired.
    DrainDeadlineExpires,
}

type Served = Pin<Box<dyn Future<Output = std::io::Result<ShutdownOutcome>>>>;
type Ping = mpsc::Sender<()>;

/// The serve step: reports its call on `called`, then serves as `how`
/// says, answering each ping on `pings` while it does.
fn serve_step(
    how: Serving,
    called: mpsc::Sender<()>,
    mut pings: tokio::sync::mpsc::UnboundedReceiver<Ping>,
) -> impl FnOnce(AuthorityHandle, watch::Receiver<bool>) -> Result<Served, String> {
    move |handle, mut shutdown| {
        let _reported = called.send(());
        match how {
            Serving::BindFails => return Err("the bind was refused".to_owned()),
            Serving::FailsAtOnce => {
                return Ok(Box::pin(std::future::ready(Err(std::io::Error::other(
                    "the listener failed",
                )))));
            }
            Serving::Drains
            | Serving::InitialisesThenDrains
            | Serving::NeverDrains
            | Serving::DrainDeadlineExpires => {}
        }
        let mut initialising = (how == Serving::InitialisesThenDrains).then(|| {
            Box::pin(async move {
                let _answer = handle.initialise(&a()).await;
            })
        });
        let mut asked = Box::pin(async move {
            loop {
                if *shutdown.borrow_and_update() {
                    return;
                }
                if shutdown.changed().await.is_err() {
                    return;
                }
            }
        });
        let mut shut = false;
        Ok(Box::pin(std::future::poll_fn(move |cx| {
            while let Poll::Ready(Some(ping)) = pings.poll_recv(cx) {
                let _answered = ping.send(());
            }
            if let Some(call) = initialising.as_mut()
                && call.as_mut().poll(cx).is_ready()
            {
                initialising = None;
            }
            if !shut && asked.as_mut().poll(cx).is_ready() {
                shut = true;
            }
            if shut && how == Serving::DrainDeadlineExpires {
                return Poll::Ready(Ok(ShutdownOutcome::DeadlineExpired));
            }
            if shut && how != Serving::NeverDrains {
                return Poll::Ready(Ok(ShutdownOutcome::Drained));
            }
            Poll::Pending
        })) as Served)
    }
}

// --------------------------------------------------------------- the host

/// A host running on its own thread, and the test's ends of its inputs.
struct Host {
    exit: mpsc::Receiver<HostExit>,
    signal: Option<tokio::sync::oneshot::Sender<()>>,
    called: mpsc::Receiver<()>,
    pings: tokio::sync::mpsc::UnboundedSender<Ping>,
}

impl Host {
    fn launch(engine: Engine, how: Serving) -> Self {
        let (signal, signalled) = tokio::sync::oneshot::channel::<()>();
        let (called_tx, called) = mpsc::channel();
        let (pings, pinged) = tokio::sync::mpsc::unbounded_channel();
        let (exited, exit) = mpsc::channel();
        let serve = serve_step(how, called_tx, pinged);
        std::thread::Builder::new()
            .name("host-under-test".to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                // Fires on the test's signal only: a dropped sender is no
                // signal.
                let trigger = async move {
                    if signalled.await.is_err() {
                        std::future::pending::<()>().await;
                    }
                };
                let ended =
                    runtime.block_on(run_authority_host(boot(), engine, serve, trigger, BUDGET));
                let _sent = exited.send(ended);
            })
            .unwrap();
        Self {
            exit,
            signal: Some(signal),
            called,
            pings,
        }
    }

    fn signal(&mut self) {
        if let Some(signal) = self.signal.take() {
            signal.send(()).unwrap();
        }
    }

    /// The host's end, if it ends within `bound`.
    fn exit_within(&self, bound: Duration) -> Option<HostExit> {
        match self.exit.recv_timeout(bound) {
            Ok(exit) => Some(exit),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => panic!("the host's thread ended unanswered"),
        }
    }

    /// The host's code, which it must give within `bound`.
    fn code_within(&self, bound: Duration) -> i32 {
        self.exit_within(bound)
            .unwrap_or_else(|| panic!("the host did not end within {bound:?}"))
            .code
    }

    /// Whether the serve step is called within `bound`.
    fn called_within(&self, bound: Duration) -> bool {
        self.called.recv_timeout(bound).is_ok()
    }

    fn never_called(&self) -> bool {
        self.called.try_recv().is_err()
    }

    /// Whether the serving answers a ping within [`BOUND`].
    fn answers_a_ping(&self) -> bool {
        let (reply_to, replied) = mpsc::channel();
        self.pings.send(reply_to).is_ok() && replied.recv_timeout(BOUND).is_ok()
    }
}

// ---------------------------------------------------------------- the tests

/// The ordinary path: served, signalled, drained and stopped, clean
/// written: 0.
#[test]
fn a_signal_while_serving_drains_stops_and_exits_zero() {
    let world = World::new(None);
    let mut host = Host::launch(world.engine(Then::Run), Serving::Drains);
    assert!(host.called_within(BOUND));
    assert!(host.answers_a_ping());
    host.signal();
    assert_eq!(host.code_within(BOUND), EXIT_DRAINED);
    assert_eq!(world.marker_says(), Some(RunMarker::Clean));
}

/// A drain that ends on its own deadline is the shutdown budget expiring:
/// 3, though the engine stopped and wrote clean.
#[test]
fn a_drain_ending_on_its_own_deadline_exits_three() {
    let world = World::new(None);
    let mut host = Host::launch(world.engine(Then::Run), Serving::DrainDeadlineExpires);
    assert!(host.called_within(BOUND));
    host.signal();
    assert_eq!(host.code_within(BOUND), EXIT_DEADLINE_EXPIRED);
    assert_eq!(world.marker_says(), Some(RunMarker::Clean));
}

/// A signal during a start held at its classification: the host does not
/// end while the start is held; released in time, the start completes,
/// the engine is stopped without the serve step ever being called, and
/// the host exits 0.
#[test]
fn a_signal_during_a_held_start_stops_the_engine_after_it_and_never_serves() {
    let world = World::new(Some((Call::Read, Act::Hold)));
    let mut host = Host::launch(world.engine(Then::Run), Serving::Drains);
    assert!(
        world.hold().reached_within(BOUND),
        "the start reached its read"
    );
    host.signal();
    assert_eq!(host.exit_within(BUDGET / 4), None, "ended during the start");
    world.hold().release();
    assert_eq!(host.code_within(BOUND), EXIT_DRAINED);
    assert!(host.never_called(), "the serve step was called");
    assert_eq!(world.marker_says(), Some(RunMarker::Clean));
}

/// A signal during a start held past the budget: no exit before the
/// budget, and 3 by the deadline. The serve step is never called.
#[test]
fn a_signal_during_a_start_held_past_the_budget_exits_three_by_the_deadline() {
    let world = World::new(Some((Call::Read, Act::Hold)));
    let mut host = Host::launch(world.engine(Then::Run), Serving::Drains);
    assert!(world.hold().reached_within(BOUND));
    host.signal();
    assert_eq!(
        host.exit_within(BUDGET / 2),
        None,
        "ended before the budget"
    );
    assert_eq!(host.code_within(BUDGET + SLACK), EXIT_DEADLINE_EXPIRED);
    assert!(host.never_called());
}

/// Readiness: while the start is held at its classification the serve
/// step is not called; once the start returns a handle, it is.
#[test]
fn serve_is_not_called_until_the_start_returns_a_handle() {
    let world = World::new(Some((Call::Read, Act::Hold)));
    let mut host = Host::launch(world.engine(Then::Run), Serving::Drains);
    assert!(world.hold().reached_within(BOUND));
    assert!(
        !host.called_within(BUDGET),
        "served while the start was held"
    );
    world.hold().release();
    assert!(host.called_within(BOUND), "not served after the start");
    assert!(host.answers_a_ping());
    host.signal();
    assert_eq!(host.code_within(BOUND), EXIT_DRAINED);
}

/// A bind failure after an admitted start: the engine stops, **clean** is
/// durable, and the host exits 2 naming the failure.
#[test]
fn a_bind_failure_after_admission_stops_the_engine_writes_clean_and_exits_two() {
    let world = World::new(None);
    let host = Host::launch(world.engine(Then::Run), Serving::BindFails);
    let exit = host.exit_within(BOUND).unwrap();
    assert_eq!(exit.code, EXIT_STARTUP_FAILED);
    assert_eq!(exit.reason.as_deref(), Some("the bind was refused"));
    assert!(host.called_within(BOUND));
    assert_eq!(world.marker_says(), Some(RunMarker::Clean));
}

/// Serving that ends on its own is a shutdown cause: the engine stops and
/// writes clean, and the host exits 1.
#[test]
fn serving_that_fails_on_its_own_stops_the_engine_and_exits_one() {
    let world = World::new(None);
    let host = Host::launch(world.engine(Then::Run), Serving::FailsAtOnce);
    assert_eq!(host.code_within(BOUND), EXIT_SERVE_FAILED);
    assert_eq!(world.marker_says(), Some(RunMarker::Clean));
}

/// A fence during the final **clean** write: 4.
#[test]
fn a_fence_during_the_final_clean_write_exits_four() {
    let world = World::new(Some((Call::Clean, Act::Fail)));
    let mut host = Host::launch(world.engine(Then::Run), Serving::Drains);
    assert!(host.called_within(BOUND));
    host.signal();
    assert_eq!(host.code_within(BOUND), EXIT_FENCED);
    assert_eq!(world.marker_says(), Some(RunMarker::Running(boot())));
}

/// A final **clean** write that hangs: no exit before the budget, then 3
/// by the deadline.
#[test]
fn a_hung_final_clean_write_exits_three_by_the_deadline() {
    let world = World::new(Some((Call::Clean, Act::Hold)));
    let mut host = Host::launch(world.engine(Then::Run), Serving::Drains);
    assert!(host.called_within(BOUND));
    host.signal();
    assert!(world.hold().reached_within(BOUND));
    assert_eq!(
        host.exit_within(BUDGET / 2),
        None,
        "ended before the budget"
    );
    assert_eq!(host.code_within(BUDGET + SLACK), EXIT_DEADLINE_EXPIRED);
}

/// A fence and an expired budget both observed: the clean write fences
/// and the serving never drains. The fence wins: 4.
#[test]
fn a_fence_and_an_expiry_both_observed_exit_four() {
    let world = World::new(Some((Call::Clean, Act::Fail)));
    let mut host = Host::launch(world.engine(Then::Run), Serving::NeverDrains);
    assert!(host.called_within(BOUND));
    host.signal();
    assert_eq!(
        host.exit_within(BUDGET / 2),
        None,
        "ended before the budget"
    );
    assert_eq!(host.code_within(BUDGET + SLACK), EXIT_FENCED);
}

/// A fence while serving, with no signal, is a shutdown cause: the
/// serving is shut down and the host exits 4.
#[test]
fn a_fence_while_serving_shuts_down_and_exits_four() {
    let world = World::new(Some((Call::Initialise, Act::Fail)));
    let host = Host::launch(world.engine(Then::Run), Serving::InitialisesThenDrains);
    assert_eq!(host.code_within(BOUND), EXIT_FENCED);
}

/// A driver dropped unrun answers the stop `Abandoned`: 1.
#[test]
fn an_abandoned_run_exits_one() {
    let world = World::new(None);
    let mut host = Host::launch(world.engine(Then::DropAndHold), Serving::Drains);
    assert!(host.called_within(BOUND));
    host.signal();
    let exit = host.exit_within(BOUND).unwrap();
    assert_eq!(exit.code, EXIT_SERVE_FAILED);
    assert_eq!(
        exit.reason.as_deref(),
        Some("the authority's driver was dropped unfinished")
    );
}

/// The driver ending without being asked, with no signal, is a shutdown
/// cause, and never 0: 1.
#[test]
fn a_driver_ending_unasked_exits_one() {
    let world = World::new(None);
    let host = Host::launch(world.engine(Then::DropAndReturn), Serving::Drains);
    let exit = host.exit_within(BOUND).unwrap();
    assert_eq!(exit.code, EXIT_SERVE_FAILED);
    assert_eq!(
        exit.reason.as_deref(),
        Some("the authority's driver ended unasked")
    );
}

/// The authority thread ending with no start answer (here a panic): 1,
/// and nothing served.
#[test]
fn the_authority_thread_ending_without_a_result_exits_one() {
    let world = World::new(None);
    let host = Host::launch(world.engine(Then::Panic), Serving::Drains);
    assert_eq!(host.code_within(BOUND), EXIT_SERVE_FAILED);
    assert!(host.never_called());
}

/// A refusal before the marker admits the start (running in this boot):
/// 2 at once, nothing served, the marker untouched.
#[test]
fn a_refusal_before_admission_exits_two_at_once() {
    let world = World::new(None);
    world.seed_marker(&RunMarker::Running(boot()));
    let host = Host::launch(world.engine(Then::Run), Serving::Drains);
    let exit = host.exit_within(BOUND).unwrap();
    assert_eq!(exit.code, EXIT_STARTUP_FAILED);
    assert!(exit.reason.unwrap().contains("running in this boot"));
    assert!(host.never_called());
    assert_eq!(world.marker_says(), Some(RunMarker::Running(boot())));
}

/// Parts that could not be built: 2, naming why.
#[test]
fn parts_not_built_exit_two() {
    let engine: Engine = Box::new(|seat: AuthoritySeat| -> EngineRun {
        Box::pin(async move { seat.not_built("the state directory is absent") })
    });
    let host = Host::launch(engine, Serving::Drains);
    let exit = host.exit_within(BOUND).unwrap();
    assert_eq!(exit.code, EXIT_STARTUP_FAILED);
    assert_eq!(
        exit.reason.as_deref(),
        Some("the state directory is absent")
    );
    assert!(host.never_called());
}

/// A volume refused after admission whose clean write succeeds: 2, clean
/// durable, nothing served.
#[test]
fn a_volume_refused_after_admission_whose_clean_write_succeeds_exits_two() {
    let world = World::refusing(None);
    let host = Host::launch(world.engine(Then::Run), Serving::Drains);
    let exit = host.exit_within(BOUND).unwrap();
    assert_eq!(exit.code, EXIT_STARTUP_FAILED);
    assert!(exit.reason.unwrap().contains("vol-a refused the start"));
    assert!(host.never_called());
    assert_eq!(world.marker_says(), Some(RunMarker::Clean));
}

/// A volume refused after admission, with a signal before the start
/// returns: still 2, since clean was written.
#[test]
fn a_volume_refused_after_a_signal_still_exits_two() {
    let world = World::refusing(Some((Call::Read, Act::Hold)));
    let mut host = Host::launch(world.engine(Then::Run), Serving::Drains);
    assert!(world.hold().reached_within(BOUND));
    host.signal();
    world.hold().release();
    assert_eq!(host.code_within(BOUND), EXIT_STARTUP_FAILED);
    assert_eq!(world.marker_says(), Some(RunMarker::Clean));
}

/// A volume refused after admission whose clean write fences: 4.
#[test]
fn a_volume_refused_after_admission_whose_clean_write_fences_exits_four() {
    let world = World::refusing(Some((Call::Clean, Act::Fail)));
    let host = Host::launch(world.engine(Then::Run), Serving::Drains);
    assert_eq!(host.code_within(BOUND), EXIT_FENCED);
    assert!(host.never_called());
    assert_eq!(world.marker_says(), Some(RunMarker::Running(boot())));
}

/// A volume refused after admission whose clean write hangs, with no
/// signal at all: the refusal notice starts the budget, and the host
/// exits 3 by the deadline, not before.
#[test]
fn a_volume_refused_after_admission_whose_clean_write_hangs_exits_three_without_a_signal() {
    let world = World::refusing(Some((Call::Clean, Act::Hold)));
    let host = Host::launch(world.engine(Then::Run), Serving::Drains);
    assert!(world.hold().reached_within(BOUND));
    assert_eq!(
        host.exit_within(BUDGET / 2),
        None,
        "ended before the budget"
    );
    assert_eq!(host.code_within(BUDGET + SLACK), EXIT_DEADLINE_EXPIRED);
    assert!(host.never_called());
}

/// A flush that never returns blocks only the authority thread: the
/// serving still answers while it is held, and a signal then exits 3 by
/// the deadline.
#[test]
fn a_hung_flush_does_not_stop_serving_and_a_signal_then_exits_three() {
    let world = World::new(Some((Call::Initialise, Act::Hold)));
    let mut host = Host::launch(world.engine(Then::Run), Serving::InitialisesThenDrains);
    assert!(host.called_within(BOUND));
    assert!(world.hold().reached_within(BOUND), "the flush was not held");
    for _ in 0..3 {
        assert!(host.answers_a_ping(), "the serving stopped answering");
    }
    host.signal();
    assert_eq!(
        host.exit_within(BUDGET / 2),
        None,
        "ended before the budget"
    );
    assert_eq!(host.code_within(BUDGET + SLACK), EXIT_DEADLINE_EXPIRED);
}

// ------------------------------------------- the decision reads the present

type NoServe = fn(
    AuthorityHandle,
    watch::Receiver<bool>,
) -> Result<std::future::Ready<std::io::Result<ShutdownOutcome>>, String>;

/// A host state whose shutdown has finished cleanly as far as its polls
/// saw: a signal began it, the engine answered stopped, the serving
/// drained. `fence` is the fence's sender; the watchdog never fires on its
/// own within a test.
fn finished_cleanly(
    fence: &watch::Sender<Option<Fence>>,
) -> Lifecycle<
    NoServe,
    std::future::Ready<std::io::Result<ShutdownOutcome>>,
    std::future::Pending<()>,
> {
    let watchdog = Watchdog::spawn(Duration::from_hours(1))
        .unwrap_or_else(|error| panic!("the watchdog's thread: {error}"));
    let (shutdown, _) = watch::channel(true);
    Lifecycle {
        trigger: None,
        watchdog,
        fence: None,
        fence_now: fence.subscribe(),
        refusal: None,
        reported: None,
        thread_ended: None,
        serve: None,
        serving: None,
        shutdown,
        handle: None,
        stop: Stop::Answered(StopObserved::Stopped),
        fenced: false,
        cause: Some(ShutdownCause::Signal),
        drain: Drain::Done,
        ended_unasked: false,
        reason: None,
    }
}

/// A fence set after the pass polled the fence notice, and before the
/// exit is decided, is still the exit.
#[test]
fn a_fence_set_after_its_poll_and_before_the_decision_exits_four() {
    let (fence, _) = watch::channel(None);
    let mut lifecycle = finished_cleanly(&fence);
    assert_eq!(lifecycle.decide().code, EXIT_DRAINED, "the control");
    fence.send_replace(Some(Fence {
        call: crate::authority::LogCall::WriteMarker,
        volume: None,
        cause: crate::authority::FenceCause::Failed(LogIoError::SyncFailed),
    }));
    assert_eq!(lifecycle.decide().code, EXIT_FENCED);
}

/// A budget that expired after the pass checked it, and before the exit
/// is decided, is still the exit: the stop and drain did not finish
/// before the deadline as the host saw it.
#[test]
fn a_budget_expired_after_its_check_and_before_the_decision_exits_three() {
    let (fence, _) = watch::channel(None);
    let mut lifecycle = finished_cleanly(&fence);
    assert_eq!(lifecycle.decide().code, EXIT_DRAINED, "the control");
    lifecycle.watchdog.expiry.fire();
    assert_eq!(lifecycle.decide().code, EXIT_DEADLINE_EXPIRED);
}

#[test]
fn a_later_cause_does_not_restart_the_first_shutdown_budget() {
    let (fence, _) = watch::channel(None);
    let mut lifecycle = finished_cleanly(&fence);
    lifecycle.cause = None;
    // The first cause must send the watchdog's arm signal. Observe the
    // channel directly so this check is independent of thread scheduling.
    let (arm, arm_calls) = mpsc::channel();
    lifecycle.watchdog = Watchdog {
        arm,
        armed: false,
        expiry: Arc::default(),
    };
    lifecycle.begin(ShutdownCause::Signal);
    assert_eq!(arm_calls.try_recv(), Ok(()), "first cause arms the budget");
    lifecycle.begin(ShutdownCause::StartupFailedAfterAdmission);
    assert_eq!(
        arm_calls.try_recv(),
        Err(mpsc::TryRecvError::Empty),
        "later cause sent another arm signal or replaced the watchdog"
    );
    assert_eq!(lifecycle.cause, Some(ShutdownCause::Signal));
    lifecycle.watchdog.expiry.fire();
    assert_eq!(lifecycle.decide().code, EXIT_DEADLINE_EXPIRED);
}
