// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a host is told as it happens: the fence's notification, sent
//! when the fence is set and not when the run ends, for every cause; and
//! the start's post-admission refusal, sent before its **clean** write
//! begins, so a host sees it while that write succeeds, fences or hangs.

use std::pin::pin;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Poll, Waker};

use granary_core::authlog::GrammarRule;
use tokio::sync::watch;

use super::super::gate::{FenceCell, LogGate};
use super::*;

/// Drive `fut` once: every gate call here completes on its first poll,
/// since nothing else holds the token and the calls it makes are ready.
fn at_once<T>(fut: impl Future<Output = T>) -> T {
    let mut fut = pin!(fut);
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the gate call did not complete at once"),
    }
}

// ------------------------------------------- the fence, at its one setter

/// Every fence cause reaches the receivers through the gate's one
/// mutation point: a failed call, a dropped call, and each record
/// refusal. A second fence changes nothing and notifies no one.
#[test]
fn every_fence_cause_notifies_the_receivers() {
    let refusal = ApplyError {
        seq: 1,
        rule: GrammarRule::Rule1SequencePosition,
    };
    let causes = [
        FenceCause::Failed(LogIoError::SyncFailed),
        FenceCause::Dropped,
        FenceCause::AttestationRefused(RecordRefusal::NoLog),
        FenceCause::RecordRefused(RecordRefusal::NoLog),
        FenceCause::CommittedRecordRefused(refusal),
    ];
    for cause in causes {
        let cell = FenceCell::default();
        let gate = LogGate::default();
        let mut receiver = cell.subscribe();
        let volume = a();
        let fence = Fence {
            call: LogCall::Append,
            volume: Some(volume.clone()),
            cause,
        };
        match cause {
            FenceCause::Failed(error) => {
                let failed = at_once(gate.fencing(&cell, LogCall::Append, Some(&volume), || {
                    std::future::ready(Err::<(), _>(error))
                }));
                assert_eq!(failed, Err(fence.clone()));
            }
            FenceCause::Dropped => {
                let mut in_flight = Box::pin(gate.fencing(
                    &cell,
                    LogCall::Append,
                    Some(&volume),
                    std::future::pending::<Result<(), LogIoError>>,
                ));
                let polled = in_flight
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()));
                assert!(polled.is_pending(), "the call is in flight");
                drop(in_flight);
            }
            FenceCause::CommittedRecordRefused(e) => {
                let refused = at_once(gate.settling(
                    &cell,
                    LogCall::Append,
                    Some(&volume),
                    || std::future::ready(Ok(())),
                    |_| Err::<(), _>(FenceCause::CommittedRecordRefused(e)),
                ));
                assert_eq!(refused, Err(fence.clone()));
            }
            FenceCause::AttestationRefused(_) | FenceCause::RecordRefused(_) => {
                assert_eq!(at_once(gate.fence(&cell, fence.clone())), fence);
            }
        }
        assert!(matches!(receiver.has_changed(), Ok(true)), "{cause:?}");
        assert_eq!(*receiver.borrow_and_update(), Some(fence.clone()));
        // The first fence is kept; a later one is not sent.
        let later = Fence {
            call: LogCall::Truncate,
            volume: None,
            cause: FenceCause::Dropped,
        };
        assert_eq!(at_once(gate.fence(&cell, later)), fence);
        assert!(matches!(receiver.has_changed(), Ok(false)), "{cause:?}");
        // A receiver made after the fence reads it at once.
        assert_eq!(*cell.subscribe().borrow(), Some(fence));
    }
}

// ---------------------------------- the fence, before the run has ended

/// A world whose volume A holds an attested open entry whose publication
/// read is held until released, so the run cannot end until the test
/// releases it, and whose volume B holds `b_records`. A is configured
/// first, so the run's first poll begins A's step, and a step once begun
/// is driven to its end even after a fence.
fn kept_running(log_faults: LogFaults, b_records: &[Record]) -> World {
    let sim = Sim::new();
    let log = sim_log(&sim, log_faults);
    let world = World::over(sim, log, Faults::none());
    let c1 = good_root(&a(), 1, None, 1);
    let d = decision_of(1, 1, &c1);
    seed(
        &world.log,
        &a(),
        log_bytes(&envelope(&a(), WORLD_EPOCH), &[d.clone(), attestation(&d)]),
    );
    seed(
        &world.log,
        &b(),
        log_bytes(&envelope(&b(), WORLD_EPOCH), b_records),
    );
    world.store.hold_read(&a(), 1);
    world
}

/// B's one decision, owed its attestation: B's first step is an append.
fn b_decided() -> Vec<Record> {
    vec![decision(&b(), 1, 1, 1, None, 0)]
}

/// Run `driver` under seed `seed_n` beside a host that waits for the
/// fence's notification on a receiver taken before the run, then notes
/// whether the run had ended, releases A's held read and stops. The
/// fence notified, whether the run was still going when it was, and the
/// run's and the stop's ends.
fn notified_while_running(
    world: &World,
    handle: AuthorityHandle,
    driver: Driver,
    seed_n: u64,
) -> (Fence, bool, RunEnd, RunEnd) {
    let mut fenced = handle.watch_fence();
    let store = world.store.clone();
    let (end, (fence, running, stopped)) = run_beside(seed_n, driver, async move {
        fenced.changed().await.unwrap();
        let fence = fenced.borrow_and_update().clone().unwrap();
        let running = handle.inner.ended.borrow().is_none();
        store.release();
        (fence, running, handle.stop().await)
    });
    (fence, running, end, stopped)
}

/// Start `world` over A and B, let `prepare` plant a fault in the
/// driver, and check that the host is notified of `expected` while the
/// run is still going, and that the run and the stop end with it.
fn assert_notified_while_running(
    world: &World,
    seed_n: u64,
    expected: &Fence,
    prepare: impl FnOnce(&mut Driver),
) {
    let (handle, mut driver) = world.start(&[a(), b()]);
    prepare(&mut driver);
    let (fence, running, end, stopped) = notified_while_running(world, handle, driver, seed_n);
    assert_eq!(&fence, expected, "seed {seed_n}");
    assert!(running, "seed {seed_n}: the run had not ended");
    assert_eq!(end, RunEnd::Fenced(expected.clone()), "seed {seed_n}");
    assert_eq!(stopped, end, "seed {seed_n}");
    assert_eq!(world.log.violations(), [], "seed {seed_n}");
}

/// A failed log call (B's attestation's record sync) notifies the host
/// while the run is still going.
#[test]
fn a_failed_log_call_notifies_before_the_run_ends() {
    let dry = kept_running(LogFaults::none(), &b_decided());
    dry.start(&[a(), b()]);
    // B's append: its record write is the first step after the start,
    // its record sync the second. A makes no log call while its read is
    // held.
    let fail_at = dry.log.steps() + 1;
    let expected = Fence {
        call: LogCall::Append,
        volume: Some(b()),
        cause: FenceCause::Failed(LogIoError::SyncFailed),
    };
    for seed_n in 0..8 {
        let world = kept_running(
            LogFaults::just(LogFault::FailSync { at: fail_at }),
            &b_decided(),
        );
        assert_notified_while_running(&world, seed_n, &expected, |_| {});
    }
}

/// An owed attestation refused before its append notifies the host while
/// the run is still going.
#[test]
fn a_refused_attestation_notifies_before_the_run_ends() {
    let expected = Fence {
        call: LogCall::Append,
        volume: Some(b()),
        cause: FenceCause::AttestationRefused(RecordRefusal::State(ApplyError {
            seq: 1,
            rule: GrammarRule::Rule5IdentityMismatch,
        })),
    };
    for seed_n in 0..8 {
        let world = kept_running(LogFaults::none(), &b_decided());
        assert_notified_while_running(&world, seed_n, &expected, |driver| {
            let other = RootBytes::new(sample_root(&b(), 1, None, 9)).unwrap();
            driver.workers[1]
                .state_mut()
                .unwrap()
                .replace_open_candidate(other);
        });
    }
}

/// A committed record the state refuses notifies the host while the run
/// is still going.
#[test]
fn a_refused_committed_record_notifies_before_the_run_ends() {
    let refusal = ApplyError {
        seq: 1,
        rule: GrammarRule::Rule1SequencePosition,
    };
    let expected = Fence {
        call: LogCall::Append,
        volume: Some(b()),
        cause: FenceCause::CommittedRecordRefused(refusal),
    };
    for seed_n in 0..8 {
        let world = kept_running(LogFaults::none(), &b_decided());
        assert_notified_while_running(&world, seed_n, &expected, |driver| {
            driver.workers[1]
                .state_mut()
                .unwrap()
                .refuse_next_apply(refusal);
        });
    }
}

/// A run dropped mid-append notifies the host of the drop's fence; the
/// run never ended.
#[test]
fn a_dropped_call_notifies_the_host() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    let (env, records) = decided_log(&a());
    seed(&log, &a(), log_bytes(&env, &records));
    seed_marker(&log, &RunMarker::Clean);
    let (handle, driver) = start_on(&log, boot(1), &[a()]).unwrap();
    let mut fenced = handle.watch_fence();
    let started = log.steps();
    {
        let mut run = Box::pin(driver.run());
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            if log.steps() > started {
                break;
            }
            assert!(run.as_mut().poll(&mut cx).is_pending());
        }
        assert!(log.steps() > started, "the run began no append");
        assert!(matches!(fenced.has_changed(), Ok(false)), "not fenced yet");
    }
    assert!(matches!(fenced.has_changed(), Ok(true)));
    assert_eq!(
        *fenced.borrow_and_update(),
        Some(Fence {
            call: LogCall::Append,
            volume: Some(a()),
            cause: FenceCause::Dropped,
        })
    );
    assert!(handle.inner.ended.borrow().is_none(), "the run never ended");
}

/// The final **clean** write's failure notifies the host: the fence the
/// run and the stop end with.
#[test]
fn a_failed_final_clean_write_notifies_the_host() {
    let dry = World::new(Faults::none());
    let (handle, driver) = dry.start(&[a()]);
    let started = dry.log.steps();
    run_to_stop(0, handle, driver);
    assert!(dry.log.steps() > started, "the stop wrote clean");
    for seed_n in 0..4 {
        let sim = Sim::new();
        // A has no log, so the clean write is the first step after the
        // start.
        let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: started }));
        let world = World::over(sim, log, Faults::none());
        let (handle, driver) = world.start(&[a()]);
        let mut fenced = handle.watch_fence();
        // A handle kept past the run keeps the channel open.
        let kept = handle.clone();
        let (end, stopped) = run_to_stop(seed_n, handle, driver);
        let RunEnd::Fenced(fence) = end.clone() else {
            panic!("seed {seed_n}: the clean write did not fence: {end:?}");
        };
        assert_eq!(
            (fence.call, fence.volume.clone()),
            (LogCall::WriteMarker, None)
        );
        assert_eq!(stopped, end, "seed {seed_n}");
        assert!(matches!(fenced.has_changed(), Ok(true)), "seed {seed_n}");
        assert_eq!(*fenced.borrow_and_update(), Some(fence), "seed {seed_n}");
        drop(kept);
    }
}

// ----------------------------- the start's refusal, before its clean write

/// How the double's **clean** write behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanWrite {
    /// As the log underneath does.
    Through,
    /// It waits, having taken no step, until released.
    Hang,
}

/// The simulator's log with its **clean** write watched: at the moment
/// that write begins it notes whether the refusal notice was already
/// sent, and the log's step count; with [`CleanWrite::Hang`] it then
/// waits for the test's release before making it.
#[derive(Debug, Clone)]
struct WatchedClean {
    log: SharedLog,
    notice: watch::Receiver<Option<AdmittedRefusal>>,
    how: CleanWrite,
    /// At the clean write's start: whether the notice was there, and the
    /// step count.
    began: Arc<Mutex<Option<(bool, u32)>>>,
    released: Arc<AtomicBool>,
}

impl WatchedClean {
    fn new(
        log: &Arc<SimDecisionLog>,
        notice: watch::Receiver<Option<AdmittedRefusal>>,
        how: CleanWrite,
    ) -> Self {
        Self {
            log: SharedLog(Arc::clone(log)),
            notice,
            how,
            began: Arc::new(Mutex::new(None)),
            released: Arc::new(AtomicBool::new(false)),
        }
    }

    fn began(&self) -> Option<(bool, u32)> {
        *self.began.lock().unwrap()
    }
}

impl DecisionLog for WatchedClean {
    fn read_marker(&self) -> impl Future<Output = Result<MarkerRead, LogIoError>> + Send {
        self.log.read_marker()
    }

    async fn write_marker(&self, marker: &EncodedMarker) -> Result<(), LogIoError> {
        if marker.as_bytes() == encode_marker(&RunMarker::Clean).as_bytes() {
            let seen = self.notice.borrow().is_some();
            *self.began.lock().unwrap() = Some((seen, self.log.0.steps()));
            if self.how == CleanWrite::Hang {
                while !self.released.load(Ordering::SeqCst) {
                    yield_once().await;
                }
            }
        }
        self.log.write_marker(marker).await
    }

    fn read(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, LogIoError>> + Send {
        self.log.read(volume)
    }

    fn remove_temporary(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<bool, LogIoError>> + Send {
        self.log.remove_temporary(volume)
    }

    fn initialise(
        &self,
        envelope: &EncodedEnvelope,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.initialise(envelope)
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

type WatchedParts =
    AuthorityParts<WatchedClean, TestStore, FixedClock, SimRng, SeededSecureRandom, YieldPause>;

fn watched_parts(log: WatchedClean) -> WatchedParts {
    AuthorityParts {
        admission: crate::Admission::chain_fixture(),
        log,
        store: TestStore::dead(),
        clock: FixedClock,
        rng: rng(1),
        secure_random: secure(1),
        pause: YieldPause,
    }
}

/// A clean marker, A with an envelope and no record, and at B's name a
/// log under another volume's envelope: the marker admits the start, A
/// classifies, and B refuses it as damaged.
fn plant_refused_b(log: &Arc<SimDecisionLog>) {
    seed_marker(log, &RunMarker::Clean);
    seed(log, &a(), log_bytes(&envelope(&a(), WORLD_EPOCH), &[]));
    let (other, records) = landed_log(&vol("vol-z"));
    seed(log, &b(), log_bytes(&other, &records));
}

/// The refusal B's planted log gives, as the notice carries it.
fn is_b_damaged(refusal: Option<&AdmittedRefusal>) -> bool {
    matches!(
        refusal,
        Some(AdmittedRefusal {
            volume,
            reason: VolumeRefusal::Damaged(_),
        }) if *volume == b()
    )
}

/// A watched start's result, its double, and the notices' receivers of
/// the refusal and the fence.
type Watched = (
    Result<(), StartRefused>,
    WatchedClean,
    watch::Receiver<Option<AdmittedRefusal>>,
    watch::Receiver<Option<Fence>>,
);

/// Start over `log` with the clean write behaving as `how`.
fn start_watched(log: &Arc<SimDecisionLog>, how: CleanWrite) -> Watched {
    let notices = Notices::new();
    let refusal = notices.refusal();
    let fence = notices.fence();
    let watched = WatchedClean::new(log, notices.refusal(), how);
    let parts = watched_parts(watched.clone());
    let started = block(async move {
        start_observed(parts, boot(1), configs(&[a(), b()]), notices)
            .await
            .map(|_| ())
    });
    (started, watched, refusal, fence)
}

/// A refused volume after admission: the notice is sent before the clean
/// write begins, the write succeeds, and the start returns the refusal.
#[test]
fn a_refused_volume_notifies_before_a_clean_write_that_succeeds() {
    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::none());
    plant_refused_b(&log);
    let (started, watched, mut refusal, fence) = start_watched(&log, CleanWrite::Through);
    let Err(StartRefused::Volume { volume, reason }) = started else {
        panic!("the start was not refused by a volume: {started:?}");
    };
    assert_eq!(volume, b());
    let (seen, _) = watched.began().expect("the clean write began");
    assert!(seen, "the notice was sent before the clean write began");
    assert_eq!(
        *refusal.borrow_and_update(),
        Some(AdmittedRefusal {
            volume: b(),
            reason,
        })
    );
    assert!(is_b_damaged(refusal.borrow().as_ref()));
    assert_eq!(*fence.borrow(), None);
    assert_eq!(marker_says(&log), Some(RunMarker::Clean));
    assert_eq!(log.violations(), []);
}

/// A refused volume after admission whose clean write fails: the notice
/// is sent before the write begins, and the write's fence reaches the
/// host's fence receiver taken before the start.
#[test]
fn a_refused_volume_notifies_before_a_clean_write_that_fences() {
    let dry = Sim::new();
    let dry_log = sim_log(&dry, LogFaults::none());
    plant_refused_b(&dry_log);
    let (_, dry_watched, _, _) = start_watched(&dry_log, CleanWrite::Through);
    let (_, clean_at) = dry_watched.began().expect("the clean write began");

    let sim = Sim::new();
    let log = sim_log(&sim, LogFaults::just(LogFault::FailSync { at: clean_at }));
    plant_refused_b(&log);
    let (started, watched, mut refusal, mut fence) = start_watched(&log, CleanWrite::Through);
    let Err(StartRefused::Fenced(fenced)) = started else {
        panic!("the clean write did not fence: {started:?}");
    };
    assert_eq!(
        (fenced.call, fenced.volume.clone()),
        (LogCall::WriteMarker, None)
    );
    let (seen, _) = watched.began().expect("the clean write began");
    assert!(seen, "the notice was sent before the clean write began");
    assert!(is_b_damaged(refusal.borrow_and_update().as_ref()));
    assert_eq!(*fence.borrow_and_update(), Some(fenced));
    assert_eq!(marker_says(&log), Some(RunMarker::Running(boot(1))));
}

/// What one task of the hanging start's run finished with.
enum Hung {
    Start(Result<(), StartRefused>),
    Host,
}

/// A refused volume after admission whose clean write hangs: while it
/// hangs, with the start not returned and nothing else signalled, the
/// host already holds the notice. Released, the start returns the
/// refusal.
#[test]
fn a_refused_volume_notifies_while_its_clean_write_hangs() {
    for seed_n in 0..8 {
        let sim = Sim::new();
        let log = sim_log(&sim, LogFaults::none());
        plant_refused_b(&log);
        let notices = Notices::new();
        let mut refusal = notices.refusal();
        let watched = WatchedClean::new(&log, notices.refusal(), CleanWrite::Hang);
        let parts = watched_parts(watched.clone());
        let returned = Arc::new(AtomicBool::new(false));
        let start_returned = Arc::clone(&returned);
        let start: Task<Hung> = Box::pin(async move {
            let started = start_observed(parts, boot(1), configs(&[a(), b()]), notices)
                .await
                .map(|_| ());
            start_returned.store(true, Ordering::SeqCst);
            Hung::Start(started)
        });
        let host_watched = watched.clone();
        let host: Task<Hung> = Box::pin(async move {
            while host_watched.began().is_none() {
                yield_once().await;
            }
            // The clean write is hanging, and the start has not returned.
            assert!(!returned.load(Ordering::SeqCst), "seed {seed_n}");
            assert!(matches!(refusal.has_changed(), Ok(true)), "seed {seed_n}");
            assert!(
                is_b_damaged(refusal.borrow_and_update().as_ref()),
                "seed {seed_n}"
            );
            host_watched.released.store(true, Ordering::SeqCst);
            Hung::Host
        });
        let mut out = Scheduler::new(seed_n).run(vec![start, host]).into_iter();
        let (Some(Hung::Start(started)), Some(Hung::Host)) = (out.next(), out.next()) else {
            panic!("the scheduler returns results in task order");
        };
        assert!(
            matches!(started, Err(StartRefused::Volume { ref volume, .. }) if *volume == b()),
            "seed {seed_n}: {started:?}"
        );
        assert_eq!(watched.began().map(|(seen, _)| seen), Some(true));
        assert_eq!(marker_says(&log), Some(RunMarker::Clean), "seed {seed_n}");
        assert_eq!(log.violations(), [], "seed {seed_n}");
    }
}
