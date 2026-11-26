// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A shutdown over a mount whose view hook is bound, as production's is:
//! a landing installs through the hook without the adapter's gate, and the
//! pin follows the base, so every read after it is served.

use super::super::super::shutdown::{
    HANG, PROFILES, Probe, ResumeOnDrop, begin_on_thread, closed, controller, create, start,
    unmount_lines, wait_fired, wait_until,
};
use super::*;
use crate::sync::{Cause, MountShutdown as _, Outcome, ShutdownReport, Trigger};
use granary_core::overlay_ownership::{Operation, Phase};
use granary_fuse::{MountBackend as _, OverlayMutation as M};

impl BoundMount {
    fn probe(&self) -> Probe {
        Probe {
            state: self.state.clone(),
            volume: self.tree.volume.clone(),
            mediator: self.mediator(),
        }
    }
    /// The pin's `(id, seq)` and the overlay's base, read together.
    fn pin_and_base(&self) -> (Option<Base>, Option<Base>) {
        self.mediator()
            .with(|store| {
                Ok((
                    store.mount_pin().map(|pin| (pin.base_id, pin.base_seq)),
                    store.overlay_base_for_test(),
                ))
            })
            .unwrap()
    }
    /// Write over `f.txt` through a held object, returned open.
    fn dirty(&self) -> u64 {
        self.with_mount(|mount| {
            let object = mount
                .overlay_open(&handler_path(b"f.txt"))
                .unwrap()
                .unwrap();
            mount.prepare_object(object).unwrap();
            mount
                .overlay_mutate(M::BoundWrite {
                    object,
                    offset: 0,
                    bytes: b"commit-route",
                    append: false,
                })
                .unwrap();
            object
        })
        .unwrap()
    }
    fn create(&self, name: &str, bytes: &[u8]) {
        self.with_mount(|mount| create(mount, name, bytes)).unwrap();
    }
    /// A lane its first drive left retained, cut at `phase`; a cut before a
    /// rebase finds another writer's head published first.
    fn retained_lane_at(&self, phase: &'static str) {
        let object = self.dirty();
        self.faults
            .arm("sync.commit", phase, 1, crate::FaultAction::Fail);
        let lane = self.construct(70);
        if phase == "before_rebase" {
            disjoint_head(&self.tree, &self.runtime);
        }
        assert!(
            self.drive(&lane, 80)
                .is_err_and(|error| error.to_string().contains("SyncInjectedFault")),
            "premise: the first drive is cut"
        );
        self.close(object);
    }
    fn controller(&self, bound: std::time::Duration) -> super::super::super::shutdown::Controller {
        controller(
            &self.engine,
            self.mediator(),
            self.runtime.handle().clone(),
            bound,
        )
    }
    /// Run the sequence under paused time. Only its virtual deadline governs
    /// the retry waits, even when disk transactions take real time.
    fn shutdown_sequence(&self, bound: std::time::Duration) -> ShutdownReport {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let controller = controller(
            &self.engine,
            self.mediator(),
            runtime.handle().clone(),
            bound,
        );
        runtime.block_on(controller.run_session_end_sequence_for_test())
    }
    /// The shutdown the mount's own backend runs, with its default bound.
    fn shut_down(&self) -> Outcome {
        self.with_mount(|mount| mount.shutdown_for_test())
            .unwrap()
            .expect("an attached engine's shutdown")
            .begin(Trigger::SessionEnd)
            .outcome
    }
}

/// The adapter's slot is abandoned, as it is once the session has ended,
/// over a retained lane and a file written after it: step 1's landing
/// installs without the gate, which is never tried, and the pin follows the
/// base, so step 3's sync of the file and step 4's commit are served. The
/// shutdown commits both and the journal is on the second landing.
#[test]
fn shutdown_installs_locally_with_the_adapter_gone() {
    let fixture = BoundMount::new();
    fixture.retained_lane_at("before_submit");
    fixture.create("later", b"synced after the landing");
    fixture
        .gate
        .forced
        .lock()
        .unwrap()
        .push_back(Forced::Busy(SlotBusy::Abandoned));
    // The landing's refresh registers first; step 3's sync of the file is
    // the second registration.
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        2,
        crate::FaultAction::Block,
    );
    let resume = ResumeOnDrop(fixture.faults.clone());
    let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(15)));
    let outcome = begin_on_thread(&controller);
    wait_fired(&fixture.faults, "sync.registration", "before_dispatch");
    let after_step_1 = fixture.pin_and_base();
    drop(resume);
    let outcome = outcome.recv_timeout(HANG).ok();
    let (pin, base) = fixture.pin_and_base();
    assert_eq!(
        (
            after_step_1.0.map(|(_, seq)| seq),
            after_step_1.0 == after_step_1.1,
            outcome,
            fixture.gate.attempts.load(Ordering::SeqCst),
            base.map(|(_, seq)| seq),
            pin == base,
            fixture.probe().phase(),
        ),
        (
            Some(2),
            true,
            Some(Outcome::Committed(3)),
            0,
            Some(3),
            true,
            Phase::Released
        ),
        "(pin seq and pin == base after step 1, outcome, gate attempts, base seq, pin == base, phase)"
    );
}

/// A lane retained before the shutdown lands first, under explicit
/// recovery, and the records after it take one more publication: the head
/// moves by two, the outcome names the second, and the pin is its root.
#[test]
fn shutdown_drives_a_retained_lane_first() {
    let mut cases = 0;
    for profile in PROFILES {
        let fixture = BoundMount::with_profile(profile);
        fixture.retained_lane_at("before_submit");
        fixture.create("later", b"later bytes");
        let outcome = fixture.shut_down();
        let (pin, base) = fixture.pin_and_base();
        assert_eq!(
            (
                outcome,
                remote_seq(&fixture.tree, &fixture.runtime),
                pin == base,
                fixture.probe().phase(),
            ),
            (Outcome::Committed(3), 3, true, Phase::Released),
            "profile={profile:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A lane its first drive left retained, with no later records, lands in
/// step 1 and is the shutdown's whole commit: the outcome names its seq,
/// read from the base, and nothing more is published. A lane cut before
/// its rebase onto another writer's head lands only under explicit
/// recovery, one seq above that head.
#[test]
fn shutdown_reports_a_step_1_only_landing_as_committed() {
    let mut cases = 0;
    for profile in PROFILES {
        for (phase, seq) in [("before_submit", 2), ("before_rebase", 3)] {
            let fixture = BoundMount::with_profile(profile);
            fixture.retained_lane_at(phase);
            let before = fixture.state.lock().unwrap().publications.len();
            let outcome = fixture.shut_down();
            let published = fixture.state.lock().unwrap().publications.len() - before;
            assert_eq!(
                (
                    outcome,
                    published,
                    remote_seq(&fixture.tree, &fixture.runtime),
                    fixture.pin_and_base().1.map(|(_, seq)| seq),
                    fixture.probe().phase(),
                ),
                (Outcome::Committed(seq), 1, seq, Some(seq), Phase::Released),
                "profile={profile:?}, cut at {phase}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

/// A lane step 1 lands, followed by a file whose registration the
/// authority never answers: the step's error outranks the moved base, so
/// the outcome is incomplete, the intent is kept and the event says so.
/// Advancing the wall clock across retry backoff exhausts the send budget.
#[test]
fn a_landing_in_step_1_then_a_failed_step_is_incomplete() {
    let mut cases = 0;
    for profile in PROFILES {
        // Two reads separate a backoff from its check, and no backoff
        // exceeds 3.3 s: the schedule caps attempts at 6 (100 ms doubled
        // five times) plus up to 100 ms of jitter.
        let tick_per_read = 3_000;
        let fixture = BoundMount::with_profile(profile);
        fixture.retained_lane_at("before_submit");
        fixture.create("later", b"never registers");
        {
            let mut state = fixture.state.lock().unwrap();
            // The landing's refresh is served; the file's registration
            // is not.
            state.registrations_served = Some(1);
            state.tick_per_read = tick_per_read;
        }
        let events = Events::default();
        let shutdown = tracing::subscriber::with_default(events.subscriber(), || {
            fixture
                .with_mount(granary_fuse::MountBackend::shutdown)
                .unwrap()
        });
        let lines = unmount_lines(&events);
        let report = fixture
            .with_mount(|mount| mount.shutdown_for_test())
            .unwrap()
            .and_then(|shutdown| shutdown.report())
            .map(|report| report.outcome);
        assert_eq!(
            (
                (shutdown, report),
                fixture.probe().releases(),
                remote_seq(&fixture.tree, &fixture.runtime),
                fixture.pin_and_base().1.map(|(_, seq)| seq),
                lines
                    .first()
                    .is_some_and(|line| line.contains("\"outcome\":\"incomplete\"")),
            ),
            (
                (
                    Ok(()),
                    Some(Outcome::Incomplete(Cause::Failed(
                        crate::FailureClass::Unavailable,
                    )))
                ),
                0,
                2,
                Some(2),
                true
            ),
            "profile={profile:?}, tick_per_read={tick_per_read}: {lines:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// Rejects ending at the first early admission or spending an attempt on a
/// frozen wall clock. Complete the landing with the fixture's normal budget
/// first, then give the shutdown sequence its own virtual deadline.
#[test]
fn after_a_landing_a_frozen_retry_waits_for_the_bound() {
    let mut cases = 0;
    for profile in PROFILES {
        let fixture = BoundMount::with_profile(profile);
        let object = fixture.dirty();
        fixture.close(object);
        let landing = fixture.drive(&fixture.construct(70), 80);
        assert!(landed(&landing), "premise: {landing:?}");
        fixture.create("later", b"never registers");
        {
            let mut state = fixture.state.lock().unwrap();
            state.registrations_served = Some(0);
            state.tick_per_read = 0;
        }
        let probe = fixture.probe();
        let registrations_before = probe.registration_count();
        let events = Events::default();
        let bound = std::time::Duration::from_millis(700);
        let report = tracing::subscriber::with_default(events.subscriber(), || {
            fixture.shutdown_sequence(bound)
        });
        let attempts = probe
            .mediator
            .with(|store| {
                Ok(store
                    .snapshot()
                    .pending
                    .iter()
                    .filter_map(|pending| {
                        (pending.operation == Operation::Register && !pending.terminal)
                            .then_some(pending.attempts)
                    })
                    .collect::<Vec<_>>())
            })
            .unwrap();
        assert_eq!(
            (
                (
                    report.outcome,
                    std::time::Duration::from_millis(report.elapsed_ms) >= bound,
                ),
                (probe.registration_count() - registrations_before, attempts),
                (
                    probe.releases(),
                    remote_seq(&fixture.tree, &fixture.runtime)
                ),
                fixture.pin_and_base().1.map(|(_, seq)| seq),
                unmount_lines(&events)
                    .first()
                    .is_some_and(|line| line.contains("\"cause\":\"deadline\"")),
            ),
            (
                (Outcome::Incomplete(Cause::Deadline), true),
                (1, vec![1]),
                (0, 2),
                Some(2),
                true,
            ),
            "profile={profile:?}: {:?}",
            String::from_utf8_lossy(&events.0.lock().unwrap()),
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// Rejects treating expiry found at Release dispatch as an early shutdown
/// failure. The first exchange is unanswered and the stepped clock reaches
/// expiry between sampling retry eligibility and admission of the second.
#[test]
fn release_dispatch_expiry_waits_for_the_shutdown_bound() {
    let fixture = BoundMount::new();
    let bound = std::time::Duration::from_millis(500);
    let probe = fixture.probe();
    {
        let mut authority = probe.state.lock().unwrap();
        authority.release_answer = crate::overlay_test_support::ReleaseAnswer::Unavailable;
        let wall = probe.state.clone();
        let mediator = probe.mediator.clone();
        authority.on_release = Some(Box::new(move || {
            let expires = mediator
                .with(|store| {
                    let release = store.snapshot().pending.last().unwrap();
                    assert_eq!(release.operation, Operation::Release);
                    Ok(release.expires)
                })
                .unwrap();
            let mut state = wall.lock().unwrap();
            // Time adds 1,000 ms to tick. Completion samples 500 ms before
            // expiry, retry_delay samples 250 ms before, and dispatch at expiry.
            state.tick = expires - 1_500;
            state.tick_per_read = 250;
        }));
    }
    let report = fixture.shutdown_sequence(bound);
    let pending_retry = probe
        .mediator
        .with(|store| {
            Ok(store
                .snapshot()
                .pending
                .iter()
                .find(|pending| pending.operation == Operation::Release)
                .map(|pending| {
                    (
                        pending.attempts,
                        pending.expires.saturating_sub(pending.eligible),
                    )
                }))
        })
        .unwrap();
    assert_eq!(
        (
            report.outcome,
            std::time::Duration::from_millis(report.elapsed_ms) >= bound,
            probe.releases(),
            // Backoff makes the first retry eligible 100–200 ms after completion.
            pending_retry.is_some_and(|(attempts, until_expiry)| {
                attempts == 1 && (300..=400).contains(&until_expiry)
            }),
        ),
        (Outcome::Incomplete(Cause::Deadline), true, 1, true),
        "persisted Release retry: {pending_retry:?}",
    );
}

/// Rejects looping after a single-pass admission without a deadline, or
/// ending at the early check when a deadline supplies time for another wait.
#[test]
fn start_readmission_requires_a_monotonic_deadline() {
    use crate::SyncRuntime as _;
    use granary_core::clock::Clock;

    struct SteppedWall {
        eligible: u64,
        frozen: bool,
        reads: std::sync::atomic::AtomicU64,
    }
    impl Clock for SteppedWall {
        fn now(&self) -> granary_core::root::Timestamp {
            let read = self.reads.fetch_add(1, Ordering::Relaxed);
            let tick = self.eligible - u64::from(read == 1 || (self.frozen && read > 1));
            granary_core::root::Timestamp {
                secs: i64::try_from(tick / 1000).unwrap(),
                nanos: u32::try_from(tick % 1000).unwrap() * 1_000_000,
            }
        }
    }

    for (bounded, expected) in [(false, "IntentRetryNotEligible"), (true, "SyncDeadline")] {
        let fixture = BoundMount::new();
        let probe = fixture.probe();
        let before = probe.registration_count();
        let remote = Authority::new(&fixture.tree, &fixture.state);
        fixture.state.lock().unwrap().intent_wait_frozen = true;
        // drive_inner runs to completion on this runtime without a separate
        // real-time wait for its report.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let _context = runtime.enter();
        let started = crate::TokioSyncRuntime.now();
        let deadline = bounded.then(|| started + std::time::Duration::from_millis(40));
        let (error, attempts) = probe
            .mediator
            .with(|store| {
                let time = Time(fixture.state.clone());
                let request = store.prepare_registration(
                    &store.snapshot().root.clone(),
                    vec![],
                    &time,
                    |_, _| true,
                )?;
                let pending = store.snapshot().pending.last().unwrap();
                let wall = SteppedWall {
                    eligible: pending.eligible,
                    frozen: bounded,
                    reads: 0.into(),
                };
                let scope = store.snapshot().scope.clone();
                let result = crate::writable_start::drive_inner(
                    store,
                    &remote,
                    &runtime,
                    &scope,
                    &request,
                    fixture.tree.key.public_key(),
                    &wall,
                    &mut granary_core::rng::SeededRng::new(1),
                    false,
                    deadline,
                );
                Ok((result, store.snapshot().pending.last().unwrap().attempts))
            })
            .unwrap();
        assert_eq!(
            (
                error.map_err(|error| (error.name(), error.class())),
                (probe.registration_count() - before, attempts),
                deadline.is_some_and(|deadline| crate::TokioSyncRuntime.now() >= deadline),
            ),
            (
                Err((expected, crate::FailureClass::Unavailable)),
                (0, 0),
                bounded
            ),
        );
    }
}

/// An fsync admitted before the latch and waiting for a retained lane is
/// drained after step 1 lands that lane: it registers and answers, then
/// the shutdown's own sync and commit follow, one publication. A published
/// fsync drives the lane itself, so only the durable one is held waiting.
#[test]
fn drain_waits_for_a_sync_admitted_before_the_latch() {
    use granary_fuse::MountSyncRequest;
    let mut cases = 0;
    for profile in PROFILES {
        let fixture = BoundMount::with_profile(profile);
        fixture.retained_lane_at("before_submit");
        let object = fixture.dirty();
        let held = profile == crate::SyncProfile::DurablePrepared;
        if held {
            fixture
                .faults
                .arm("sync.commit_wait", "before", 1, crate::FaultAction::Block);
        }
        let resume = ResumeOnDrop(fixture.faults.clone());
        let job = fixture
            .with_mount(|mount| {
                mount.prepare_sync(MountSyncRequest::File {
                    object,
                    datasync: false,
                })
            })
            .unwrap()
            .unwrap();
        let synced = start(job);
        if held {
            wait_fired(&fixture.faults, "sync.commit_wait", "before");
        }
        let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(15)));
        let outcome = begin_on_thread(&controller);
        if held {
            // The fsync waits on the lane until step 1 has landed it.
            wait_until("step 1 landed the lane", || {
                fixture.pin_and_base().1.is_some_and(|(_, seq)| seq == 2)
            });
        }
        drop(resume);
        let synced = synced.recv_timeout(HANG).ok();
        let outcome = outcome.recv_timeout(HANG).ok();
        assert_eq!(
            (synced, outcome, remote_seq(&fixture.tree, &fixture.runtime)),
            (Some(Ok(())), Some(Outcome::Committed(3)), 3),
            "profile={profile:?}"
        );
        fixture.close(object);
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A published fsync admitted before the shutdown is still sealing when
/// step 1 looks, so it finds admission open. The fsync then retains its
/// lane and fails its drive at its own bound, leaving the lane with no
/// driver. The drain sees its answer, goes back to step 1, and that drive
/// lands the lane: the base moved, so the outcome is committed, not clean.
#[test]
fn drain_then_drives_a_lane_a_pre_latch_published_fsync_retained() {
    let fixture = BoundMount::with_profile(crate::SyncProfile::Published);
    let object = fixture.dirty();
    let stage = fixture
        .with_mount(|mount| mount.overlay_object(object).unwrap().stage.unwrap())
        .unwrap();
    let mediator = fixture.mediator();
    fixture
        .faults
        .arm("sync.capture", "after", 1, crate::FaultAction::Block);
    let resume = ResumeOnDrop(fixture.faults.clone());
    fixture.state.lock().unwrap().publish_delay = Some(std::time::Duration::from_secs(6));
    let admitted = mediator.admit_sync().unwrap();
    let entered = fixture.runtime.enter();
    let waiter = fixture.engine.publish_sync(
        crate::SyncTarget::Stage(stage),
        crate::SyncOptions {
            deadline: Some(
                crate::SyncRuntime::now(&FastWaitRuntime) + std::time::Duration::from_secs(3),
            ),
            ..crate::SyncOptions::default()
        },
        Entropy(50),
    );
    let (answered, fsync) = std::sync::mpsc::channel();
    drop(fixture.runtime.spawn(async move {
        let result = waiter.wait().await;
        drop(admitted);
        let _ = answered.send(result.is_ok());
    }));
    drop(entered);
    wait_fired(&fixture.faults, "sync.capture", "after");
    // The landing waits out the six-second publication delay, so the bound
    // leaves the rest of the work twelve seconds under load, and with its
    // margin stays inside the wait for the outcome.
    let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(18)));
    let outcome = begin_on_thread(&controller);
    wait_until("the latch closed", || closed(&mediator));
    // Step 1 has looked at an open admission; the fsync's seal goes on.
    std::thread::sleep(std::time::Duration::from_millis(200));
    drop(resume);
    let fsync = fsync.recv_timeout(HANG).ok();
    let outcome = outcome.recv_timeout(HANG).ok();
    assert_eq!(
        (
            fsync,
            outcome,
            fixture.probe().phase(),
            remote_seq(&fixture.tree, &fixture.runtime)
        ),
        (Some(false), Some(Outcome::Committed(2)), Phase::Released, 2)
    );
    fixture.close(object);
}

/// A signal or owner stop runs while the session serves, so its landing
/// installs through the adapter's gate: the gate is tried, later landings are
/// not set to install without it, and the retained lane commits. A signal
/// that set the unattended install would never try the gate.
#[test]
fn signal_trigger_installs_through_the_gate() {
    let mut cases = 0;
    for trigger in [Trigger::Signal, Trigger::Umount] {
        let fixture = BoundMount::new();
        fixture.retained_lane_at("before_submit");
        let report = fixture
            .controller(std::time::Duration::from_secs(15))
            .begin(trigger);
        assert_eq!(
            (
                fixture.gate.attempts.load(Ordering::SeqCst) >= 1,
                fixture.engine.installs_locally_for_test(),
                report.outcome,
            ),
            (true, false, Outcome::Committed(2)),
            "(gate tried, unattended install set, outcome)"
        );

        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A session that ends while a pre-unmount sequence is held before its
/// landing's submission makes that landing install without the gate: the
/// session end's own call sets the unattended install before it waits for
/// the running sequence, so the landing that resumes never tries the
/// adapter, whose slot is abandoned, and both callers answer the one
/// committed report. Setting it only for the call that runs the sequence
/// leaves the landing on the gate, which refuses it.
#[test]
fn a_session_end_during_a_signal_shutdown_installs_locally() {
    let mut cases = 0;
    for trigger in [Trigger::Signal, Trigger::Umount] {
        let fixture = BoundMount::new();
        fixture.retained_lane_at("before_submit");
        fixture
            .faults
            .arm("sync.commit", "before_submit", 1, crate::FaultAction::Block);
        let resume = ResumeOnDrop(fixture.faults.clone());
        let controller = Arc::new(fixture.controller(std::time::Duration::from_secs(15)));
        let begin = |trigger| {
            let (send, receive) = std::sync::mpsc::channel();
            let controller = controller.clone();
            std::thread::spawn(move || {
                let _ = send.send(controller.begin(trigger));
            });
            receive
        };
        let signal = begin(trigger);
        wait_fired(&fixture.faults, "sync.commit", "before_submit");
        fixture
            .gate
            .forced
            .lock()
            .unwrap()
            .push_back(Forced::Busy(SlotBusy::Abandoned));
        let session_end = begin(Trigger::SessionEnd);
        wait_until("the session end set the unattended install", || {
            fixture.engine.installs_locally_for_test()
        });
        drop(resume);
        let signal = signal.recv_timeout(HANG).ok();
        let session_end = session_end.recv_timeout(HANG).ok();
        assert_eq!(
            (
                signal.map(|report| report.outcome),
                session_end == signal,
                fixture.gate.attempts.load(Ordering::SeqCst),
                fixture.probe().phase(),
            ),
            (Some(Outcome::Committed(2)), true, 0, Phase::Released),
            "(the signal's outcome, both callers' reports equal, gate attempts, phase)"
        );

        cases += 1;
    }
    assert_eq!(cases, 2);
}
