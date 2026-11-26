// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::decision_log` — the simulator's
//! crash-consistency `DecisionLog`: the shared conformance body with
//! faults off, the crash draws by row, the two ends of a run, the media
//! faults, and each ordering check with the fake variant that breaks it.
//!
//! Out-of-line: `granary-sim` has its own `tests/` directory and its
//! own `[[bin]]`, so its modules' unit tests live beside them.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use granary_core::authlog::{
    EPOCH_LEN, Envelope, Epoch, LogErrorReason, Record, encode_append, encode_envelope,
};

use super::*;
use crate::scenario::run;
use crate::sched::{Scheduler, Task};
use granary_core::runmarker::{BootId, RunMarker, encode_marker};
use std::sync::Arc as SharedLog;

/// Drive a fake's future to completion. Every step suspends once and
/// wakes itself, so polling in a loop needs no scheduler.
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// The marker a running process writes.
fn marker() -> EncodedMarker {
    encode_marker(&RunMarker::Running(BootId::from_bytes([0x5A; 16])))
}

/// The marker a clean shutdown writes.
fn clean_marker() -> EncodedMarker {
    encode_marker(&RunMarker::Clean)
}
const SEEDS: u64 = 64;

fn volume() -> VolumeName {
    VolumeName::new("dlog".to_owned()).unwrap()
}

fn envelope(epoch: u8) -> Envelope {
    Envelope::new(volume(), Epoch::from_bytes([epoch; EPOCH_LEN]))
}

/// The `n`th record (from 1) of one legal log for `volume`: each entry's
/// decision, attestation and landed outcome in turn, so every prefix
/// classifies, and no two records are alike.
fn record(volume: &VolumeName, n: u64) -> Record {
    let n = usize::try_from(n).unwrap();
    crate::scenario::script_records(volume, n).swap_remove(n - 1)
}

fn append(env: &Envelope, n: u64) -> Append {
    encode_append(env, &record(env.volume(), n)).unwrap()
}

/// The envelope plus each of `seqs`' record and mark.
fn log_bytes(env: &Envelope, seqs: impl IntoIterator<Item = u64>) -> Vec<u8> {
    let mut bytes = encode_envelope(env).as_bytes().to_vec();
    for seq in seqs {
        let a = append(env, seq);
        bytes.extend_from_slice(a.record());
        bytes.extend_from_slice(a.mark());
    }
    bytes
}

/// A run's start: the marker, then the log.
fn start(log: &SimDecisionLog, env: &Envelope) {
    block_on(log.write_marker(&marker())).unwrap();
    block_on(log.initialise(&encode_envelope(env))).unwrap();
}

fn read(log: &SimDecisionLog) -> Option<Vec<u8>> {
    block_on(log.read(&volume())).unwrap()
}

fn seeded(seed: u64) -> Rng {
    Rng::seeded(seed, 0x0D15_C0DE)
}

// ------------------------------------------------------ conformance

/// The shared body the core fake and the production adapter run, here
/// with faults off. Its only ordering violations are fence ones: the
/// body deliberately re-initialises an existing log, whose
/// `AlreadyExists` comes after the call began and so fences, and it
/// carries on to exercise the rest of the seam.
#[test]
fn the_fake_passes_decisionlog_conformance_with_faults_disabled() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let task: Task<Vec<LogViolation>> = Box::pin(async move {
        granary_core::testkit::decisionlog_conformance(&log).await;
        log.violations()
    });
    let violations = run(1, task);
    assert!(
        !violations.is_empty() && violations.iter().all(|v| *v == LogViolation::AfterFence),
        "only the deliberate re-initialise's fence: {violations:?}"
    );
    assert!(
        !sim.trace().is_empty(),
        "a conformance run that recorded nothing would be a vacuous pass"
    );
}

/// Every seam call suspends once per step, so a scheduler can
/// interleave between any two of them.
#[test]
fn every_step_suspends() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let marker = marker();
    let mut fut = pin!(log.write_marker(&marker));
    let mut cx = Context::from_waker(Waker::noop());
    let mut pends = 0u32;
    while fut.as_mut().poll(&mut cx).is_pending() {
        pends += 1;
    }
    assert_eq!(pends, log.steps(), "one suspension per step");
    assert_eq!(pends, 8, "a first marker write is eight steps");
}

/// Records name the actual append's four operations, in index order;
/// a new call starts its within-call index at zero.
#[test]
fn step_records_cover_completed_calls() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let env = envelope(1);
    start(&log, &env);
    let base = log.steps();
    for n in 1..=2 {
        let append = append(&env, n);
        block_on(log.append(&append)).unwrap();
        let index = base + u32::try_from(n - 1).unwrap() * 4;
        let path = log_path(&volume());
        let ops = [
            LogOp::Write {
                path: path.clone(),
                len: u64::try_from(append.record().len()).unwrap(),
                addr: Address::new(*GrainId::of(append.record()).digest()),
            },
            LogOp::FileSync { path: path.clone() },
            LogOp::Write {
                path: path.clone(),
                len: u64::try_from(append.mark().len()).unwrap(),
                addr: Address::new(*GrainId::of(append.mark()).digest()),
            },
            LogOp::FileSync { path },
        ];
        let expected: Vec<_> = ops
            .into_iter()
            .enumerate()
            .map(|(within, op)| StepRecord {
                index: index + u32::try_from(within).unwrap(),
                call: LogCall::Append,
                within: u32::try_from(within).unwrap(),
                op,
                fired: None,
            })
            .collect();
        assert_eq!(
            &log.step_records()[usize::try_from(index).unwrap()..],
            expected
        );
    }
    assert_eq!(log.steps(), base + 8);
    assert_eq!(
        log.step_records()
            .iter()
            .map(|r| r.index)
            .collect::<Vec<_>>(),
        (0..log.steps()).collect::<Vec<_>>()
    );
    assert_eq!(log.violations(), []);
}

/// The claimed step is visible before it applies, survives cancellation,
/// and does not claim its scheduled fault fired before resumption.
#[test]
fn step_records_include_suspended_and_cancelled_calls() {
    let sim = Sim::new();
    let base = second_append_base();
    let log = sim.decision_log(0, LogFaults::just(LogFault::CrashAt(base + 1)));
    let env = envelope(1);
    start(&log, &env);
    block_on(log.append(&append(&env, 1))).unwrap();
    assert_eq!(log.steps(), base);
    let append = append(&env, 2);
    let mut pending = Box::pin(log.append(&append));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(pending.as_mut().poll(&mut cx).is_pending());
    let records = log.step_records();
    let first = records.last().unwrap();
    assert_eq!(
        (first.index, first.call, first.within, first.fired),
        (base, LogCall::Append, 0, None)
    );
    assert!(matches!(first.op, LogOp::Write { .. }));
    assert_eq!(log.steps(), base + 1);
    assert!(pending.as_mut().poll(&mut cx).is_pending());
    let suspended = log.step_records();
    let sync = suspended.last().unwrap();
    assert_eq!(
        (sync.index, sync.call, sync.within, sync.fired),
        (base + 1, LogCall::Append, 1, None)
    );
    assert!(matches!(sync.op, LogOp::FileSync { .. }));
    drop(pending);
    assert_eq!(log.steps(), base + 2);
    assert_eq!(
        log.step_records(),
        suspended,
        "cancelled steps remain recorded"
    );
    assert!(!log.crashed(), "a suspended fault has not fired");
}

#[test]
fn step_records_distinguish_crash_from_failed_sync() {
    let base = second_append_base();
    for (fault, kind, error) in [
        (LogFault::CrashAt(base + 1), FiredFault::Crash, dead()),
        (
            LogFault::FailSync { at: base + 1 },
            FiredFault::FailSync,
            LogIoError::SyncFailed,
        ),
    ] {
        let sim = Sim::new();
        let (log, result) = two_appends(&sim, LogFaults::just(fault));
        assert_eq!(result, Err(error));
        assert_eq!(log.crashed(), kind == FiredFault::Crash);
        let fired: Vec<_> = log
            .step_records()
            .into_iter()
            .filter(|r| r.fired.is_some())
            .collect();
        assert_eq!(
            fired,
            vec![StepRecord {
                index: base + 1,
                call: LogCall::Append,
                within: 1,
                op: LogOp::FileSync {
                    path: log_path(&volume())
                },
                fired: Some(kind),
            }]
        );
    }
}

// ------------------------------------------------ the rows of a crash

/// The steps before the second append, in a fault-free run of
/// [`two_appends`].
fn second_append_base() -> u32 {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let env = envelope(1);
    start(&log, &env);
    block_on(log.append(&append(&env, 1))).unwrap();
    log.steps()
}

/// Start, append seq 1, append seq 2 — which `faults` may interrupt.
fn two_appends(sim: &Sim, faults: LogFaults) -> (SimDecisionLog, Result<(), LogIoError>) {
    let log = sim.decision_log(0, faults);
    let env = envelope(1);
    start(&log, &env);
    block_on(log.append(&append(&env, 1))).unwrap();
    let second = block_on(log.append(&append(&env, 2)));
    (log, second)
}

/// Seeded host crashes at each step of an append reach every outcome
/// [`DrawRow`] names, and each lands where recovery says: a survivor
/// leaves two committed records, every other outcome one.
#[test]
fn seeded_crashes_reach_every_row_of_the_table() {
    let base = second_append_base();
    let env = envelope(1);
    let one = log_bytes(&env, [1]);
    let two = log_bytes(&env, [1, 2]);
    let mut counts: BTreeMap<DrawRow, u32> = BTreeMap::new();
    for step in 0..4 {
        for seed in 0..SEEDS {
            let sim = Sim::new();
            let (log, second) = two_appends(&sim, LogFaults::just(LogFault::CrashAt(base + step)));
            assert!(second.is_err(), "the crash interrupts the second append");
            let report = log.crash_host(&mut seeded(seed));
            let bytes = read(&log).expect("the log survives: it was durable before");
            let classified = classify(&bytes, &volume()).expect("a crash never damages history");
            let Classified::Log {
                records,
                committed_len,
                ..
            } = classified
            else {
                panic!("a log with an envelope classifies as a log");
            };
            let rows: Vec<DrawRow> = report.rows.iter().map(|(_, _, row)| *row).collect();
            assert!(rows.len() <= 1, "one append was in flight: {rows:?}");
            let expected = if rows == [DrawRow::Survivor] {
                &two
            } else {
                &one
            };
            assert_eq!(
                records.len() + 1,
                if rows == [DrawRow::Survivor] { 3 } else { 2 }
            );
            assert_eq!(bytes.get(..committed_len), Some(expected.as_slice()));
            for row in rows {
                *counts.entry(row).or_default() += 1;
            }
        }
    }
    eprintln!("rows reached: {counts:?}");
    for row in [
        DrawRow::RecordAbsent,
        DrawRow::RecordTorn,
        DrawRow::RecordWholeUnsynced,
        DrawRow::MarkAbsentOrTorn,
        DrawRow::Survivor,
    ] {
        assert!(
            counts.get(&row).copied().unwrap_or(0) > 0,
            "no seeded run reached {row}: {counts:?}"
        );
    }
}

/// The same seed replays the same draw into the same artifact, and a
/// different draw renders differently.
#[test]
fn a_crash_draw_is_in_the_artifact() {
    let base = second_append_base();
    let render = |seed: u64| {
        let sim = Sim::new();
        let (log, _) = two_appends(&sim, LogFaults::just(LogFault::CrashAt(base + 1)));
        let report = log.crash_host(&mut seeded(seed));
        (sim.trace().render(), read(&log), report)
    };
    let (first, bytes, _) = render(3);
    assert_eq!(render(3).0, first, "one seed, one artifact");
    let other = (0..SEEDS)
        .map(render)
        .find(|(_, b, _)| *b != bytes)
        .expect("some seed draws different bytes");
    assert_ne!(other.0, first, "different drawn bytes render differently");
    assert!(first.contains("log-draw path=log:dlog"), "{first}");
    assert!(first.contains("log-file path=log:dlog"), "{first}");
}

// ------------------------------------------------ the ends of a run

/// After a failed sync, a process restart still reads every byte
/// written — the failed ones included — and they stay pending, so a
/// later host crash draws them like any other.
#[test]
fn restart_keeps_failed_sync_bytes_readable() {
    let base = second_append_base();
    let env = envelope(1);
    let mut dropped = false;
    for seed in 0..SEEDS {
        let sim = Sim::new();
        let (log, second) = two_appends(&sim, LogFaults::just(LogFault::FailSync { at: base + 3 }));
        assert_eq!(second, Err(LogIoError::SyncFailed));
        log.restart_process();
        assert_eq!(
            read(&log),
            Some(log_bytes(&env, [1, 2])),
            "the page cache keeps the failed mark readable"
        );
        let report = log.crash_host(&mut seeded(seed));
        dropped |= report
            .rows
            .iter()
            .any(|(_, _, r)| *r == DrawRow::MarkAbsentOrTorn);
    }
    assert!(dropped, "a failed sync's bytes are still drawn at a crash");
}

/// What one crash persisted, no later crash redraws.
#[test]
fn a_second_crash_never_redraws_the_first() {
    let base = second_append_base();
    let (log, survivor) = (0..SEEDS)
        .find_map(|seed| {
            let sim = Sim::new();
            let (log, _) = two_appends(&sim, LogFaults::just(LogFault::CrashAt(base + 3)));
            let report = log.crash_host(&mut seeded(seed));
            report
                .rows
                .iter()
                .any(|(_, _, r)| *r == DrawRow::Survivor)
                .then(|| {
                    let bytes = read(&log);
                    (log, bytes)
                })
        })
        .expect("some seed keeps the survivor");
    for seed in 0..SEEDS {
        let report = log.crash_host(&mut seeded(seed));
        assert!(report.rows.is_empty(), "nothing is pending any more");
        assert_eq!(read(&log), survivor, "seed {seed} redrew a persisted byte");
    }
}

// ---------------------------------------------------- media faults

/// Three acknowledged records, then a host crash carrying `fault`.
fn three_records_then(fault: LogFault) -> (SimDecisionLog, CrashReport) {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::just(fault));
    let env = envelope(1);
    start(&log, &env);
    for seq in 1..=3 {
        block_on(log.append(&append(&env, seq))).unwrap();
    }
    let report = log.crash_host(&mut seeded(0));
    (log, report)
}

#[test]
fn detectable_corruption_makes_recovery_refuse() {
    for record in 0..3 {
        let (log, report) = three_records_then(LogFault::CorruptDetectable {
            volume: volume(),
            record,
        });
        assert_eq!(report.damaged.len(), 1, "the fault fired");
        let bytes = read(&log).unwrap();
        let err = classify(&bytes, &volume()).expect_err("damage before a valid mark refuses");
        assert_eq!(err.reason, LogErrorReason::DamagedCommittedHistory);
    }
    let (_, report) = three_records_then(LogFault::CorruptDetectable {
        volume: volume(),
        record: 3,
    });
    assert_eq!(report.unfired, 1, "a fourth record does not exist");
}

/// [`LogFault::ResidualLoss`] with `into_record: false` leaves the
/// damaged span's first record's own bytes untouched — only its mark
/// and everything after are destroyed. The tail bound then holds
/// that intact record to the
/// LEGAL NEXT record's own length plus
/// `MARK_LEN`: fine when it is the only record damaged (its mark alone
/// follows), but every later record's own bytes plus mark push the tail
/// past that bound, so recovery refuses rather than discards. Damage
/// starting `into_record: true` instead breaks that first record's own
/// check, so the tail falls to the (much larger) `RECORD_V1_MAX` bound
/// instead — comfortably inside it here, since these fixture records
/// are a few hundred bytes each — and recovery discards every time.
#[test]
fn residual_loss_follows_the_tail_bound() {
    let env = envelope(1);
    for records in 1..=3u32 {
        for into_record in [false, true] {
            let (log, report) = three_records_then(LogFault::ResidualLoss {
                volume: volume(),
                records,
                into_record,
            });
            assert_eq!(report.damaged.len(), 1, "the fault fired");
            let bytes = read(&log).unwrap();
            let verdict = classify(&bytes, &volume());
            if into_record || records == 1 {
                let kept = 3 - u64::from(records);
                let Ok(Classified::Log {
                    records: recovered,
                    committed_len,
                    ..
                }) = verdict
                else {
                    panic!(
                        "records={records} into_record={into_record}: within the tail bound, \
                         recovery must discard, never refuse: {verdict:?}"
                    );
                };
                assert_eq!(
                    recovered,
                    (1..=kept).map(|n| record(&volume(), n)).collect::<Vec<_>>()
                );
                assert_eq!(
                    bytes.get(..committed_len),
                    Some(log_bytes(&env, 1..=kept).as_slice())
                );
            } else {
                // `records` in `2..=3`, `into_record: false`: more than
                // one intact record's own bytes lie in the tail, past
                // the legal-next record's own length plus `MARK_LEN`.
                assert_eq!(
                    verdict.map_err(|e| e.reason),
                    Err(LogErrorReason::DamagedCommittedHistory),
                    "records={records} into_record={into_record}: an intact record followed by \
                     more than one destroyed mark must refuse"
                );
            }
        }
    }
}

// ---------------------------------------- crashes inside the namespace

/// The steps a fault-free `initialise` takes after the marker, and the
/// offset of its link among them.
const INITIALISE_STEPS: u32 = 8;
const INITIALISE_LINK: u32 = 4;

/// A host crash at each step of `initialise`: the log's name is either
/// absent or names the whole envelope — never a torn one — and only a
/// crash after the link can leave it present.
#[test]
fn a_crash_at_each_step_of_initialise() {
    let env = envelope(1);
    let whole = encode_envelope(&env).as_bytes().to_vec();
    let base = {
        let sim = Sim::new();
        let log = sim.decision_log(0, LogFaults::none());
        block_on(log.write_marker(&marker())).unwrap();
        let base = log.steps();
        block_on(log.initialise(&encode_envelope(&env))).unwrap();
        assert_eq!(log.steps() - base, INITIALISE_STEPS);
        base
    };
    for step in 0..INITIALISE_STEPS {
        let (mut present, mut absent) = (0, 0);
        for seed in 0..SEEDS {
            let sim = Sim::new();
            let log = sim.decision_log(0, LogFaults::just(LogFault::CrashAt(base + step)));
            block_on(log.write_marker(&marker())).unwrap();
            assert!(block_on(log.initialise(&encode_envelope(&env))).is_err());
            log.crash_host(&mut seeded(seed));
            assert_eq!(
                block_on(log.read_marker()),
                Ok(MarkerRead::Present(marker().as_bytes().to_vec())),
                "the marker was durable before initialise began"
            );
            block_on(log.remove_temporary(&volume())).unwrap();
            match read(&log) {
                Some(bytes) => {
                    assert_eq!(bytes, whole, "a linked log holds the whole synced envelope");
                    present += 1;
                }
                None => absent += 1,
            }
        }
        match step {
            s if s <= INITIALISE_LINK => assert_eq!(present, 0, "step {s}: no link yet"),
            s if s == INITIALISE_STEPS - 1 => {
                assert_eq!(absent, 0, "step {s}: the state directory's sync returned");
            }
            s => assert!(
                present > 0 && absent > 0,
                "step {s}: an unsynced link may or may not survive ({present}/{absent})"
            ),
        }
    }
}

/// A host crash at each step of a first marker write: the marker is
/// missing — with the state directory absent, empty, or holding the
/// temporary — or present with exactly the new bytes; once the state
/// directory's sync has returned (a crash at the anchor sync, the last
/// step), always present.
#[test]
fn a_crash_at_each_step_of_a_first_marker_write() {
    let steps = 8;
    for step in 0..steps {
        let mut seen = BTreeMap::new();
        for seed in 0..SEEDS {
            let sim = Sim::new();
            let log = sim.decision_log(0, LogFaults::just(LogFault::CrashAt(step)));
            assert!(block_on(log.write_marker(&marker())).is_err());
            log.crash_host(&mut seeded(seed));
            let outcome = match block_on(log.read_marker()).unwrap() {
                MarkerRead::Present(bytes) => {
                    assert_eq!(bytes, marker().as_bytes(), "a marker is never torn");
                    "present"
                }
                MarkerRead::Missing {
                    state_dir: StateDirectory::Absent,
                } => "absent",
                MarkerRead::Missing {
                    state_dir: StateDirectory::Empty,
                } => "empty",
                MarkerRead::Missing {
                    state_dir: StateDirectory::Occupied,
                } => "occupied",
            };
            *seen.entry(outcome).or_insert(0u32) += 1;
        }
        if step == 0 {
            assert_eq!(seen.keys().copied().collect::<Vec<_>>(), ["absent"]);
        }
        if step == steps - 1 {
            assert_eq!(
                seen.keys().copied().collect::<Vec<_>>(),
                ["present"],
                "the state directory's sync returned before the anchor sync"
            );
        }
        if step == steps - 2 {
            for outcome in ["empty", "occupied", "present"] {
                assert!(
                    seen.contains_key(outcome),
                    "a crash before the directory sync returned can leave {outcome}: {seen:?}"
                );
            }
        }
    }
}

/// A host crash at each step of a marker rename-over: the old marker
/// stays the medium's answer until the state directory's sync returns,
/// so the marker is always the old or the new one, whole.
#[test]
fn a_crash_at_each_step_of_a_marker_rename_over() {
    let old = clean_marker();
    // The second write's steps: unlink the temporary, create, write,
    // file sync, rename, state-directory sync.
    let steps = 6;
    let base = 8;
    for step in 0..steps {
        let (mut olds, mut news) = (0, 0);
        for seed in 0..SEEDS {
            let sim = Sim::new();
            let log = sim.decision_log(0, LogFaults::just(LogFault::CrashAt(base + step)));
            block_on(log.write_marker(&old)).unwrap();
            assert_eq!(log.steps(), base);
            assert!(block_on(log.write_marker(&marker())).is_err());
            log.crash_host(&mut seeded(seed));
            match block_on(log.read_marker()).unwrap() {
                MarkerRead::Present(bytes) if bytes == old.as_bytes() => olds += 1,
                MarkerRead::Present(bytes) if bytes == marker().as_bytes() => news += 1,
                other => panic!("step {step}: the marker is old or new, whole: {other:?}"),
            }
        }
        if step < 5 {
            assert_eq!(news, 0, "step {step}: no rename yet");
        } else {
            assert!(
                olds > 0 && news > 0,
                "an unsynced rename-over may go either way"
            );
        }
    }
}

// ---------------------------------------------- the ordering checks

fn has(log: &SimDecisionLog, violation: LogViolation) -> bool {
    log.violations().contains(&violation)
}

fn barrier(b: Barrier) -> LogViolation {
    LogViolation::WriteBeforeBarrier(b)
}

/// A correct fake and a correct caller: start, two appends, a
/// truncation, a resync — no violation.
#[test]
fn a_correct_run_records_no_violation() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let env = envelope(1);
    start(&log, &env);
    block_on(log.append(&append(&env, 1))).unwrap();
    let len = u64::try_from(read(&log).unwrap().len()).unwrap();
    block_on(log.append(&append(&env, 2))).unwrap();
    block_on(log.truncate(&volume(), len)).unwrap();
    block_on(log.resync(&volume())).unwrap();
    block_on(log.append(&append(&env, 2))).unwrap();
    assert_eq!(log.violations(), []);
}

#[test]
fn mutation_mark_before_record_sync_is_caught() {
    let sim = Sim::new();
    let log = sim.decision_log_variant(0, LogFaults::none(), Mutation::MarkBeforeRecordSync);
    let env = envelope(1);
    start(&log, &env);
    block_on(log.append(&append(&env, 1))).unwrap();
    assert!(
        has(&log, LogViolation::MarkBeforeRecordSync),
        "{:?}",
        log.violations()
    );
}

#[test]
fn a_log_write_before_the_marker_is_caught() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    block_on(log.initialise(&encode_envelope(&envelope(1)))).unwrap();
    assert_eq!(log.violations(), [barrier(Barrier::Marker)]);
}

#[test]
fn mutation_marker_skips_dir_sync_is_caught() {
    let sim = Sim::new();
    let log = sim.decision_log_variant(0, LogFaults::none(), Mutation::MarkerSkipsDirSync);
    start(&log, &envelope(1));
    assert_eq!(log.violations(), [barrier(Barrier::Marker)]);
}

#[test]
fn mutation_marker_skips_anchor_sync_is_caught() {
    let sim = Sim::new();
    let log = sim.decision_log_variant(0, LogFaults::none(), Mutation::MarkerSkipsAnchorSync);
    start(&log, &envelope(1));
    assert_eq!(log.violations(), [barrier(Barrier::Marker)]);
}

#[test]
fn mutation_marker_skips_anchor_sync_is_caught_over_an_existing_empty_state_dir() {
    // The directory exists before the first marker write, so this
    // process never creates it; the parent sync is still owed.
    let sim = Sim::new();
    let log = sim.decision_log_variant(0, LogFaults::none(), Mutation::MarkerSkipsAnchorSync);
    block_on(log.seed_empty_state_dir());
    start(&log, &envelope(1));
    assert_eq!(log.violations(), [barrier(Barrier::Marker)]);
}

#[test]
fn a_second_marker_rename_does_not_discharge_the_first_ones_anchor_sync() {
    // The first write created the marker and skipped the anchor sync;
    // the second renames over it and owes none of its own. The first
    // write's debt still stands at the log write.
    let sim = Sim::new();
    let log = sim.decision_log_variant(0, LogFaults::none(), Mutation::MarkerSkipsAnchorSync);
    block_on(log.seed_empty_state_dir());
    block_on(log.write_marker(&marker())).unwrap();
    start(&log, &envelope(1));
    assert!(
        has(&log, barrier(Barrier::Marker)),
        "{:?}",
        log.violations()
    );
}

#[test]
fn an_append_after_an_unfinished_initialise_is_caught() {
    // The state directory's sync is initialise's seventh step after the
    // marker's eight.
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::just(LogFault::FailSync { at: 8 + 6 }));
    let env = envelope(1);
    block_on(log.write_marker(&marker())).unwrap();
    assert_eq!(
        block_on(log.initialise(&encode_envelope(&env))),
        Err(LogIoError::SyncFailed)
    );
    let _ = block_on(log.append(&append(&env, 1)));
    assert!(
        has(&log, barrier(Barrier::Initialise)),
        "{:?}",
        log.violations()
    );
}

#[test]
fn mutation_initialise_skips_namespace_sync_is_caught() {
    let sim = Sim::new();
    let log =
        sim.decision_log_variant(0, LogFaults::none(), Mutation::InitialiseSkipsNamespaceSync);
    let env = envelope(1);
    start(&log, &env);
    block_on(log.append(&append(&env, 1))).unwrap();
    assert_eq!(log.violations(), [barrier(Barrier::Initialise)]);
}

/// An adopted empty log: initialised, then a host crash, then a second
/// process that writes its marker (the state directory exists, so no
/// anchor sync) and runs `recover` before appending.
fn adopted_empty(log: &SimDecisionLog, recover: impl FnOnce(&SimDecisionLog)) {
    let env = envelope(1);
    start(log, &env);
    log.crash_host(&mut seeded(0));
    block_on(log.write_marker(&marker())).unwrap();
    recover(log);
    block_on(log.append(&append(&env, 1))).unwrap();
}

#[test]
fn an_append_to_an_adopted_empty_log_needs_complete_namespace() {
    let sim = Sim::new();
    let skipped = sim.decision_log(0, LogFaults::none());
    adopted_empty(&skipped, |_| {});
    assert_eq!(skipped.violations(), [barrier(Barrier::CompleteNamespace)]);

    let sim = Sim::new();
    let completed = sim.decision_log(0, LogFaults::none());
    adopted_empty(&completed, |log| {
        block_on(log.complete_namespace(&volume())).unwrap();
    });
    assert_eq!(completed.violations(), []);
}

#[test]
fn mutation_complete_namespace_skips_sync_is_caught() {
    let sim = Sim::new();
    let log = sim.decision_log_variant(0, LogFaults::none(), Mutation::CompleteNamespaceSkipsSync);
    adopted_empty(&log, |log| {
        block_on(log.complete_namespace(&volume())).unwrap();
    });
    assert_eq!(log.violations(), [barrier(Barrier::CompleteNamespace)]);
}

/// Start and one append; then truncate back to the envelope and append
/// again.
fn truncate_then_append(log: &SimDecisionLog) -> Result<(), LogIoError> {
    let env = envelope(1);
    start(log, &env);
    let len = u64::try_from(encode_envelope(&env).as_bytes().len()).unwrap();
    block_on(log.append(&append(&env, 1))).unwrap();
    let truncated = block_on(log.truncate(&volume(), len));
    let _ = block_on(log.append(&append(&env, 1)));
    truncated
}

#[test]
fn an_append_after_an_unsynced_truncation_is_caught() {
    // The truncation's sync: 8 marker steps, 8 initialise, 4 append,
    // then the truncate step.
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::just(LogFault::FailSync { at: 8 + 8 + 4 + 1 }));
    assert_eq!(truncate_then_append(&log), Err(LogIoError::SyncFailed));
    assert!(
        has(&log, barrier(Barrier::Truncation)),
        "{:?}",
        log.violations()
    );
}

#[test]
fn mutation_truncate_skips_sync_is_caught() {
    let sim = Sim::new();
    let log = sim.decision_log_variant(0, LogFaults::none(), Mutation::TruncateSkipsSync);
    assert_eq!(truncate_then_append(&log), Ok(()));
    assert_eq!(log.violations(), [barrier(Barrier::Truncation)]);
}

/// A log with one record, a host crash, then a second process that
/// writes its marker and runs `recover` before appending.
fn adopted_survivor(log: &SimDecisionLog, recover: impl FnOnce(&SimDecisionLog)) {
    let env = envelope(1);
    start(log, &env);
    block_on(log.append(&append(&env, 1))).unwrap();
    log.crash_host(&mut seeded(0));
    block_on(log.write_marker(&marker())).unwrap();
    recover(log);
    block_on(log.append(&append(&env, 2))).unwrap();
}

#[test]
fn an_append_to_an_adopted_log_needs_a_resync() {
    let sim = Sim::new();
    let skipped = sim.decision_log(0, LogFaults::none());
    adopted_survivor(&skipped, |_| {});
    assert_eq!(skipped.violations(), [barrier(Barrier::SurvivorResync)]);

    let sim = Sim::new();
    let resynced = sim.decision_log(0, LogFaults::none());
    adopted_survivor(&resynced, |log| block_on(log.resync(&volume())).unwrap());
    assert_eq!(resynced.violations(), []);
}

#[test]
fn mutation_resync_skips_sync_is_caught() {
    let sim = Sim::new();
    let log = sim.decision_log_variant(0, LogFaults::none(), Mutation::ResyncSkipsSync);
    adopted_survivor(&log, |log| block_on(log.resync(&volume())).unwrap());
    assert_eq!(log.violations(), [barrier(Barrier::SurvivorResync)]);
}

/// The first append's record sync: 8 marker steps, 8 initialise, then
/// the record write.
const FIRST_RECORD_SYNC: u32 = 8 + 8 + 1;

#[test]
fn a_mutating_call_after_a_failed_sync_is_caught() {
    let sim = Sim::new();
    let log = sim.decision_log(
        0,
        LogFaults::just(LogFault::FailSync {
            at: FIRST_RECORD_SYNC,
        }),
    );
    let env = envelope(1);
    start(&log, &env);
    assert_eq!(
        block_on(log.append(&append(&env, 1))),
        Err(LogIoError::SyncFailed)
    );
    assert_eq!(log.violations(), []);
    let _ = block_on(log.resync(&volume()));
    assert_eq!(log.violations(), [LogViolation::AfterFence]);
}

#[test]
fn mutation_swallow_sync_failure_is_caught() {
    let sim = Sim::new();
    let log = sim.decision_log_variant(
        0,
        LogFaults::just(LogFault::FailSync {
            at: FIRST_RECORD_SYNC,
        }),
        Mutation::SwallowSyncFailure,
    );
    let env = envelope(1);
    start(&log, &env);
    assert_eq!(
        block_on(log.append(&append(&env, 1))),
        Ok(()),
        "the variant hides the failure"
    );
    block_on(log.append(&append(&env, 2))).unwrap();
    assert!(
        has(&log, LogViolation::AfterFence),
        "{:?}",
        log.violations()
    );
    assert!(
        has(&log, LogViolation::MarkBeforeRecordSync),
        "{:?}",
        log.violations()
    );
}

#[test]
fn an_append_under_another_epoch_is_caught() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    start(&log, &envelope(1));
    block_on(log.append(&append(&envelope(2), 1))).unwrap();
    assert_eq!(log.violations(), [LogViolation::EpochMismatch]);
}

/// A log under epoch 1 survives a host crash; the second process
/// initialises epoch 2 over it and appends under epoch 2. The correct
/// fake refuses the initialise; the variant accepts it, and the append
/// that follows is caught.
#[test]
fn mutation_initialise_succeeds_on_existing_is_caught() {
    let run = |log: &SimDecisionLog| {
        start(log, &envelope(1));
        log.crash_host(&mut seeded(0));
        block_on(log.write_marker(&marker())).unwrap();
        block_on(log.initialise(&encode_envelope(&envelope(2))))
    };
    let sim = Sim::new();
    let correct = sim.decision_log(0, LogFaults::none());
    assert_eq!(run(&correct), Err(LogIoError::AlreadyExists));

    let sim = Sim::new();
    let variant =
        sim.decision_log_variant(0, LogFaults::none(), Mutation::InitialiseSucceedsOnExisting);
    assert_eq!(run(&variant), Ok(()));
    block_on(variant.complete_namespace(&volume())).unwrap();
    block_on(variant.append(&append(&envelope(2), 1))).unwrap();
    assert_eq!(variant.violations(), [LogViolation::EpochMismatch]);
}

// ------------------------------------------- fences, crashes, claims

/// A failed sync's bytes stay unsynced through a process restart and a
/// re-sync that reports success — the next host crash can still lose
/// them.
#[test]
fn a_failed_sync_survives_a_restart_and_a_resync() {
    let base = second_append_base();
    let mut lost = 0;
    for seed in 0..SEEDS {
        let sim = Sim::new();
        let (log, second) = two_appends(&sim, LogFaults::just(LogFault::FailSync { at: base + 3 }));
        assert_eq!(second, Err(LogIoError::SyncFailed));
        log.restart_process();
        assert_eq!(
            block_on(log.resync(&volume())),
            Ok(()),
            "the re-sync succeeds"
        );
        let report = log.crash_host(&mut seeded(seed));
        if report
            .rows
            .iter()
            .any(|(_, _, r)| *r == DrawRow::MarkAbsentOrTorn)
        {
            lost += 1;
        }
    }
    assert!(
        lost > 0,
        "a re-sync after a failed sync made nothing durable"
    );
}

/// A process restart does not clear a fence; a host crash does.
#[test]
fn the_fence_survives_a_process_restart() {
    let base = second_append_base();
    let sim = Sim::new();
    let (log, second) = two_appends(&sim, LogFaults::just(LogFault::FailSync { at: base + 3 }));
    assert_eq!(second, Err(LogIoError::SyncFailed));
    log.restart_process();
    block_on(log.resync(&volume())).unwrap();
    assert_eq!(log.violations(), [LogViolation::SameBootAfterFence]);
    log.crash_host(&mut seeded(0));
    block_on(log.resync(&volume())).unwrap();
    assert_eq!(
        log.violations(),
        [LogViolation::SameBootAfterFence],
        "a host crash clears the fence"
    );
}

/// A call suspended between its record's write and its sync dies when
/// a host crash happens meanwhile: it applies nothing more.
#[test]
fn a_host_crash_kills_an_in_flight_call() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let env = envelope(1);
    start(&log, &env);
    block_on(log.append(&append(&env, 1))).unwrap();
    let second = append(&env, 2);
    let mut fut = pin!(log.append(&second));
    let mut cx = Context::from_waker(Waker::noop());
    // The record's write step, then the suspension before its sync.
    assert!(fut.as_mut().poll(&mut cx).is_pending());
    assert!(fut.as_mut().poll(&mut cx).is_pending());
    let before = block_on(log.read(&volume())).unwrap().unwrap();
    assert_eq!(before, {
        let mut b = log_bytes(&env, [1]);
        b.extend_from_slice(second.record());
        b
    });
    log.crash_host(&mut seeded(0));
    let after_crash = read(&log);
    let result = loop {
        if let Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            break r;
        }
    };
    assert!(result.is_err(), "the in-flight call dies");
    assert_eq!(
        read(&log),
        after_crash,
        "and applies nothing after the crash"
    );
}

/// Two appends joined on one volume's log: the second's start is a
/// concurrent call.
#[test]
fn a_concurrent_call_on_one_log_is_caught() {
    let sim = Sim::new();
    let log = SharedLog::new(sim.decision_log(0, LogFaults::none()));
    let env = envelope(1);
    start(&log, &env);
    let tasks: Vec<Task<Result<(), LogIoError>>> = [1u64, 2]
        .into_iter()
        .map(|seq| {
            let log = SharedLog::clone(&log);
            let a = append(&env, seq);
            let task: Task<Result<(), LogIoError>> = Box::pin(async move { log.append(&a).await });
            task
        })
        .collect();
    let _ = Scheduler::new(1).run(tasks);
    assert!(
        log.violations().contains(&LogViolation::ConcurrentCall),
        "{:?}",
        log.violations()
    );
}

/// `initialise` on an existing log answers `AlreadyExists` after it
/// began — it removed and created its temporary — so it fences.
#[test]
fn an_initialise_refused_after_it_began_fences() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let env = envelope(1);
    start(&log, &env);
    assert_eq!(
        block_on(log.initialise(&encode_envelope(&env))),
        Err(LogIoError::AlreadyExists)
    );
    block_on(log.append(&append(&env, 1))).unwrap();
    assert_eq!(log.violations(), [LogViolation::AfterFence]);
}

/// A dropped mutating call fences, as the seam's cancellation rule
/// says.
#[test]
fn a_dropped_mutating_call_fences() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let env = envelope(1);
    start(&log, &env);
    {
        let a = append(&env, 1);
        let mut fut = pin!(log.append(&a));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        assert!(fut.as_mut().poll(&mut cx).is_pending());
    }
    let _ = block_on(log.resync(&volume()));
    assert!(
        log.violations().contains(&LogViolation::AfterFence),
        "{:?}",
        log.violations()
    );
}

/// A crash that leaves a torn tail: an append that follows a re-sync
/// but no truncation is caught; one after the truncation is not.
#[test]
fn an_append_over_an_untruncated_tail_is_caught() {
    let base = second_append_base();
    let env = envelope(1);
    let torn = |seed: u64| {
        let sim = Sim::new();
        let (log, _) = two_appends(&sim, LogFaults::just(LogFault::CrashAt(base + 1)));
        log.crash_host(&mut seeded(seed));
        let bytes = read(&log).unwrap();
        match classify(&bytes, &volume()) {
            Ok(Classified::Log {
                committed_len,
                tail_len,
                ..
            }) if tail_len > 0 => Some((log, committed_len)),
            _ => None,
        }
    };
    let seed = (0..SEEDS)
        .find(|&seed| torn(seed).is_some())
        .expect("some seed leaves a torn tail");

    let (log, _) = torn(seed).unwrap();
    block_on(log.write_marker(&marker())).unwrap();
    block_on(log.resync(&volume())).unwrap();
    block_on(log.append(&append(&env, 2))).unwrap();
    assert!(
        log.violations().contains(&LogViolation::TailNotTruncated),
        "{:?}",
        log.violations()
    );

    let (log, committed_len) = torn(seed).unwrap();
    block_on(log.write_marker(&marker())).unwrap();
    block_on(log.truncate(&volume(), u64::try_from(committed_len).unwrap())).unwrap();
    block_on(log.append(&append(&env, 2))).unwrap();
    assert_eq!(log.violations(), []);
}

/// An adopted empty log's barrier is its own `complete_namespace`'s:
/// another volume's does not satisfy it.
#[test]
fn complete_namespace_is_per_volume() {
    let other = VolumeName::new("other".to_owned()).unwrap();
    let other_env = Envelope::new(other.clone(), Epoch::from_bytes([7; EPOCH_LEN]));
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let env = envelope(1);
    start(&log, &env);
    block_on(log.initialise(&encode_envelope(&other_env))).unwrap();
    log.crash_host(&mut seeded(0));
    block_on(log.write_marker(&marker())).unwrap();
    block_on(log.complete_namespace(&other)).unwrap();
    block_on(log.append(&append(&env, 1))).unwrap();
    assert_eq!(log.violations(), [barrier(Barrier::CompleteNamespace)]);
}

/// A truncation the crash undoes takes the append written after it
/// with it, and the report names that append.
#[test]
fn an_undone_truncation_reports_the_appends_it_loses() {
    // 16 start steps, two appends of 4, the truncation (its sync
    // skipped), then the re-append's record write and its sync.
    let crash_at = 16 + 8 + 1 + 1;
    let env = envelope(1);
    let mut undone = 0;
    for seed in 0..SEEDS {
        let sim = Sim::new();
        let log = sim.decision_log_variant(
            0,
            LogFaults::just(LogFault::CrashAt(crash_at)),
            Mutation::TruncateSkipsSync,
        );
        start(&log, &env);
        block_on(log.append(&append(&env, 1))).unwrap();
        let len = u64::try_from(log_bytes(&env, [1]).len()).unwrap();
        block_on(log.append(&append(&env, 2))).unwrap();
        block_on(log.truncate(&volume(), len)).unwrap();
        assert!(block_on(log.append(&append(&env, 2))).is_err());
        let report = log.crash_host(&mut seeded(seed));
        if report
            .rows
            .iter()
            .any(|(_, _, r)| *r == DrawRow::LostWithUndoneTruncation)
        {
            assert_eq!(read(&log), Some(log_bytes(&env, [1, 2])));
            undone += 1;
        }
    }
    assert!(undone > 0, "some seed undoes the truncation");
}

/// Media faults target the records `classify` reports, so they reach a
/// log planted through the fixture hooks, which this fake never
/// appended to.
#[test]
fn damage_reaches_a_planted_log() {
    let env = envelope(1);
    let sim = Sim::new();
    let log = sim.decision_log(
        0,
        LogFaults::just(LogFault::CorruptDetectable {
            volume: volume(),
            record: 1,
        }),
    );
    block_on(log.seed_bytes(&volume(), log_bytes(&env, 1..=3)));
    let report = log.crash_host(&mut seeded(0));
    assert_eq!(report.damaged.len(), 1, "the fault fired");
    let err = classify(&read(&log).unwrap(), &volume()).expect_err("detectable damage refuses");
    assert_eq!(err.reason, LogErrorReason::DamagedCommittedHistory);
}

/// One live handle per world.
#[test]
#[should_panic(expected = "one live decision-log handle per sim world")]
fn a_second_live_handle_is_refused() {
    let sim = Sim::new();
    let _first = sim.decision_log(0, LogFaults::none());
    let _second = sim.decision_log(1, LogFaults::none());
}

// ------------------------------------------ settling cut-off calls

/// Poll `fut` until it has issued its record write and suspended before
/// the sync: two polls for an append.
fn suspend_after_record_write<F: Future>(fut: &mut std::pin::Pin<Box<F>>) {
    let mut cx = Context::from_waker(Waker::noop());
    assert!(fut.as_mut().poll(&mut cx).is_pending());
    assert!(fut.as_mut().poll(&mut cx).is_pending());
}

/// A call cut off by a restart fences the disk at the restart, while
/// its future is still alive and unpolled.
#[test]
fn a_restart_fences_at_the_cut() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let env = envelope(1);
    start(&log, &env);
    let a = append(&env, 1);
    let mut old = Box::pin(log.append(&a));
    suspend_after_record_write(&mut old);
    log.restart_process();
    block_on(log.write_marker(&marker())).unwrap();
    assert_eq!(log.violations(), [LogViolation::SameBootAfterFence]);
    drop(old);
    assert_eq!(
        log.violations(),
        [LogViolation::SameBootAfterFence],
        "the retired call's drop settles nothing twice"
    );
}

/// A host crash retires the old process's claims: a new call on the
/// same log is no concurrent call, the old future's drop does not
/// release the new call's claim, and a third call while the new one is
/// in flight still is one.
#[test]
fn claims_belong_to_their_process() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let env = envelope(1);
    start(&log, &env);
    let a = append(&env, 1);
    let mut old = Box::pin(log.append(&a));
    suspend_after_record_write(&mut old);
    log.crash_host(&mut seeded(0));
    block_on(log.write_marker(&marker())).unwrap();

    let vol = volume();
    let mut new = Box::pin(log.resync(&vol));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        new.as_mut().poll(&mut cx).is_pending(),
        "the new call is in flight"
    );
    assert!(!log.violations().contains(&LogViolation::ConcurrentCall));

    drop(old);
    let _ = block_on(log.resync(&vol));
    assert!(
        log.violations().contains(&LogViolation::ConcurrentCall),
        "{:?}",
        log.violations()
    );
    let _ = block_on(new);
}

/// A failed marker write fences the disk like any other failed sync
/// (spec §6.2): a same-boot restart's retry is not a clean retry, and
/// only a host crash clears the fence.
#[test]
fn a_failed_first_marker_write_fences_until_a_host_crash() {
    // Step 7 is the first marker write's anchor sync: mkdir, unlink the
    // temporary, create it, write, file sync, rename over the marker,
    // state-directory sync, anchor sync.
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::just(LogFault::FailSync { at: 7 }));
    assert_eq!(
        block_on(log.write_marker(&marker())),
        Err(LogIoError::SyncFailed)
    );
    // The rename and the state-directory sync already landed before the
    // anchor sync failed, so the marker reads present, under the
    // current boot, for the next read.
    assert_eq!(
        block_on(log.read_marker()),
        Ok(MarkerRead::Present(marker().as_bytes().to_vec())),
        "the marker reads present despite the failed write"
    );

    log.restart_process();
    block_on(log.write_marker(&marker())).unwrap();
    assert_eq!(
        log.violations(),
        [LogViolation::SameBootAfterFence],
        "a same-boot retry is not a clean recovery"
    );

    log.crash_host(&mut seeded(0));
    block_on(log.write_marker(&marker())).unwrap();
    assert_eq!(
        log.violations(),
        [LogViolation::SameBootAfterFence],
        "a host crash clears the fence"
    );
}

/// A call that answers `NotFound` before any step does not fence, even
/// while another call on another log has issued steps. Beginning it
/// beside the busy call is still an overlap: the engine's log token
/// covers a call from its start, whatever it then finds.
#[test]
fn an_early_not_found_beside_a_busy_call_does_not_fence() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let env = envelope(1);
    start(&log, &env);
    let vol = volume();
    let mut busy = Box::pin(log.resync(&vol));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(busy.as_mut().poll(&mut cx).is_pending());
    let missing = VolumeName::new("missing".to_owned()).unwrap();
    assert_eq!(
        block_on(log.complete_namespace(&missing)),
        Err(LogIoError::NotFound)
    );
    block_on(busy).unwrap();
    block_on(log.resync(&vol)).unwrap();
    assert_eq!(log.violations(), [LogViolation::OverlappingCall]);
}

// ------------------------------------- one log call at a time, anywhere

fn volume_b() -> VolumeName {
    VolumeName::new("dlog-b".to_owned()).unwrap()
}

fn envelope_b(epoch: u8) -> Envelope {
    Envelope::new(volume_b(), Epoch::from_bytes([epoch; EPOCH_LEN]))
}

/// A run's start over two logs: the marker, then both logs.
fn start_two(log: &SimDecisionLog) {
    start(log, &envelope(1));
    block_on(log.initialise(&encode_envelope(&envelope_b(2)))).unwrap();
}

/// Two appends to two different logs, one after the other: no overlap.
#[test]
fn appends_to_two_logs_in_turn_do_not_overlap() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    start_two(&log);
    block_on(log.append(&append(&envelope(1), 1))).unwrap();
    block_on(log.append(&append(&envelope_b(2), 1))).unwrap();
    assert_eq!(log.violations(), []);
}

/// Two appends to two different logs, the second begun while the first
/// is suspended after its record write: an overlap, though neither log
/// sees a concurrent call.
#[test]
fn appends_overlapping_on_two_logs_are_caught() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    start_two(&log);
    let a = append(&envelope(1), 1);
    let mut first = Box::pin(log.append(&a));
    suspend_after_record_write(&mut first);
    block_on(log.append(&append(&envelope_b(2), 1))).unwrap();
    block_on(first).unwrap();
    assert_eq!(log.violations(), [LogViolation::OverlappingCall]);
}

/// `remove_temporary` is outside the token: beside an append on
/// another log it is no overlap.
#[test]
fn remove_temporary_beside_an_append_is_no_overlap() {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    start_two(&log);
    let a = append(&envelope(1), 1);
    let mut first = Box::pin(log.append(&a));
    suspend_after_record_write(&mut first);
    assert_eq!(block_on(log.remove_temporary(&volume_b())), Ok(false));
    block_on(first).unwrap();
    assert_eq!(log.violations(), []);
}

/// Poll `fut` once: it registers its call and suspends inside its first
/// step, before that step applies.
fn suspend_before_first_step<F: Future>(fut: &mut std::pin::Pin<Box<F>>) {
    let mut cx = Context::from_waker(Waker::noop());
    assert!(fut.as_mut().poll(&mut cx).is_pending());
}

/// How many steps [`start_two`] issues, so a fault can be placed after
/// it.
fn start_two_steps() -> u32 {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    start_two(&log);
    log.steps()
}

/// Volume B's append is in flight — suspended in its record write —
/// when volume A's append fails its record sync. B's steps that apply
/// after the failure are caught, though B began before the fence.
#[test]
fn a_step_of_an_in_flight_call_after_a_failed_sync_is_caught() {
    // B's record write claims the first step after the start; A's
    // record write the next; A's record sync the one after.
    let fail_at = start_two_steps() + 2;
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::just(LogFault::FailSync { at: fail_at }));
    start_two(&log);
    let b = append(&envelope_b(2), 1);
    let mut pending = Box::pin(log.append(&b));
    suspend_before_first_step(&mut pending);
    assert_eq!(
        block_on(log.append(&append(&envelope(1), 1))),
        Err(LogIoError::SyncFailed)
    );
    assert!(
        !log.violations().contains(&LogViolation::StepAfterFence),
        "nothing of B has applied since the failure yet"
    );
    let _ = block_on(pending);
    let violations = log.violations();
    assert!(
        violations.contains(&LogViolation::StepAfterFence),
        "{violations:?}"
    );
    assert!(
        !violations.contains(&LogViolation::AfterFence),
        "B began before the fence: {violations:?}"
    );
}

/// The same two appends, B waiting until A's failure has returned and
/// then never issued, as the engine's token and fence make it: nothing
/// is caught.
#[test]
fn nothing_after_a_failed_sync_is_no_violation() {
    let fail_at = start_two_steps() + 1;
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::just(LogFault::FailSync { at: fail_at }));
    start_two(&log);
    assert_eq!(
        block_on(log.append(&append(&envelope(1), 1))),
        Err(LogIoError::SyncFailed)
    );
    assert_eq!(log.violations(), []);
}
