// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::scenario::log_run`: the seed's decoding, the
//! script, the draws' presence in the artifact and the oracle's verdicts.
//! The seeded counts and the cross-process replay live in `tests/`.

use super::*;

use granary_core::authlog::{LogErrorReason, classify};

use granary_core::testkit::DecisionLogFixture;

use crate::decision_log::Mutation;

const SWEEP: u64 = 512;

fn seed(n: u64) -> u64 {
    n | DECISION_LOG_SEEDS
}

fn run_of(n: u64) -> LogRun {
    decision_log_run(seed(n)).unwrap_or_else(|e| panic!("{e}\n{}", e.trace.render()))
}

/// The lines of `text` containing any of `needles`, joined.
fn lines_with(text: &str, needles: &[&str]) -> String {
    text.lines()
        .filter(|line| needles.iter().any(|n| line.contains(n)))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn a_seed_decodes_to_one_plan_whatever_its_selector_bit() {
    for n in 0..64 {
        assert_eq!(LogPlan::decode(n), LogPlan::decode(seed(n)));
        assert_eq!(LogPlan::decode(seed(n)), LogPlan::decode(seed(n)));
    }
    assert_ne!(LogPlan::decode(1), LogPlan::decode(2));
}

#[test]
fn the_seed_space_reaches_every_choice_a_plan_makes() {
    let plans: Vec<LogPlan> = (0..SWEEP).map(LogPlan::decode).collect();
    for kind in LogFaultKind::ALL {
        assert!(
            plans.iter().any(|p| p.kind == kind),
            "no seed decodes to {kind}"
        );
    }
    assert!(plans.iter().any(|p| p.second_crash.is_some()));
    assert!(plans.iter().any(|p| p.mid_crash.is_some()));
    assert!(
        plans
            .iter()
            .all(|p| p.mid_crash.is_none() || p.kind == LogFaultKind::None)
    );
    assert!(plans.iter().any(|p| p.second_crash.is_none()));
    assert!(plans.iter().any(|p| p.into_record));
    assert!(plans.iter().any(|p| !p.into_record));
    let appends: std::collections::BTreeSet<u32> = plans.iter().map(|p| p.appends).collect();
    assert_eq!(appends, (3..=6).collect());
    assert!(plans.iter().all(|p| p.record < p.appends));
    assert!(plans.iter().all(|p| (1..=3).contains(&p.records)));
}

/// Every prefix of the script is a log recovery accepts with exactly
/// that many records, and no record is longer than the format's largest.
#[test]
fn the_script_is_a_legal_log_at_every_length() {
    let script = Script::new(12);
    for count in 0..=12 {
        let bytes = script.prefix_bytes(count);
        let Ok(Classified::Log {
            records,
            committed_len,
            tail_len,
            ..
        }) = classify(&bytes, &script.volume)
        else {
            panic!("the first {count} records do not classify as a log");
        };
        assert_eq!(
            records.as_slice(),
            script.records.get(..count).unwrap_or_default()
        );
        assert_eq!((committed_len, tail_len), (bytes.len(), 0));
    }
    assert!(
        (0..12).all(|i| script.record_len(i) <= RECORD_V1_MAX),
        "a script record is longer than the format allows"
    );
    let kinds: Vec<u8> = script
        .appends
        .iter()
        .take(6)
        .map(|a| a.record().first().copied().unwrap_or(0))
        .collect();
    assert_eq!(
        kinds,
        [1, 2, 3, 1, 2, 3],
        "decision, attestation, landed, again"
    );
}

#[test]
fn a_run_is_a_function_of_its_seed() {
    for n in 0..24 {
        let (a, b) = (
            run_of(n).sim.trace().render(),
            run_of(n).sim.trace().render(),
        );
        assert!(!a.is_empty());
        assert_eq!(a, b, "seed {n} rendered two artifacts");
    }
}

/// Every failed sync lands on the step of the fault-free script the seed
/// names, read off the trace: the fault's own entry, at its own index.
#[test]
fn a_fail_sync_fails_a_real_sync_on_the_step_it_names() {
    let mut fired = 0;
    for n in 0..SWEEP {
        let run = run_of(n);
        let trace = run.sim.trace();
        match (run.plan.kind, run.fail_sync_at) {
            (LogFaultKind::FailSync, Some(at)) => {
                assert!(at < run.steps, "seed {n}");
                assert!(
                    failed_sync_at(&trace, at),
                    "seed {n}: no failed sync at step {at}"
                );
                assert_eq!(failed_syncs(&trace), 1, "seed {n}");
                if let Some(second) = run.second_crash_at {
                    assert!(
                        second > at,
                        "seed {n}: a second crash before the failed sync"
                    );
                }
                fired += 1;
            }
            (LogFaultKind::FailSync, None) => panic!("seed {n}: a fail-sync with no step"),
            (_, at) => {
                assert_eq!(at, None);
                assert_eq!(failed_syncs(&trace), 0, "seed {n}: a sync failed unasked");
            }
        }
    }
    assert!(fired > 0);
}

/// A crash is recorded as an injected step and never as a failed sync, so
/// the fault guard cannot count one for the other.
#[test]
fn a_crash_is_not_a_failed_sync() {
    let mut seen = 0;
    for n in 0..SWEEP {
        let run = run_of(n);
        let trace = run.sim.trace();
        if run.plan.kind != LogFaultKind::FailSync && injected_steps(&trace) > 0 {
            assert!(!fault_fired(LogFaultKind::FailSync, &trace), "seed {n}");
            assert_eq!(failed_syncs(&trace), 0, "seed {n}");
            seen += 1;
        }
    }
    assert!(seen > 0, "no run of the sweep was cut by a crash");
}

#[test]
fn a_second_crash_is_a_second_host_crash() {
    let mut seen = 0;
    for n in 0..SWEEP {
        let run = run_of(n);
        if run.second_crash_at.is_some() {
            let trace = run.sim.trace();
            assert!(host_crashes(&trace) >= 2, "seed {n}");
            assert!(injected_steps(&trace) > 0, "seed {n}");
            seen += 1;
        }
    }
    assert!(seen > 0, "no seed in the sweep has a second crash");
}

/// A crash in the append phase cuts the first process before its first
/// host crash, and only a plan with no other fault has one.
#[test]
fn a_mid_append_crash_cuts_the_first_process() {
    let mut seen = 0;
    for n in 0..SWEEP {
        let run = run_of(n);
        let trace = run.sim.trace();
        assert_eq!(
            cut_by_a_crash(&trace),
            run.mid_crash_at.is_some(),
            "seed {n}"
        );
        if let Some(at) = run.mid_crash_at {
            assert_eq!(run.plan.kind, LogFaultKind::None, "seed {n}");
            assert!(at < run.steps);
            seen += 1;
        }
    }
    assert!(seen > 0, "no seed in the sweep crashes mid-append");
}

/// What holds in every run, from the trace alone: no ordering violation;
/// an honest crash is never refused, so a refusal follows injected damage
/// (the check the run's own oracle makes, made again from the artifact);
/// and no append is ever written after an unsynced truncation.
#[test]
fn every_run_in_a_sweep_holds_the_run_wide_properties() {
    for n in 0..SWEEP {
        let run = run_of(n);
        let trace = run.sim.trace();
        let text = trace.render();
        assert!(!text.contains("log-violation"), "seed {n}:\n{text}");
        let refused = log_verdicts(&trace)
            .iter()
            .any(|v| matches!(v, Verdict::Refused { .. }));
        assert!(
            !refused || !log_damage(&trace).is_empty(),
            "seed {n}: recovery refused a crash with no injected damage:\n{text}"
        );
        assert!(
            !log_rows(&trace).contains(&DrawRow::LostWithUndoneTruncation),
            "seed {n}: an append was written after an unsynced truncation"
        );
        assert!(
            fault_fired(run.plan.kind, &trace),
            "seed {n}: the fault did not fire"
        );
    }
}

/// The plan every draw test varies, written out rather than decoded so a
/// change to the decoding cannot move it: a failed sync of the sync of
/// the last append's mark, so the crash draws over the 97 bytes of one
/// mark and two draws can agree on every boundary while differing in the
/// garbage bytes.
const DRAW_PLAN_TARGET: u32 = 13;

fn draw_plan_run(draw_seed: u64) -> String {
    let plan = LogPlan {
        kind: LogFaultKind::FailSync,
        target: DRAW_PLAN_TARGET,
        draw_seed,
        appends: 4,
        record: 0,
        records: 1,
        into_record: false,
        second_crash: None,
        mid_crash: None,
    };
    run_plan(seed(0), &plan)
        .unwrap_or_else(|e| panic!("{e}"))
        .sim
        .trace()
        .render()
}

/// Two draw seeds, everything else in the plan equal, render different
/// artifacts: the draw is a function of its seed, and it reaches the
/// digest of the file after the crash.
#[test]
fn the_draw_depends_on_the_draw_seed() {
    let files = |t: &str| lines_with(t, &["log-file"]);
    let renders: Vec<String> = (0..32).map(draw_plan_run).collect();
    let digests: std::collections::BTreeSet<String> = renders.iter().map(|t| files(t)).collect();
    assert!(
        digests.len() > 1,
        "32 draw seeds left the same file on the medium: the draw ignores its seed"
    );
    let distinct: std::collections::BTreeSet<&String> = renders.iter().collect();
    assert!(distinct.len() > 1, "32 draw seeds rendered one artifact");
}

/// One drawn byte changes the artifact, and so does one drawn boundary,
/// each measured in something other than the line that records it. The
/// pair draws the same boundaries (`log-draw`, `log-row` and `log-crash`
/// lines equal) and different garbage bytes, so only the digest of the
/// file after the draw can tell them apart. A second pair moves a
/// boundary and must change the file's digest and its length too. The
/// guards re-measure both pairs.
#[test]
fn one_drawn_byte_or_boundary_changes_the_artifact() {
    const SAME_BOUNDARIES: (u64, u64) = (420, 430);
    let boundaries = |t: &str| lines_with(t, &["log-draw", "log-row", "log-crash"]);
    let files = |t: &str| lines_with(t, &["log-file"]);
    let (a, b) = (
        draw_plan_run(SAME_BOUNDARIES.0),
        draw_plan_run(SAME_BOUNDARIES.1),
    );
    assert_eq!(
        boundaries(&a),
        boundaries(&b),
        "draw seeds {SAME_BOUNDARIES:?} no longer draw the same boundaries; re-pin the pair"
    );
    assert!(
        boundaries(&a).contains("fill=seeded"),
        "the pair drew no garbage bytes"
    );
    assert_ne!(
        files(&a),
        files(&b),
        "draw seeds {SAME_BOUNDARIES:?} no longer draw different bytes; re-pin the pair"
    );
    assert_ne!(a, b, "one drawn byte changed and the artifact did not");
    // A boundary alone: a draw seed whose kept prefix differs must leave a
    // different file, so the digest and the length both move.
    let kept = |t: &str| {
        t.lines()
            .find(|l| l.contains("log-draw path=log:sim-log"))
            .and_then(|l| l.split(" kept=").nth(1))
            .and_then(|l| l.split(' ').next())
            .map(str::to_owned)
    };
    let other = (0..SWEEP)
        .map(|d| (d, draw_plan_run(d)))
        .find(|(_, t)| kept(t) != kept(&a) && boundaries(t) != boundaries(&a))
        .unwrap_or_else(|| panic!("no draw seed in the sweep moves a boundary"));
    assert_ne!(
        files(&other.1),
        files(&a),
        "draw seed {} moved a boundary and the file after the crash did not change",
        other.0
    );
}

// ------------------------------------------------------------- the oracle

/// Run `f` over a runner expecting `expect` of a log that holds
/// `committed` script records, `initialised` saying whether `initialise`
/// has returned.
fn with_runner<R>(
    expect: Expect,
    committed: usize,
    initialised: bool,
    f: impl FnOnce(&Runner<'_>, &Script) -> R,
) -> R {
    let sim = Sim::new();
    let log = sim.decision_log(0, LogFaults::none());
    let script = Script::new(8);
    let plan = LogPlan::decode(0);
    let runner = Runner {
        log: &log,
        script: &script,
        plan: &plan,
        rng: Rng::seeded(0, DRAW_STREAM),
        scheduled: Scheduled::default(),
        initialised,
        append_window: None,
        committed,
        expect,
        window: None,
    };
    f(&runner, &script)
}

fn classified(script: &Script, count: usize) -> (Vec<u8>, Result<Classified, LogError>) {
    let bytes = script.prefix_bytes(count);
    let verdict = classify(&bytes, &script.volume);
    (bytes, verdict)
}

fn refusal() -> Result<Classified, LogError> {
    Err(LogError {
        offset: 44,
        reason: LogErrorReason::DamagedCommittedHistory,
    })
}

#[test]
fn the_oracle_accepts_the_expected_records() {
    with_runner(Expect::Committed { honest: true }, 2, false, |r, script| {
        let (bytes, verdict) = classified(script, 2);
        assert_eq!(r.check("recovery", Some(&bytes), Some(&verdict)), Ok(()));
    });
}

/// The assertion the run rests on: a crash with no injected damage that
/// recovery refuses is a contract violation, whatever the refusal.
#[test]
fn an_honest_crash_that_recovery_refuses_fails_the_run() {
    with_runner(Expect::Committed { honest: true }, 2, false, |r, script| {
        let (bytes, _) = classified(script, 2);
        let failure = r.check("recovery", Some(&bytes), Some(&refusal()));
        assert!(
            matches!(
                failure,
                Err(LogRunFailure::HonestCrashRefused {
                    stage: "recovery",
                    ..
                })
            ),
            "{failure:?}"
        );
    });
}

#[test]
fn a_refusal_of_a_promised_discard_is_a_mismatch_not_a_contract_violation() {
    with_runner(
        Expect::Committed { honest: false },
        2,
        false,
        |r, script| {
            let (bytes, _) = classified(script, 2);
            let failure = r.check("recovery", Some(&bytes), Some(&refusal()));
            assert!(
                matches!(failure, Err(LogRunFailure::Mismatch { .. })),
                "{failure:?}"
            );
        },
    );
}

#[test]
fn recovery_must_refuse_what_the_damage_makes_unrecoverable() {
    with_runner(Expect::Refuse { offset: 44 }, 2, false, |r, script| {
        assert_eq!(r.check("recovery", None, Some(&refusal())), Ok(()));
        let (bytes, verdict) = classified(script, 2);
        let failure = r.check("recovery", Some(&bytes), Some(&verdict));
        assert!(
            matches!(failure, Err(LogRunFailure::Mismatch { .. })),
            "{failure:?}"
        );
        assert!(matches!(
            r.check("recovery", None, None),
            Err(LogRunFailure::Mismatch { .. })
        ));
    });
}

#[test]
fn the_oracle_refuses_the_wrong_records_and_the_wrong_bytes() {
    with_runner(Expect::Committed { honest: true }, 2, false, |r, script| {
        for count in [1, 3] {
            let (bytes, verdict) = classified(script, count);
            let failure = r.check("recovery", Some(&bytes), Some(&verdict));
            assert!(
                matches!(failure, Err(LogRunFailure::Mismatch { .. })),
                "{count} records: {failure:?}"
            );
        }
        // Right verdict, but the log's own bytes differ from the script's
        // in the committed prefix.
        let (mut bytes, verdict) = classified(script, 2);
        if let Some(byte) = bytes.get_mut(60) {
            *byte ^= 0xFF;
        }
        let failure = r.check("recovery", Some(&bytes), Some(&verdict));
        assert!(
            matches!(failure, Err(LogRunFailure::Mismatch { .. })),
            "{failure:?}"
        );
    });
}

#[test]
fn an_absent_log_is_only_right_when_nothing_was_committed() {
    with_runner(Expect::Committed { honest: true }, 0, false, |r, _| {
        assert_eq!(r.check("recovery", None, None), Ok(()));
    });
    with_runner(Expect::Committed { honest: true }, 1, false, |r, _| {
        assert!(matches!(
            r.check("recovery", None, None),
            Err(LogRunFailure::Mismatch { .. })
        ));
    });
}

/// Once the log's name is durable, recovery that finds it missing has
/// lost committed state.
#[test]
fn a_lost_initialised_log_fails_the_run() {
    with_runner(Expect::Committed { honest: true }, 0, true, |r, _| {
        let failure = r.check("recovery", None, None);
        assert!(
            matches!(failure, Err(LogRunFailure::Mismatch { .. })),
            "{failure:?}"
        );
    });
    // Before it is, an absent log is a crash that came first.
    with_runner(Expect::Committed { honest: true }, 0, false, |r, _| {
        assert_eq!(r.check("recovery", None, None), Ok(()));
    });
}

/// `initialise` links the log's name only once the envelope is durable, so
/// a file with no envelope at that name is never a crash outcome: not
/// after `initialise` returned, and not before.
#[test]
fn a_log_with_no_envelope_is_never_acceptable() {
    for initialised in [false, true] {
        with_runner(
            Expect::Committed { honest: true },
            0,
            initialised,
            |r, _| {
                let failure = r.check("recovery", None, Some(&Ok(Classified::NoEnvelope)));
                assert!(
                    matches!(failure, Err(LogRunFailure::Mismatch { .. })),
                    "initialised {initialised}: {failure:?}"
                );
            },
        );
    }
}

/// The plan the mutation tests vary: no fault of its own, three appends.
fn plain_plan(draw_seed: u64) -> LogPlan {
    LogPlan {
        kind: LogFaultKind::None,
        target: 0,
        draw_seed,
        appends: 3,
        record: 0,
        records: 1,
        into_record: false,
        second_crash: None,
        mid_crash: None,
    }
}

/// A fake that links before its file sync can leave a name bound to bytes
/// that never reached the medium; the oracle must fail the run when it
/// does, and must not fail the same crashes on the correct fake.
#[test]
fn a_fake_that_links_before_its_sync_fails_the_run() {
    let scan = |mutation: Option<Mutation>| -> Vec<LogRunFailure> {
        let mut failures = Vec::new();
        for step in 0..30 {
            for draw in 0..16 {
                let scheduled = Scheduled {
                    sync_fail: None,
                    crashes: vec![step],
                };
                let faults = LogFaults::just(LogFault::CrashAt(step));
                if let Err(e) = execute_variant(1, &plain_plan(draw), faults, scheduled, mutation) {
                    failures.push(e.failure);
                }
            }
        }
        failures
    };
    assert_eq!(scan(None), [], "the correct fake fails a run");
    let broken = scan(Some(Mutation::InitialiseLinksBeforeSync));
    assert!(
        broken.iter().any(|f| matches!(
            f,
            LogRunFailure::Mismatch { detail, .. } if detail.contains("no envelope")
        )),
        "no crash of the broken fake left a log with no envelope that the oracle caught: {broken:?}"
    );
}

/// A refusal must be for damaged committed history, at the offset the
/// committed prefix ends.
#[test]
fn a_refusal_must_name_its_reason_and_its_place() {
    with_runner(Expect::Refuse { offset: 44 }, 2, false, |r, _| {
        assert_eq!(r.check("recovery", None, Some(&refusal())), Ok(()));
        let other_reason = Err(LogError {
            offset: 44,
            reason: LogErrorReason::WrongVolume,
        });
        let other_place = Err(LogError {
            offset: 45,
            reason: LogErrorReason::DamagedCommittedHistory,
        });
        for verdict in [other_reason, other_place] {
            let failure = r.check("recovery", None, Some(&verdict));
            assert!(
                matches!(failure, Err(LogRunFailure::Mismatch { .. })),
                "{failure:?}"
            );
        }
    });
}

/// A call that fails must fail with an error a scheduled fault produces
/// at the step the fault names: a crash is not a failed sync's error, a
/// fault scheduled elsewhere does not explain it, and neither does none.
#[test]
fn only_the_errors_a_scheduled_fault_produces_at_its_step_end_a_process() {
    let plan = LogPlan::decode(seed(0));
    let free = execute(1, &plan, LogFaults::none(), Scheduled::default()).unwrap();
    let a_sync = *free.sync_steps.first().unwrap();
    let crash = |steps: &[u32]| Scheduled {
        sync_fail: None,
        crashes: steps.to_vec(),
    };
    let failed_sync = |step: u32| Scheduled {
        sync_fail: Some(step),
        crashes: Vec::new(),
    };
    let cases = [
        (LogFault::CrashAt(a_sync), failed_sync(a_sync)),
        (LogFault::FailSync { at: a_sync }, crash(&[a_sync])),
        (LogFault::CrashAt(a_sync), Scheduled::default()),
        // Scheduled, but at another step.
        (LogFault::CrashAt(a_sync), crash(&[a_sync + 1])),
        (LogFault::FailSync { at: a_sync }, failed_sync(a_sync + 1)),
    ];
    for (fault, scheduled) in cases {
        let failure = execute(1, &plan, LogFaults::just(fault.clone()), scheduled.clone())
            .err()
            .map(|e| e.failure);
        assert!(
            matches!(failure, Some(LogRunFailure::UnscheduledError(_))),
            "{fault:?} under {scheduled:?}: {failure:?}"
        );
    }
    // Declared at its own step, the same faults are modelled deaths.
    for (fault, scheduled) in [
        (LogFault::CrashAt(a_sync), crash(&[a_sync])),
        (LogFault::FailSync { at: a_sync }, failed_sync(a_sync)),
    ] {
        assert!(
            execute(1, &plan, LogFaults::just(fault.clone()), scheduled).is_ok(),
            "{fault:?}"
        );
    }
}

/// A failure names the seed that replays it, selector bit and all, however
/// the caller spelled it.
#[test]
fn a_failure_names_the_replayable_seed() {
    let plan = LogPlan::decode(seed(7));
    let free = execute(7, &plan, LogFaults::none(), Scheduled::default()).unwrap();
    let a_sync = *free.sync_steps.first().unwrap();
    let error = execute(
        7,
        &plan,
        LogFaults::just(LogFault::CrashAt(a_sync)),
        Scheduled::default(),
    )
    .err()
    .unwrap();
    assert_eq!(error.seed, seed(7));
    assert!(
        error
            .to_string()
            .contains(&format!("sim-replay {}", seed(7))),
        "{error}"
    );
}

/// A plan edited by a caller is not the plan its seed decodes to, so its
/// failure must not claim a seed replays it.
#[test]
fn an_edited_plan_names_no_replayable_seed() {
    let plan = LogPlan {
        draw_seed: LogPlan::decode(seed(7)).draw_seed ^ 1,
        ..LogPlan::decode(seed(7))
    };
    let free = execute(7, &plan, LogFaults::none(), Scheduled::default()).unwrap();
    let a_sync = *free.sync_steps.first().unwrap();
    let error = execute(
        7,
        &plan,
        LogFaults::just(LogFault::CrashAt(a_sync)),
        Scheduled::default(),
    )
    .err()
    .unwrap();
    assert!(!error.replayable);
    assert!(
        !error.to_string().contains("(replay: sim-replay"),
        "{error}"
    );
    assert!(error.to_string().contains("edited plan"), "{error}");
    // The unedited plan is replayable.
    let plan = LogPlan::decode(seed(7));
    let error = execute(
        7,
        &plan,
        LogFaults::just(LogFault::CrashAt(a_sync)),
        Scheduled::default(),
    )
    .err()
    .unwrap();
    assert!(error.replayable);
}

/// Once recovery's `complete_namespace` has returned, the log's name is
/// durable: a log that is missing after that has been lost, and the run
/// must fail. The log here is planted durable with no records, so recovery
/// takes the `complete_namespace` path; a draw that keeps nothing is then
/// the fixture's `reset`.
#[test]
fn a_log_lost_after_complete_namespace_fails_the_run() {
    let task: Task<(bool, Result<(), LogRunFailure>)> = Box::pin(async {
        let sim = Sim::new();
        let log = sim.decision_log(0, LogFaults::none());
        let script = Script::new(8);
        let plan = plain_plan(0);
        log.seed_bytes(
            &script.volume,
            encode_envelope(&script.envelope).as_bytes().to_vec(),
        )
        .await;
        let mut runner = Runner {
            log: &log,
            script: &script,
            plan: &plan,
            rng: Rng::seeded(0, DRAW_STREAM),
            scheduled: Scheduled::default(),
            initialised: false,
            append_window: None,
            committed: 0,
            expect: Expect::Committed { honest: true },
            window: None,
        };
        assert!(runner.recover().await.is_ok());
        let named_durable = runner.initialised;
        // The draw keeps nothing.
        log.reset().await;
        runner.committed = 0;
        (named_durable, runner.check("recovery", None, None))
    });
    let (named_durable, verdict) = run(1, task);
    assert!(
        named_durable,
        "complete_namespace returned and the log's name is not counted durable"
    );
    assert!(
        matches!(verdict, Err(LogRunFailure::Mismatch { .. })),
        "{verdict:?}"
    );
}
