// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The decision-log seed space, in one process: which outcome rows and
//! faults a sweep of seeds reaches, and how [`scenario::select`] and
//! [`scenario::replay_run`] divide the seed space.
//!
//! The cross-process half (the same seed, two processes, one artifact,
//! and the pinned digests of a sample of bit-62-clear seeds) is
//! `replay_across_processes.rs`.
//!
//! # The count table, and why a zero fails
//!
//! A sweep that never reaches a row proves nothing about it: the oracle
//! inside each run passes vacuously for a crash outcome that no seed
//! draws. So every row of the table is a predicate over one run's TRACE
//! alone, never over the seed or the plan that produced it, and every
//! count must be non-zero. The one row expected to be zero says why.

use std::collections::BTreeMap;

use granary_sim::scenario::{self, DECISION_LOG_SEEDS, DEFERRED_SEEDS, ReplayError, SeedSpace};
use granary_sim::trace::{
    Damage, DrawRow, LogCall, LogOp, Op, Outcome, Trace, TraceError, TruncationDraw, Verdict,
};

/// How many decision-log seeds the sweep runs.
const SWEEP: u64 = 512;

/// One row of the table: a name and the predicate that says a run
/// reached it.
struct Row {
    name: &'static str,
    reached: fn(&Trace) -> bool,
}

fn has_row(trace: &Trace, row: DrawRow) -> bool {
    scenario::log_rows(trace).contains(&row)
}

/// A row the first host crash drew, in a run whose first process a host
/// crash cut in the middle of its appends.
fn via_mid_append_crash(trace: &Trace, row: DrawRow) -> bool {
    scenario::cut_by_a_crash(trace) && scenario::first_crash_rows(trace).contains(&row)
}

/// The final verdict of the run: what its last recovery said.
fn last_verdict(trace: &Trace) -> Option<Verdict> {
    scenario::log_verdicts(trace).last().copied()
}

fn refused(trace: &Trace) -> bool {
    matches!(last_verdict(trace), Some(Verdict::Refused { .. }))
}

fn damaged(trace: &Trace, kind: Damage) -> bool {
    scenario::log_damage(trace).contains(&kind)
}

/// Whether a `resync` call returned after a survivor row: the adopted
/// record was made durable again before serving.
fn survivor_resynced(trace: &Trace) -> bool {
    let mut survivor = false;
    for entry in trace.entries() {
        match &entry.op {
            Op::Log(LogOp::Row {
                row: DrawRow::Survivor,
                ..
            }) => survivor = true,
            Op::Log(LogOp::Call {
                call: LogCall::Resync,
                ..
            }) if survivor && entry.outcome == Outcome::Ok => return true,
            _ => {}
        }
    }
    false
}

/// A recovery that found a tail and truncated it.
fn tail_discarded(trace: &Trace) -> bool {
    scenario::log_verdicts(trace)
        .iter()
        .any(|v| matches!(v, Verdict::Log { tail, .. } if *tail > 0))
}

/// A host crash between a truncation and its sync: the sync step is the
/// one the crash refused.
fn crash_between_truncate_and_sync(trace: &Trace) -> bool {
    let steps = scenario::log_steps(trace);
    steps.windows(2).any(|pair| {
        matches!(
            pair,
            [
                (LogOp::Truncate { .. }, Outcome::Ok),
                (
                    LogOp::FileSync { .. },
                    Outcome::Failed(TraceError::Injected)
                ),
            ]
        )
    })
}

const ROWS: &[Row] = &[
    Row {
        name: "row 1: record absent (unsynced record lost)",
        reached: |t| has_row(t, DrawRow::RecordAbsent),
    },
    Row {
        name: "row 2: record torn (prefix, or garbage in its tail)",
        reached: |t| has_row(t, DrawRow::RecordTorn),
    },
    Row {
        name: "row 2: record whole but unsynced, no mark",
        reached: |t| has_row(t, DrawRow::RecordWholeUnsynced),
    },
    Row {
        name: "row 3: record synced, mark absent or torn",
        reached: |t| has_row(t, DrawRow::MarkAbsentOrTorn),
    },
    Row {
        name: "row 4: synced, mark whole, unacknowledged (survivor)",
        reached: |t| has_row(t, DrawRow::Survivor),
    },
    Row {
        name: "row 4: survivor adopted and re-synced before serving",
        reached: survivor_resynced,
    },
    Row {
        name: "row 1 via a crash mid-append",
        reached: |t| via_mid_append_crash(t, DrawRow::RecordAbsent),
    },
    Row {
        name: "row 2 (torn) via a crash mid-append",
        reached: |t| via_mid_append_crash(t, DrawRow::RecordTorn),
    },
    Row {
        name: "row 2 (whole, unsynced) via a crash mid-append",
        reached: |t| via_mid_append_crash(t, DrawRow::RecordWholeUnsynced),
    },
    Row {
        name: "row 3 via a crash mid-append",
        reached: |t| via_mid_append_crash(t, DrawRow::MarkAbsentOrTorn),
    },
    Row {
        name: "row 4 via a crash mid-append",
        reached: |t| via_mid_append_crash(t, DrawRow::Survivor),
    },
    Row {
        name: "recovery of an honest crash discards a tail (rows 1 to 3)",
        reached: |t| scenario::log_damage(t).is_empty() && tail_discarded(t),
    },
    Row {
        name: "no fault: an honest crash, recovered, never refused",
        reached: |t| {
            scenario::failed_syncs(t) == 0
                && scenario::log_damage(t).is_empty()
                && !scenario::log_verdicts(t).is_empty()
                && !refused(t)
        },
    },
    Row {
        name: "fail-sync: a sync failed",
        reached: |t| scenario::failed_syncs(t) > 0,
    },
    Row {
        name: "corrupt-detectable: fired, recovery refused",
        reached: |t| damaged(t, Damage::Detectable) && refused(t),
    },
    Row {
        name: "tail led by an intact record, legal next: discarded",
        reached: |t| damaged(t, Damage::Residual) && !refused(t),
    },
    Row {
        name: "tail led by an intact record, legal next: refused (beyond it and a mark)",
        reached: |t| damaged(t, Damage::Residual) && refused(t),
    },
    Row {
        name: "tail led by an intact record that is not the legal next: refused",
        reached: |t| damaged(t, Damage::ForeignRecord) && refused(t),
    },
    Row {
        name: "tail led by the legal next record under the wrong sequence: refused",
        reached: |t| damaged(t, Damage::WrongSeqRecord) && refused(t),
    },
    Row {
        name: "tail led by a record of another epoch that would be illegal here: discarded",
        reached: |t| damaged(t, Damage::OtherEpochRecord) && !refused(t),
    },
    Row {
        name: "no intact record at the tail's start: discarded (within RECORD_V1_MAX)",
        reached: |t| damaged(t, Damage::ResidualIntoRecord) && !refused(t),
    },
    Row {
        name: "no intact record at the tail's start: discarded (exactly RECORD_V1_MAX)",
        reached: |t| damaged(t, Damage::AtBound) && !refused(t),
    },
    Row {
        name: "no intact record at the tail's start: refused (beyond RECORD_V1_MAX)",
        reached: |t| damaged(t, Damage::Oversize) && refused(t),
    },
    Row {
        name: "a second crash inside recovery",
        reached: |t| scenario::host_crashes(t) >= 2 && scenario::injected_steps(t) > 0,
    },
    Row {
        name: "a second crash between a truncation and its sync",
        reached: crash_between_truncate_and_sync,
    },
    Row {
        name: "a crash that keeps an unsynced truncation",
        reached: |t| scenario::truncation_draws(t).contains(&TruncationDraw::Kept),
    },
    Row {
        name: "a crash that undoes an unsynced truncation",
        reached: |t| scenario::truncation_draws(t).contains(&TruncationDraw::Undone),
    },
];

/// The row no run may reach. A correct writer waits for a truncation's
/// sync before appending, so no append is ever written after a
/// truncation a crash could undo: the fake's barrier check would record
/// the violation and the run would fail. Its count is asserted zero
/// rather than left off the table.
const UNREACHABLE: &str = "append written after an unsynced truncation (a barrier violation)";

/// **The seeded counts.** Per row of the [`ROWS`] crash-outcome table and
/// per fault, how many runs of the sweep reached it, printed as a table.
/// A zero fails, naming the row.
#[test]
fn a_sweep_of_decision_log_seeds_reaches_every_row_and_fault() {
    let mut counts: BTreeMap<&str, u64> = ROWS.iter().map(|row| (row.name, 0)).collect();
    let mut unreachable = 0;
    let mut refused_runs = 0;
    for n in 0..SWEEP {
        let seed = DECISION_LOG_SEEDS + n;
        let run = scenario::decision_log_run(seed)
            .unwrap_or_else(|e| panic!("{e}\n{}", e.trace.render()));
        let trace = run.sim.trace();
        for row in ROWS {
            if (row.reached)(&trace) {
                *counts.entry(row.name).or_default() += 1;
            }
        }
        unreachable += u64::from(has_row(&trace, DrawRow::LostWithUndoneTruncation));
        refused_runs += u64::from(refused(&trace));
    }
    let width = ROWS.iter().map(|r| r.name.len()).max().unwrap_or(0);
    eprintln!("decision-log seeds 0..{SWEEP}: runs reaching each row");
    for row in ROWS {
        eprintln!(
            "  {:<width$}  {:>5}",
            row.name,
            counts.get(row.name).copied().unwrap_or(0)
        );
    }
    eprintln!("  {UNREACHABLE:<width$}  {unreachable:>5}");
    eprintln!("  (runs whose last recovery refused: {refused_runs})");
    for row in ROWS {
        assert!(
            counts.get(row.name).copied().unwrap_or(0) > 0,
            "no seed of the sweep 0..{SWEEP} reached: {}",
            row.name
        );
    }
    assert_eq!(unreachable, 0, "{UNREACHABLE}");
}

// ------------------------------------------------------ the seed space

#[test]
fn select_names_the_space_and_clears_its_bit() {
    assert_eq!(scenario::select(5).ok(), Some((SeedSpace::Race, 5)));
    assert_eq!(
        scenario::select(DEFERRED_SEEDS + 5).ok(),
        Some((SeedSpace::Deferred, 5))
    );
    assert_eq!(
        scenario::select(DECISION_LOG_SEEDS + 5).ok(),
        Some((SeedSpace::DecisionLog, 5))
    );
    assert_eq!(scenario::select(0).ok(), Some((SeedSpace::Race, 0)));
}

#[test]
fn a_seed_with_both_selector_bits_is_refused_as_a_usage_error() {
    for seed in [
        DEFERRED_SEEDS | DECISION_LOG_SEEDS,
        (DEFERRED_SEEDS | DECISION_LOG_SEEDS) + 3,
        u64::MAX,
    ] {
        let select = scenario::select(seed);
        assert!(
            matches!(select, Err(ReplayError::BothSelectors { seed: given }) if given == seed),
            "select({seed}): {select:?}"
        );
        let replay = scenario::replay_run(seed);
        assert!(
            matches!(&replay, Err(ReplayError::BothSelectors { seed: given }) if *given == seed),
            "replay_run({seed}) is not a usage error: {replay:?}"
        );
    }
    assert!(
        scenario::replay_run(DECISION_LOG_SEEDS + 3).is_ok_and(|sim| !sim.trace().is_empty()),
        "the decision-log bit alone is a seed space"
    );
}

/// Every error names the seed as given, selector bits and all, so
/// `sim-replay <that seed>` reproduces it.
#[test]
fn a_refusal_names_the_seed_that_replays_it() {
    let both = DEFERRED_SEEDS | DECISION_LOG_SEEDS | 5;
    let message = scenario::replay_run(both)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(message.contains(&both.to_string()), "{message}");
}
