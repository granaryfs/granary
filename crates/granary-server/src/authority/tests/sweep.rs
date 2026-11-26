// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The authority crash sweep runs the engine over the simulator's
//! crash-consistency log and store. One scripted workload runs to its end under every crash point,
//! every failed sync, and each crash outcome the log can draw, with two
//! restarts after each (the same boot, which must answer by the marker
//! table, then a modelled reboot, which recovers), and the durability
//! properties checked after every run.
//!
//! - [`harness`]: the kill, the timeline, the gated log and store.
//! - [`workload`]: the roots, the client's script, the expected records.
//! - [`run`]: one point's processes, restarts and crashes.
//! - [`oracle`]: the properties, checked against what the harness saw.
//!
//! A failing point prints its id and the command that runs it alone: a
//! labelled id naming, beside each index it uses, the operation this
//! build's dry run found there. [`checked`] recomputes those labels
//! against the run it just made and refuses by name
//! ([`verify_labels`]) if one no longer matches, rather than reporting a
//! pass or fail on an index that now means something else.

mod harness;
mod matrix;
mod oracle;
mod run;
mod workload;

use std::collections::{BTreeMap, BTreeSet};

use granary_core::authlog::{EPOCH_LEN, Epoch, RecordBody};
use granary_core::root::VolumeName;
use granary_core::secure_random::SecureRandom;
use granary_sim::decision_log::{FiredFault, StepRecord};
use granary_sim::secure_random::SeededSecureRandom;
use granary_sim::trace::{
    DrawRow, LogCall, LogOp, LogPath, Op, Outcome, TraceError, TruncationDraw, Volume,
};

use harness::{Cut, Ev, StoreOp};
use run::{Inject, LogKind, OpLabel, Point, PointParseError, Run};

/// The volumes the sweep configures.
pub(super) const VOLUMES: [&str; 2] = ["vol-a", "vol-b"];

pub(super) fn vol(name: &str) -> VolumeName {
    super::vol(name)
}

pub(super) fn a() -> VolumeName {
    vol(VOLUMES[0])
}

pub(super) fn b() -> VolumeName {
    vol(VOLUMES[1])
}

/// The environment variable that names one point for [`one_point`].
const POINT_ENV: &str = "GRANARY_SWEEP_POINT";

/// The environment variable naming the file [`one_point`] writes its
/// trace digest to.
const DIGEST_ENV: &str = "GRANARY_SWEEP_DIGEST";

/// The environment variable naming a directory each schedule's sweep
/// writes its coverage table to, for the evidence a PR records. The
/// crate's sources write to no standard stream.
const COVERAGE_ENV: &str = "GRANARY_SWEEP_COVERAGE";

/// The command that re-runs `point` alone.
fn replay_command(point: Point) -> String {
    format!(
        "{POINT_ENV}='{point}' cargo nextest run -p granary-server -E 'test(=authority::tests::sweep::one_point)'"
    )
}

/// Run `point` and check it; panic naming the point and how to re-run it.
fn checked(point: Point) -> Run {
    let run = run::run(point);
    verify_labels(&run);
    let failures = oracle::check(&run);
    assert!(
        failures.is_empty(),
        "point {point} failed:\n  {}\nre-run it alone with: {}",
        failures.join("\n  "),
        replay_command(point)
    );
    run
}

// ----------------------------------------------------------- discovery

/// One log step: its op, the seam call it belongs to, and its place
/// among that call's steps.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Step {
    op: LogOp,
    call: LogCall,
    within: u32,
}

/// The log steps `run`'s process `process` issued, with their indices,
/// as the fake recorded each when it claimed its index: its calls, their
/// places, their ops, exactly, whatever order the trace shows them in and
/// whether or not a kill dropped the call before the step was traced.
fn process_steps(run: &Run, process: u32) -> Vec<(u32, Step)> {
    let at = usize::try_from(process - 1).unwrap();
    let (begin, end) = (run.first_steps[at], run.last_steps[at]);
    run.log
        .step_records()
        .into_iter()
        .filter(|r| (begin..end).contains(&r.index))
        .map(|r| {
            (
                r.index,
                Step {
                    op: r.op,
                    call: r.call,
                    within: r.within,
                },
            )
        })
        .collect()
}

/// The store-operation index of process `process`'s first `put_root` at
/// `volume`'s `seq` in `run`, as its store claimed it: the index a cut or
/// a deferral at that PUT names. Not its place among the trace's store
/// operations, which is the order they returned in
/// ([`harness::SweepStore`]).
fn put_index(run: &Run, process: u32, volume: &VolumeName, seq: u64) -> Option<u32> {
    let at = usize::try_from(process - 1).unwrap();
    run.claims[at].iter().find_map(|c| match c.op {
        StoreOp::Put { volume: v, seq: s } if v == harness::tag(volume.as_str()) && s == seq => {
            Some(c.index)
        }
        _ => None,
    })
}

// ------------------------------------------------------------- labels

/// The label of the log op `step` is: what a labelled point id names for
/// a log-step index whose `Step` is already at hand.
fn log_label_of(step: &Step) -> OpLabel {
    OpLabel::Log(LogKind::from(&step.op))
}

/// The label of the log op `run`'s own trace recorded at global step
/// `index`, or `None` if the run never issued a step there.
fn log_label_at(run: &Run, index: u32) -> Option<OpLabel> {
    run.log
        .step_records()
        .into_iter()
        .find(|r| r.index == index)
        .map(|r| OpLabel::Log(LogKind::from(&r.op)))
}

/// The label of the store operation process `process` of `run` claimed
/// at index `index`, or `None` if it was never reached: the deferred
/// PUT's fault is independent of a point's own injection, so a run whose
/// injection ends the process first can leave it untried.
fn store_label(run: &Run, process: u32, index: u32) -> Option<OpLabel> {
    let at = usize::try_from(process - 1).unwrap();
    run.claims[at]
        .iter()
        .find(|c| c.index == index)
        .map(|c| OpLabel::Store(c.op))
}

/// `run`'s own label at `inject`'s index in process `process`: `Ok(None)`
/// for [`Inject::None`], `Ok(Some(_))` for the label this build's trace
/// finds there, or `Err(index)` naming the index this build's run never
/// reached — a fault that never fires leaves nothing to compare.
fn label_at(run: &Run, inject: Inject, process: u32) -> Result<Option<OpLabel>, u32> {
    match inject {
        Inject::None => Ok(None),
        Inject::LogCrash(s) | Inject::LogFail(s) => log_label_at(run, s).map(Some).ok_or(s),
        Inject::Store(k, _) => store_label(run, process, k).map(Some).ok_or(k),
    }
}

/// `claimed` (a label a point carries) against `found` (what `point`'s
/// own run shows there now): equal, or a refusal naming both.
fn check_label(point: Point, what: &str, claimed: Option<OpLabel>, found: OpLabel) {
    let claimed = claimed.expect("a point with an index at this slot carries its label");
    assert!(
        claimed == found,
        "{point}: {what} was labelled `{claimed}` here but this build finds `{found}` there \
         — this point was discovered on a different build"
    );
}

/// Refuse: `point`'s `what` names an index this build's run never
/// reached, naming the label the point claims for it.
fn refuse_unreached(point: Point, what: &str, claimed: Option<OpLabel>, index: u32) -> ! {
    let claimed = claimed.expect("a point with an index at this slot carries its label");
    panic!(
        "{point}: {what} was labelled `{claimed}`, but this build never reaches index {index}; \
         this point was discovered on a different build"
    );
}

/// The global step index whose fault fired and ended process `process`
/// of `run`, if a log fault (a crash or a failed sync) is what ended it —
/// `run.rs`'s `SimDecisionLog::step` records `fired` on the step whose
/// index matched an indexed fault, regardless of which point field
/// registered it, so this reads that record rather than assuming a
/// crashed process died to its own field's index.
fn fired_step(run: &Run, process: u32) -> Option<u32> {
    let at = usize::try_from(process - 1).unwrap();
    let (begin, end) = (run.first_steps[at], run.last_steps[at]);
    run.log
        .step_records()
        .into_iter()
        .find(|r| (begin..end).contains(&r.index) && r.fired.is_some())
        .map(|r| r.index)
}

/// Whether `point.first` is itself what ended process 1 of `run`: a log
/// fault is only legitimate if the index that actually fired there is
/// `first`'s own, since `Runner::new` registers `point.recovery`'s fault
/// too, by the same global step counter — on a build where process 1
/// takes more steps, recovery's index can fire first and would otherwise
/// look like `first`'s own crash. A store cut is unambiguous: it is only
/// ever wired to process 1 (`run.rs`'s `Runner::process`), so its own cut
/// firing there is checked directly against the timeline.
fn first_fired_in_process_one(run: &Run) -> bool {
    match run.point.first {
        Inject::None => false,
        Inject::LogCrash(f) | Inject::LogFail(f) => fired_step(run, 1) == Some(f),
        Inject::Store(k, cut) => run
            .timeline
            .iter()
            .any(|(p, ev)| *p == 1 && *ev == Ev::Cut { index: k, cut }),
    }
}

/// Refuse: `point`'s recovery injection fired inside process 1 of `run`
/// at `index`, naming the label it claims. The recovery belongs to
/// process 2; this build's process 1 stepped far enough to trip it
/// first, so the point's own first injection — and everything after —
/// never ran as this build's process 1 at all.
fn refuse_recovery_in_process_one(point: Point, claimed: Option<OpLabel>, index: u32) -> ! {
    let claimed = claimed.expect("a point with an index at this slot carries its label");
    panic!(
        "{point}: the recovery injection was labelled `{claimed}`, but on this build it fires \
         inside process 1 at index {index}, not process 2 where the recovery belongs; this \
         point was discovered on a different build"
    );
}

/// Refuse if a label `run.point` carries no longer matches the operation
/// `run`'s own trace finds at that index: the point was discovered on a
/// build whose indices meant something else here.
fn verify_labels(run: &Run) {
    let point = run.point;
    if let Inject::LogCrash(r) | Inject::LogFail(r) = point.recovery
        && fired_step(run, 1) == Some(r)
    {
        refuse_recovery_in_process_one(point, point.recovery_label, r);
    }
    if let Some(at) = point.defer_at {
        match store_label(run, 1, at) {
            Some(found) => check_label(point, "the deferred PUT", point.defer_label, found),
            // Legitimate: the point's own first injection ended process 1
            // before it ever reached the deferred PUT's index (an
            // independent, unrelated fault), so there is nothing there to
            // compare. The check above already ruled out the recovery
            // injection as the actual cause.
            None if first_fired_in_process_one(run) => {}
            // Process 1 ran to its own end with no injection cutting it
            // short, yet made fewer store operations than the deferred
            // index names: that index is not one this build ever
            // produces, and an old id claiming otherwise is refused.
            None => refuse_unreached(point, "the deferred PUT", point.defer_label, at),
        }
    }
    for (what, inject, claimed, process) in [
        ("the first injection", point.first, point.first_label, 1),
        (
            "the recovery injection",
            point.recovery,
            point.recovery_label,
            2,
        ),
    ] {
        match label_at(run, inject, process) {
            Ok(Some(found)) => check_label(point, what, claimed, found),
            Ok(None) => {}
            Err(index) => refuse_unreached(point, what, claimed, index),
        }
    }
}

/// A sweep's dry run: the deferred PUT's index and label, and its steps
/// and store operations.
struct Dry {
    run: Run,
    sched: u64,
    defer_at: u32,
    defer_label: OpLabel,
    steps: Vec<Step>,
    /// How many log steps process 1 made.
    log_steps: u32,
    store_ops: u32,
}

/// The label this dry run's process 1 found at `inject`'s index, or
/// `None` for [`Inject::None`]: what [`labelled_point`] attaches to a
/// point it builds from `dry`.
fn label_of(dry: &Dry, inject: Inject, process: u32) -> Option<OpLabel> {
    match inject {
        Inject::None => None,
        Inject::LogCrash(s) | Inject::LogFail(s) => {
            Some(log_label_of(&dry.steps[usize::try_from(s).unwrap()]))
        }
        Inject::Store(k, _) => {
            Some(store_label(&dry.run, process, k).expect("the dry run reaches every store index"))
        }
    }
}

/// A point of `dry`'s discovery: `first` (labelled from it) under `draw`,
/// with no recovery injection.
fn labelled_point(dry: &Dry, first: Inject, draw: u64) -> Point {
    Point {
        sched: dry.sched,
        defer_at: Some(dry.defer_at),
        defer_label: Some(dry.defer_label),
        first,
        first_label: label_of(dry, first, 1),
        draw,
        recovery: Inject::None,
        recovery_label: None,
        recovery_draw: 0,
    }
}

/// Discover the sweep under scheduler seed `sched`. The deferred PUT is
/// found by a run without it (identical up to that PUT), then the dry run
/// holds it, and must pass the oracle itself.
fn discover(sched: u64) -> Dry {
    let base = Point {
        sched,
        defer_at: None,
        defer_label: None,
        first: Inject::None,
        first_label: None,
        draw: 0,
        recovery: Inject::None,
        recovery_label: None,
        recovery_draw: 0,
    };
    let undeferred = checked(base);
    let a_name = Volume::from_checked(&a());
    let defer_at = put_index(&undeferred, 1, &a(), 2).expect("the dry run PUTs A's seq 2");
    let defer_label =
        store_label(&undeferred, 1, defer_at).expect("the dry run reaches the deferred PUT");
    let dry = checked(Point {
        defer_at: Some(defer_at),
        defer_label: Some(defer_label),
        ..base
    });
    let deferred = dry.sim.trace().entries().iter().any(|e| {
        e.node == 1
            && matches!(&e.op, Op::PutRoot { volume, seq: 2, .. } if *volume == a_name)
            && e.outcome == Outcome::Failed(TraceError::Deferred)
    });
    assert!(deferred, "sched {sched}: the deferred PUT did not fire");
    assert_step_coverage(&dry.log.step_records(), dry.log.steps());
    let steps: Vec<Step> = process_steps(&dry, 1).into_iter().map(|(_, s)| s).collect();
    let log_steps = *dry.last_steps.first().unwrap();
    let store_ops = dry.store_ops[0];
    Dry {
        run: dry,
        sched,
        defer_at,
        defer_label,
        steps,
        log_steps,
        store_ops,
    }
}

/// Check that the step records are nonempty, complete, unique and contiguous.
#[track_caller]
fn assert_step_coverage(records: &[StepRecord], count: u32) {
    assert!(count > 0, "step coverage must be nonempty");
    assert_eq!(
        records.iter().map(|r| r.index).collect::<Vec<_>>(),
        (0..count).collect::<Vec<_>>(),
        "step coverage must be complete, unique and contiguous"
    );
}

#[test]
fn step_coverage_rejects_missing_duplicate_and_out_of_range_indices() {
    let dry = discover(0);
    let records = dry.run.log.step_records();
    let count = dry.run.log.steps();
    assert_step_coverage(&records, count);
    let mut missing = records.clone();
    missing.remove(1);
    let mut duplicate = records.clone();
    duplicate[1] = duplicate[0].clone();
    let mut outside = records.clone();
    outside[1].index = count;
    for broken in [missing, duplicate, outside, vec![]] {
        assert!(std::panic::catch_unwind(|| assert_step_coverage(&broken, count)).is_err());
    }
}

// ------------------------------------------------------------ coverage

/// Which record an append is, for the coverage table.
fn kind(body: &RecordBody) -> &'static str {
    match body {
        RecordBody::Decision { .. } => "decision",
        RecordBody::Attestation { .. } => "attestation",
        RecordBody::Landed { .. } => "landed",
        RecordBody::Lost { .. } => "lost",
    }
}

/// What the sweep reached: counts, and the obligations each satisfied.
#[derive(Debug, Default)]
struct Coverage {
    /// Points run, by kind.
    points: BTreeMap<String, u32>,
    /// Draw rows reached, by (record kind, row, where).
    rows: BTreeMap<(&'static str, DrawRow, &'static str), u32>,
    /// Truncation draws reached.
    truncations: BTreeMap<String, u32>,
    /// Namespace draws: (pending, kept).
    namespace: BTreeSet<(u64, u64)>,
    /// Same-boot restarts, by the table's answer and whether admitted.
    restarts: BTreeMap<String, u32>,
    /// Runs by end.
    ends: BTreeMap<String, u32>,
    /// Script arms reached.
    arms: BTreeMap<&'static str, u32>,
    /// Distinct states a first crash left, each recovery-swept once.
    states: usize,
}

impl Coverage {
    fn add(&mut self, run: &Run, label: &str) {
        *self.points.entry(label.to_owned()).or_default() += 1;
        *self.ends.entry(format!("{:?}", run.end)).or_default() += 1;
        for (name, n) in &run.script.arms {
            *self.arms.entry(name).or_default() += n;
        }
        for r in &run.restarts {
            *self
                .restarts
                .entry(format!("{:?} admitted={}", r.expected, r.admitted))
                .or_default() += 1;
        }
        for (process, report) in &run.crashes {
            let place = if *process == 1 {
                "process 1"
            } else {
                "recovery"
            };
            let failed = matches!(
                (process, run.point.first, run.point.recovery),
                (1, Inject::LogFail(_), _) | (2, _, Inject::LogFail(_))
            );
            let place = if failed { "after a failed sync" } else { place };
            for (path, offset, row) in &report.rows {
                let LogPath::Log(volume) = path else { continue };
                let record = run.timeline.iter().find_map(|(p, ev)| match ev {
                    Ev::Appending {
                        volume: v,
                        record,
                        offset: o,
                    } if p == process && v.as_str() == volume.as_str() && o == offset => {
                        Some(kind(record.body()))
                    }
                    _ => None,
                });
                let record = record.unwrap_or("unmatched");
                *self.rows.entry((record, *row, place)).or_default() += 1;
            }
        }
        let trace = run.sim.trace();
        for entry in trace.entries() {
            match &entry.op {
                Op::Log(LogOp::Draw { truncation, .. }) if *truncation != TruncationDraw::None => {
                    *self.truncations.entry(truncation.to_string()).or_default() += 1;
                }
                Op::Log(LogOp::Crash { pending, kept }) if *pending > 0 => {
                    self.namespace.insert((*pending, *kept));
                }
                _ => {}
            }
        }
    }

    /// The obligations the design names, each asserted.
    #[track_caller]
    fn assert_obligations(&self) {
        let mut missing = Vec::new();
        for kind in ["decision", "attestation", "landed", "lost"] {
            for row in [
                DrawRow::RecordAbsent,
                DrawRow::RecordTorn,
                DrawRow::RecordWholeUnsynced,
                DrawRow::MarkAbsentOrTorn,
                DrawRow::Survivor,
            ] {
                for place in ["process 1", "recovery", "after a failed sync"] {
                    if !self.rows.contains_key(&(kind, row, place)) {
                        missing.push(format!("{kind} {row} {place}"));
                    }
                }
            }
        }
        for t in ["kept", "undone"] {
            if !self.truncations.contains_key(t) {
                missing.push(format!("a truncation {t}"));
            }
        }
        for (pending, _) in self.namespace.clone() {
            for kept in 0..=pending {
                if !self.namespace.contains(&(pending, kept)) {
                    missing.push(format!("namespace draw {kept} of {pending}"));
                }
            }
        }
        if self.rows.keys().any(|(kind, _, _)| *kind == "unmatched") {
            missing.push("a draw row with no append at its offset".to_owned());
        }
        assert!(
            missing.is_empty(),
            "coverage obligations not met: {missing:?}\n{self:#?}"
        );
    }
}

/// The draw rows a crash at `step` can leave for the append it is in.
fn drawable(step: &Step, failed: bool) -> BTreeSet<Outcome_> {
    let mut out = BTreeSet::new();
    if step.call == LogCall::Append {
        let rows: &[DrawRow] = match (step.within, failed) {
            (1, _) => &[
                DrawRow::RecordAbsent,
                DrawRow::RecordTorn,
                DrawRow::RecordWholeUnsynced,
            ],
            (2, false) => &[DrawRow::MarkAbsentOrTorn],
            (3, _) => &[DrawRow::MarkAbsentOrTorn, DrawRow::Survivor],
            _ => &[],
        };
        out.extend(rows.iter().map(|row| Outcome_::Row(*row)));
    }
    out
}

/// One outcome a host crash can draw: an append's row, a pending
/// truncation's fate, or how many pending namespace operations reached
/// the medium.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Outcome_ {
    Row(DrawRow),
    Truncation(bool),
    Namespace { pending: u64, kept: u64 },
}

/// What the `n`th host crash of `run` drew.
fn drawn(run: &Run, n: usize) -> BTreeSet<Outcome_> {
    let Some((_, report)) = run.crashes.get(n) else {
        return BTreeSet::new();
    };
    let mut out: BTreeSet<Outcome_> = report
        .rows
        .iter()
        .map(|(_, _, row)| Outcome_::Row(*row))
        .collect();
    let trace = run.sim.trace();
    let mut crashes = 0;
    let mut inside = false;
    for entry in trace.entries() {
        let Op::Log(op) = &entry.op else {
            inside = false;
            continue;
        };
        match op {
            LogOp::Crash { pending, kept } => {
                inside = crashes == n;
                crashes += 1;
                if inside && *pending > 0 {
                    out.insert(Outcome_::Namespace {
                        pending: *pending,
                        kept: *kept,
                    });
                }
            }
            LogOp::Draw { truncation, .. } if inside => match truncation {
                TruncationDraw::Kept => {
                    out.insert(Outcome_::Truncation(true));
                }
                TruncationDraw::Undone => {
                    out.insert(Outcome_::Truncation(false));
                }
                TruncationDraw::None => {}
            },
            LogOp::Draw { .. }
            | LogOp::Row { .. }
            | LogOp::File { .. }
            | LogOp::StateDir { .. }
            | LogOp::Damage { .. } => {}
            _ => inside = false,
        }
    }
    out
}

/// What a crash that drew `drew` could draw, beyond `step`'s rows: both
/// fates of a pending truncation, and every prefix of its pending
/// namespace operations.
fn drawable_at(drew: &BTreeSet<Outcome_>, step: Option<&Step>, failed: bool) -> BTreeSet<Outcome_> {
    let mut want = step.map(|s| drawable(s, failed)).unwrap_or_default();
    for outcome in drew.iter().copied() {
        match outcome {
            Outcome_::Truncation(_) => {
                want.extend([Outcome_::Truncation(true), Outcome_::Truncation(false)]);
            }
            Outcome_::Namespace { pending, .. } => {
                want.extend((0..=pending).map(|kept| Outcome_::Namespace { pending, kept }));
            }
            Outcome_::Row(_) => {}
        }
    }
    want
}

/// The most draws one point takes to meet its obligation.
const DRAW_CAP: u64 = 48;

/// Run `point` under the draws `draw_of` sets, from 0, until the `n`th
/// crash has drawn everything it could (one draw when it could draw
/// nothing), checking each run. Every run is returned.
fn with_draws(
    point: Point,
    n: usize,
    step: Option<&Step>,
    set_draw: impl Fn(Point, u64) -> Point,
    label: &str,
    coverage: &mut Coverage,
) -> Vec<Run> {
    let inject = if n == 0 { point.first } else { point.recovery };
    let failed = matches!(inject, Inject::LogFail(_));
    let mut want = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut runs = Vec::new();
    let inject = if n == 0 { point.first } else { point.recovery };
    for draw in 0..DRAW_CAP {
        let run = checked(set_draw(point, draw));
        assert_fired(&run, inject, u32::try_from(n).unwrap() + 1, step);
        coverage.add(&run, label);
        let drew = drawn(&run, n);
        want.extend(drawable_at(&drew, step, failed));
        seen.extend(drew);
        runs.push(run);
        if want.is_subset(&seen) {
            return runs;
        }
    }
    panic!(
        "{}: drew {seen:?} of {want:?} in {DRAW_CAP} draws",
        set_draw(point, 0)
    );
}

fn first_label(first: Inject, step: Option<&Step>) -> String {
    match (first, step) {
        (Inject::LogCrash(_), Some(s)) => format!("crash in {}", s.call),
        (Inject::LogFail(_), Some(s)) => format!("failed sync in {}", s.call),
        (Inject::Store(_, Cut::Before), _) => "store, before".to_owned(),
        (Inject::Store(_, Cut::After), _) => "store, after".to_owned(),
        _ => "none".to_owned(),
    }
}

/// Whether `op` is a sync step.
const fn is_sync(op: &LogOp) -> bool {
    matches!(op, LogOp::FileSync { .. } | LogOp::DirSync { .. })
}

/// The whole sweep under scheduler seed `sched`: every first point under
/// its draws, then, for each distinct state a first crash left, every
/// step of the recovery from it.
fn sweep(sched: u64) -> Coverage {
    let dry = discover(sched);
    let mut coverage = Coverage::default();
    let mut firsts: Vec<(Inject, Option<Step>)> = Vec::new();
    for (s, step) in dry.steps.iter().enumerate().take(dry.log_steps as usize) {
        let s = u32::try_from(s).unwrap();
        firsts.push((Inject::LogCrash(s), Some(step.clone())));
        if is_sync(&step.op) {
            firsts.push((Inject::LogFail(s), Some(step.clone())));
        }
    }
    for k in 0..dry.store_ops {
        firsts.push((Inject::Store(k, Cut::Before), None));
        firsts.push((Inject::Store(k, Cut::After), None));
    }
    let mut states = BTreeSet::new();
    for (first, step) in firsts {
        let point = labelled_point(&dry, first, 0);
        let label = first_label(first, step.as_ref());
        let runs = with_draws(
            point,
            0,
            step.as_ref(),
            |p, draw| Point { draw, ..p },
            &label,
            &mut coverage,
        );
        for run in runs {
            if let Some(state) = run.crash_states.first()
                && states.insert(state.clone())
            {
                recovery_points(&run, &mut coverage);
            }
        }
    }
    coverage.states = states.len();
    coverage
}

/// That `run`'s injection into process `process` fired where it was
/// aimed: the fake's record of the injected index names the intended
/// step (its call, its place and its op) and says a fault fired there;
/// a store cut is recorded at its operation, before or after as named.
#[track_caller]
fn assert_fired(run: &Run, inject: Inject, process: u32, intended: Option<&Step>) {
    let point = run.point;
    let index = match inject {
        Inject::Store(k, cut) => {
            assert!(
                run.timeline
                    .iter()
                    .any(|(p, ev)| *p == process && *ev == Ev::Cut { index: k, cut }),
                "{point}: the store cut never fired at operation {k}"
            );
            return;
        }
        Inject::LogCrash(s) | Inject::LogFail(s) => s,
        Inject::None => return,
    };
    let at = usize::try_from(process - 1).unwrap();
    assert!(
        (run.first_steps[at]..run.last_steps[at]).contains(&index),
        "{point}: injected step {index} does not belong to process {process}"
    );
    let fault = match inject {
        Inject::LogCrash(_) => FiredFault::Crash,
        Inject::LogFail(_) => FiredFault::FailSync,
        _ => unreachable!(),
    };
    let record = run
        .log
        .step_records()
        .into_iter()
        .find(|r| r.index == index);
    let got = record.as_ref().map(|r| {
        (
            Step {
                op: r.op.clone(),
                call: r.call,
                within: r.within,
            },
            r.fired,
        )
    });
    assert_eq!(
        got,
        intended.map(|step| (step.clone(), Some(fault))),
        "{point}: the injection at step {index} of process {process} did not fire where aimed"
    );
}

/// Every step of `run`'s first recovery (process 2) up to and including
/// its first append, crashed, and failed where it is a sync.
fn recovery_points(run: &Run, coverage: &mut Coverage) {
    if run.processes < 2 {
        return;
    }
    let steps = process_steps(run, 2);
    let upto = steps
        .iter()
        .position(|(_, s)| s.call == LogCall::Append && s.within == 3)
        .map_or(steps.len(), |i| i + 1);
    for (r, step) in &steps[..upto] {
        let mut injections = vec![Inject::LogCrash(*r)];
        if is_sync(&step.op) {
            injections.push(Inject::LogFail(*r));
        }
        for recovery in injections {
            let point = Point {
                recovery,
                recovery_label: Some(log_label_of(step)),
                ..run.point
            };
            with_draws(
                point,
                1,
                Some(step),
                |p, recovery_draw| Point { recovery_draw, ..p },
                &format!("recovery {}", step.call),
                coverage,
            );
        }
    }
}

// ---------------------------------------------------------------- tests

/// Epoch probes precede the crash and recur after recovery under schedules 0–2.
/// Retransmissions keep their original epoch.
#[test]
fn epoch_probes_before_and_after_crash_recovery() {
    for sched in 0..3 {
        let dry = discover(sched);
        let index = dry
            .steps
            .iter()
            .position(|s| s.call == LogCall::Append && s.within == 3)
            .unwrap();
        let inject = Inject::LogCrash(u32::try_from(index).unwrap());
        let run = checked(labelled_point(&dry, inject, 0));
        assert_fired(&run, inject, 1, Some(&dry.steps[index]));
        for process in [1, 2] {
            for volume in [a(), b()] {
                assert!(run.timeline.iter().any(|(p, ev)| *p == process && matches!(ev,
                    Ev::Emit { volume: v, reply: super::Reply::Answer(super::Answer::EpochMismatch { epoch, .. }) }
                        if v == &volume && Some(epoch) == run.script.created.get(&volume))),
                    "epoch mismatch probe must complete before and after recovery for {volume:?}");
            }
        }
        // The settle path checks retransmission epochs: a dropped epoch fails as EpochMismatch.
        // A matching global index must not pass for the wrong process or fault kind.
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_fired(
                &run,
                inject,
                2,
                Some(&dry.steps[index])
            )))
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_fired(
                &run,
                Inject::LogFail(u32::try_from(index).unwrap()),
                1,
                Some(&dry.steps[index])
            )))
            .is_err()
        );
    }
}

/// The sweep under scheduler seed `sched`, meeting every coverage
/// obligation on its own.
fn sweep_and_cover(sched: u64) {
    let coverage = sweep(sched);
    if let Ok(dir) = std::env::var(COVERAGE_ENV) {
        let path = std::path::Path::new(&dir).join(format!("sweep-coverage-{sched}.txt"));
        std::fs::write(path, format!("{coverage:#?}\n")).unwrap();
    }
    coverage.assert_obligations();
}

/// The whole sweep under scheduler seed 0.
#[test]
fn the_crash_sweep_holds_under_schedule_0() {
    sweep_and_cover(0);
}

/// The whole sweep under scheduler seed 1.
#[test]
fn the_crash_sweep_holds_under_schedule_1() {
    sweep_and_cover(1);
}

/// The whole sweep under scheduler seed 2.
#[test]
fn the_crash_sweep_holds_under_schedule_2() {
    sweep_and_cover(2);
}

/// One point, named by [`POINT_ENV`]: how a failing point is re-run
/// alone. With the variable unset it does nothing. [`checked`] recomputes
/// the point's labels against this run and refuses by name if the build
/// that discovered it meant something different by one of its indices.
#[test]
fn one_point() {
    let Ok(point) = std::env::var(POINT_ENV) else {
        return;
    };
    let point = Point::parse(&point).unwrap_or_else(|e| panic!("{e}"));
    let run = checked(point);
    if let Ok(path) = std::env::var(DIGEST_ENV) {
        std::fs::write(path, digest(&run.sim.trace().render())).unwrap();
    }
}

/// A digest of a rendered trace.
fn digest(rendered: &str) -> String {
    let id = granary_core::hash::GrainId::of(rendered.as_bytes());
    id.digest().iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Replay across processes: a few points, one crashed with a draw, one
/// failed, one crashed again in recovery, and one cut at a store
/// operation, each re-run alone in a fresh process of this test binary
/// ([`one_point`]); the rendered trace is identical to this process's.
#[test]
fn a_point_replays_identically_in_a_fresh_process() {
    let dry = discover(0);
    let step_of = |call: LogCall, within: u32| {
        let at = dry
            .steps
            .iter()
            .position(|s| s.call == call && s.within == within)
            .unwrap();
        u32::try_from(at).unwrap()
    };
    let base = labelled_point(&dry, Inject::LogCrash(step_of(LogCall::Append, 3)), 1);
    let crashed = checked(base);
    let recovery_step = process_steps(&crashed, 2).first().map(|(r, _)| *r).unwrap();
    let fail_at = step_of(LogCall::Append, 1);
    let recovery_crash_at = recovery_step + 2;
    let store_at = dry.store_ops / 2;
    let points = [
        base,
        Point {
            first: Inject::LogFail(fail_at),
            first_label: label_of(&dry, Inject::LogFail(fail_at), 1),
            ..base
        },
        Point {
            recovery: Inject::LogCrash(recovery_crash_at),
            recovery_label: Some(
                log_label_at(&crashed, recovery_crash_at)
                    .expect("the recovery step this test computed is real"),
            ),
            recovery_draw: 3,
            ..base
        },
        Point {
            first: Inject::Store(store_at, Cut::After),
            first_label: label_of(&dry, Inject::Store(store_at, Cut::After), 1),
            ..base
        },
    ];
    let exe = std::env::current_exe().unwrap();
    for point in points {
        let here = digest(&checked(point).sim.trace().render());
        // Named by the point and the digest this process expects: two
        // runs that could share the name write the same bytes.
        let file = std::env::temp_dir().join(format!(
            "granary-sweep-{}-{here}",
            point.to_string().replace('/', "_")
        ));
        let output = std::process::Command::new(&exe)
            .args(["--exact", "authority::tests::sweep::one_point"])
            .env(POINT_ENV, point.to_string())
            .env(DIGEST_ENV, &file)
            .output()
            .unwrap();
        assert!(output.status.success(), "{point}: {output:?}");
        let there = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("{point}: the fresh process wrote no digest: {e}"));
        let _ = std::fs::remove_file(&file);
        assert_eq!(there, here, "{point} replayed differently");
    }
}

/// **Every epoch a run draws is fixed by its replay seed.** A run with no
/// injection under scheduler seed 0 creates both volumes' logs in its
/// first process, under the first two 16-byte draws of that process's
/// stream (`SeededSecureRandom::for_incarnation(0, 1)`); the same point
/// again draws the same epochs, and the run under seed 1 draws others.
/// A stream not keyed by the point's seed and the process's index, or a
/// draw taken anywhere but the stream, fails one of the three.
#[test]
fn a_runs_epochs_follow_its_replay_seed() {
    let created = |sched| {
        let dry = discover(sched);
        checked(labelled_point(&dry, Inject::None, 0))
            .script
            .created
            .into_values()
            .collect::<BTreeSet<Epoch>>()
    };
    let mut stream = SeededSecureRandom::for_incarnation(0, 1);
    let draws: BTreeSet<Epoch> = (0..2)
        .map(|_| {
            let mut bytes = [0u8; EPOCH_LEN];
            stream.fill(&mut bytes).unwrap();
            Epoch::from_bytes(bytes)
        })
        .collect();
    let (first, again, other) = (created(0), created(0), created(1));
    assert_eq!(
        (
            &first,
            &again,
            first.intersection(&other).count(),
            other.len()
        ),
        (&draws, &draws, 0, 2)
    );
}

// --------------------------------------------------------- point labels

/// A labelled point's display round-trips through [`Point::parse`]: with
/// every index labelled, and with none.
#[test]
fn a_labelled_points_display_round_trips_through_parse() {
    // A store cut is only ever valid in `first` (a cut always targets
    // process 1's store), so the store example sits there and the
    // recovery slot carries a log example instead.
    let labelled = Point {
        sched: 7,
        defer_at: Some(3),
        defer_label: Some(OpLabel::Store(StoreOp::Put {
            volume: VOLUMES[0],
            seq: 2,
        })),
        first: Inject::Store(9, Cut::After),
        first_label: Some(OpLabel::Store(StoreOp::ReadHint { volume: VOLUMES[1] })),
        draw: 4,
        recovery: Inject::LogFail(11),
        recovery_label: Some(OpLabel::Log(LogKind::FileSync)),
        recovery_draw: 6,
    };
    let text = labelled.to_string();
    assert_eq!(Point::parse(&text), Ok(labelled), "{text}");

    let bare = Point {
        sched: 0,
        defer_at: None,
        defer_label: None,
        first: Inject::None,
        first_label: None,
        draw: 0,
        recovery: Inject::None,
        recovery_label: None,
        recovery_draw: 0,
    };
    let text = bare.to_string();
    assert_eq!(Point::parse(&text), Ok(bare), "{text}");
}

/// A labelled point whose label matches what this run's own trace finds
/// there runs cleanly: [`verify_labels`] does not refuse it. `Inject::None`
/// still reaches the deferred PUT's index (it is the dry run's own
/// configuration), so its label is checked too.
#[test]
fn a_point_whose_label_matches_runs() {
    let dry = discover(0);
    let point = labelled_point(&dry, Inject::None, 0);
    let _ = checked(point);
}

/// A point whose recorded label no longer matches what this build's
/// trace finds at its index is refused, naming both labels, instead of
/// being run as if it were still the operation it no longer names.
#[test]
#[should_panic(
    expected = "was labelled `max-seq:vol-a` here but this build finds `put:vol-a:2` there"
)]
fn a_point_whose_label_is_altered_is_refused() {
    let dry = discover(0);
    let altered = Point {
        defer_label: Some(OpLabel::Store(StoreOp::MaxSeq { volume: VOLUMES[0] })),
        ..labelled_point(&dry, Inject::None, 0)
    };
    let _ = checked(altered);
}

/// The old, unlabelled point id form is refused, not silently accepted
/// as if it still named the operation its indices meant on the build
/// that printed it: [`Point::parse`] requires a label at every index.
#[test]
fn an_id_without_labels_is_refused() {
    let old_form = "0/2/crash@5/0/none/0";
    let err = Point::parse(old_form).expect_err("the old form carries no labels");
    assert_eq!(err, PointParseError::Unlabelled);
    assert!(
        err.to_string().contains("must label every index"),
        "the message should say a label is required: {err}"
    );
}

/// A point whose injection names an index this build's run never
/// reaches (its fault never fires) is refused by name — the point, the
/// slot, its claimed label, and the unreached index — never silently run
/// as if that index still existed.
#[test]
#[should_panic(
    expected = "the first injection was labelled `file-sync`, but this build never reaches index 1000000"
)]
fn a_point_beyond_this_builds_steps_is_refused() {
    let dry = discover(0);
    let point = Point {
        first: Inject::LogCrash(1_000_000),
        first_label: Some(OpLabel::Log(LogKind::FileSync)),
        ..labelled_point(&dry, Inject::None, 0)
    };
    let _ = checked(point);
}

/// An id whose deferred index exceeds this build's store operations —
/// process 1 ends cleanly (no injection of its own cuts it short) having
/// made fewer — is refused by name, not silently run as a point with no
/// deferral at all.
#[test]
#[should_panic(
    expected = "the deferred PUT was labelled `put:vol-a:2`, but this build never reaches index"
)]
fn an_old_id_beyond_this_builds_store_operations_is_refused() {
    let dry = discover(0);
    let point = Point {
        defer_at: Some(dry.store_ops + 1_000),
        defer_label: Some(dry.defer_label),
        ..labelled_point(&dry, Inject::None, 0)
    };
    let _ = checked(point);
}

/// A store cut in the recovery field is refused at parse: the runner
/// only ever applies a cut to process 1's store (`run.rs`'s
/// `Runner::process`), so accepting one in the recovery field would mean
/// indexing process 2's store even when a one-process run never has one.
#[test]
fn a_recovery_store_cut_is_refused_at_parse() {
    let with_recovery_cut = "0/none/none/0/store-before@3=put:vol-a:2/0";
    let err = Point::parse(with_recovery_cut).expect_err("a cut never targets recovery");
    assert_eq!(err, PointParseError::RecoveryStoreCut);
    assert!(
        err.to_string().contains("process 1"),
        "the message should say a cut is process 1's: {err}"
    );
}

/// An id whose recovery index has drifted into process 1's own step
/// range on this build — the recovery's fault fires there instead of in
/// process 2 — is refused by name, not silently run as if process 1 had
/// simply crashed on its own.
#[test]
#[should_panic(expected = "but on this build it fires inside process 1 at index 0")]
fn a_recovery_index_inside_process_one_is_refused() {
    let dry = discover(0);
    let point = Point {
        recovery: Inject::LogCrash(0),
        recovery_label: Some(log_label_of(&dry.steps[0])),
        ..labelled_point(&dry, Inject::None, 0)
    };
    let _ = checked(point);
}

/// A point whose first injection legitimately cuts process 1 short
/// before the deferred PUT's index still passes: the skip applies
/// because process 1's own first injection is confirmed as what fired
/// there, not merely because process 1 crashed for some reason.
#[test]
fn a_points_own_first_injection_cutting_it_short_still_passes() {
    let dry = discover(0);
    let point = labelled_point(&dry, Inject::LogCrash(0), 0);
    let _ = checked(point);
}
