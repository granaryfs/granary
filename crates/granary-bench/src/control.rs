// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The committed positive control — non-negotiable:
//! "a 1-byte prepend must give fixed ~100% novel and CDC ~0% novel, and
//! must pass before any headline number is admissible. Without it a
//! null result cannot be distinguished from a broken chunker."
//!
//! "Committed" here means committed CODE with committed thresholds and
//! a deterministic generator (`granary_core::testkit::fill`, seeded, no
//! ambient entropy) — not 64 MiB of committed bytes. Re-runnable by
//! anyone at any commit, which is the property that matters.
//!
//! The gate is structural, not procedural: [`ControlsPassed`] has
//! private fields, and the only functions that can return one are the
//! per-suite production entry points — [`run_production`]
//! (average-sweep) and [`run_factorial_production`] (factorial), each
//! of which fixes its own arm list, buffer sizes and cutter, and stamps
//! the token with its [`SuiteKind`]; [`crate::report::write_record`]
//! derives the suite a record REQUIRES from the record's own kind, so a
//! caller can neither mint a token from a cheap subset nor gate one
//! protocol's record with the other's token. [`run_diagnostic`] and
//! [`run_factorial_diagnostic`] exist for tests and return outcomes
//! with no token at all, by type. Because
//! [`crate::report::write_record`] requires a token, a headline number
//! cannot be written without the FULL production controls having passed
//! in the same process — and that link is checked by the
//! `RUSTDOCFLAGS="-D warnings"` gate, so a rename that breaks the
//! reference fails the build rather than rotting.
//!
//! `run` was once public, took an arm list and a cutter, and returned a
//! token — an empty arm list minted one having exercised nothing. That
//! is why it is split into `run_production` / `run_diagnostic`.
//!
//! # The factorial controls
//!
//! The factorial run has four controls. A failure is not an escalation:
//! no decision output exists until they pass. As built, `granary-bench
//! factorial` refuses to write a record unless controls 1, 2 and 4 pass in
//! the same process; control 3 is a `cargo` test suite that nothing in the
//! factorial command runs or checks.
//!
//! 1. **Reproduction (the harness anchor).** The four arms the factorial
//!    shares with the average sweep — the baseline cell, `fixed-256K`,
//!    `fixed-4M`, `whole-file` — reproduce the committed
//!    average-sweep records' figures field-for-field
//!    on every pair; new fields are additive. Pinned for the baseline cell:
//!    objective 402,231,140 B deciding / 278,617,405 B replication, coalesced
//!    ranges 740 / 741. A failure invalidates the run; restore comparability
//!    (toolchain, zstd, dataset bytes) and re-run. Never waived, never
//!    re-baselined to make a new number pass. Executed by `reproduce.rs`.
//!    As built, one subtree is exempt: when the committed and fresh
//!    `min_grain_bytes` differ (the shipped floor moved 512 KiB → 128 KiB),
//!    the `cdc_relevant` subtree is skipped as a different population and
//!    the move is recorded as `population_moved`; `reproduce.rs`'s module
//!    doc states the rule and when it closes.
//! 2. **Liveness (the vacuity guard, coding-standards rule 16).** Arms that
//!    are label-distinct but cut-identical would produce 28 plausible, wrong
//!    rows. The probe runs through all 28 cells AS THE ARM-BUILDER
//!    CONSTRUCTS THEM, so a factorial-loop transposition or a parameter
//!    threaded at only some cells is caught in the path that measures, on a
//!    deterministic probe of at least 8 MiB (`granary_core::testkit::fill`,
//!    seed and size fixed here: [`FACTORIAL_PROBE_SEED`],
//!    [`FACTORIAL_PROBE_LEN`]):
//!    - **(a) normalization is live:** at `min = 128 KiB` the four levels
//!      yield pairwise-distinct cut-point sets, AND on a fixed set of
//!      sub-`avg` inputs ([`SUBAVG_PROBE_COUNT`] files of
//!      [`SUBAVG_PROBE_LEN`] bytes) the fraction that cuts is strictly decreasing
//!      L0 > L1 > L2 > L3, checked on the `min = 4 KiB` arms — at a 128 KiB
//!      floor a 96 KiB input is returned whole, every fraction is 0, and the
//!      check would read red on correct code.
//!    - **(b) the floor is live:** **(i) configured = intended** — each arm's
//!      recorded `(min, normalization)`, written from the SAME `GrainTuple`
//!      handed to the chunker, equals its intended cell; **(ii) floor
//!      honoured (stuck-low guard)** — no non-terminal grain is shorter than
//!      its arm's own floor; **(iii) floor binding (stuck-high guard)** — the
//!      4 KiB-floor arm emits at least one non-terminal grain shorter than
//!      256 KiB. A (iii) failure HALTS the run for investigation. As built,
//!      (ii) is checked on every factorial arm over a non-empty non-terminal
//!      domain, and (iii) is required of EACH of the four 4 KiB arms, one
//!      outcome row per arm.
//! 3. **Parity stays.** The parity tests (`tests/parity.rs`) bind the bench
//!    chunker to `granary-core` at the SHIPPED tuple. As built this is a test
//!    gate only: a factorial run does not consult it.
//! 4. **Cell completeness (the absent-as-measured guard).** The run is
//!    invalid unless all 28 cells are `manifest_status = exact` on both W1
//!    pairs. As built it is enforced on EVERY measured pair, W2 and W3
//!    included: the CLI refuses any pair with an inexact cell before any
//!    decision code runs, and the decision re-validates each grid (missing,
//!    duplicate, off-grid or inexact cell). A cell that fails to measure is a
//!    control failure — never a
//!    band member with a zero manifest term, never a silent exclusion from
//!    the admissible set (decision step 1, `cost.rs`'s module doc).
//!    Structurally satisfied at `max = 2 MiB < 8 MiB`, where the manifest
//!    encoder never refuses a grain; kept so a future grid or harness
//!    change cannot reintroduce the shape.
//!
//! As built, (b)(i) has no outcome row of its own: the recorded
//! coordinates come from the tuple that cuts, the `factorial-arm-list` row
//! validates the list, and `sweep`'s tests pin the record shape.

use granary_core::hash::GrainId;
use granary_core::testkit;
use std::collections::BTreeSet;

use crate::chunk::{Arm, Span, all_arms, factorial_arms, validate_factorial_arms};
use crate::json::Json;
use crate::tuple::{FACTORIAL_AVG, SWEEP_AVGS};

/// Degenerate controls (identical / disjoint) are size-insensitive;
/// 4 MiB keeps a full control pass under ~10 s.
pub const CONTROL_SMALL_LEN: usize = 4 << 20;

/// The prepend control needs enough grains that one resync chunk is a
/// small fraction — the pilot used 64 MiB and measured CDC at 2.33%
/// novel with a 1 MiB average. 32 MiB keeps 16 grains at the coarsest
/// arm (see [`MIN_PREPEND_GRAINS`]) while keeping a full production
/// pass affordable inside `cargo nextest run`.
pub const CONTROL_PREPEND_LEN: usize = 32 << 20;

/// Fixed blocks must be ~fully invalidated by a 1-byte prepend.
pub const PREPEND_FIXED_MIN_NOVEL_PCT: f64 = 99.0;

/// CDC must resync. Two bounds, both required: an absolute cap in
/// grains (resync costs O(1) grains, not O(size)) and a percentage cap
/// that stays sharp at the coarse end of the grid.
pub const PREPEND_CDC_MAX_NOVEL_GRAINS: u64 = 4;
/// See [`PREPEND_CDC_MAX_NOVEL_GRAINS`].
pub const PREPEND_CDC_MAX_NOVEL_PCT: f64 = 15.0;

/// The prepend buffer must hold at least this many NOMINAL grains at
/// the COARSEST arm under test, or `novel_grains <= 4` stops
/// discriminating (a chunker that invalidates everything would still
/// pass with only four grains in the file). 16 is nominal
/// (`CONTROL_PREPEND_LEN / avg` at the coarsest grid point) — the real
/// chunker realizes a coarser average than configured, so the actual
/// span count runs lower: measured 10 spans at cdc-2M (1.60x its
/// 2 MiB configured average; cdc-1M realizes 1.39x, cdc-8K 1.32x).
/// The real margin over the four-grain bound is therefore 2.5x
/// (10 / 4), not the nominal 4x (16 / 4). Self-protecting: the suite
/// emits a failing `control-configuration` outcome rather than a
/// quietly weak control.
pub const MIN_PREPEND_GRAINS: u64 = 16;

/// Max of a slice, by recursive slice-pattern fold — no `[]`
/// indexing, which `clippy::indexing_slicing` denies in library code
/// even inside a `const fn` (a compile-time-provable-in-bounds index
/// is still flagged; verified empirically, not assumed). Used ONLY to
/// derive the tripwire below from [`SWEEP_AVGS`] directly, so the
/// tripwire can never drift from a re-literalled copy of the grid's
/// top point.
const fn max_of(s: &[usize]) -> usize {
    match s {
        [] => 0,
        [only] => *only,
        [first, rest @ ..] => {
            let rest_max = max_of(rest);
            if *first > rest_max { *first } else { rest_max }
        }
    }
}

/// Compile-time tripwire: `CONTROL_PREPEND_LEN` satisfies
/// `control-configuration`'s `need = MIN_PREPEND_GRAINS *
/// coarsest_avg` check with EXACTLY ZERO slack at the coarsest sweep
/// point (2 MiB). `MIN_PREPEND_GRAINS` anywhere in `17..=64`, or
/// `CONTROL_PREPEND_LEN` moved down (even to 0 or 1 KiB), leaves
/// EVERY existing test green — no test in this crate exercises
/// `run_production`'s real constants — while `run_production` can
/// never mint a token again. This assert pins the relationship
/// itself, derived from the constants via [`max_of`], so a one-line
/// edit to either side fails the build instead of shipping a
/// silently-dead production gate.
const _: () =
    assert!(CONTROL_PREPEND_LEN as u64 == MIN_PREPEND_GRAINS * max_of(&SWEEP_AVGS) as u64);

/// Which production suite a token proves. Two suites exist because two
/// protocols do: the average sweep's (its arm list is `all_arms()`)
/// and the factorial's (`factorial_arms()` plus the control-2 liveness
/// controls). `report::write_record` derives the suite a record
/// REQUIRES from the record's own kind (never from the caller — a
/// caller-chosen requirement was the bypass this closed), so a token
/// earned by the cheaper-to-satisfy suite can never gate the other
/// protocol's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteKind {
    /// The average-sweep suite (identical/disjoint/prepend over
    /// `all_arms()`).
    AverageSweep,
    /// The factorial suite (identical/disjoint/prepend over
    /// `factorial_arms()`, plus the registered liveness controls: arm-list
    /// validation, normalization-live, floor-live).
    Factorial,
}

impl SuiteKind {
    /// Stable label, recorded with the outcomes.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AverageSweep => "average-sweep",
            Self::Factorial => "factorial",
        }
    }
}

/// Proof that the FULL production controls passed in this process, and
/// the outcomes that constitute that proof.
///
/// The outcomes live INSIDE the token rather than travelling alongside
/// it, so a record's `controls` section is necessarily the run that
/// gated it. Passing them separately would let a caller earn a token
/// once and then write a headline with substituted or empty outcomes —
/// the guarantee would be about the caller's discipline rather than
/// about the record.
#[derive(Debug)]
pub struct ControlsPassed {
    outcomes: Vec<ControlOutcome>,
    suite: SuiteKind,
}

impl ControlsPassed {
    /// The passing outcomes this token was minted from.
    #[must_use]
    pub fn outcomes(&self) -> &[ControlOutcome] {
        &self.outcomes
    }

    /// Which production suite minted this token.
    #[must_use]
    pub const fn suite(&self) -> SuiteKind {
        self.suite
    }

    /// Consume the token, yielding the outcomes that gated it. Taking
    /// the token by value is what makes one control run gate exactly one
    /// record.
    #[must_use]
    pub fn into_outcomes(self) -> Vec<ControlOutcome> {
        self.outcomes
    }
}

/// One control result, recorded in every result file.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlOutcome {
    /// Control name (`identical`, `disjoint`, `prepend-1-byte`).
    pub control: String,
    /// Arm label.
    pub arm: String,
    /// Novel bytes as a percentage of the newer version.
    pub novel_pct: f64,
    /// Novel bytes.
    pub novel_bytes: u64,
    /// Novel grains.
    pub novel_grains: u64,
    /// The pre-registered expectation, in words.
    pub expectation: String,
    /// Whether this arm met it.
    pub passed: bool,
}

/// Run the FULL average-sweep control suite: every arm, production
/// sizes, the real chunker. The only mint of a
/// [`SuiteKind::AverageSweep`] token — and an average-sweep record's
/// only path to being written ([`run_factorial_production`] is the
/// factorial protocol's mint; `write_record` refuses a token from the
/// wrong suite).
#[must_use]
pub fn run_production() -> (Vec<ControlOutcome>, Option<ControlsPassed>) {
    let (outcomes, passed) = run_inner(
        CONTROL_SMALL_LEN,
        CONTROL_PREPEND_LEN,
        &all_arms(),
        |arm, data, out| {
            arm.cut_into(data, out);
        },
    );
    let token = passed.then(|| ControlsPassed {
        outcomes: outcomes.clone(),
        suite: SuiteKind::AverageSweep,
    });
    (outcomes, token)
}

/// Run the FULL factorial control suite: the 31 registered arms through the
/// identical/disjoint/prepend controls at production sizes, plus the
/// registered liveness controls, all with the real chunker. The only mint of
/// a [`SuiteKind::Factorial`] token.
#[must_use]
pub fn run_factorial_production() -> (Vec<ControlOutcome>, Option<ControlsPassed>) {
    let arms = factorial_arms();
    let (outcomes, passed) = factorial_inner(
        CONTROL_SMALL_LEN,
        CONTROL_PREPEND_LEN,
        &arms,
        |arm, data, out| {
            arm.cut_into(data, out);
        },
    );
    let token = passed.then(|| ControlsPassed {
        outcomes: outcomes.clone(),
        suite: SuiteKind::Factorial,
    });
    (outcomes, token)
}

/// The factorial suite with an injectable arm list and cutter, for
/// tests and diagnosis. No token, by type — same rule as
/// [`run_diagnostic`], same `cut` contract.
#[must_use]
pub fn run_factorial_diagnostic<F>(
    small_len: usize,
    prepend_len: usize,
    arms: &[Arm],
    cut: F,
) -> Vec<ControlOutcome>
where
    F: Fn(Arm, &[u8], &mut Vec<Span>),
{
    factorial_inner(small_len, prepend_len, arms, cut).0
}

/// Run the controls with an injectable arm list, sizes and cutter, for
/// tests and ad-hoc diagnosis. Returns outcomes and NO token: a subset
/// run cannot gate a headline number, and the type says so.
///
/// # The `cut` contract
///
/// `cut(arm, data, out)` MUST replace the whole of `out` with the spans
/// of `data` — that is, CLEAR it first, exactly as
/// [`Arm::cut_into`](crate::chunk::Arm::cut_into) documents ("Cut `data`
/// into `out` (cleared first)"). The private `novelty` helper reuses ONE
/// `Vec<Span>` across the older and newer cuts, so a cutter that APPENDS
/// would carry the older version's spans into the newer version's tally
/// and report wrong `novel_bytes`/`novel_grains` with nothing failing.
/// An empty `data` must yield no spans, not the previous call's.
///
/// This is a documentation-level contract, not an enforced one: it is
/// bounded by the type, since `run_diagnostic` returns no
/// [`ControlsPassed`] and therefore cannot gate a record however wrong
/// its outcomes are.
#[must_use]
pub fn run_diagnostic<F>(
    small_len: usize,
    prepend_len: usize,
    arms: &[Arm],
    cut: F,
) -> Vec<ControlOutcome>
where
    F: Fn(Arm, &[u8], &mut Vec<Span>),
{
    run_inner(small_len, prepend_len, arms, cut).0
}

/// The control-2 liveness probe: seeded, sized and REGISTERED — seed and
/// size fixed here, at least 8 MiB (control 2 in the module doc).
pub const FACTORIAL_PROBE_SEED: u64 = 0x4d34_0001;
/// See [`FACTORIAL_PROBE_SEED`].
pub const FACTORIAL_PROBE_LEN: usize = 16 << 20;

/// The liveness (a) sub-average input set: the configuration the mechanism
/// figures were measured at (96 KiB files — below `avg`, above a 4 KiB
/// floor; 1,000 of them, seeds derived from the
/// base). At the 4 KiB floor the measured cut fractions were
/// 31.7 / 20.1 / 10.0 / 4.3% across L0..L3, so strict decrease has
/// double-digit margins at this count.
pub const SUBAVG_PROBE_COUNT: usize = 1000;
/// See [`SUBAVG_PROBE_COUNT`].
pub const SUBAVG_PROBE_LEN: usize = 96 << 10;
/// See [`SUBAVG_PROBE_COUNT`].
pub const SUBAVG_PROBE_SEED_BASE: u64 = 0x4d34_1000;

/// Liveness (a), both halves — see the module doc for the stated
/// control; split out only to keep each body reviewable.
fn normalization_liveness<F>(
    arms: &[Arm],
    probe: &[u8],
    cut: &F,
    outcomes: &mut Vec<ControlOutcome>,
) where
    F: Fn(Arm, &[u8], &mut Vec<Span>),
{
    let mut spans: Vec<Span> = Vec::new();
    // Liveness (a) first half — normalization is live: at min = 128 KiB the
    // four levels give pairwise-distinct cut-point sets on the probe
    // (robust: measured on 200/200 seeds).
    let at_128k: Vec<Arm> = arms
        .iter()
        .filter(|a| matches!(a, Arm::FactorialCdc(t) if t.min == 128 << 10))
        .copied()
        .collect();
    let mut cut_sets: Vec<(String, Vec<usize>)> = Vec::new();
    for arm in &at_128k {
        cut(*arm, probe, &mut spans);
        cut_sets.push((arm.label(), spans.iter().map(|s| s.offset).collect()));
    }
    let mut distinct = at_128k.len() == 4;
    for i in 0..cut_sets.len() {
        for j in (i + 1)..cut_sets.len() {
            if let (Some(a), Some(b)) = (cut_sets.get(i), cut_sets.get(j))
                && a.1 == b.1
            {
                distinct = false;
            }
        }
    }
    outcomes.push(ControlOutcome {
        control: "normalization-live-distinct".to_owned(),
        arm: "cdc-min128K-nc0..3".to_owned(),
        novel_pct: 0.0,
        novel_bytes: 0,
        novel_grains: 0,
        expectation: "4 arms at min=128K with pairwise-distinct cut-point sets \
                      on the registered probe"
            .to_owned(),
        passed: distinct,
    });

    // Liveness (a) second half — the cut fraction on the registered sub-average
    // input set is STRICTLY decreasing L0 > L1 > L2 > L3, checked on the
    // factorial's own min = 4 KiB arms: at a 128 KiB floor a 96 KiB input is
    // <= min and returns whole, so every fraction would be 0 and the check
    // would read red on correct code — the exact class the liveness design
    // forbids: a control that reads red on correct code is itself a defect.
    let mut at_4k: Vec<Arm> = arms
        .iter()
        .filter(|a| matches!(a, Arm::FactorialCdc(t) if t.min == 4 << 10))
        .copied()
        .collect();
    at_4k.sort_by_key(|a| match a {
        Arm::FactorialCdc(t) => t.normalization.as_u8(),
        _ => u8::MAX,
    });
    let mut fractions: Vec<(String, u64)> = Vec::new();
    for arm in &at_4k {
        let mut cut_count = 0u64;
        for i in 0..SUBAVG_PROBE_COUNT {
            let file = testkit::fill(
                SUBAVG_PROBE_SEED_BASE.wrapping_add(i as u64),
                SUBAVG_PROBE_LEN,
            );
            cut(*arm, &file, &mut spans);
            if spans.len() >= 2 {
                cut_count += 1;
            }
        }
        fractions.push((arm.label(), cut_count));
    }
    let monotone = at_4k.len() == 4
        && fractions.windows(2).all(|w| match w {
            [(_, hi), (_, lo)] => hi > lo,
            _ => false,
        });
    outcomes.push(ControlOutcome {
        control: "normalization-live-monotone".to_owned(),
        arm: "cdc-min4K-nc0..3".to_owned(),
        novel_pct: 0.0,
        novel_bytes: 0,
        novel_grains: 0,
        expectation: format!(
            "cut fraction strictly decreasing L0 > L1 > L2 > L3 over \
             {SUBAVG_PROBE_COUNT} x {SUBAVG_PROBE_LEN}-byte sub-average \
             inputs; measured {fractions:?}"
        ),
        passed: monotone,
    });
}

/// Liveness (b)(ii)/(iii) — see the module doc.
fn floor_liveness<F>(arms: &[Arm], probe: &[u8], cut: &F, outcomes: &mut Vec<ControlOutcome>)
where
    F: Fn(Arm, &[u8], &mut Vec<Span>),
{
    let mut spans: Vec<Span> = Vec::new();
    let at_4k: Vec<Arm> = arms
        .iter()
        .filter(|a| matches!(a, Arm::FactorialCdc(t) if t.min == 4 << 10))
        .copied()
        .collect();
    // Liveness (b)(ii) — floor honoured (stuck-low guard): no NON-TERMINAL
    // grain shorter than its arm's own floor, per arm, on the probe.
    for arm in arms {
        let Arm::FactorialCdc(t) = arm else { continue };
        cut(*arm, probe, &mut spans);
        let non_terminal = spans.len().saturating_sub(1);
        let violations = spans
            .iter()
            .take(non_terminal)
            .filter(|s| s.len < t.min)
            .count() as u64;
        outcomes.push(ControlOutcome {
            control: "floor-live-honoured".to_owned(),
            arm: arm.label(),
            novel_pct: 0.0,
            novel_bytes: 0,
            novel_grains: violations,
            expectation: format!(
                "no non-terminal grain shorter than the arm's floor ({} bytes), \
                 over a NON-EMPTY non-terminal domain",
                t.min
            ),
            // `non_terminal >= 1` is the non-vacuity conjunct: over an
            // empty domain `violations == 0` holds having checked
            // nothing (rule 16) — a one-span cutter satisfied all 28
            // rows while 34 sibling outcomes failed. Guaranteed true on
            // the 16 MiB probe for every registered arm.
            passed: violations == 0 && non_terminal >= 1,
        });
    }

    // Liveness (b)(iii) — floor binding (stuck-high guard): every 4 KiB-floor
    // arm emits at least one non-terminal grain shorter than `avg`
    // (256 KiB), or its floor is effectively the coarsest and not
    // 4 KiB. Expected on any rich multi-MiB probe; a failure HALTS the
    // run for investigation (the failing outcome withholds the token)
    // rather than passing silently.
    for arm in &at_4k {
        cut(*arm, probe, &mut spans);
        let non_terminal = spans.len().saturating_sub(1);
        let below_avg = spans
            .iter()
            .take(non_terminal)
            .filter(|s| s.len < FACTORIAL_AVG)
            .count() as u64;
        outcomes.push(ControlOutcome {
            control: "floor-live-binding".to_owned(),
            arm: arm.label(),
            novel_pct: 0.0,
            novel_bytes: 0,
            novel_grains: below_avg,
            expectation: format!(
                "at least one non-terminal grain shorter than avg \
                 ({FACTORIAL_AVG} bytes) — a failure HALTS the run"
            ),
            passed: below_avg >= 1,
        });
    }
}

/// The factorial suite body: the shared identical/disjoint/prepend
/// controls, then the registered liveness controls, every one
/// of them run through the arms AS GIVEN — never a separate
/// re-derivation, so a factorial-loop transposition or a parameter
/// threaded at only some cells is caught in the SAME list that
/// measures.
///
/// Deliberately NOT asserted: "seven floors ⇒ seven distinct cut-point
/// sets". That invariant was measured seed-fragile and can be FALSE
/// on correct code — only ~3% of seeds satisfy it, because `min` only
/// sets where scanning starts, so adjacent floors legitimately cut
/// identically.
/// A control that reads red on correct code is itself the defect class;
/// do not "strengthen" it back in.
fn factorial_inner<F>(
    small_len: usize,
    prepend_len: usize,
    arms: &[Arm],
    cut: F,
) -> (Vec<ControlOutcome>, bool)
where
    F: Fn(Arm, &[u8], &mut Vec<Span>),
{
    let (mut outcomes, _) = run_inner(small_len, prepend_len, arms, &cut);

    // Liveness (b)(i)-adjacent, list-level: the arm list about to be trusted is
    // exactly the registered design (31 arms, distinct cell labels, the
    // 28-cell grid, the fixed avg/max on every cell).
    let arm_check = validate_factorial_arms(arms);
    outcomes.push(ControlOutcome {
        control: "factorial-arm-list".to_owned(),
        arm: "n/a".to_owned(),
        novel_pct: 0.0,
        novel_bytes: 0,
        novel_grains: 0,
        expectation: match &arm_check {
            Ok(()) => "the registered 31-arm factorial (28 distinct cells + \
                       fixed-256K + fixed-4M + whole-file)"
                .to_owned(),
            Err(e) => format!("the registered 31-arm factorial — VIOLATED: {e}"),
        },
        passed: arm_check.is_ok(),
    });

    let probe = testkit::fill(FACTORIAL_PROBE_SEED, FACTORIAL_PROBE_LEN);
    normalization_liveness(arms, &probe, &cut, &mut outcomes);
    floor_liveness(arms, &probe, &cut, &mut outcomes);

    let passed = outcomes.iter().all(|o| o.passed);
    (outcomes, passed)
}

/// The shared body. The `bool` is exactly the token predicate.
fn run_inner<F>(
    small_len: usize,
    prepend_len: usize,
    arms: &[Arm],
    cut: F,
) -> (Vec<ControlOutcome>, bool)
where
    F: Fn(Arm, &[u8], &mut Vec<Span>),
{
    let mut outcomes = Vec::new();

    // A suite with no CDC arm controls nothing: the prepend control is
    // the only one that can tell a resyncing chunker from a broken one,
    // and it needs a CDC arm to be about. An empty arm list must fail
    // here, not pass vacuously.
    let coarsest = arms
        .iter()
        .filter(|a| matches!(a, Arm::Cdc(_) | Arm::FactorialCdc(_)))
        .map(|a| a.avg_hint() as u64)
        .max();
    let need = MIN_PREPEND_GRAINS.saturating_mul(coarsest.unwrap_or(u64::MAX));
    outcomes.push(ControlOutcome {
        control: "control-configuration".to_owned(),
        arm: "n/a".to_owned(),
        novel_pct: 0.0,
        // NOT a novelty measurement — this row checks the SUITE's shape
        // (a CDC arm exists, the buffers are non-empty and large enough),
        // it does not run a chunker over anything. Reporting the prepend
        // buffer size here (as `prepend_len as u64`, verbatim) put the
        // LARGEST `novel_bytes` in the whole record next to `novel_pct:
        // 0.0` on a row whose `control` name reads like every other
        // measured control — a reader would see a
        // "control" claiming 33.5 MB novel at 0% novelty. The real buffer
        // size is already stated in `expectation` above; `0` loses no
        // information and cannot be mistaken for a measurement.
        novel_bytes: 0,
        novel_grains: 0,
        expectation: format!(
            "at least one CDC arm, a non-empty small buffer, and a \
             prepend buffer >= {need} bytes ({MIN_PREPEND_GRAINS} \
             coarsest grains)"
        ),
        // `small_len > 0` is symmetric with the `prepend_len` guard
        // above: a zero-length small buffer is a misconfiguration this
        // outcome should name directly, rather than surfacing only as
        // mysteriously-passing `identical`/`disjoint` outcomes below.
        // The load-bearing fix for the vacuous-pass bypass itself is
        // the non-vacuity conjunct on `identical`/`disjoint` — this
        // guard is the diagnostic half.
        passed: coarsest.is_some() && small_len > 0 && prepend_len as u64 >= need,
    });

    let a = testkit::fill(0x_c0_11, small_len);
    let b = testkit::fill(0x_d1_5c, small_len);
    let base = testkit::fill(0x_9e_ed, prepend_len);
    let mut shifted = Vec::with_capacity(prepend_len + 1);
    shifted.push(0x42);
    shifted.extend_from_slice(&base);

    for &arm in arms {
        let label = arm.label();
        // A factorial arm is a CDC arm to every control: same cutter,
        // same resync expectation.
        let is_cdc = matches!(arm, Arm::Cdc(_) | Arm::FactorialCdc(_));

        let (nb, ng, total) = novelty(&cut, arm, &a, &a);
        outcomes.push(ControlOutcome {
            control: "identical".to_owned(),
            arm: label.clone(),
            novel_pct: pct(nb, total),
            novel_bytes: nb,
            novel_grains: ng,
            expectation: "0 novel bytes".to_owned(),
            // `total > 0` is the non-vacuity conjunct: on an empty
            // buffer `nb == 0` holds trivially having measured
            // nothing. This is the load-bearing fix — it closes the
            // hole on the measurement itself, so it cannot be
            // bypassed by any route to a zero-length small buffer,
            // including one that skips `control-configuration`'s own
            // guard.
            passed: nb == 0 && total > 0,
        });

        let (nb, ng, total) = novelty(&cut, arm, &a, &b);
        outcomes.push(ControlOutcome {
            control: "disjoint".to_owned(),
            arm: label.clone(),
            novel_pct: pct(nb, total),
            novel_bytes: nb,
            novel_grains: ng,
            expectation: "100% novel".to_owned(),
            // See the `identical` control above: `total > 0` is the
            // same non-vacuity conjunct, needed because `nb == total`
            // degenerates to `0 == 0` on an empty buffer.
            passed: nb == total && total > 0,
        });

        let (nb, ng, total) = novelty(&cut, arm, &base, &shifted);
        let novel_pct = pct(nb, total);
        let (expectation, passed) = if is_cdc {
            (
                format!(
                    "CDC resyncs: <= {PREPEND_CDC_MAX_NOVEL_GRAINS} novel grains and \
                     <= {PREPEND_CDC_MAX_NOVEL_PCT}% novel"
                ),
                ng <= PREPEND_CDC_MAX_NOVEL_GRAINS && novel_pct <= PREPEND_CDC_MAX_NOVEL_PCT,
            )
        } else {
            (
                format!("fixed shifts: >= {PREPEND_FIXED_MIN_NOVEL_PCT}% novel"),
                novel_pct >= PREPEND_FIXED_MIN_NOVEL_PCT,
            )
        };
        outcomes.push(ControlOutcome {
            control: "prepend-1-byte".to_owned(),
            arm: label,
            novel_pct,
            novel_bytes: nb,
            novel_grains: ng,
            expectation,
            passed,
        });
    }

    let passed = outcomes.iter().all(|o| o.passed);
    (outcomes, passed)
}

/// Novel bytes, novel grains, and total bytes of `newer` under `arm`.
///
/// ONE `spans` buffer is reused across both cuts, so this relies on
/// `cut` clearing it — see the `cut` contract on [`run_diagnostic`].
fn novelty<F>(cut: &F, arm: Arm, older: &[u8], newer: &[u8]) -> (u64, u64, u64)
where
    F: Fn(Arm, &[u8], &mut Vec<Span>),
{
    let mut spans = Vec::new();
    let mut seen: BTreeSet<GrainId> = BTreeSet::new();
    cut(arm, older, &mut spans);
    for s in &spans {
        if let Some(bytes) = older.get(s.offset..s.offset + s.len) {
            seen.insert(GrainId::of(bytes));
        }
    }
    cut(arm, newer, &mut spans);
    let mut novel_bytes = 0u64;
    let mut novel_grains = 0u64;
    let mut fresh: BTreeSet<GrainId> = BTreeSet::new();
    for s in &spans {
        if let Some(bytes) = newer.get(s.offset..s.offset + s.len) {
            let id = GrainId::of(bytes);
            if !seen.contains(&id) && fresh.insert(id) {
                novel_bytes += s.len as u64;
                novel_grains += 1;
            }
        }
    }
    (novel_bytes, novel_grains, newer.len() as u64)
}

#[expect(
    clippy::cast_precision_loss,
    reason = "control buffers are megabytes; the result is a reported percentage"
)]
fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    (part as f64 / whole as f64) * 100.0
}

/// Render the outcomes for a result file.
#[must_use]
pub fn outcomes_json(outcomes: &[ControlOutcome]) -> Json {
    Json::Arr(
        outcomes
            .iter()
            .map(|o| {
                Json::Obj(vec![
                    ("control".to_owned(), Json::s(o.control.clone())),
                    ("arm".to_owned(), Json::s(o.arm.clone())),
                    ("novel_bytes".to_owned(), Json::UInt(o.novel_bytes)),
                    ("novel_grains".to_owned(), Json::UInt(o.novel_grains)),
                    ("novel_pct".to_owned(), Json::Num(o.novel_pct)),
                    ("expectation".to_owned(), Json::s(o.expectation.clone())),
                    ("passed".to_owned(), Json::Bool(o.passed)),
                ])
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests;
