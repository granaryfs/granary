// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::control` — the committed positive control gate
//! and the structural `ControlsPassed` token that gates a headline run.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::tuple::{GrainTuple, NormalizationLevel};

fn cheap_arms() -> Vec<Arm> {
    let t = crate::tuple::GrainTuple::from_avg(64 << 10).expect("grid point");
    vec![Arm::Cdc(t), Arm::Fixed(64 << 10), Arm::WholeFile]
}

/// Pins `pct` as floating-point division, not integer division.
/// `pct(1, 3)` is exactly 100/3 = 33.333...%, a value only
/// reachable by float division — integer division truncates to a
/// whole number (mutation M16), and `novel_pct` is written into
/// every record via `outcomes_json`, so a truncated percentage
/// would ship silently.
#[test]
fn pct_is_float_division_and_keeps_the_fraction() {
    assert!(
        (pct(1, 3) - 100.0 / 3.0).abs() < 1e-9,
        "pct(1, 3) = {}",
        pct(1, 3)
    );
    assert!(
        (pct(1, 7) - 100.0 / 7.0).abs() < 1e-9,
        "pct(1, 7) = {}",
        pct(1, 7)
    );
    assert!(
        (pct(0, 0) - 0.0).abs() < 1e-9,
        "whole == 0 stays the documented special case"
    );
}

/// Mechanism check at a size cheap enough for every `nextest` run;
/// the production pass over every arm is `tests/controls.rs`.
#[test]
fn controls_pass_with_the_real_chunker() {
    let outcomes = run_diagnostic(1 << 20, 4 << 20, &cheap_arms(), |arm, data, out| {
        arm.cut_into(data, out);
    });
    let failed: Vec<&ControlOutcome> = outcomes.iter().filter(|o| !o.passed).collect();
    assert!(failed.is_empty(), "{failed:#?}");
}

#[test]
fn every_arm_and_control_is_covered() {
    let outcomes = run_diagnostic(1 << 20, 4 << 20, &cheap_arms(), |arm, data, out| {
        arm.cut_into(data, out);
    });
    assert_eq!(outcomes.len(), cheap_arms().len() * 3 + 1);
}

/// NEGATIVE, and the one that matters: a chunker that does not
/// resync must drive the token predicate to false. `run_inner`'s
/// `bool` IS that predicate, so this tests the gate itself and not
/// a proxy for it. (The committed positive control is non-negotiable.)
#[test]
fn a_broken_cdc_drives_the_token_predicate_false() {
    let (outcomes, passed) = run_inner(1 << 20, 4 << 20, &cheap_arms(), |arm, data, out| {
        // The sabotage: CDC arms cut like fixed blocks.
        match arm {
            Arm::Cdc(t) => Arm::Fixed(t.avg).cut_into(data, out),
            other => other.cut_into(data, out),
        }
    });
    assert!(!passed, "a broken chunker must not satisfy the gate");
    let prepend_cdc: Vec<&ControlOutcome> = outcomes
        .iter()
        .filter(|o| o.control == "prepend-1-byte" && o.arm.starts_with("cdc-"))
        .collect();
    assert!(!prepend_cdc.is_empty());
    assert!(prepend_cdc.iter().all(|o| !o.passed), "{prepend_cdc:#?}");
    // The degenerate controls stay green — they cannot catch this,
    // which is why the prepend control is the non-negotiable one.
    assert!(
        outcomes
            .iter()
            .filter(|o| o.control == "identical" || o.control == "disjoint")
            .all(|o| o.passed)
    );
}

/// NEGATIVE, mirroring the CDC-side test above: the metric requires
/// "fixed ~100% novel AND CDC ~0% novel" — both halves. Only the
/// CDC half had a demonstrated failure mode; a gate whose failure
/// was never demonstrated does not exist. The sabotage here swaps
/// the arms the other way: Fixed cuts like CDC, so it resyncs
/// around the 1-byte prepend instead of invalidating everything,
/// and the fixed control must catch that.
#[test]
fn a_resyncing_fixed_arm_drives_the_token_predicate_false() {
    let (outcomes, passed) = run_inner(1 << 20, 4 << 20, &cheap_arms(), |arm, data, out| {
        // The sabotage: Fixed arms cut like CDC (they resync).
        match arm {
            Arm::Fixed(block) => {
                let t = crate::tuple::GrainTuple::from_avg(block).expect("grid point");
                Arm::Cdc(t).cut_into(data, out);
            }
            other => other.cut_into(data, out),
        }
    });
    assert!(!passed, "a resyncing fixed arm must not satisfy the gate");
    let prepend_fixed: Vec<&ControlOutcome> = outcomes
        .iter()
        .filter(|o| o.control == "prepend-1-byte" && o.arm.starts_with("fixed-"))
        .collect();
    assert!(!prepend_fixed.is_empty());
    assert!(
        prepend_fixed.iter().all(|o| !o.passed),
        "{prepend_fixed:#?}"
    );
}

/// NEGATIVE: pins the grain bound (`PREPEND_CDC_MAX_NOVEL_GRAINS`)
/// independently of the pct bound. `a_broken_cdc_drives_the_token_
/// predicate_false` fails through the pct bound alone — a fully
/// broken chunker reports ~100% novel, so the grain bound carries
/// zero tested weight there. Here the cut closure hand-crafts
/// exactly 5 distinct "novel" spans (deterministic, not measured)
/// for the shifted buffer at cdc-8K: 5 * 8192 bytes / 32 MiB +1 is
/// ~0.12% novel — comfortably under the 15% pct cap — while
/// 5 grains exceeds the 4-grain cap.
#[test]
fn the_grain_bound_alone_drives_the_token_predicate_false() {
    const NOVEL_GRAINS: usize = 5;
    let t = crate::tuple::GrainTuple::from_avg(8 << 10).expect("grid point");
    let prepend_len = CONTROL_PREPEND_LEN;
    let block = t.avg;
    let (outcomes, passed) = run_inner(
        1 << 10,
        prepend_len,
        &[Arm::Cdc(t)],
        move |arm, data, out| {
            if matches!(arm, Arm::Cdc(_)) && data.len() == prepend_len + 1 {
                out.clear();
                for i in 0..NOVEL_GRAINS {
                    out.push(Span {
                        offset: i * block,
                        len: block,
                    });
                }
                return;
            }
            arm.cut_into(data, out);
        },
    );
    assert!(!passed, "a grain-bound breach must fail the gate");
    let prepend: Vec<&ControlOutcome> = outcomes
        .iter()
        .filter(|o| o.control == "prepend-1-byte")
        .collect();
    assert_eq!(prepend.len(), 1);
    let o = prepend[0];
    assert_eq!(o.novel_grains, NOVEL_GRAINS as u64, "{o:#?}");
    assert!(
        o.novel_pct <= PREPEND_CDC_MAX_NOVEL_PCT,
        "the pct bound must stay satisfied here: {o:#?}"
    );
    assert!(
        o.novel_grains > PREPEND_CDC_MAX_NOVEL_GRAINS,
        "the grain bound must be the one that fails: {o:#?}"
    );
    assert!(!o.passed, "{o:#?}");
}

/// NEGATIVE: pins the pct bound (`PREPEND_CDC_MAX_NOVEL_PCT`)
/// independently of the grain bound — the mirror of the test
/// above. At cdc-2M, 3 hand-crafted novel spans of 2 MiB each are
/// ~18.75% of the 32 MiB +1 prepend buffer: over the 15% pct cap,
/// while 3 grains stays under the 4-grain cap. Together the two
/// tests demonstrate BOTH bounds are load-bearing, independently.
#[test]
fn the_pct_bound_alone_drives_the_token_predicate_false() {
    const NOVEL_GRAINS: usize = 3;
    let t = crate::tuple::GrainTuple::from_avg(2 << 20).expect("grid point");
    let prepend_len = CONTROL_PREPEND_LEN;
    let block = t.avg;
    let (outcomes, passed) = run_inner(
        1 << 10,
        prepend_len,
        &[Arm::Cdc(t)],
        move |arm, data, out| {
            if matches!(arm, Arm::Cdc(_)) && data.len() == prepend_len + 1 {
                out.clear();
                for i in 0..NOVEL_GRAINS {
                    out.push(Span {
                        offset: i * block,
                        len: block,
                    });
                }
                return;
            }
            arm.cut_into(data, out);
        },
    );
    assert!(!passed, "a pct-bound breach must fail the gate");
    let prepend: Vec<&ControlOutcome> = outcomes
        .iter()
        .filter(|o| o.control == "prepend-1-byte")
        .collect();
    assert_eq!(prepend.len(), 1);
    let o = prepend[0];
    assert_eq!(o.novel_grains, NOVEL_GRAINS as u64, "{o:#?}");
    assert!(
        o.novel_grains <= PREPEND_CDC_MAX_NOVEL_GRAINS,
        "the grain bound must stay satisfied here: {o:#?}"
    );
    assert!(
        o.novel_pct > PREPEND_CDC_MAX_NOVEL_PCT,
        "the pct bound must be the one that fails: {o:#?}"
    );
    assert!(!o.passed, "{o:#?}");
}

/// NEGATIVE: an empty arm list exercises nothing, so it must not
/// satisfy the predicate. This was the bypass.
#[test]
fn an_empty_arm_list_fails_the_suite() {
    let (outcomes, passed) = run_inner(1 << 10, CONTROL_PREPEND_LEN, &[], |arm, data, out| {
        arm.cut_into(data, out);
    });
    assert!(!passed, "an empty suite must not satisfy the gate");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].control, "control-configuration");
    assert!(!outcomes[0].passed, "{:#?}", outcomes[0]);
    // Pins the `unwrap_or(u64::MAX)` mechanism specifically
    // (mutation M20): with no CDC arm, `need` must come from the
    // SATURATING default, not a mutated fallback like `0`. u64::MAX
    // is large enough that no realistic `prepend_len` could ever
    // satisfy `prepend_len >= need`, which is exactly why
    // `coarsest.is_some()` (mutation M7) is defense-in-depth here
    // rather than the sole guard: dropping it alone cannot flip
    // this outcome, since the saturated `need` already fails the
    // numeric comparison on its own for every constructible input
    // (verified: M7 alone stays green against every assertion in
    // this test, by hand — it is a provable equivalent mutant
    // given `unwrap_or(u64::MAX)` and `MIN_PREPEND_GRAINS > 0`;
    // killing it would require restructuring the guard, which is
    // out of scope here).
    assert!(
        outcomes[0].expectation.contains(&u64::MAX.to_string()),
        "the no-CDC-arm branch must compute `need` from the \
         saturating default: {:#?}",
        outcomes[0]
    );
}

/// NEGATIVE: a control buffer too small for its coarsest arm is
/// caught by the suite's own configuration check.
#[test]
fn an_undersized_prepend_buffer_fails_the_suite() {
    let t = crate::tuple::GrainTuple::from_avg(1 << 20).expect("grid point");
    let (outcomes, passed) = run_inner(1 << 16, 1 << 20, &[Arm::Cdc(t)], |arm, data, out| {
        arm.cut_into(data, out);
    });
    assert!(!passed);
    assert!(
        outcomes
            .iter()
            .any(|o| o.control == "control-configuration" && !o.passed)
    );
}

/// NEGATIVE: a zero-length small buffer must not satisfy the token
/// predicate. `nb == 0` and `nb == total` both hold vacuously when
/// `total == 0`. Checks the `control-configuration` outcome names
/// the failure (the diagnostic half) AND that
/// `identical`/`disjoint` themselves would not pass even if a
/// different route reached a zero-length small buffer (the
/// load-bearing half).
#[test]
fn a_zero_length_small_buffer_fails_the_suite() {
    let (outcomes, passed) = run_inner(0, CONTROL_PREPEND_LEN, &cheap_arms(), |arm, data, out| {
        arm.cut_into(data, out);
    });
    assert!(!passed, "an empty small buffer must not satisfy the gate");
    assert!(
        outcomes
            .iter()
            .any(|o| o.control == "control-configuration" && !o.passed),
        "{outcomes:#?}"
    );
    assert!(
        outcomes
            .iter()
            .filter(|o| o.control == "identical" || o.control == "disjoint")
            .all(|o| !o.passed),
        "identical/disjoint must not pass vacuously on an empty buffer: {outcomes:#?}"
    );
}

// ---- The factorial suite. -------------------------------------------

fn real_cut(arm: Arm, data: &[u8], out: &mut Vec<Span>) {
    arm.cut_into(data, out);
}

/// The full factorial suite passes with the real chunker at
/// production sizes — including the liveness controls, whose
/// expected values (distinct cut sets at min=128K; strictly
/// decreasing cut fractions at min=4K; floors honoured and binding)
/// were measured true before they were registered.
#[test]
fn factorial_production_controls_pass_and_mint_a_factorial_token() {
    let (outcomes, token) = run_factorial_production();
    let failed: Vec<&ControlOutcome> = outcomes.iter().filter(|o| !o.passed).collect();
    assert!(failed.is_empty(), "{failed:#?}");
    let token = token.expect("a passing factorial suite mints a token");
    assert_eq!(token.suite(), SuiteKind::Factorial);
    // 31 arms x 3 shared controls + control-configuration +
    // factorial-arm-list + normalization-live (2) + floor-live-honoured
    // (28) + floor-live-binding (4).
    assert_eq!(outcomes.len(), 31 * 3 + 1 + 1 + 2 + 28 + 4);
}

/// NEGATIVE (liveness, the transposed-loop shape): a cutter that
/// silently ignores the normalization level — every factorial arm
/// cuts at its floor's L1 cell — must fail BOTH normalization
/// liveness controls and mint nothing.
#[test]
fn a_cutter_that_ignores_normalization_fails_the_liveness_controls() {
    let arms = factorial_arms();
    let outcomes = run_factorial_diagnostic(1 << 20, 8 << 20, &arms, |arm, data, out| match arm {
        Arm::FactorialCdc(t) => {
            let flat =
                GrainTuple::factorial_cell(t.min, NormalizationLevel::L1).expect("grid cell");
            Arm::FactorialCdc(flat).cut_into(data, out);
        }
        other => other.cut_into(data, out),
    });
    let dead: Vec<&ControlOutcome> = outcomes
        .iter()
        .filter(|o| o.control.starts_with("normalization-live") && !o.passed)
        .collect();
    assert_eq!(dead.len(), 2, "both halves must fail: {outcomes:#?}");
}

/// NEGATIVE (liveness (b)(ii), the stuck-low shape): a cutter that emits a
/// non-terminal grain below its arm's floor is caught by the
/// floor-honoured control on exactly that arm.
#[test]
fn a_grain_below_its_arms_floor_fails_floor_honoured() {
    let arms = factorial_arms();
    let outcomes = run_factorial_diagnostic(1 << 20, 8 << 20, &arms, |arm, data, out| {
        arm.cut_into(data, out);
        // Sabotage one arm: split its first span into a sliver and
        // the remainder.
        if matches!(arm, Arm::FactorialCdc(t) if t.min == 64 << 10
            && t.normalization == NormalizationLevel::L2)
            && let Some(first) = out.first().copied()
            && first.len > 100
        {
            let sliver = Span {
                offset: first.offset,
                len: 100,
            };
            let rest = Span {
                offset: first.offset + 100,
                len: first.len - 100,
            };
            out.splice(0..1, [sliver, rest]);
        }
    });
    let failing: Vec<&ControlOutcome> = outcomes
        .iter()
        .filter(|o| o.control == "floor-live-honoured" && !o.passed)
        .collect();
    assert_eq!(failing.len(), 1, "{outcomes:#?}");
    assert_eq!(
        failing.first().map(|o| o.arm.as_str()),
        Some("cdc-min64K-nc2")
    );
}

/// NEGATIVE (liveness (b)(iii), the stuck-high shape): a cutter whose 4 KiB
/// floors secretly behave like 256 KiB floors — every non-terminal
/// grain at or above `avg` — HALTS via a failing floor-binding
/// outcome, and the suite mints nothing.
#[test]
fn a_floor_stuck_at_the_ceiling_fails_floor_binding() {
    let arms = factorial_arms();
    let stuck = GrainTuple::factorial_cell(256 << 10, NormalizationLevel::L1).expect("grid cell");
    let outcomes =
        run_factorial_diagnostic(1 << 20, 8 << 20, &arms, move |arm, data, out| match arm {
            Arm::FactorialCdc(t) if t.min == 4 << 10 => {
                Arm::FactorialCdc(stuck).cut_into(data, out);
            }
            other => other.cut_into(data, out),
        });
    let binding: Vec<&ControlOutcome> = outcomes
        .iter()
        .filter(|o| o.control == "floor-live-binding")
        .collect();
    assert_eq!(binding.len(), 4);
    assert!(
        binding.iter().all(|o| !o.passed),
        "every 4K-floor arm must fail: {binding:#?}"
    );
}

/// NEGATIVE: a narrowed arm list (a dropped cell) fails the
/// factorial-arm-list control — the suite checks the list it is
/// about to trust, not a count of what it happened to run.
#[test]
fn a_narrowed_arm_list_fails_the_arm_list_control() {
    let mut arms = factorial_arms();
    arms.retain(|a| {
        !matches!(a, Arm::FactorialCdc(t) if t.min == 4 << 10
        && t.normalization == NormalizationLevel::L3)
    });
    let outcomes = run_factorial_diagnostic(1 << 20, 8 << 20, &arms, real_cut);
    assert!(
        outcomes
            .iter()
            .any(|o| o.control == "factorial-arm-list" && !o.passed),
        "{outcomes:#?}"
    );
}
