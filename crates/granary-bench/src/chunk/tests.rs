// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::chunk` — the CDC, fixed-block and whole-file
//! chunking arms, and the parity check against `granary_core::thresh`.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::tuple::{BASELINE_CELL, NormalizationLevel, SWEEP_AVGS};
use granary_core::testkit;

fn spans(arm: Arm, data: &[u8]) -> Vec<Span> {
    let mut out = Vec::new();
    arm.cut_into(data, &mut out);
    out
}

#[test]
fn every_arm_covers_the_input_contiguously() {
    let data = testkit::fill(11, 5 * 1024 * 1024 + 777);
    let mut arms = vec![Arm::WholeFile, Arm::Fixed(4 << 20)];
    for avg in SWEEP_AVGS {
        let t = GrainTuple::from_avg(avg).expect("grid point");
        arms.push(Arm::Cdc(t));
        arms.push(Arm::Fixed(avg));
    }
    for arm in arms {
        let cut = spans(arm, &data);
        let mut pos = 0usize;
        for s in &cut {
            assert_eq!(s.offset, pos, "{} not contiguous", arm.label());
            assert!(s.len > 0, "{} emitted an empty span", arm.label());
            pos += s.len;
        }
        assert_eq!(pos, data.len(), "{} does not cover the input", arm.label());
    }
}

/// `avg_hint` pinned per arm: `WholeFile` reports `usize::MAX`
/// (it has no size parameter — never the smallest thing to sort
/// against), `Cdc` reports `t.avg` (the target, not `t.min`), and
/// `Fixed` reports its own block size.
#[test]
fn avg_hint_reports_the_real_target_for_each_arm() {
    assert_eq!(Arm::WholeFile.avg_hint(), usize::MAX);
    assert_eq!(Arm::Fixed(4096).avg_hint(), 4096);
    let t = GrainTuple::shipped();
    assert_eq!(Arm::Cdc(t).avg_hint(), t.avg);
    assert_ne!(
        Arm::Cdc(t).avg_hint(),
        t.min,
        "avg_hint must be the target average, not the floor"
    );
}

#[test]
fn empty_input_yields_no_spans_for_every_arm() {
    assert!(spans(Arm::WholeFile, &[]).is_empty());
    assert!(spans(Arm::Fixed(4096), &[]).is_empty());
    assert!(spans(Arm::Cdc(GrainTuple::shipped()), &[]).is_empty());
}

/// `WholeFile` is one of the two reference arms constraint 1 names
/// (`all_arms_covers_every_grid_point_plus_the_two_references`), and
/// it is supposed to stay the DEGENERATE baseline — one grain, no
/// matter the input. `every_arm_covers_the_input_contiguously`
/// accepts any contiguous cover, including a `WholeFile` quietly
/// split into two spans, so it needs its own pin.
#[test]
fn whole_file_is_exactly_one_span_covering_everything() {
    let data = testkit::fill(13, 5 * 1024 * 1024 + 1);
    let cut = spans(Arm::WholeFile, &data);
    assert_eq!(
        cut,
        vec![Span {
            offset: 0,
            len: data.len()
        }]
    );
}

/// `cut_into`'s doc says it clears `out` first. The sweep reuses ONE
/// `Vec` across every file — that's the whole reason the API takes
/// `&mut Vec` instead of returning a fresh one — so a lost
/// `out.clear()` would silently accumulate every prior file's spans
/// into every later count.
#[test]
fn cut_into_clears_stale_entries_from_a_reused_buffer() {
    let data = testkit::fill(14, 10_000);
    let mut out = vec![
        Span {
            offset: 999,
            len: 999,
        },
        Span {
            offset: 1998,
            len: 1,
        },
    ];
    Arm::Fixed(4096).cut_into(&data, &mut out);
    assert_eq!(
        out,
        vec![
            Span {
                offset: 0,
                len: 4096
            },
            Span {
                offset: 4096,
                len: 4096
            },
            Span {
                offset: 8192,
                len: 10_000 - 8192
            },
        ]
    );
}

#[test]
fn fixed_blocks_are_exactly_the_block_size_except_the_tail() {
    let data = testkit::fill(12, 10_000);
    let cut = spans(Arm::Fixed(4096), &data);
    assert_eq!(cut.len(), 3);
    assert_eq!(cut[0].len, 4096);
    assert_eq!(cut[1].len, 4096);
    assert_eq!(cut[2].len, 10_000 - 8192);
}

/// A grid point silently dropped by `from_avg` would leave the
/// sweep and the control quietly narrower than the grid.
#[test]
fn all_arms_covers_every_grid_point_plus_the_two_references() {
    let arms = all_arms();
    assert_eq!(arms.len(), 2 * SWEEP_AVGS.len() + 2);
    for avg in SWEEP_AVGS {
        let t = GrainTuple::from_avg(avg).expect("grid point");
        assert!(arms.contains(&Arm::Cdc(t)), "{avg} cdc missing");
        assert!(arms.contains(&Arm::Fixed(avg)), "{avg} fixed missing");
    }
    assert!(arms.contains(&Arm::Fixed(4 << 20)));
    assert!(arms.contains(&Arm::WholeFile));
}

/// `Fixed(0)` never terminates in `cut_into` (see the hazard note on
/// `Arm::Fixed`'s doc). It is not reachable from `all_arms()` today,
/// and this test pins the invariant that keeps it that way — a
/// direct, composition-independent check — in place of a runtime
/// guard for a path a frozen plan does not authorise.
/// (`avg_hint`'s own non-zero-ness is pinned separately in
/// `avg_hint_reports_the_real_target_for_each_arm`; checked again
/// here per-arm because a `Fixed(0)` slipping into `all_arms()` is
/// the concrete way that could ever happen.)
#[test]
fn all_arms_never_yields_a_zero_sized_fixed_block() {
    for arm in all_arms() {
        if let Arm::Fixed(block) = arm {
            assert_ne!(block, 0, "Fixed(0) loops forever in cut_into");
        }
    }
}

#[test]
fn labels_are_stable() {
    assert_eq!(Arm::Cdc(GrainTuple::shipped()).label(), "cdc-256K");
    assert_eq!(Arm::Fixed(4 << 20).label(), "fixed-4M");
    assert_eq!(Arm::WholeFile.label(), "whole-file");
}

/// The factorial label scheme, pinned at the corners and the baseline. The
/// baseline cell is `cdc-min128K-nc1`, NOT the average sweep's `cdc-256K` —
/// the reproduction comparator maps one to the other through its
/// correspondence map: a legacy label would read as a `min = 256 KiB` cell in
/// a grid where `min` is a swept axis.
#[test]
fn factorial_arm_labels_encode_the_cell() {
    let cell = |min, l| Arm::FactorialCdc(GrainTuple::factorial_cell(min, l).expect("grid cell"));
    assert_eq!(
        cell(4 << 10, NormalizationLevel::L0).label(),
        "cdc-min4K-nc0"
    );
    assert_eq!(
        cell(128 << 10, NormalizationLevel::L1).label(),
        "cdc-min128K-nc1"
    );
    assert_eq!(
        cell(256 << 10, NormalizationLevel::L3).label(),
        "cdc-min256K-nc3"
    );
    assert_eq!(Arm::FactorialCdc(BASELINE_CELL).label(), "cdc-min128K-nc1");
}

/// A factorial arm cuts EXACTLY as a plain CDC arm at the same
/// tuple: the variant changes the label, never the cutter.
#[test]
fn a_factorial_arm_cuts_identically_to_a_cdc_arm_at_the_same_tuple() {
    let t = BASELINE_CELL;
    let data = testkit::fill(15, 5 * 1024 * 1024 + 123);
    assert_eq!(
        spans(Arm::FactorialCdc(t), &data),
        spans(Arm::Cdc(t), &data)
    );
}

/// The registered arm set: 28 cells + fixed-256K + fixed-4M +
/// whole-file = 31, all labels distinct, and it validates.
#[test]
fn factorial_arms_is_the_registered_31_arm_set() {
    let arms = factorial_arms();
    assert_eq!(arms.len(), 31);
    assert_eq!(validate_factorial_arms(&arms), Ok(()));
    let labels: Vec<String> = arms.iter().map(|a| a.label()).collect();
    assert!(labels.contains(&"cdc-min128K-nc1".to_owned()));
    assert!(labels.contains(&"fixed-256K".to_owned()));
    assert!(labels.contains(&"fixed-4M".to_owned()));
    assert!(labels.contains(&"whole-file".to_owned()));
    assert_eq!(
        arms.iter()
            .filter(|a| matches!(a, Arm::FactorialCdc(_)))
            .count(),
        28
    );
}

/// NEGATIVE (the unauditable-records clause): a duplicated
/// cell label must fail loudly, never measure.
#[test]
fn a_duplicated_cell_label_is_refused() {
    let mut arms = factorial_arms();
    let dup = arms
        .iter()
        .find(|a| matches!(a, Arm::FactorialCdc(_)))
        .copied()
        .expect("a factorial arm");
    // Replace a DIFFERENT cell with a copy, keeping the count at 31.
    let victim = arms
        .iter()
        .rposition(|a| matches!(a, Arm::FactorialCdc(_)))
        .expect("a factorial arm");
    if let Some(slot) = arms.get_mut(victim) {
        *slot = dup;
    }
    assert_eq!(
        validate_factorial_arms(&arms),
        Err(FactorialArmsError::DuplicateLabel { label: dup.label() })
    );
}

/// NEGATIVE: a wrong arm count, a substituted cell, and a factorial
/// arm smuggling a non-registered avg/max are each refused.
#[test]
fn a_narrowed_or_substituted_factorial_list_is_refused() {
    let mut arms = factorial_arms();
    arms.pop();
    assert_eq!(
        validate_factorial_arms(&arms),
        Err(FactorialArmsError::WrongCount { found: 30 })
    );

    // A cell replaced by an off-grid cell (min 2 KiB is not on the
    // registered grid but is a legal fastcdc tuple).
    let mut arms = factorial_arms();
    let off_grid =
        GrainTuple::factorial_cell(2 << 10, NormalizationLevel::L0).expect("legal but off-grid");
    if let Some(slot) = arms.iter_mut().find(|a| matches!(a, Arm::FactorialCdc(_))) {
        *slot = Arm::FactorialCdc(off_grid);
    }
    assert_eq!(
        validate_factorial_arms(&arms),
        Err(FactorialArmsError::NotTheRegisteredGrid)
    );

    // A tuple that matches a registered CELL by (min, norm) while its
    // fixed coordinates are wrong: min 128K and L1 are both on the grid,
    // but the 1 MiB average is not the registered `FACTORIAL_AVG`. Caught
    // by the fixed-coordinate check, which exists because the cell-set
    // comparison cannot see it.
    let mut arms = factorial_arms();
    let wrong_avg = GrainTuple::new(128 << 10, 1 << 20, 2 << 20, NormalizationLevel::L1, false)
        .expect("legal tuple");
    if let Some(slot) = arms.iter_mut().find(|a| matches!(a, Arm::FactorialCdc(_))) {
        *slot = Arm::FactorialCdc(wrong_avg);
    }
    assert!(matches!(
        validate_factorial_arms(&arms),
        Err(FactorialArmsError::WrongFixedCoordinates { .. })
    ));
}
