// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::tuple` — the pre-registered candidate grain
//! tuples and the sweep grid built from them.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

/// The policy fact that predates the format event and is unchanged by
/// it: the shipped tuple sits on the `min = avg/2` grid at the shipped
/// level. The ratified tuple is the incumbent, which follows that
/// policy, so this invariant still holds at the new constants and the
/// test stays as written — it is never weakened or re-pointed to
/// accommodate a tuple. (Had any OTHER cell been ratified, this test
/// would have been REMOVED in the format-event commit: from that event
/// on the shipped tuple is chosen by the factorial rule, not by the grid
/// policy.)
#[test]
fn shipped_tuple_is_the_grid_point_at_its_average() {
    let from_grid = GrainTuple::from_avg(CHUNKER_SPEC.avg).expect("shipped avg is on the grid");
    assert_eq!(from_grid, GrainTuple::shipped());
    assert!(
        !from_grid.max_clamped,
        "8 * 256 KiB = 2 MiB, under the 8 MiB ceiling — nothing reduced"
    );
}

/// Pins the pre-registered grid ITSELF, independent of any code that
/// consumes it. Every other test in this module iterates
/// `SWEEP_AVGS` — so dropping a point, reordering it, substituting
/// one octave for another, or trimming it to a shorter grid (e.g.
/// `[8K, 1M, 2M]`) leaves them all green, because none of them checks
/// the grid against anything outside itself.
///
/// Writing the nine octave values out again looks like the thing
/// this crate's own no-re-literal rule forbids — but that rule
/// targets constants IMPORTED from elsewhere (the `fastcdc` bounds,
/// `GRAIN_UNPACKED_MAX`), where re-typing an upstream number is pure
/// duplication that can drift out from under you. `SWEEP_AVGS` is
/// the opposite case: it is DEFINED in this crate, which is where the
/// average sweep's grid is fixed, and changing it changes what the
/// sweep measures — it is not a value ordinary code review tunes.
/// Pinning this locally-defined grid
/// constant against an independent literal is the same sanctioned
/// idiom as `cost::tests::binmap_entry_is_forty_nine_bytes`: the
/// literal is an independent second statement, so editing either fails.
#[test]
fn sweep_avgs_is_the_pre_registered_nine_point_grid() {
    assert_eq!(SWEEP_AVGS.len(), 9);
    assert_eq!(
        SWEEP_AVGS,
        [
            8 << 10,
            16 << 10,
            32 << 10,
            64 << 10,
            128 << 10,
            256 << 10,
            512 << 10,
            1 << 20,
            2 << 20,
        ]
    );
}

/// Extended (not split into a second test) because "shippable" and
/// "follows the policy formula" are the same loop over the same
/// grid: a second, separate loop could silently drift from this one
/// and re-check nothing new. The formula itself is pinned here, not
/// just its consequences (`max <= ceiling`, `min <= avg <= max`) —
/// those alone are satisfied by e.g. `max = GRAIN_MAX_CEILING` at
/// EVERY grid point, which destroys the constant max/avg ratio the
/// registered grid relies on to vary one thing at a time.
#[test]
fn every_grid_point_is_shippable() {
    for avg in SWEEP_AVGS {
        let t = GrainTuple::from_avg(avg)
            .unwrap_or_else(|e| panic!("grid point {} rejected: {e}", si_label(avg)));
        assert_eq!(t.avg, avg);
        assert!(t.max <= GRAIN_MAX_CEILING);
        assert!(t.min <= t.avg && t.avg <= t.max);
        assert_eq!(t.min, avg / 2, "min policy broke at {}", si_label(avg));
        assert_eq!(
            t.max,
            (8 * avg).min(GRAIN_MAX_CEILING),
            "max policy broke at {}",
            si_label(avg)
        );
    }
}

#[test]
fn only_the_2mib_point_is_clamped() {
    let clamped: Vec<usize> = SWEEP_AVGS
        .into_iter()
        .filter(|&a| GrainTuple::from_avg(a).is_ok_and(|t| t.max_clamped))
        .collect();
    assert_eq!(clamped, vec![2 << 20]);
}

/// NEGATIVE: the grid stops at 2 MiB because 4 MiB is not
/// shippable — `min = 2 MiB` exceeds `fastcdc`'s `MINIMUM_MAX`.
/// A future grid extension goes red here, not silently wrong.
#[test]
fn four_mib_average_is_rejected() {
    assert_eq!(
        GrainTuple::from_avg(4 << 20),
        Err(TupleError::MinOutOfRange { min: 2 << 20 })
    );
}

/// NEGATIVE: the frozen manifest ceiling is enforced, not assumed.
#[test]
fn max_above_the_manifest_ceiling_is_rejected() {
    assert_eq!(
        GrainTuple::new(512 << 10, 1 << 20, 16 << 20, NormalizationLevel::L1, false),
        Err(TupleError::MaxOverManifestCeiling {
            max: 16 << 20,
            ceiling: GRAIN_MAX_CEILING,
        })
    );
}

#[test]
fn non_power_of_two_average_is_rejected() {
    assert_eq!(
        GrainTuple::new(3000, 6000, 48_000, NormalizationLevel::L1, false),
        Err(TupleError::AvgNotPowerOfTwo { avg: 6000 })
    );
}

/// `avg` outside `fastcdc`'s accepted range, checked directly
/// through `new()`: `from_avg` never picks an out-of-range `avg`
/// itself (it is only ever called with `SWEEP_AVGS` members and
/// `CHUNKER_SPEC.avg`), so this arm is only reachable by a caller
/// who bypasses the grid — exactly what a direct `new()` test does.
#[test]
fn avg_out_of_range_is_rejected() {
    assert_eq!(
        GrainTuple::new(64, 100, 1_000, NormalizationLevel::L1, false),
        Err(TupleError::AvgOutOfRange { avg: 100 })
    );
}

/// `min <= avg <= max` violated, checked directly through `new()`
/// with three individually in-range fields that are out of order.
#[test]
fn not_ordered_is_rejected() {
    assert_eq!(
        GrainTuple::new(1 << 20, 256 << 10, 4 << 20, NormalizationLevel::L1, false),
        Err(TupleError::NotOrdered {
            min: 1 << 20,
            avg: 256 << 10,
            max: 4 << 20,
        })
    );
}

/// `max` outside `fastcdc`'s accepted range (1024..=16 MiB).
///
/// REACHABILITY, confirmed by hand: `from_avg` can NEVER produce
/// this error. `from_avg` only reaches the max-range check with an
/// `avg` that already survived the earlier min/avg checks in `new`
/// — `min = avg/2` in `MINIMUM_MIN..=MINIMUM_MAX` forces `avg >=
/// 256` once combined with `avg` itself needing `AVERAGE_MIN =
/// 256`, so the smallest `max` `from_avg` can ever pass in is `8 *
/// 256 = 2048`, comfortably above `MAXIMUM_MIN` (1024) — the low
/// side is therefore masked. And `from_avg` caps
/// `max` at `GRAIN_MAX_CEILING` (8 MiB), strictly under `fastcdc`'s
/// `MAXIMUM_MAX` (16 MiB), so the high side can't fire either.
///
/// But "unreachable through `from_avg`" is not "unreachable" full
/// stop: `new()` is a public constructor callable with ANY numbers,
/// same as `max_above_the_manifest_ceiling_is_rejected` above
/// already tests a branch (`MaxOverManifestCeiling`) that `from_avg`
/// equally can never reach, by direct construction. This is that
/// same, already-established idiom — not a fake.
#[test]
fn max_out_of_range_is_rejected() {
    assert_eq!(
        GrainTuple::new(64, 256, 100, NormalizationLevel::L1, false),
        Err(TupleError::MaxOutOfRange { max: 100 }),
        "low side"
    );
    assert_eq!(
        GrainTuple::new(64, 256, 20_000_000, NormalizationLevel::L1, false),
        Err(TupleError::MaxOutOfRange { max: 20_000_000 }),
        "high side"
    );
}

#[test]
fn labels_are_stable() {
    assert_eq!(si_label(8 << 10), "8K");
    assert_eq!(si_label(1 << 20), "1M");
    assert_eq!(si_label(1500), "1500");
}

/// Pins the pre-registered factorial ITSELF, independent of any code
/// that consumes it — the same sanctioned idiom as
/// `sweep_avgs_is_the_pre_registered_nine_point_grid` above, for the
/// same reason: every other test iterates these constants, so only
/// an independent literal can catch a dropped or substituted cell.
/// (The grid may not change at all once the amendment window that
/// `cost.rs`'s module doc states has closed.)
#[test]
fn the_factorial_constants_are_the_pre_registered_grid() {
    assert_eq!(FACTORIAL_AVG, 262_144);
    assert_eq!(FACTORIAL_MAX, 2_097_152);
    assert_eq!(
        FACTORIAL_MINS,
        [4_096, 8_192, 16_384, 32_768, 65_536, 131_072, 262_144]
    );
    assert_eq!(FACTORIAL_LEVELS.len(), 4);
    assert_eq!(BASELINE_MIN, 131_072);
    assert_eq!(BASELINE_LEVEL, NormalizationLevel::L1);
}

/// Legality of every cell, against the real constructor — the grid's
/// claim ("64..=1,048,576 covers 4,096..=262,144; min <= avg holds
/// at the top of the grid") discharged by execution, plus: no cell
/// is ever clamped, and the enumeration is 28 cells in min-major
/// registered order with no duplicates.
#[test]
fn the_factorial_grid_is_28_legal_unclamped_cells_in_registered_order() {
    let grid = GrainTuple::factorial_grid();
    assert_eq!(grid.len(), 28);
    let mut expect = Vec::new();
    for min in FACTORIAL_MINS {
        for level in FACTORIAL_LEVELS {
            expect.push((min, level));
        }
    }
    for (t, (min, level)) in grid.iter().zip(expect) {
        assert_eq!((t.min, t.normalization), (min, level));
        assert_eq!(t.avg, FACTORIAL_AVG);
        assert_eq!(t.max, FACTORIAL_MAX);
        assert!(!t.max_clamped, "no factorial cell is clamped");
    }
    let mut cells: Vec<(usize, u8)> = grid
        .iter()
        .map(|t| (t.min, t.normalization.as_u8()))
        .collect();
    cells.sort_unstable();
    cells.dedup();
    assert_eq!(cells.len(), 28, "no duplicate cells");
}

#[test]
fn the_baseline_cell_is_adr_0011s_adopted_tuple_and_is_on_the_grid() {
    let b = BASELINE_CELL;
    assert_eq!(b.min, 128 << 10);
    assert_eq!(b.avg, 256 << 10);
    assert_eq!(b.max, 2 << 20);
    assert_eq!(b.normalization, NormalizationLevel::L1);
    assert!(GrainTuple::factorial_grid().contains(&b));
}

/// NEGATIVE: the grid's structural ceiling is real — `min` above
/// `avg` is not a legal fastcdc tuple, so there is nothing above
/// 256 KiB to explore at this average. A
/// future "extend the floor grid upward" edit goes red here.
#[test]
fn a_floor_above_the_factorial_average_is_rejected() {
    assert_eq!(
        GrainTuple::factorial_cell(512 << 10, NormalizationLevel::L1),
        Err(TupleError::NotOrdered {
            min: 512 << 10,
            avg: FACTORIAL_AVG,
            max: FACTORIAL_MAX,
        })
    );
}

#[test]
fn normalization_level_round_trips_through_u8() {
    assert_eq!(NormalizationLevel::L0.as_u8(), 0);
    assert_eq!(NormalizationLevel::L1.as_u8(), 1);
    assert_eq!(NormalizationLevel::L2.as_u8(), 2);
    assert_eq!(NormalizationLevel::L3.as_u8(), 3);
    for level in [
        NormalizationLevel::L0,
        NormalizationLevel::L1,
        NormalizationLevel::L2,
        NormalizationLevel::L3,
    ] {
        assert_eq!(
            NormalizationLevel::from_u8(level.as_u8()),
            Some(level),
            "{level:?} did not round-trip"
        );
    }
}

/// The valid range is exactly 0..=3; every other `u8` value,
/// including the one just past the top, must be rejected.
#[test]
fn normalization_level_from_u8_rejects_out_of_range() {
    for v in 4..=u8::MAX {
        assert_eq!(NormalizationLevel::from_u8(v), None, "v={v}");
    }
}
