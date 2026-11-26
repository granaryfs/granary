// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the full pre-registered factorial decision
//! (`crate::cost::decide_factorial`) over the complete, exactly-measured
//! 28-cell grid.
//!
//! Out-of-line, because a module's second conforming test body
//! becomes a leaf under `tests`, declared by `cost/tests.rs`'s `mod
//! factorial_tests;` rather than a second sibling declaration in
//! the parent (`cost.rs`). This file has no `super::X` named paths,
//! but it does open `use super::*;`, which is a `super::` path like
//! any other: nesting one level deeper under `tests` changes what
//! `super` reaches, so it is rewritten to `use super::super::*;` to
//! keep glob-importing `cost` rather than `tests`.

use super::super::*;

/// A full, valid 28-cell grid whose objective is `value(cell)` and
/// whose binmap-sensitive term is `grains(cell)` — everything else
/// benign, ranges 100 everywhere so E5 stays quiet unless a test
/// raises it.
fn grid_with(label: &str, value: impl Fn(Cell) -> u64, grains: impl Fn(Cell) -> u64) -> PairGrid {
    let mut cells = Vec::new();
    for min in FACTORIAL_MINS {
        for level in FACTORIAL_LEVELS {
            let cell = Cell {
                min,
                level: level.as_u8(),
            };
            cells.push(CellMeasure {
                cell,
                manifest_exact: true,
                novel_stored_bytes: value(cell),
                novel_manifest_bytes: 0,
                novel_grain_count: grains(cell),
                store_stored_bytes: 10_000_000,
                store_manifest_bytes: 0,
                store_grain_count: 0,
                coalesced_ranges: 100,
            });
        }
    }
    PairGrid {
        label: label.to_owned(),
        cells,
    }
}

fn flat(label: &str) -> PairGrid {
    grid_with(label, |_| 1_000_000, |_| 0)
}

/// THE FLAT-LANDSCAPE SCENARIO (the reason argmin-with-tiebreak is
/// not this rule): on a flat
/// landscape — all 28 cells within 2% — preference alone may never
/// move the tuple. The incumbent is selected, E7 does not fire, and
/// the sensitivity replays agree.
#[test]
fn a_flat_landscape_selects_the_incumbent() {
    let d = decide_factorial(&flat("deciding"), &flat("replication")).expect("valid grids");
    assert_eq!(d.selection, Some(Cell::BASELINE));
    assert_eq!(d.intersection.len(), 28, "a flat landscape fills A");
    assert!(
        !d.escalations
            .iter()
            .any(|e| matches!(e, Escalation::IncumbentDisplaced { .. })),
        "{:?}",
        d.escalations
    );
    assert!(
        d.replays
            .iter()
            .all(|r| r.selection == Some(Cell::BASELINE))
    );
    // On a truly flat grid the per-pair argmin is a TIE, broken
    // deterministically to the smallest floor — which sits at the
    // 4 KiB edge, so E2's argmin disjunct fires. That is the
    // conservative reading: a flat landscape genuinely cannot rule
    // out an optimum below the grid.
    assert!(
        d.escalations
            .iter()
            .any(|e| matches!(e, Escalation::FloorEdgeArgmin { .. })),
        "{:?}",
        d.escalations
    );
}

/// NEGATIVE (decision step 2, `cost.rs`'s module doc): an empty
/// intersection is E1 and NO selection — the rule does not choose, and the
/// bands are still reported so Adrian can see where the pairs disagreed.
#[test]
fn an_empty_intersection_yields_e1_and_no_selection() {
    // Pair 1's band lives at the 4 KiB floor, pair 2's at 256 KiB.
    let d = grid_with(
        "deciding",
        |c| if c.min == 4 << 10 { 100_000 } else { 1_000_000 },
        |_| 0,
    );
    let r = grid_with(
        "replication",
        |c| {
            if c.min == 256 << 10 {
                100_000
            } else {
                1_000_000
            }
        },
        |_| 0,
    );
    let out = decide_factorial(&d, &r).expect("valid grids");
    assert_eq!(out.selection, None);
    assert!(out.intersection.is_empty());
    assert!(
        out.escalations
            .contains(&Escalation::EmptyAdmissibleIntersection {
                binmap_entry: BINMAP_ENTRY_BYTES
            })
    );
    // The E2 argmin disjunct still applies under E1 (decision
    // step 5, `cost.rs`'s module doc: it checks the pairs' argmins,
    // not the selection).
    assert!(
        out.escalations
            .iter()
            .any(|e| matches!(e, Escalation::FloorEdgeArgmin { pair, .. } if pair == "deciding")),
        "{:?}",
        out.escalations
    );
}

/// NEGATIVE (decision step 4, `cost.rs`'s module doc): a replay that FAILS to
/// select — empty intersection at binmap 98 — is E3, never "not different".
#[test]
fn a_replay_that_fails_to_select_yields_e3() {
    // Deciding pair: only the baseline is ever in band.
    let d = grid_with(
        "deciding",
        |c| {
            if c == Cell::BASELINE {
                1_000_000
            } else {
                1_030_000
            }
        },
        |_| 0,
    );
    // Replication pair: the baseline rides a grain term that pushes
    // it out of band at 98 (1M + 400*98 = 1_039_200 > 1_020_000)
    // while an alternative cell anchors the band at every point.
    let alt = Cell {
        min: 64 << 10,
        level: 1,
    };
    let r = grid_with(
        "replication",
        move |c| {
            if c == Cell::BASELINE || c == alt {
                1_000_000
            } else {
                2_000_000
            }
        },
        |c| if c == Cell::BASELINE { 400 } else { 0 },
    );
    let out = decide_factorial(&d, &r).expect("valid grids");
    assert_eq!(
        out.selection,
        Some(Cell::BASELINE),
        "selected at nominal 49"
    );
    assert!(
        out.escalations.contains(&Escalation::SelectionSensitivity {
            binmap_entry: 98,
            replay_selection: None,
        }),
        "{:?}",
        out.escalations
    );
    let at_98 = out.replays.iter().find(|r| r.binmap_entry == 98);
    assert_eq!(at_98.and_then(|r| r.selection), None);
}

/// NEGATIVE (E2, the argmin disjunct at nominal binmap 49):
/// a 4 KiB argmin on ONE pair escalates even when the selection is
/// interior.
#[test]
fn a_four_kib_argmin_with_an_interior_selection_yields_e2() {
    // Both pairs put the baseline comfortably in band; the deciding
    // pair's MINIMUM sits at (4K, L0), 1.5% under — in band, argmin
    // at the edge, selection still the incumbent.
    let edge = Cell {
        min: 4 << 10,
        level: 0,
    };
    let d = grid_with(
        "deciding",
        move |c| {
            if c == edge {
                985_000
            } else if c == Cell::BASELINE {
                1_000_000
            } else {
                2_000_000
            }
        },
        |_| 0,
    );
    let r = grid_with(
        "replication",
        move |c| {
            if c == edge || c == Cell::BASELINE {
                1_000_000
            } else {
                2_000_000
            }
        },
        |_| 0,
    );
    let out = decide_factorial(&d, &r).expect("valid grids");
    assert_eq!(out.selection, Some(Cell::BASELINE), "interior selection");
    assert!(
        out.escalations
            .iter()
            .any(|e| matches!(e, Escalation::FloorEdgeArgmin { pair, cell }
                if pair == "deciding" && *cell == edge)),
        "{:?}",
        out.escalations
    );
    assert!(
        !out.escalations
            .iter()
            .any(|e| matches!(e, Escalation::FloorEdgeSelected { .. })),
        "the selection is interior: {:?}",
        out.escalations
    );
}

/// Residual preferences of decision step 3 in `cost.rs`'s module doc,
/// exercised without the anchor: baseline out of band,
/// A = {(64K,0), (64K,2), (32K,3)} → largest floor first, then |level-1| with
/// the tie toward the HIGHER level: (64K, L2). E7 fires because the incumbent moved.
#[test]
fn the_preference_order_is_floor_then_level_distance_then_higher_level() {
    let a0 = Cell {
        min: 64 << 10,
        level: 0,
    };
    let a2 = Cell {
        min: 64 << 10,
        level: 2,
    };
    let b3 = Cell {
        min: 32 << 10,
        level: 3,
    };
    let v = move |c: Cell| {
        if c == a0 || c == a2 || c == b3 {
            1_000_000
        } else {
            2_000_000
        }
    };
    let out = decide_factorial(
        &grid_with("deciding", v, |_| 0),
        &grid_with("replication", v, |_| 0),
    )
    .expect("valid grids");
    assert_eq!(out.selection, Some(a2));
    assert!(
        out.escalations
            .contains(&Escalation::IncumbentDisplaced { selected: a2 })
    );
}

/// E6: a winner more than 5% better than the baseline cell on
/// the DECIDING pair trips the fixed-avg tripwire (and E7, always).
#[test]
fn a_baseline_displacement_over_five_percent_yields_e6() {
    let winner = Cell {
        min: 64 << 10,
        level: 1,
    };
    let v = move |c: Cell| {
        if c == winner {
            1_000_000
        } else if c == Cell::BASELINE {
            1_100_000
        } else {
            2_000_000
        }
    };
    let out = decide_factorial(
        &grid_with("deciding", v, |_| 0),
        &grid_with("replication", v, |_| 0),
    )
    .expect("valid grids");
    assert_eq!(out.selection, Some(winner));
    assert!(
        out.escalations.iter().any(
            |e| matches!(e, Escalation::BaselineDisplacement { improvement }
                if (*improvement - 100_000.0 / 1_100_000.0).abs() < 1e-9)
        ),
        "{:?}",
        out.escalations
    );
    assert!(
        out.escalations
            .contains(&Escalation::IncumbentDisplaced { selected: winner })
    );

    // The boundary, exactly: 950_000 vs 1_000_000 is an improvement
    // of exactly 5.0% — E6's "MORE than 5%" is strict, so E6 must
    // NOT fire (E7 still does). A `>=` mutant survived the suite
    // before this arm; the other registered float boundary (the 2%
    // band) was already pinned on the same measure-zero argument.
    let at_boundary = move |c: Cell| {
        if c == winner {
            950_000
        } else if c == Cell::BASELINE {
            1_000_000
        } else {
            2_000_000
        }
    };
    let out = decide_factorial(
        &grid_with("deciding", at_boundary, |_| 0),
        &grid_with("replication", at_boundary, |_| 0),
    )
    .expect("valid grids");
    assert_eq!(out.selection, Some(winner));
    assert!(
        !out.escalations
            .iter()
            .any(|e| matches!(e, Escalation::BaselineDisplacement { .. })),
        "exactly 5% is NOT more than 5%: {:?}",
        out.escalations
    );
}

/// E5: the selected cell quadrupling the baseline cell's range
/// count on EITHER pair escalates, with the pair named.
#[test]
fn a_request_count_blowup_on_either_pair_yields_e5() {
    let winner = Cell {
        min: 64 << 10,
        level: 1,
    };
    let v = move |c: Cell| {
        if c == winner {
            1_000_000
        } else if c == Cell::BASELINE {
            1_100_000
        } else {
            2_000_000
        }
    };
    let mut r = grid_with("replication", v, |_| 0);
    for m in &mut r.cells {
        if m.cell == winner {
            m.coalesced_ranges = 500; // baseline stays at 100 -> 5x
        }
    }
    let out = decide_factorial(&grid_with("deciding", v, |_| 0), &r).expect("valid grids");
    assert!(
        out.escalations.iter().any(
            |e| matches!(e, Escalation::CellRequestCount { pair, factor }
                if pair == "replication" && (*factor - 5.0).abs() < 1e-9)
        ),
        "{:?}",
        out.escalations
    );
}

/// E4: a fat index at the selected cell escalates, pair named.
#[test]
fn a_fat_index_at_the_selected_cell_yields_e4() {
    let mut d = flat("deciding");
    for m in &mut d.cells {
        if m.cell == Cell::BASELINE {
            m.store_manifest_bytes = 1_000_000; // vs 10 MB stored: ~9.1%
        }
    }
    let out = decide_factorial(&d, &flat("replication")).expect("valid grids");
    assert_eq!(out.selection, Some(Cell::BASELINE));
    assert!(
        out.escalations
            .iter()
            .any(|e| matches!(e, Escalation::CellIndexShare { pair, share }
                if pair == "deciding" && *share > 0.05)),
        "{:?}",
        out.escalations
    );
}

/// NEGATIVE (control 4's teeth at selection time): a missing,
/// duplicated, or inexact cell INVALIDATES the run — no decision
/// output exists, not even bands.
#[test]
fn an_incomplete_grid_is_a_run_error_not_a_decision() {
    let mut missing = flat("deciding");
    missing.cells.retain(|m| {
        m.cell
            != Cell {
                min: 16 << 10,
                level: 2,
            }
    });
    assert_eq!(
        decide_factorial(&missing, &flat("replication")),
        Err(FactorialRunError::MissingCell {
            pair: "deciding".to_owned(),
            cell: Cell {
                min: 16 << 10,
                level: 2
            },
        })
    );

    let mut dup = flat("deciding");
    let copy = dup.cells.first().cloned().expect("non-empty");
    dup.cells.push(copy.clone());
    assert_eq!(
        decide_factorial(&dup, &flat("replication")),
        Err(FactorialRunError::DuplicateCell {
            pair: "deciding".to_owned(),
            cell: copy.cell,
        })
    );

    let mut off_grid = flat("deciding");
    off_grid.cells.push(CellMeasure {
        cell: Cell {
            min: 2 << 10, // legal for fastcdc, NOT on the registered grid
            level: 0,
        },
        manifest_exact: true,
        novel_stored_bytes: 1, // would anchor every band if admitted
        novel_manifest_bytes: 0,
        novel_grain_count: 0,
        store_stored_bytes: 10_000_000,
        store_manifest_bytes: 0,
        store_grain_count: 0,
        coalesced_ranges: 100,
    });
    assert_eq!(
        decide_factorial(&off_grid, &flat("replication")),
        Err(FactorialRunError::OffGridCell {
            pair: "deciding".to_owned(),
            cell: Cell {
                min: 2 << 10,
                level: 0
            },
        })
    );

    let mut inexact = flat("replication");
    if let Some(m) = inexact.cells.get_mut(5) {
        m.manifest_exact = false;
    }
    let bad_cell = inexact.cells.get(5).map(|m| m.cell).expect("cell 5");
    assert_eq!(
        decide_factorial(&flat("deciding"), &inexact),
        Err(FactorialRunError::UnmeasuredCell {
            pair: "replication".to_owned(),
            cell: bad_cell,
        })
    );
}

/// The 2% boundary is INCLUSIVE, as in the average-sweep rule: a cell exactly
/// on the cutoff is in the band.
#[test]
fn the_band_boundary_is_inclusive_at_exactly_two_percent() {
    let edge_in = Cell {
        min: 64 << 10,
        level: 1,
    };
    let v = move |c: Cell| {
        if c == Cell::BASELINE {
            1_000_000
        } else if c == edge_in {
            1_020_000
        } else {
            2_000_000
        }
    };
    let out = decide_factorial(
        &grid_with("deciding", v, |_| 0),
        &grid_with("replication", v, |_| 0),
    )
    .expect("valid grids");
    assert!(
        out.intersection.contains(&edge_in),
        "{:?}",
        out.intersection
    );
    assert_eq!(out.selection, Some(Cell::BASELINE), "the anchor still wins");
}
