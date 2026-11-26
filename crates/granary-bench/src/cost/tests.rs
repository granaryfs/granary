// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::cost` — the pre-registered decision rule
//! that chooses the shipped grain tuple.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

fn candidate(avg: usize, novel: u64, grains: u64) -> Candidate {
    Candidate {
        avg,
        eligible: true,
        novel_stored_bytes: novel,
        novel_manifest_bytes: 0,
        novel_grain_count: grains,
        store_stored_bytes: novel * 2,
        store_manifest_bytes: 0,
        store_grain_count: grains * 2,
        coalesced_ranges: grains,
    }
}

#[test]
fn binmap_entry_is_forty_nine_bytes() {
    assert_eq!(BINMAP_ENTRY_BYTES, 33 + 4 + 8 + 4);
}

#[test]
fn index_bytes_are_part_of_the_objective() {
    let c = candidate(8 << 10, 1_000_000, 100);
    assert_eq!(
        c.republish_bytes(BINMAP_ENTRY_BYTES),
        1_000_000 + 100 * BINMAP_ENTRY_BYTES as u64
    );
    assert_eq!(c.republish_bytes(0), 1_000_000);
}

#[test]
fn manifest_bytes_are_part_of_the_objective() {
    let c = Candidate {
        novel_manifest_bytes: 7_000,
        ..candidate(8 << 10, 1_000_000, 100)
    };
    assert_eq!(
        c.republish_bytes(BINMAP_ENTRY_BYTES),
        1_000_000 + 7_000 + 100 * BINMAP_ENTRY_BYTES as u64
    );
    assert_eq!(c.republish_bytes(0), 1_000_000 + 7_000);
}

/// The manifest term is not decoration: at W1-plausible magnitudes it alone
/// flips which grain size wins. A zero passed where the encoder result
/// belongs would change the shipped tuple, silently.
#[test]
fn the_manifest_term_alone_can_decide_the_winner() {
    let cands = vec![
        Candidate {
            novel_manifest_bytes: 200_000,
            ..candidate(8 << 10, 1_000_000, 0)
        },
        Candidate {
            novel_manifest_bytes: 1_000,
            ..candidate(1 << 20, 1_100_000, 0)
        },
    ];
    match choose(&cands, (8 << 10, 2 << 20), 1 << 20) {
        Decision::Chosen { avg, .. } => assert_eq!(avg, 1 << 20),
        Decision::NoEligibleCandidate => panic!("expected a winner"),
    }
}

#[test]
fn the_minimum_wins_when_it_is_not_close() {
    let cands = vec![
        candidate(8 << 10, 900_000, 100),
        candidate(1 << 20, 2_000_000, 10),
    ];
    let d = choose(&cands, (8 << 10, 2 << 20), 1 << 20);
    match d {
        Decision::Chosen { avg, .. } => assert_eq!(avg, 8 << 10),
        Decision::NoEligibleCandidate => panic!("expected a winner"),
    }
}

/// The tie-break is the pre-registered rule, not a preference
/// applied afterwards: 1% apart means the larger grain wins.
#[test]
fn near_ties_go_to_the_larger_grain() {
    let cands = vec![
        candidate(8 << 10, 1_000_000, 0),
        candidate(1 << 20, 1_010_000, 0),
    ];
    let d = choose(&cands, (8 << 10, 2 << 20), 1 << 20);
    match d {
        Decision::Chosen { avg, .. } => assert_eq!(avg, 1 << 20),
        Decision::NoEligibleCandidate => panic!("expected a winner"),
    }
}

/// The registered tolerance is exactly 2%, and the
/// boundary is inclusive. Pinned so a nudge to 1.5% or 2.5% goes red.
#[test]
fn the_tolerance_boundary_is_exactly_two_percent() {
    let inside = vec![
        candidate(8 << 10, 1_000_000, 0),
        candidate(1 << 20, 1_020_000, 0),
    ];
    match choose(&inside, (8 << 10, 2 << 20), 1 << 20) {
        Decision::Chosen { avg, .. } => assert_eq!(avg, 1 << 20),
        Decision::NoEligibleCandidate => panic!("expected a winner"),
    }

    let outside = vec![
        candidate(8 << 10, 1_000_000, 0),
        candidate(1 << 20, 1_020_001, 0),
    ];
    match choose(&outside, (8 << 10, 2 << 20), 1 << 20) {
        Decision::Chosen { avg, .. } => assert_eq!(avg, 8 << 10),
        Decision::NoEligibleCandidate => panic!("expected a winner"),
    }
}

/// The published headline can be a point the
/// tie-break PROMOTED rather than the grid minimum, and nothing in
/// the record said so — `TIE_BREAK_TOLERANCE` appeared nowhere in
/// any result file. A report must not be able to conflate
/// "minimises republish bytes" with "was tie-broken into", so the
/// decision carries the minimum it moved away from and the margin
/// by which the promotion survives.
#[test]
fn the_decision_records_the_minimum_the_tie_break_moved_away_from() {
    let cands = vec![
        candidate(8 << 10, 1_000_000, 0),
        candidate(1 << 20, 1_010_000, 0),
    ];
    let Decision::Chosen {
        avg,
        republish_bytes,
        argmin_avg,
        argmin_republish_bytes,
        headroom_to_cutoff_bytes,
        ..
    } = choose(&cands, (8 << 10, 2 << 20), 1 << 20)
    else {
        panic!("expected a winner");
    };
    assert_eq!(avg, 1 << 20, "the tie-break promotes the coarser point");
    assert_eq!(republish_bytes, 1_010_000);
    assert_eq!(
        argmin_avg,
        8 << 10,
        "8K is the minimum; 1M was tie-broken into, not chosen by the objective"
    );
    assert_eq!(argmin_republish_bytes, 1_000_000);
    // cutoff = 1_000_000 * 1.02 = 1_020_000; the winner is 10_000 under it.
    assert!(
        (headroom_to_cutoff_bytes - 10_000.0).abs() < 1e-6,
        "{headroom_to_cutoff_bytes}"
    );
}

/// The mirror: when the winner IS the minimum the two agree, and the
/// headroom is the whole tie-break band. Without this, an
/// implementation that always reported the winner as its own argmin
/// would look correct on the promoted case alone.
#[test]
fn a_winner_that_is_the_minimum_reports_itself_as_the_argmin() {
    let cands = vec![
        candidate(8 << 10, 900_000, 0),
        candidate(1 << 20, 2_000_000, 0),
    ];
    let Decision::Chosen {
        avg,
        argmin_avg,
        argmin_republish_bytes,
        headroom_to_cutoff_bytes,
        ..
    } = choose(&cands, (8 << 10, 2 << 20), 1 << 20)
    else {
        panic!("expected a winner");
    };
    assert_eq!(avg, 8 << 10);
    assert_eq!(argmin_avg, avg);
    assert_eq!(argmin_republish_bytes, 900_000);
    assert!(
        (headroom_to_cutoff_bytes - 18_000.0).abs() < 1e-6,
        "the full 2% band: {headroom_to_cutoff_bytes}"
    );
}

/// A promotion that sits exactly ON the cutoff has zero headroom —
/// the boundary case the 0.351% W1 margin is a scaled version of.
#[test]
fn the_headroom_is_zero_at_the_tolerance_boundary() {
    let cands = vec![
        candidate(8 << 10, 1_000_000, 0),
        candidate(1 << 20, 1_020_000, 0),
    ];
    let Decision::Chosen {
        avg,
        headroom_to_cutoff_bytes,
        ..
    } = choose(&cands, (8 << 10, 2 << 20), 1 << 20)
    else {
        panic!("expected a winner");
    };
    assert_eq!(avg, 1 << 20);
    assert!(
        headroom_to_cutoff_bytes.abs() < 1e-6,
        "{headroom_to_cutoff_bytes}"
    );
}

#[test]
fn just_outside_the_tolerance_the_minimum_wins() {
    let cands = vec![
        candidate(8 << 10, 1_000_000, 0),
        candidate(1 << 20, 1_030_000, 0),
    ];
    let d = choose(&cands, (8 << 10, 2 << 20), 1 << 20);
    match d {
        Decision::Chosen { avg, .. } => assert_eq!(avg, 8 << 10),
        Decision::NoEligibleCandidate => panic!("expected a winner"),
    }
}

/// Why a chunker that ignores the swept
/// tuple is not merely untidy but arithmetically fatal, stated as
/// arithmetic rather than as a worry: if `cdc-128K` through
/// `cdc-2M` all secretly cut at 128 KiB, those five points report
/// the SAME objective, all five sit at the minimum, and the
/// tie-break — working exactly as pre-registered — publishes the
/// COARSEST of them. The record would carry `avg: 2097152`, a
/// genuine `ControlsPassed` token and 61/61 passing controls.
/// `sweep::check_cdc_grid_fidelity` is what stops that record
/// existing.
#[test]
fn a_flattened_coarse_half_of_the_grid_publishes_the_coarsest_point() {
    let mut cands = vec![
        candidate(8 << 10, 2_000_000, 0),
        candidate(16 << 10, 1_800_000, 0),
        candidate(32 << 10, 1_600_000, 0),
        candidate(64 << 10, 1_400_000, 0),
    ];
    // The saboteur's signature: five identical measurements under
    // five different labels.
    for avg in [128 << 10, 256 << 10, 512 << 10, 1 << 20, 2 << 20] {
        cands.push(candidate(avg, 1_000_000, 0));
    }
    let Decision::Chosen {
        avg, argmin_avg, ..
    } = choose(&cands, (8 << 10, 2 << 20), 1 << 20)
    else {
        panic!("expected a winner");
    };
    assert_eq!(avg, 2 << 20, "the tie-break takes the coarsest of the tie");
    assert_eq!(
        argmin_avg,
        128 << 10,
        "and the minimum it was promoted from is the finest of the flat run"
    );
}

#[test]
fn ineligible_points_are_never_chosen() {
    let mut cheap = candidate(8 << 10, 1, 0);
    cheap.eligible = false;
    let cands = vec![cheap, candidate(1 << 20, 1_000_000, 0)];
    let d = choose(&cands, (8 << 10, 2 << 20), 1 << 20);
    match d {
        Decision::Chosen { avg, .. } => assert_eq!(avg, 1 << 20),
        Decision::NoEligibleCandidate => panic!("expected a winner"),
    }
}

#[test]
fn all_ineligible_yields_no_candidate() {
    let mut c = candidate(1 << 20, 1, 0);
    c.eligible = false;
    assert_eq!(
        choose(&[c], (8 << 10, 2 << 20), 1 << 20),
        Decision::NoEligibleCandidate
    );
}

#[test]
fn a_grid_edge_winner_escalates() {
    let cands = vec![
        candidate(8 << 10, 1_000_000, 0),
        candidate(1 << 20, 9_000_000, 0),
    ];
    let Decision::Chosen { escalations, .. } = choose(&cands, (8 << 10, 2 << 20), 1 << 20) else {
        panic!("expected a winner");
    };
    assert!(escalations.contains(&Escalation::GridEdge { avg: 8 << 10 }));
}

#[test]
fn a_sensitivity_dependent_winner_escalates() {
    // 8K wins on raw bytes; 1M wins once index bytes are counted.
    let cands = vec![
        candidate(8 << 10, 1_000_000, 100_000),
        candidate(1 << 20, 1_200_000, 100),
    ];
    let Decision::Chosen { escalations, .. } = choose(&cands, (8 << 10, 2 << 20), 1 << 20) else {
        panic!("expected a winner");
    };
    assert!(
        escalations
            .iter()
            .any(|e| matches!(e, Escalation::SensitivityDependent { .. })),
        "{escalations:?}"
    );
}

#[test]
fn a_request_count_blowup_escalates() {
    let mut small = candidate(8 << 10, 1_000_000, 10);
    small.coalesced_ranges = 1000;
    let mut reference = candidate(1 << 20, 9_000_000, 10);
    reference.coalesced_ranges = 100;
    let Decision::Chosen { escalations, .. } =
        choose(&[small, reference], (8 << 10, 2 << 20), 1 << 20)
    else {
        panic!("expected a winner");
    };
    assert!(
        escalations
            .iter()
            .any(|e| matches!(e, Escalation::RequestCount { .. })),
        "{escalations:?}"
    );
}

#[test]
fn a_dissenting_replication_pair_escalates_without_voting() {
    let deciding = vec![
        candidate(8 << 10, 1_000_000, 0),
        candidate(1 << 20, 9_000_000, 0),
    ];
    // The replication pair would pick 1 MiB.
    let replication = vec![
        candidate(8 << 10, 9_000_000, 0),
        candidate(1 << 20, 1_000_000, 0),
    ];
    let d = decide_with_replication(
        &deciding,
        &[("w1-older-pair".to_owned(), replication)],
        (8 << 10, 2 << 20),
        1 << 20,
    );
    let Decision::Chosen {
        avg, escalations, ..
    } = d
    else {
        panic!("expected a winner");
    };
    assert_eq!(avg, 8 << 10, "the deciding pair decides, always");
    assert!(
        escalations.contains(&Escalation::ReplicationDisagreement {
            pair: "w1-older-pair".to_owned(),
            alt_avg: 1 << 20,
        }),
        "{escalations:?}"
    );
}

/// A replication pair that could not be measured must SAY so — a
/// pair that produced nothing is not a pair that agreed.
#[test]
fn an_unmeasurable_replication_pair_escalates() {
    let deciding = vec![candidate(1 << 20, 1_000_000, 0)];
    let mut dead = candidate(1 << 20, 1, 0);
    dead.eligible = false;
    let d = decide_with_replication(
        &deciding,
        &[("w1-older-pair".to_owned(), vec![dead])],
        (8 << 10, 2 << 20),
        1 << 20,
    );
    let Decision::Chosen { escalations, .. } = d else {
        panic!("expected a winner");
    };
    assert!(
        escalations.contains(&Escalation::ReplicationUnmeasurable {
            pair: "w1-older-pair".to_owned(),
        }),
        "{escalations:?}"
    );
}

#[test]
fn an_agreeing_replication_pair_is_silent() {
    let cands = vec![
        candidate(8 << 10, 1_000_000, 0),
        candidate(1 << 20, 9_000_000, 0),
    ];
    let d = decide_with_replication(
        &cands,
        &[("w1-older-pair".to_owned(), cands.clone())],
        (8 << 10, 2 << 20),
        1 << 20,
    );
    let Decision::Chosen { escalations, .. } = d else {
        panic!("expected a winner");
    };
    assert!(
        !escalations
            .iter()
            .any(|e| matches!(e, Escalation::ReplicationDisagreement { .. })),
        "{escalations:?}"
    );
}

/// NEGATIVE: an unperformed check must not read as a passed one.
#[test]
fn an_unusable_request_count_reference_escalates() {
    // No 1 MiB candidate at all.
    let only_fine = vec![candidate(8 << 10, 1_000_000, 10)];
    let Decision::Chosen { escalations, .. } = choose(&only_fine, (8 << 10, 2 << 20), 1 << 20)
    else {
        panic!("expected a winner");
    };
    assert!(
        escalations
            .iter()
            .any(|e| matches!(e, Escalation::RequestCountUncheckable { .. })),
        "{escalations:?}"
    );

    // Present but ineligible.
    let mut dead_ref = candidate(1 << 20, 9_000_000, 10);
    dead_ref.eligible = false;
    let Decision::Chosen { escalations, .. } = choose(
        &[candidate(8 << 10, 1_000_000, 10), dead_ref],
        (8 << 10, 2 << 20),
        1 << 20,
    ) else {
        panic!("expected a winner");
    };
    assert!(
        escalations
            .iter()
            .any(|e| matches!(e, Escalation::RequestCountUncheckable { .. })),
        "{escalations:?}"
    );
}

#[test]
fn a_fat_index_escalates() {
    let mut c = candidate(8 << 10, 1_000_000, 0);
    c.store_stored_bytes = 1_000_000;
    c.store_manifest_bytes = 100_000;
    let Decision::Chosen { escalations, .. } = choose(&[c], (8 << 10, 2 << 20), 1 << 20) else {
        panic!("expected a winner");
    };
    assert!(
        escalations
            .iter()
            .any(|e| matches!(e, Escalation::IndexShare { .. })),
        "{escalations:?}"
    );
}

mod factorial_tests;
