// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The committed positive control at production scale, and the proof
//! that its token is what unlocks a record.
//!
//! The sabotage negative test lives INSIDE `control.rs`, because the
//! thing worth asserting is the token predicate itself and that is
//! crate-private by design.

#![expect(
    clippy::disallowed_methods,
    reason = "test scratch-dir naming; disallowed_methods has no allow-in-tests knob"
)]

use std::fs;

use granary_bench::chunk::{Arm, all_arms};
use granary_bench::control::{self, ControlOutcome};
use granary_bench::json::Json;
use granary_bench::report::{REQUIRED_METADATA, RunMetadata, write_record};
use granary_bench::tuple::{GrainTuple, SWEEP_AVGS};

/// Structural: the production suite covers BOTH contestants at EVERY
/// grid point plus the two global reference arms — and it is the SAME
/// `chunk::all_arms()` the sweep runs, so the two cannot drift apart.
#[test]
fn the_production_suite_covers_every_arm() {
    let labels: Vec<String> = all_arms().iter().map(|a| a.label()).collect();
    for avg in SWEEP_AVGS {
        let t = GrainTuple::from_avg(avg).expect("grid point");
        assert!(labels.contains(&Arm::Cdc(t).label()), "{avg} cdc missing");
        assert!(
            labels.contains(&Arm::Fixed(avg).label()),
            "{avg} fixed missing"
        );
    }
    assert!(labels.contains(&Arm::Fixed(4 << 20).label()));
    assert!(labels.contains(&Arm::WholeFile.label()));
}

/// The whole gate, end to end: the FULL production suite passes, and
/// the token it yields is what lets a record be written. There is no
/// other way to obtain one — `run_diagnostic` returns outcomes only.
#[test]
fn production_controls_pass_and_gate_a_record() {
    let (outcomes, token) = control::run_production();
    let failed: Vec<&ControlOutcome> = outcomes.iter().filter(|o| !o.passed).collect();
    assert!(failed.is_empty(), "{failed:#?}");
    let token = token.expect("production controls must yield a token");
    assert_eq!(outcomes.len(), all_arms().len() * 3 + 1);

    let dir = std::env::temp_dir().join(format!(
        "granary-bench-control-record-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");
    let path = dir.join("record.json");
    // The kind must be a REGISTERED one: write_record derives the required
    // control suite from it and refuses unknown kinds outright.
    let meta = RunMetadata::new(
        &REQUIRED_METADATA
            .iter()
            .map(|k| {
                let v = if *k == "kind" {
                    "m3-grain-sweep"
                } else {
                    "gate-test"
                };
                ((*k).to_owned(), v.to_owned())
            })
            .collect::<Vec<_>>(),
    )
    .expect("metadata");
    // The token's outcomes are checked BEFORE the write, because
    // write_record consumes it: one control run gates exactly one record.
    assert_eq!(token.outcomes().len(), outcomes.len());
    for o in token.outcomes() {
        assert!(o.passed, "a token must only carry passing outcomes: {o:#?}");
    }
    // NON-VACUITY: an empty control buffer once minted a valid token
    // from vacuous outcomes (fixed in `control.rs`'s `total > 0`
    // conjunct); a test asserting
    // only `token.is_some()`, or even that every outcome `passed`, would
    // not have caught it — `passed` alone is trivially true of a control
    // that measured zero bytes. Assert the outcomes actually measured
    // something, with exact values a vacuous run could not produce.
    //
    // The bound below is a LITERAL (`4_194_304`), not
    // `control::CONTROL_SMALL_LEN`. Comparing against the constant that
    // parameterises the very run under test is self-referential: if
    // `CONTROL_SMALL_LEN` itself ever regressed to 0 (reproduced by
    // hand: with the `total > 0` / `small_len > 0` guards
    // removed AND `CONTROL_SMALL_LEN` set to 0, `disjoint`'s `novel_bytes`
    // becomes 0 too, and `0 == CONTROL_SMALL_LEN` (also 0) still holds —
    // this exact test still passed under that reproduction). A literal
    // cannot move with the bug it is meant to catch.
    let disjoint: Vec<&ControlOutcome> = token
        .outcomes()
        .iter()
        .filter(|o| o.control == "disjoint")
        .collect();
    assert!(!disjoint.is_empty(), "{:#?}", token.outcomes());
    for o in &disjoint {
        // `disjoint`'s pass condition is `nb == total`, so this also
        // pins the measured buffer size directly, not merely "> 0".
        assert_eq!(
            o.novel_bytes, 4_194_304,
            "a disjoint control that measured nothing is not evidence: {o:#?}"
        );
    }
    // The `control-configuration` row's `novel_bytes` is not a novelty
    // measurement at all (`control.rs` zeroes it). The assertion below
    // requires at least one novel grain per arm when resyncing around
    // the 1-byte prepend.
    let prepend: Vec<&ControlOutcome> = token
        .outcomes()
        .iter()
        .filter(|o| o.control == "prepend-1-byte")
        .collect();
    assert!(!prepend.is_empty(), "{:#?}", token.outcomes());
    for o in &prepend {
        assert!(
            o.novel_grains >= 1,
            "a prepend control that measured no novel grains is not evidence: {o:#?}"
        );
    }
    write_record(
        &path,
        &meta,
        vec![("arms".to_owned(), Json::Arr(Vec::new()))],
        token,
    )
    .expect("write");
    let text = fs::read_to_string(&path).expect("read back");
    assert!(text.contains("\"controls\""), "{text}");
    assert!(text.contains("prepend-1-byte"), "{text}");
    fs::remove_dir_all(&dir).expect("cleanup");
}

/// A subset run is observable, but it can never gate anything: the
/// diagnostic entry point has no token in its return type at all.
#[test]
fn a_diagnostic_run_reports_outcomes_and_cannot_gate() {
    let arms = vec![Arm::Cdc(
        GrainTuple::from_avg(64 << 10).expect("grid point"),
    )];
    let outcomes = control::run_diagnostic(
        control::CONTROL_SMALL_LEN,
        control::CONTROL_PREPEND_LEN,
        &arms,
        Arm::cut_into,
    );
    assert!(outcomes.iter().all(|o| o.passed), "{outcomes:#?}");
}

/// The cross-suite gating guarantee had ZERO committed coverage:
/// mutating the kind→suite table to map the factorial kind to
/// `AverageSweep` left the
/// whole suite green while `write_record` wrote a factorial record gated
/// by an average-sweep token. This pins BOTH refusals with real tokens.
/// Kill-coverage of the table's other row (m3-grain-sweep) needs no new
/// test: `production_controls_pass_and_gate_a_record` writes with that
/// kind, so mutating its mapping turns that test red.
#[test]
fn write_record_refuses_cross_suite_tokens_and_unknown_kinds() {
    let dir =
        std::env::temp_dir().join(format!("granary-bench-cross-suite-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");
    let path = dir.join("refused.json");
    let meta_with_kind = |kind: &str| {
        RunMetadata::new(
            &REQUIRED_METADATA
                .iter()
                .map(|k| {
                    let v = if *k == "kind" {
                        kind
                    } else {
                        "cross-suite-test"
                    };
                    ((*k).to_owned(), v.to_owned())
                })
                .collect::<Vec<_>>(),
        )
        .expect("metadata")
    };

    // An average-sweep token must not gate a factorial record…
    let (_, token) = control::run_production();
    let token = token.expect("production controls must pass");
    let err = write_record(
        &path,
        &meta_with_kind("m4-floor-normalization-factorial"),
        vec![("pairs".to_owned(), Json::Arr(Vec::new()))],
        token,
    )
    .expect_err("a factorial record gated by an average-sweep token must refuse");
    assert!(err.to_string().contains("requires"), "{err}");
    assert!(!path.exists(), "the refusal must precede the write");

    // …and an unregistered kind has no gate at all.
    let (_, token) = control::run_production();
    let token = token.expect("production controls must pass");
    let err = write_record(
        &path,
        &meta_with_kind("unregistered-kind"),
        vec![("pairs".to_owned(), Json::Arr(Vec::new()))],
        token,
    )
    .expect_err("an unknown kind must refuse outright");
    assert!(err.to_string().contains("unregistered-kind"), "{err}");
    assert!(!path.exists(), "the refusal must precede the write");
    fs::remove_dir_all(&dir).expect("cleanup");
}
