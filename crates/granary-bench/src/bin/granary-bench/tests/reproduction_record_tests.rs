// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `reproduction_json` — the durable-disclosure rendering
//! that turns an in-process `PairReproduction` into a reproduction record's
//! evidence.
//!
//! Out-of-line, because a module's second conforming test body becomes
//! a leaf under `tests`, declared by `granary-bench/tests.rs`'s `mod
//! reproduction_record_tests;` rather than a second sibling
//! declaration in the parent (`granary-bench.rs`). Nesting under
//! `tests` makes `super` already mean `tests`, so the one named path
//! this file had — `super::tests::dummy_metrics`, reaching past a
//! sibling `tests` module — shortens to `super::dummy_metrics`. The
//! file also opens `use super::*;`, which is a `super::` path like any
//! other and is rewritten to `use super::super::*;` so it keeps
//! glob-importing the binary's root module rather than `tests`.

use super::super::*;
use super::dummy_metrics;
use granary_bench::reproduce::SHARED_ARMS;
use granary_bench::sweep::CdcRelevant;
use std::path::PathBuf;

/// THE DURABLE-DISCLOSURE TESTS. `reproduction_json` is the layer
/// that turns the in-process `PairReproduction` into the record's
/// evidence, and it had NO coverage at all: deleting the whole
/// `cdc_population_moved` rendering left the full 217-test suite
/// green. That matters precisely here —
/// against the only committed baseline the population rule fires on
/// every arm of every pair, so every record `factorial` mints today
/// depends on this rendering to disclose that `cdc_relevant` was
/// skipped. Unrendered, the record reads `passed: true,
/// fields_compared: 24` with nothing saying a subtree went
/// uncompared — silent absorption one layer above the one the
/// module doc forbids.
///
/// On `passed`: it cannot be independently falsified through this
/// API, and that is the sealing discipline succeeding, not a gap.
/// `check_reproduction` is the sole mint, it pushes exactly one arm
/// per `SHARED_ARMS` entry, and the `arm` branch always increments
/// `fields_compared` — so a returned report is
/// `all_shared_arms_compared()` by construction and no input can
/// make the derivation disagree with a hardcoded `true`. The
/// derivation stays because it is what keeps that true if the mint
/// ever changes.
fn arm(label: &str, floor: u64, files: u64) -> ArmMetrics {
    let mut m = dummy_metrics(label, ManifestStatus::Exact);
    m.cdc_relevant = CdcRelevant {
        min_grain_bytes: floor,
        files,
        bytes: files * 1000,
        raw_chunks: 7,
        unique_chunks: 5,
        realized_mean_span: 1.5,
        realized_mean_grain: 2.5,
    };
    m
}

fn all_four(floor: u64, files: u64) -> Vec<ArmMetrics> {
    SHARED_ARMS
        .iter()
        .map(|(m4, _)| arm(m4, floor, files))
        .collect()
}

/// Write a committed-shaped baseline from `arms`, relabelled to the
/// average-sweep names and with `cdc_relevant.min_grain_bytes` forced to
/// `committed_floor`.
fn baseline(dir: &Path, arms: &[ArmMetrics], committed_floor: u64) -> PathBuf {
    let rendered: Vec<Json> = SHARED_ARMS
        .iter()
        .filter_map(|(m4, m3)| {
            arms.iter().find(|m| m.arm == *m4).map(|m| {
                let mut j = arm_json(m);
                if let Json::Obj(fields) = &mut j {
                    for (k, v) in fields.iter_mut() {
                        if k == "arm" {
                            *v = Json::s(*m3);
                        }
                        if k == "cdc_relevant"
                            && let Json::Obj(sub) = v
                        {
                            for (sk, sv) in sub.iter_mut() {
                                if sk == "min_grain_bytes" {
                                    *sv = Json::UInt(committed_floor);
                                }
                            }
                        }
                    }
                }
                j
            })
        })
        .collect();
    let record = Json::Obj(vec![(
        "pairs".to_owned(),
        Json::Arr(vec![Json::Obj(vec![
            ("label".to_owned(), Json::s("p")),
            ("arms".to_owned(), Json::Arr(rendered)),
        ])]),
    )]);
    let path = dir.join("baseline.json");
    std::fs::write(&path, record.to_pretty()).expect("write baseline");
    path
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "granary-bench-reprojson-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

#[test]
fn a_moved_population_is_disclosed_in_the_record() {
    let dir = scratch("moved");
    let shipped = granary_core::thresh::MIN_GRAIN as u64;
    // Fresh at the shipped floor with MORE files than the committed
    // higher-floor baseline — a legitimate re-thresholding.
    let fresh = all_four(shipped, 900);
    let path = baseline(&dir, &all_four(shipped, 197), 524_288);
    let report = reproduce::check_reproduction(&path, "p", &fresh).expect("valid");
    let json = reproduction_json(&report);

    assert_eq!(json.get("passed"), Some(&Json::Bool(true)));
    let arms = json.get("arms").and_then(Json::items).expect("arms");
    assert_eq!(arms.len(), 4);
    for a in arms {
        let moved = a
            .get("cdc_population_moved")
            .unwrap_or_else(|| panic!("the record must DISCLOSE the skipped subtree"));
        assert_eq!(
            moved.get("committed_min_grain_bytes"),
            Some(&Json::UInt(524_288))
        );
        assert_eq!(
            moved.get("fresh_min_grain_bytes"),
            Some(&Json::UInt(shipped))
        );
    }
    // The correspondence is rendered too, so a reader can see WHICH
    // committed arm each fresh arm was checked against.
    assert_eq!(
        arms.first().and_then(|a| a.get("committed_as")),
        Some(&Json::s("cdc-256K"))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unmoved_population_renders_no_disclosure() {
    let dir = scratch("unmoved");
    let shipped = granary_core::thresh::MIN_GRAIN as u64;
    let fresh = all_four(shipped, 197);
    let path = baseline(&dir, &fresh, shipped);
    let committed_fields = {
        let text = std::fs::read_to_string(&path).expect("read");
        let rec = Json::parse(&text).expect("parse");
        let first = rec
            .get("pairs")
            .and_then(Json::items)
            .and_then(|p| p.first())
            .and_then(|p| p.get("arms"))
            .and_then(Json::items)
            .and_then(|a| a.first())
            .cloned()
            .expect("first committed arm");
        match first {
            Json::Obj(fields) => fields.len() as u64,
            other => panic!("arm is an object, got {other:?}"),
        }
    };
    let report = reproduce::check_reproduction(&path, "p", &fresh).expect("valid");
    let json = reproduction_json(&report);
    let arms = json.get("arms").and_then(Json::items).expect("arms");
    for a in arms {
        assert!(
            a.get("cdc_population_moved").is_none(),
            "no move happened — the field must be ABSENT, so its \
             presence always means the door opened"
        );
        // DERIVED, not hardcoded: this helper's baseline keeps the
        // additive factorial fields (`configured_min`,
        // `configured_normalization`) that the real committed record
        // predates, so the count here is legitimately two higher than
        // `reproduce.rs`'s 24. Deriving it asserts the real property —
        // every committed field was accounted for — without pinning a
        // number that depends on the fixture.
        assert_eq!(
            a.get("fields_compared"),
            Some(&Json::UInt(committed_fields))
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
