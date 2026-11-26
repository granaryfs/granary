// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::reproduce` using constructed baselines.

use super::*;
use crate::sweep::{CdcRelevant, ManifestStatus};
use granary_core::thresh::MIN_GRAIN;
use std::path::PathBuf;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "granary-bench-reproduce-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// A fresh arm whose rendering is fully populated.
fn fresh_arm(label: &str, novel: u64) -> ArmMetrics {
    ArmMetrics {
        arm: label.to_owned(),
        kind: if label.starts_with("cdc") {
            "cdc"
        } else {
            "fixed"
        },
        configured_avg: 262_144,
        configured_min: Some(131_072),
        configured_normalization: Some(1),
        max_policy: None,
        newer_bytes: 1_000,
        novel_raw_bytes: novel,
        novel_stored_bytes: novel,
        novel_grain_count: 7,
        novel_manifest_bytes: 11,
        store_stored_bytes: 13,
        store_grain_count: 17,
        store_manifest_bytes: 19,
        coalesced_ranges: 23,
        realized_mean_grain: 4301.5,
        realized_mean_span: 8970.25,
        realized_median_grain: 4301,
        manifest_status: ManifestStatus::Exact,
        novel_by_class: vec![("native-binary", novel)],
        cdc_relevant: CdcRelevant {
            min_grain_bytes: MIN_GRAIN as u64,
            files: 197,
            bytes: 1_339_620_535,
            raw_chunks: 924,
            unique_chunks: 900,
            realized_mean_span: 1_449_805.8,
            realized_mean_grain: 1_400_000.0,
        },
    }
}

/// A committed-shaped baseline whose four arms are the RENDERINGS of the
/// fresh arms under their average-sweep labels — a byte-identical
/// reproduction by construction.
fn baseline_for(fresh: &[ArmMetrics], dir: &std::path::Path) -> PathBuf {
    let arms: Vec<Json> = SHARED_ARMS
        .iter()
        .filter_map(|(m4, m3)| {
            fresh.iter().find(|m| m.arm == *m4).map(|m| {
                let mut rendered = arm_json(m);
                if let Json::Obj(fields) = &mut rendered {
                    for (k, v) in fields.iter_mut() {
                        if k == "arm" {
                            *v = Json::s(*m3);
                        }
                    }
                    // The committed records predate the additive factorial
                    // fields; drop them to mirror the real baseline.
                    fields
                        .retain(|(k, _)| k != "configured_min" && k != "configured_normalization");
                }
                rendered
            })
        })
        .collect();
    let record = Json::Obj(vec![(
        "pairs".to_owned(),
        Json::Arr(vec![Json::Obj(vec![
            ("label".to_owned(), Json::s("1.96.0->1.97.0")),
            ("arms".to_owned(), Json::Arr(arms)),
        ])]),
    )]);
    let path = dir.join("baseline.json");
    std::fs::write(&path, record.to_pretty()).expect("write baseline");
    path
}

fn all_fresh() -> Vec<ArmMetrics> {
    vec![
        fresh_arm("cdc-min128K-nc1", 402_231_140),
        fresh_arm("fixed-256K", 500_000_000),
        fresh_arm("fixed-4M", 600_000_000),
        fresh_arm("whole-file", 700_000_000),
    ]
}

/// The happy path: a byte-identical reproduction passes, all four
/// arms matched through the correspondence, and the field count
/// proves the comparison was not vacuous.
#[test]
fn a_byte_identical_reproduction_passes_through_the_correspondence() {
    let dir = scratch("happy");
    let fresh = all_fresh();
    let baseline = baseline_for(&fresh, &dir);
    let report = check_reproduction(&baseline, "1.96.0->1.97.0", &fresh).expect("reproduces");
    assert_eq!(report.arms.len(), 4);
    for arm in &report.arms {
        // EVERY committed field, exactly — `> 15` left 8 fields of
        // slack, so a mutant adding a second named exemption (the
        // hide-drift shape, using the `arm` branch as its template)
        // survived the suite.
        assert_eq!(
            arm.fields_compared(),
            24,
            "{} vs {}: every committed field must be compared",
            arm.m4_label(),
            arm.committed_label()
        );
        // Equal floors: the population door never opened.
        assert_eq!(arm.population_moved(), None);
    }
    assert_eq!(
        report
            .arms
            .first()
            .map(|a| (a.m4_label(), a.committed_label())),
        Some(("cdc-min128K-nc1", "cdc-256K"))
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// NEGATIVE, exhaustively per field: EVERY committed field must be
/// able to invalidate the run on its own. The count assertion in the
/// happy test cannot see an exemption that uses the `arm` branch as
/// its template (that branch INCREMENTS `compared`, so counts stay
/// perfect) — only drifting each field in turn kills that whole
/// mutant class.
#[test]
fn every_committed_field_can_invalidate_on_its_own() {
    fn swap_field(v: &mut Json, field: &str, new_value: &Json) {
        if let Json::Obj(entries) = v {
            for (k, val) in entries.iter_mut() {
                if k == "pairs" || k == "arms" {
                    if let Json::Arr(items) = val
                        && let Some(first) = items.first_mut()
                    {
                        swap_field(first, field, new_value);
                    }
                } else if k == field {
                    *val = new_value.clone();
                }
            }
        }
    }
    let dir = scratch("per-field-drift");
    let fresh = all_fresh();
    let baseline = baseline_for(&fresh, &dir);
    let text = std::fs::read_to_string(&baseline).expect("read baseline");
    let record = Json::parse(&text).expect("parse baseline");
    let first_arm = record
        .get("pairs")
        .and_then(Json::items)
        .and_then(|p| p.first())
        .and_then(|p| p.get("arms"))
        .and_then(Json::items)
        .and_then(|a| a.first())
        .cloned()
        .expect("first committed arm");
    let Json::Obj(fields) = &first_arm else {
        panic!("arm is an object");
    };
    let mut drifted_fields = 0usize;
    for (name, value) in fields {
        // Perturb one comparable leaf; skip `arm` (the correspondence
        // key) and non-leaf values (nested objects drift via their
        // own leaves when the rendering changes).
        let perturbed = match value {
            Json::UInt(v) => Json::UInt(v + 1),
            Json::Num(v) => Json::Num(v + 1.0),
            Json::Bool(v) => Json::Bool(!v),
            Json::Str(v) if name != "arm" => Json::s(format!("{v}-drift")),
            _ => continue,
        };
        let mut mutated = record.clone();
        // Swap the one field in the first arm of the first pair.
        swap_field(&mut mutated, name, &perturbed);
        let mutated_path = dir.join("mutated.json");
        std::fs::write(&mutated_path, mutated.to_pretty()).expect("write");
        let err = check_reproduction(&mutated_path, "1.96.0->1.97.0", &fresh)
            .expect_err(&format!("drift on `{name}` must invalidate"));
        match err {
            ReproError::Mismatch { field, .. } => {
                assert_eq!(field, *name, "the mismatch must name the field");
            }
            other => panic!("drift on `{name}`: expected Mismatch, got {other:?}"),
        }
        drifted_fields += 1;
    }
    assert!(
        drifted_fields >= 15,
        "the per-field sweep must cover the committed leaves, got {drifted_fields}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE POPULATION-MOVE SCENARIO: the committed
/// baseline's `cdc_relevant` was minted under the then-shipped
/// 512 KiB `MIN_GRAIN`; the format event moved the constant to
/// 128 KiB, so the two subtrees describe DIFFERENT POPULATIONS by
/// construction and no field of them is comparable. A baseline
/// whose only divergence is a moved `cdc_relevant` population must
/// PASS — with the move recorded in the report — because comparing
/// across populations measures the constant's move, not
/// measurement drift. Every OTHER field stays strict.
#[test]
fn a_moved_cdc_population_reproduces_with_the_move_recorded() {
    let dir = scratch("moved-floor");
    let fresh = all_fresh();
    let baseline = baseline_for(&fresh, &dir);
    let text = std::fs::read_to_string(&baseline).expect("read baseline");
    let mut record = Json::parse(&text).expect("parse baseline");
    // Rewrite EVERY committed arm's cdc_relevant to the old-floor
    // population: different floor AND different derived figures —
    // none of the subtree may be compared once the floor moved.
    let old_floor = Json::Obj(vec![
        ("min_grain_bytes".to_owned(), Json::UInt(524_288)),
        ("files".to_owned(), Json::UInt(197)),
        ("bytes".to_owned(), Json::UInt(1_339_620_535)),
        ("raw_chunks".to_owned(), Json::UInt(3_223)),
        ("unique_chunks".to_owned(), Json::UInt(3_100)),
        ("realized_mean_span".to_owned(), Json::Num(415_643.976_109)),
        ("realized_mean_grain".to_owned(), Json::Num(432_135.5)),
    ]);
    if let Json::Obj(top) = &mut record {
        for (k, v) in top.iter_mut() {
            if k == "pairs"
                && let Json::Arr(pairs) = v
            {
                for pair in pairs {
                    if let Json::Obj(pf) = pair {
                        for (pk, pv) in pf.iter_mut() {
                            if pk == "arms"
                                && let Json::Arr(arms) = pv
                            {
                                for arm in arms {
                                    if let Json::Obj(af) = arm {
                                        for (ak, av) in af.iter_mut() {
                                            if ak == "cdc_relevant" {
                                                *av = old_floor.clone();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let moved_path = dir.join("moved.json");
    std::fs::write(&moved_path, record.to_pretty()).expect("write");
    let report = check_reproduction(&moved_path, "1.96.0->1.97.0", &fresh)
        .expect("a moved population is not drift — the run must be VALID");
    assert!(report.all_shared_arms_compared());
    for arm in report.arms() {
        assert_eq!(
            arm.population_moved(),
            Some((524_288, MIN_GRAIN as u64)),
            "{}: the move must be recorded, not silently absorbed",
            arm.m4_label()
        );
        // Every committed field still accounted for: 22 strict +
        // the floor-checked cdc_relevant + `arm` through the map.
        assert_eq!(arm.fields_compared(), 24);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// NEGATIVE pair to the above: the moved-population door opens ONLY
/// toward the SHIPPED constant. A fresh rendering whose floor is
/// neither the committed one nor the shipped one is emission drift
/// and must invalidate.
///
/// The predicate is "committed ≠ fresh AND fresh == shipped", which
/// spans a FAMILY of format events, not one: a second move
/// (128K → 64K) against this same 512K baseline would open the door
/// again, and so would a baseline older than both. That is
/// deliberate — what pins the run is that the fresh floor is always
/// the shipped constant, so the emission itself can never drift
/// unnoticed.
#[test]
fn a_fresh_floor_that_is_not_the_shipped_constant_invalidates() {
    let dir = scratch("floor-drift");
    let baseline = baseline_for(&all_fresh(), &dir);
    let mut fresh = all_fresh();
    for m in &mut fresh {
        m.cdc_relevant.min_grain_bytes = (MIN_GRAIN as u64) + 1;
    }
    let err = check_reproduction(&baseline, "1.96.0->1.97.0", &fresh)
        .expect_err("a non-shipped fresh floor is drift");
    match err {
        ReproError::CdcFloorNotShipped {
            arm,
            fresh,
            shipped,
            ..
        } => {
            assert_eq!(arm, "cdc-min128K-nc1");
            assert_eq!(fresh, (MIN_GRAIN as u64) + 1);
            assert_eq!(shipped, MIN_GRAIN as u64);
        }
        other => panic!("expected CdcFloorNotShipped, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// NEGATIVE: the open door is not a blank cheque. The populations
/// are NESTED — a lower floor admits strictly more files — so a
/// fresh subtree claiming FEWER files than the higher-floor
/// baseline cannot be the same measurement re-thresholded, and the
/// run is invalid. Without this the rule accepted any subtree at
/// all (an all-zero population included), demonstrated by
/// execution.
#[test]
fn a_moved_population_that_shrank_is_not_a_re_thresholding() {
    let dir = scratch("moved-shrank");
    let fresh = all_fresh();
    let baseline = baseline_for(&fresh, &dir);
    let text = std::fs::read_to_string(&baseline).expect("read baseline");
    let mut record = Json::parse(&text).expect("parse baseline");
    // Committed at the OLD, HIGHER floor with MORE files than the
    // fresh arms report — impossible under a floor that dropped.
    let impossible = Json::Obj(vec![
        ("min_grain_bytes".to_owned(), Json::UInt(524_288)),
        ("files".to_owned(), Json::UInt(9_999)),
        ("bytes".to_owned(), Json::UInt(1)),
        ("raw_chunks".to_owned(), Json::UInt(1)),
        ("unique_chunks".to_owned(), Json::UInt(1)),
        ("realized_mean_span".to_owned(), Json::Num(1.0)),
        ("realized_mean_grain".to_owned(), Json::Num(1.0)),
    ]);
    if let Json::Obj(top) = &mut record {
        for (k, v) in top.iter_mut() {
            if k == "pairs"
                && let Json::Arr(pairs) = v
            {
                for pair in pairs {
                    if let Json::Obj(pf) = pair {
                        for (pk, pv) in pf.iter_mut() {
                            if pk == "arms"
                                && let Json::Arr(arms) = pv
                            {
                                for arm in arms {
                                    if let Json::Obj(af) = arm {
                                        for (ak, av) in af.iter_mut() {
                                            if ak == "cdc_relevant" {
                                                *av = impossible.clone();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let path = dir.join("shrank.json");
    std::fs::write(&path, record.to_pretty()).expect("write");
    let err = check_reproduction(&path, "1.96.0->1.97.0", &fresh)
        .expect_err("a shrinking population under a dropping floor is impossible");
    match err {
        ReproError::CdcPopulationNotMonotonic {
            field,
            floors,
            values,
            ..
        } => {
            assert_eq!(field, "files");
            assert_eq!(floors, (524_288, MIN_GRAIN as u64));
            assert_eq!(values, (9_999, 197));
        }
        other => panic!("expected CdcPopulationNotMonotonic, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// NEGATIVE: when the floors MATCH, `cdc_relevant` is compared
/// strictly like any other field — the population door is shut and
/// drift inside the subtree invalidates. (The per-field sweep above
/// skips nested objects, so this is the only probe that pins the
/// same-floor strict path.)
#[test]
fn same_floor_cdc_relevant_drift_still_invalidates() {
    let dir = scratch("same-floor-drift");
    let fresh = all_fresh();
    let baseline = baseline_for(&fresh, &dir);
    let mut drifted = fresh;
    if let Some(m) = drifted.iter_mut().find(|m| m.arm == "cdc-min128K-nc1") {
        m.cdc_relevant.files += 1;
    }
    let err = check_reproduction(&baseline, "1.96.0->1.97.0", &drifted)
        .expect_err("same-floor cdc drift must invalidate");
    match err {
        ReproError::Mismatch { arm, field, .. } => {
            assert_eq!(arm, "cdc-min128K-nc1");
            assert_eq!(field, "cdc_relevant");
        }
        other => panic!("expected Mismatch on cdc_relevant, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// NEGATIVE (the control's whole point): one drifted field on one
/// shared arm INVALIDATES the run, naming pair, arm, field, and both
/// renderings — never re-baselined.
#[test]
fn a_single_drifted_field_invalidates_the_run() {
    let dir = scratch("drift");
    let fresh = all_fresh();
    let baseline = baseline_for(&fresh, &dir);
    let mut drifted = fresh;
    if let Some(m) = drifted.iter_mut().find(|m| m.arm == "cdc-min128K-nc1") {
        m.novel_stored_bytes += 1;
    }
    let err =
        check_reproduction(&baseline, "1.96.0->1.97.0", &drifted).expect_err("must invalidate");
    match err {
        ReproError::Mismatch {
            pair,
            arm,
            field,
            committed,
            fresh,
        } => {
            assert_eq!(pair, "1.96.0->1.97.0");
            assert_eq!(arm, "cdc-min128K-nc1");
            assert_eq!(field, "novel_stored_bytes");
            assert_eq!(committed, "402231140");
            assert_eq!(fresh, "402231141");
        }
        other => panic!("expected Mismatch, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// NEGATIVE: a baseline without the pair, without a committed arm,
/// or a run without a fresh arm each invalidate — absence is never
/// agreement.
#[test]
fn missing_pieces_invalidate_rather_than_skip() {
    let dir = scratch("missing");
    let fresh = all_fresh();
    let baseline = baseline_for(&fresh, &dir);
    assert!(matches!(
        check_reproduction(&baseline, "no-such-pair", &fresh),
        Err(ReproError::MissingPair { .. })
    ));
    let three = &fresh[..3];
    assert!(matches!(
        check_reproduction(&baseline, "1.96.0->1.97.0", three),
        Err(ReproError::MissingFreshArm { .. })
    ));
    assert!(matches!(
        check_reproduction(Path::new("/no/such/file"), "x", &fresh),
        Err(ReproError::Io(_))
    ));
    let bad = dir.join("bad.json");
    std::fs::write(&bad, "{ not json").expect("write");
    assert!(matches!(
        check_reproduction(&bad, "x", &fresh),
        Err(ReproError::Parse(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
