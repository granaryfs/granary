// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `granary-bench`'s CLI binary
//! (`src/bin/granary-bench.rs`).
//!
//! The CLI once had zero tests. This covers the `HarnessError` refusal,
//! plus the two hand-parsed argument helpers — user-facing, and correct by
//! inspection, but nothing pinned them. Covering the whole binary (I/O,
//! `cmd_sweep`/`cmd_retention`/`cmd_control` end to end) is out of scope.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use granary_bench::sweep::MaxPolicy;

fn dummy_metrics(arm: &str, manifest_status: ManifestStatus) -> ArmMetrics {
    ArmMetrics {
        arm: arm.to_owned(),
        kind: "cdc",
        configured_avg: 1 << 20,
        configured_min: None,
        configured_normalization: None,
        max_policy: None,
        newer_bytes: 0,
        novel_raw_bytes: 0,
        novel_stored_bytes: 0,
        novel_grain_count: 0,
        novel_manifest_bytes: 0,
        store_stored_bytes: 0,
        store_grain_count: 0,
        store_manifest_bytes: 0,
        coalesced_ranges: 0,
        realized_mean_grain: 0.0,
        realized_mean_span: 0.0,
        realized_median_grain: 0,
        manifest_status,
        novel_by_class: Vec::new(),
        cdc_relevant: sweep::CdcRelevant {
            min_grain_bytes: granary_core::thresh::MIN_GRAIN as u64,
            files: 0,
            bytes: 0,
            raw_chunks: 0,
            unique_chunks: 0,
            realized_mean_span: 0.0,
            realized_mean_grain: 0.0,
        },
    }
}

#[test]
fn refuse_harness_errors_names_the_pair_arm_and_reason() {
    let measured = vec![
        dummy_metrics("fixed-1M", ManifestStatus::Exact),
        dummy_metrics(
            "cdc-1M",
            ManifestStatus::HarnessError("bad component ordering".to_owned()),
        ),
    ];
    let err = refuse_harness_errors("v1->v2", &measured).expect_err("a harness error must refuse");
    assert!(err.contains("v1->v2"), "{err}");
    assert!(err.contains("cdc-1M"), "{err}");
    assert!(err.contains("bad component ordering"), "{err}");
}

/// `Unrepresentable` (a genuine frozen-format limit) must NOT be
/// refused here — collapsing it into the same refusal as
/// `HarnessError` would be exactly the confusion `refuse_harness_errors`
/// exists to prevent, the other way around.
#[test]
fn refuse_harness_errors_allows_exact_and_unrepresentable() {
    let measured = vec![
        dummy_metrics("fixed-1M", ManifestStatus::Exact),
        dummy_metrics(
            "whole-file",
            ManifestStatus::Unrepresentable("grain over the 8 MiB cap".to_owned()),
        ),
    ];
    assert!(refuse_harness_errors("v1->v2", &measured).is_ok());
}

#[test]
fn refuse_harness_errors_allows_an_empty_arm_list() {
    assert!(refuse_harness_errors("v1->v2", &[]).is_ok());
}

/// The arm record must carry the
/// CDC-relevant split (so the designated cross-check comparison is
/// computable from committed artefacts alone) and enough of the max
/// policy that a reader cannot see `max_clamped: false` and conclude
/// the frozen cap is not binding.
#[test]
fn arm_json_carries_the_cdc_relevant_split_and_the_whole_max_policy() {
    let mut m = dummy_metrics("cdc-1M", ManifestStatus::Exact);
    let ceiling = granary_core::manifest::GRAIN_UNPACKED_MAX as usize;
    m.max_policy = Some(MaxPolicy {
        max: ceiling,
        unclamped: ceiling,
        ceiling,
        clamped: false,
    });
    m.cdc_relevant = sweep::CdcRelevant {
        min_grain_bytes: granary_core::thresh::MIN_GRAIN as u64,
        files: 197,
        bytes: 1_339_620_535,
        raw_chunks: 924,
        unique_chunks: 900,
        realized_mean_span: 1_449_805.8,
        realized_mean_grain: 1_400_000.0,
    };
    // The coordinates must SERIALIZE
    // non-null for a tuple-bearing arm — the struct-level pin lives
    // in sweep.rs; this is the record-file half.
    m.configured_min = Some(131_072);
    m.configured_normalization = Some(1);
    let text = arm_json(&m).to_pretty();
    assert!(text.contains("\"configured_min\": 131072"), "{text}");
    assert!(text.contains("\"configured_normalization\": 1"), "{text}");
    for key in [
        "cdc_relevant",
        "min_grain_bytes",
        "raw_chunks",
        "unique_chunks",
        "max_bytes",
        "max_unclamped_bytes",
        "max_ceiling_bytes",
        "max_at_ceiling",
    ] {
        assert!(text.contains(key), "{key} missing from {text}");
    }
    assert!(text.contains("924"), "the raw chunk count: {text}");
    assert!(text.contains("\"max_clamped\": false"), "{text}");
    assert!(
        text.contains("\"max_at_ceiling\": true"),
        "at the ceiling WITHOUT having been clamped is the exact case \
         that must be visible: {text}"
    );

    // An arm with no tuple reports `null`, never a misleading `0`.
    let wf = dummy_metrics("whole-file", ManifestStatus::Exact);
    let text = arm_json(&wf).to_pretty();
    assert!(text.contains("\"max_bytes\": null"), "{text}");
    assert!(text.contains("\"max_at_ceiling\": null"), "{text}");
    assert!(text.contains("\"configured_min\": null"), "{text}");
    assert!(
        text.contains("\"configured_normalization\": null"),
        "{text}"
    );
}

/// The decision block must be self-explaining.
/// W1 published `avg: 1048576` with `republish_bytes: 408043345`
/// while the grid MINIMUM was `cdc-128K` at `401448129` — 1 MiB was
/// promoted by `TIE_BREAK_TOLERANCE`, which appeared nowhere in any
/// record. A reader must be able to see the argmin, the tolerance
/// that moved the answer, and how thin the surviving margin is.
#[test]
fn decision_json_carries_the_argmin_the_tolerance_and_the_headroom() {
    let d = Decision::Chosen {
        avg: 1 << 20,
        republish_bytes: 408_043_345,
        argmin_avg: 128 << 10,
        argmin_republish_bytes: 401_448_129,
        headroom_to_cutoff_bytes: 1_433_746.58,
        escalations: Vec::new(),
    };
    let text = decision_json(&d).to_pretty();
    for key in [
        "argmin_avg",
        "argmin_republish_bytes",
        "tie_break_tolerance",
        "headroom_to_cutoff_bytes",
    ] {
        assert!(text.contains(key), "{key} missing from {text}");
    }
    assert!(text.contains("131072"), "the argmin's avg: {text}");
    assert!(text.contains("401448129"), "the grid minimum: {text}");
    assert!(
        text.contains("0.020000"),
        "the pre-registered 2% tolerance: {text}"
    );
    assert!(text.contains("1433746.58"), "the headroom: {text}");
}

#[test]
fn parse_pair_splits_on_the_first_colon_and_labels_by_basename() {
    let (old, new, label) = parse_pair("/data/v1:/data/v2").expect("valid pair");
    assert_eq!(old, PathBuf::from("/data/v1"));
    assert_eq!(new, PathBuf::from("/data/v2"));
    assert_eq!(label, "v1->v2");
}

#[test]
fn parse_pair_rejects_a_tree_compared_with_itself() {
    let err = parse_pair("/data/v1:/data/v1").expect_err("must refuse a self-pair");
    assert!(err.contains("itself"), "{err}");
}

/// NEGATIVE, and the point of the guard: a self-pair must be refused
/// however it is SPELLED. Every one of these was ACCEPTED by the raw
/// `old == new` string compare — verified by running this test
/// against it, which reported all seven.
#[test]
fn parse_pair_rejects_a_self_pair_however_it_is_spelled() {
    let here = env!("CARGO_MANIFEST_DIR");
    let specs = [
        // Refused by the LEXICAL rule, so refused whether or not the
        // trees exist: a trailing slash, and a `.` component.
        "/data/v1:/data/v1/".to_owned(),
        "/data/v1/:/data/v1".to_owned(),
        "/data/./v1:/data/v1".to_owned(),
        "./v1:v1".to_owned(),
        "v1:./v1".to_owned(),
        // Refused only once the filesystem RESOLVES them: `..`, and a
        // second route to the same directory. No lexical rule may
        // collapse these — a symlinked component would make it wrong.
        format!("{here}/src:{here}/src/../src"),
        format!("{here}/src:{here}/../granary-bench/src"),
    ];
    let accepted: Vec<&String> = specs.iter().filter(|s| parse_pair(s).is_ok()).collect();
    assert!(accepted.is_empty(), "self-pairs accepted: {accepted:#?}");
}

/// Pins WHICH mechanism catches what, so a later simplification
/// cannot quietly drop one and stay green on the other's cases.
/// `Path::components()` normalizes `.` away everywhere except at the
/// START of a path — verified here by execution, not assumed: it is
/// why `lexical` filters `CurDir` rather than comparing `components()`
/// directly.
#[test]
fn the_lexical_rule_drops_curdir_and_leaves_parentdir_to_the_filesystem() {
    assert_eq!(
        Path::new("./v1").components().count(),
        2,
        "a LEADING `.` survives components(); a bare components() \
         comparison would not catch `./v1` against `v1`"
    );
    assert_eq!(
        Path::new("a/./v1").components().count(),
        2,
        "a non-leading `.` does not"
    );

    assert_eq!(lexical(Path::new("./v1")), lexical(Path::new("v1")));
    assert_eq!(lexical(Path::new("v1/")), lexical(Path::new("v1")));
    assert_eq!(lexical(Path::new("a/./v1")), lexical(Path::new("a/v1")));
    assert_ne!(
        lexical(Path::new("a/../v1")),
        lexical(Path::new("v1")),
        "`..` is NOT resolved lexically — `a` may be a symlink"
    );

    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(resolves_to_the_same_tree(
        &here.join("src"),
        &here.join("src/../src")
    ));
    assert!(!resolves_to_the_same_tree(
        &here.join("src"),
        &here.join("tests")
    ));
    // I/O that cannot answer must answer `false`, never refuse.
    assert!(!resolves_to_the_same_tree(
        Path::new("/no/such/v1"),
        Path::new("/no/such/v1")
    ));
}

/// The guard must not cost a legitimate pair. `canonicalize` is I/O
/// and fallible, so a pair it cannot resolve falls back to the
/// lexical rule and stays acceptable — it must never turn a real
/// pair into an error.
#[test]
fn parse_pair_accepts_two_different_trees_resolvable_or_not() {
    let here = env!("CARGO_MANIFEST_DIR");
    for spec in [
        "v1:v2".to_owned(),
        "/data/v1:/data/v2".to_owned(),
        // Neither half exists: canonicalize fails on both.
        "/no/such/v1:/no/such/v2".to_owned(),
        // One half exists, the other does not.
        format!("{here}/src:/no/such/v2"),
        // Both exist and are genuinely different.
        format!("{here}/src:{here}/tests"),
    ] {
        let (_, _, label) =
            parse_pair(&spec).unwrap_or_else(|e| panic!("`{spec}` must be accepted: {e}"));
        assert!(label.contains("->"), "{spec}: {label}");
    }
}

/// `ceiling` returned a plain `f64` and gave
/// `0.0` — printed as `0.000x` — for `novel == 0`, the MAXIMALLY
/// deduplicable pair. The three cases must be distinguishable, and
/// the printed form must read correctly to a human screening
/// candidate datasets by this pre-check.
#[test]
fn ceiling_tells_unbounded_headroom_from_no_data_from_a_ratio() {
    assert_eq!(ceiling(0, 1_000), Ceiling::Unbounded);
    assert_eq!(ceiling(0, 0), Ceiling::NoData);
    assert_eq!(ceiling(500, 1_000), Ceiling::Ratio(2.0));
    assert_eq!(ceiling(1_000, 1_000), Ceiling::Ratio(1.0));

    // What a reader actually sees on the retention pre-check.
    let unbounded = ceiling(0, 1_000).to_string();
    assert!(unbounded.starts_with("unbounded"), "{unbounded}");
    assert!(
        !unbounded.contains("0.000"),
        "the old rendering read as `no dedup achievable`: {unbounded}"
    );
    assert!(ceiling(0, 0).to_string().starts_with("n/a"));
    assert_eq!(ceiling(500, 1_000).to_string(), "2.000x");
    assert_eq!(ceiling(1_000, 1_000).to_string(), "1.000x");
}

#[test]
fn parse_pair_rejects_a_missing_colon_and_an_empty_half() {
    assert!(parse_pair("no-colon-here").is_err());
    assert!(parse_pair(":/data/v2").is_err());
    assert!(parse_pair("/data/v1:").is_err());
}

#[test]
fn parse_flags_pairs_consecutive_args_and_keeps_repeats() {
    let args: Vec<String> = [
        "--older",
        "/a",
        "--newer",
        "/b",
        "--replication-pair",
        "/c:/d",
        "--replication-pair",
        "/e:/f",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    let flags = parse_flags(&args).expect("valid flags");
    assert_eq!(
        flags,
        vec![
            ("older".to_owned(), "/a".to_owned()),
            ("newer".to_owned(), "/b".to_owned()),
            ("replication-pair".to_owned(), "/c:/d".to_owned()),
            ("replication-pair".to_owned(), "/e:/f".to_owned()),
        ]
    );
    assert_eq!(all(&flags, "replication-pair").len(), 2);
}

#[test]
fn parse_flags_rejects_a_bare_value_and_a_dangling_flag() {
    let missing_prefix: Vec<String> = vec!["older".to_owned(), "/a".to_owned()];
    assert!(parse_flags(&missing_prefix).is_err());
    let dangling: Vec<String> = vec!["--older".to_owned()];
    assert!(parse_flags(&dangling).is_err());
}

#[test]
fn need_rejects_a_flag_given_more_than_once() {
    let flags: Flags = vec![
        ("older".to_owned(), "/a".to_owned()),
        ("older".to_owned(), "/b".to_owned()),
    ];
    let err = need(&flags, "older").expect_err("must refuse a duplicate flag");
    assert!(err.contains("only once"), "{err}");
}

#[expect(
    clippy::disallowed_methods,
    reason = "test scratch-dir naming; disallowed_methods has no allow-in-tests knob"
)]
mod reproduction_record_tests;
