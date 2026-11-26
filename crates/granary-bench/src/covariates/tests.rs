// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::covariates` — the registered covariates, and the
//! structural boundary asserting `cost.rs` cannot see this module.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use std::path::PathBuf;

/// Process-unique scratch dir (the corpus/sweep test convention).
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "granary-bench-covariates-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn tree(root: &std::path::Path, files: &[(&str, Vec<u8>)]) -> Corpus {
    for (name, data) in files {
        std::fs::write(root.join(name), data).expect("write");
    }
    crate::corpus::load(root).expect("load")
}

/// THE BOUNDARY (the selection never sees covariates): the decision
/// module's source does not mention this module. Same source-scan
/// idiom as `tests/gen_w3_constants.rs` — crude, executable, and it
/// turns an architectural claim into a failing test.
#[test]
fn the_decision_module_cannot_see_covariates() {
    // A MODULE'S TESTS CAN LEAVE THE FILE ITS SUBJECT LIVES IN: `crate::cost`
    // is three files, not `cost.rs` — the two test bodies went out of line to
    // `cost/tests.rs` and `cost/tests/factorial_tests.rs`, and `cost.rs` itself
    // fell from 1,947 lines to 976. A scan of `../cost.rs` alone then covers
    // only part of the surface it means to cover, and the POSITIVE control
    // below cannot see that: it proves the PATH still lands on cost.rs, not
    // that cost.rs is still the whole module. Read all three files, and
    // control EACH of them — a negative assertion is only as good as its surface.
    let cost_src = concat!(
        include_str!("../cost.rs"),
        include_str!("../cost/tests.rs"),
        include_str!("../cost/tests/factorial_tests.rs"),
    );

    // POSITIVE CONTROL, and it runs BEFORE the verdict.
    //
    // The verdict below is a NEGATIVE — `!contains` — so ANY failure to
    // read the intended file satisfies it: an empty slice, or a re-rooted
    // path that happens to land on a different existing file, both pass
    // while proving nothing. This is the one self-reader in the tree
    // measured as failing OPEN: a self-reader with no positive control
    // passes vacuously forever once its subject leaves the file, so it may
    // not be split past, which moving this module's bodies would otherwise do.
    //
    // MEASURED: repointing this `include_str!` at `json.rs` (20,481 bytes)
    // makes the control fail and the test red; with the control removed,
    // the SAME repoint passes. That difference is the fail-open.
    //
    // `pub fn choose(` is the anchor because it IS cost.rs's subject: the
    // boundary is a statement about the average sweep's selection entry
    // point (the factorial's `decide_factorial` sits beside it), so a
    // cost.rs without it is not the file this test means, and the verdict
    // below would be about nothing.
    for (anchor, whose) in [
        ("pub fn choose(", "cost.rs"),
        ("fn binmap_entry_is_forty_nine_bytes(", "cost/tests.rs"),
        (
            "fn a_flat_landscape_selects_the_incumbent(",
            "cost/tests/factorial_tests.rs",
        ),
    ] {
        assert!(
            cost_src.contains(anchor),
            "the include_str! set did not read {whose} — {} bytes total, no `{anchor}`. \
             The verdict below is a NEGATIVE and would have passed on this, \
             proving nothing. Re-root the path; do not weaken the assert",
            cost_src.len()
        );
    }

    assert!(
        !cost_src.contains("covariates"),
        "module `crate::cost` mentions `covariates` — the covariate boundary says the \
         selection code can never import covariate outputs. This scans the \
         module's THREE files, not just `cost.rs`"
    );
}

#[test]
fn c1_buckets_thresholds_and_novelty_are_computed_from_the_trees() {
    let root = scratch("c1");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    std::fs::create_dir_all(&older_dir).expect("mkdir");
    std::fs::create_dir_all(&newer_dir).expect("mkdir");
    let older = tree(
        &older_dir,
        &[
            ("kept", vec![b'k'; 3000]),
            ("renamed-away", vec![b'r'; 5000]),
        ],
    );
    let newer = tree(
        &newer_dir,
        &[
            ("kept", vec![b'k'; 3000]),         // identical: not novel
            ("renamed-here", vec![b'r'; 5000]), // rename: deduped, NOT novel
            ("fresh", vec![b'f'; 9000]),        // novel
            // EXACTLY 16 KiB: C1 defines strict `size < m`, and no
            // fixture sat on a threshold, so `<=` survived the suite.
            // The m16 row's counts kill the boundary mutant.
            ("on-threshold", vec![b't'; 16 << 10]),
            ("big", vec![b'b'; 600 << 10]), // above every threshold
            ("empty", Vec::new()),          // the no-bucket case
        ],
    );
    let c = c1(&older, &newer).expect("c1");
    assert_eq!(c.total_files, 6);
    assert_eq!(c.empty_files, 1);
    // 3000 -> k=11, 5000 -> k=12, 9000 -> k=13, 16384 -> k=14,
    // 600K -> k=19.
    assert_eq!(
        c.buckets,
        vec![
            (11, 1, 3000),
            (12, 1, 5000),
            (13, 1, 9000),
            (14, 1, 16384),
            (19, 1, (600 << 10)),
        ]
    );
    // Every registered threshold row is present, min grid + 512K.
    assert_eq!(
        c.thresholds.iter().map(|r| r.threshold).collect::<Vec<_>>(),
        c1_thresholds()
    );
    // At m = 16 KiB: kept, renamed-here, fresh, empty are below;
    // only `fresh` is whole-file novel (the rename matched an older
    // whole file ANYWHERE in the tree, not by path).
    let m16 = c
        .thresholds
        .iter()
        .find(|r| r.threshold == 16 << 10)
        .expect("16K row");
    assert_eq!(m16.files, 4);
    assert_eq!(m16.bytes, 3000 + 5000 + 9000);
    assert_eq!(m16.whole_file_novel_bytes, 9000);
    let _ = std::fs::remove_dir_all(&root);
}

/// NEGATIVE (C1's own required red case): a bucket histogram that
/// disagrees with the walked totals fails the run. The public API
/// cannot produce one, so the check function is exercised directly
/// — the same direct-unit idiom as `manifest_status_for`.
#[test]
fn a_histogram_that_disagrees_with_the_walk_fails() {
    let bad = C1 {
        buckets: vec![(11, 1, 3000)],
        empty_files: 0,
        thresholds: c1_thresholds()
            .into_iter()
            .map(|threshold| C1Threshold {
                threshold,
                files: 0,
                bytes: 0,
                whole_file_novel_bytes: 0,
            })
            .collect(),
        total_files: 2, // one more than the buckets hold
        total_bytes: 3000,
    };
    assert!(validate_c1(&bad).is_err());

    let no_512k = C1 {
        buckets: Vec::new(),
        empty_files: 0,
        thresholds: Vec::new(), // the 512 KiB row is gone
        total_files: 0,
        total_bytes: 0,
    };
    assert!(validate_c1(&no_512k).is_err());
}

#[test]
fn c2_locality_domain_and_blind_population_are_reported() {
    let root = scratch("c2");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    std::fs::create_dir_all(&older_dir).expect("mkdir");
    std::fs::create_dir_all(&newer_dir).expect("mkdir");
    // A 200 KiB file changed IN PLACE at the tail: high locality.
    let local_old = granary_core::testkit::fill(21, 200 << 10);
    let mut local_new = local_old.clone();
    for b in local_new.iter_mut().rev().take(4 << 10) {
        *b ^= 0x5a;
    }
    // A file changed THROUGHOUT: ~zero locality.
    let churn_old = granary_core::testkit::fill(22, 100 << 10);
    let churn_new = granary_core::testkit::fill(23, 100 << 10);
    // A rename the domain cannot see.
    let moved = granary_core::testkit::fill(24, 50 << 10);
    let older = tree(
        &older_dir,
        &[
            ("local.bin", local_old),
            ("churn.bin", churn_old),
            ("was-here", moved.clone()),
        ],
    );
    let newer = tree(
        &newer_dir,
        &[
            ("local.bin", local_new),
            ("churn.bin", churn_new),
            ("now-here", moved),
        ],
    );
    let c = c2(&older, &newer).expect("c2");
    assert_eq!(c.domain_files, 2, "identical and renamed files are outside");
    assert_eq!(c.domain_bytes, (200 << 10) + (100 << 10));
    assert_eq!(c.no_path_match_bytes, 50 << 10);
    assert_eq!(
        c.no_path_match_deduped_bytes,
        50 << 10,
        "the rename is whole-file deduped, and the report must say so"
    );
    // Both domain files are sub-512K, so the headline covers both:
    // strictly between the churn file's ~0 and the local file's ~1.
    assert!(
        c.headline_sub_512k > 0.3 && c.headline_sub_512k < 0.95,
        "{}",
        c.headline_sub_512k
    );
    // Decile mass sums to the domain.
    assert_eq!(c.decile_bytes.iter().sum::<u64>(), c.domain_bytes);
    // The in-place edit lands in a high decile, the churn in decile 0.
    assert_eq!(c.decile_bytes.first().copied(), Some(100 << 10));
    let high: u64 = c.decile_bytes.iter().skip(7).sum();
    assert_eq!(high, 200 << 10, "{:?}", c.decile_bytes);
    let _ = std::fs::remove_dir_all(&root);
}

/// C2's per-span counting as built (the module doc's note: every
/// matching newer span counts its length, even repeated; set
/// semantics on the OLD side only) had zero kill-coverage: a
/// first-occurrence-only mutant survived every fixture
/// (`testkit::fill` repeats no R-grains) while understating locality
/// ~6x on repeated content (measured 0.957 -> 0.157), flipping the
/// registered reading-grid label at the 0.25 boundary. Repeated
/// content is ordinary (zero blocks, repeated records); this fixture
/// makes the contract load-bearing.
#[test]
fn repeated_grains_count_at_every_span_occurrence() {
    let root = scratch("repeated-grains");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    std::fs::create_dir_all(&older_dir).expect("mkdir");
    std::fs::create_dir_all(&newer_dir).expect("mkdir");
    let block = granary_core::testkit::fill(31, 16 << 10);
    let mut old_data = Vec::new();
    for _ in 0..8 {
        old_data.extend_from_slice(&block);
    }
    let mut new_data = old_data.clone();
    let tail = new_data.len() - (1 << 10);
    for b in new_data.iter_mut().skip(tail) {
        *b ^= 0x5a;
    }
    let older = tree(&older_dir, &[("repeats.bin", old_data)]);
    let newer = tree(&newer_dir, &[("repeats.bin", new_data)]);
    let c = c2(&older, &newer).expect("c2");
    assert!(
        c.headline_sub_512k > 0.8,
        "repeated matching spans must each count: locality {}",
        c.headline_sub_512k
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The reference chunker is the fixed `R`, byte for byte, and it is not a
/// grid cell (its average sits three octaves below the factorial's).
#[test]
fn the_c2_reference_chunker_is_the_registered_one() {
    assert_eq!(C2_REFERENCE.min, 256);
    assert_eq!(C2_REFERENCE.avg, 4 << 10);
    assert_eq!(C2_REFERENCE.max, 32 << 10);
    assert_eq!(C2_REFERENCE.normalization, NormalizationLevel::L0);
    assert!(
        !GrainTuple::factorial_grid().contains(&C2_REFERENCE),
        "R must never be a cell"
    );
}

#[test]
fn locality_boundary_is_the_registered_quarter() {
    assert!((LOCALITY_BOUNDARY - 0.25).abs() < f64::EPSILON);
}
