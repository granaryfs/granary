// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::sweep` — the measurement engine computing novel
//! and republish bytes for one arm over one version pair.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::tuple::{GrainTuple, NormalizationLevel};
use granary_core::manifest::Name;

fn node(path: &str, exec: bool) -> Node {
    Node {
        components: path
            .split('/')
            .map(|p| Name::new(p.as_bytes().to_vec()).expect("name"))
            .collect(),
        kind: NodeKind::File { exec, len: 0 },
    }
}

#[test]
fn classes_follow_the_pre_registered_table() {
    assert_eq!(
        FileClass::of(&node("lib/libstd.dylib", false)),
        FileClass::NativeBinary
    );
    assert_eq!(
        FileClass::of(&node("lib/libstd.rlib", false)),
        FileClass::Archive
    );
    assert_eq!(FileClass::of(&node("src/main.rs", false)), FileClass::Text);
    assert_eq!(
        FileClass::of(&node("bin/rustc", true)),
        FileClass::NativeBinary
    );
    assert_eq!(
        FileClass::of(&node("share/manifest", false)),
        FileClass::Other
    );
    // `bin/rustc` above covers the extensionless exec branch; this
    // covers the OTHER exec fallback -- an unrecognised extension
    // (not in any of the three tables) still falls through to
    // `else if exec` and lands NativeBinary, not Other.
    assert_eq!(
        FileClass::of(&node("bin/tool.xyz", true)),
        FileClass::NativeBinary
    );
}

#[test]
fn arm_kinds_and_averages_are_reported() {
    let t = GrainTuple::shipped();
    assert_eq!(kind_of(Arm::Cdc(t)), "cdc");
    assert_eq!(configured_avg(Arm::Cdc(t)), 262_144);
    assert_eq!(configured_avg(Arm::WholeFile), 0);
    // The fixed arm is constraint 1's headline comparator; it must
    // be labelled `fixed`, not fall through to `cdc`, and its
    // configured average is the block size itself, not 0.
    assert_eq!(kind_of(Arm::Fixed(4096)), "fixed");
    assert_eq!(configured_avg(Arm::Fixed(4096)), 4096);
}

/// The coalescing rule, exercised on the real function. `n` = a
/// novel grain, `o` = one the older version already holds.
fn runs(spec: &str) -> u64 {
    let ids: Vec<GrainId> = spec
        .split_whitespace()
        .map(|t| GrainId::of(t.as_bytes()))
        .collect();
    let novel: BTreeSet<GrainId> = spec
        .split_whitespace()
        .filter(|t| t.starts_with('n'))
        .map(|t| GrainId::of(t.as_bytes()))
        .collect();
    novel_runs(&ids, &novel).1
}

#[test]
fn a_repeat_of_a_novel_grain_does_not_split_a_range() {
    assert_eq!(runs("n1 n1 n2"), 1, "a repeat must be transparent");
    assert_eq!(runs("n1 o1 n2"), 2, "an already-held grain breaks the run");
    assert_eq!(runs("o1 n1 n2 o2 n3"), 2);
    assert_eq!(runs("n1 n1"), 1);
    assert_eq!(runs("o1 o2"), 0);
    assert_eq!(runs(""), 0);
}

#[test]
fn first_occurrence_flags_line_up_with_the_order() {
    let a = GrainId::of(b"a");
    let b = GrainId::of(b"b");
    let novel: BTreeSet<GrainId> = [a].into_iter().collect();
    let (flags, ranges) = novel_runs(&[a, a, b, a], &novel);
    assert_eq!(flags, vec![true, false, false, false]);
    assert_eq!(ranges, 1);
}

/// A CDC arm record carrying only what the fidelity check reads.
fn cdc_at(avg: usize, span: f64) -> ArmMetrics {
    let t = GrainTuple::from_avg(avg).expect("grid point");
    ArmMetrics {
        arm: Arm::Cdc(t).label(),
        kind: "cdc",
        configured_avg: avg as u64,
        configured_min: Some(t.min as u64),
        configured_normalization: Some(t.normalization.as_u8()),
        max_policy: max_policy_of(Arm::Cdc(t)),
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
        realized_mean_span: span,
        realized_median_grain: 0,
        manifest_status: ManifestStatus::Exact,
        novel_by_class: Vec::new(),
        cdc_relevant: CdcRelevant {
            min_grain_bytes: MIN_GRAIN as u64,
            files: 0,
            bytes: 0,
            raw_chunks: 0,
            unique_chunks: 0,
            realized_mean_span: 0.0,
            realized_mean_grain: 0.0,
        },
    }
}

/// The whole grid, with spans that separate — the shape every
/// measured pair actually has.
fn honest_grid() -> Vec<ArmMetrics> {
    SWEEP_AVGS
        .into_iter()
        .enumerate()
        .map(|(i, avg)| {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a test index, not a measurement"
            )]
            let span = 1000.0 + i as f64;
            cdc_at(avg, span)
        })
        .collect()
}

/// The check accepts a grid whose points
/// separate, and it is not vacuous: the non-CDC arms are ignored
/// rather than counted towards the grid.
#[test]
fn a_grid_whose_points_separate_is_accepted() {
    let mut arms = honest_grid();
    arms.push(ArmMetrics {
        kind: "whole-file",
        configured_avg: 0,
        realized_mean_span: 0.0,
        ..cdc_at(1 << 20, 0.0)
    });
    assert_eq!(check_cdc_grid_fidelity(&arms), Ok(()));
}

/// NEGATIVE, and the one that matters: two adjacent points that do
/// not separate mean the arms did not use their own tuples.
#[test]
fn a_grid_point_that_does_not_separate_is_refused() {
    let mut arms = honest_grid();
    // cdc-256K reports cdc-128K's span: the flat-grid saboteur's
    // signature.
    let flat = arms.get(4).map(|m| m.realized_mean_span).expect("128K");
    if let Some(m) = arms.get_mut(5) {
        m.realized_mean_span = flat;
    }
    assert_eq!(
        check_cdc_grid_fidelity(&arms),
        Err(GridFidelityError::SpanNotIncreasing {
            finer_avg: 128 << 10,
            finer_span: flat,
            coarser_avg: 256 << 10,
            coarser_span: flat,
        })
    );
}

/// NEGATIVE: a grid that lost a point must not pass by having
/// fewer comparisons to fail. Vacuity is the failure mode every
/// gate in this crate has had to close at least once.
#[test]
fn an_incomplete_grid_is_refused() {
    let mut arms = honest_grid();
    arms.pop();
    assert_eq!(
        check_cdc_grid_fidelity(&arms),
        Err(GridFidelityError::IncompleteGrid {
            found: SWEEP_AVGS.len() - 1,
            expected: SWEEP_AVGS.len(),
        })
    );
    assert_eq!(
        check_cdc_grid_fidelity(&[]),
        Err(GridFidelityError::IncompleteGrid {
            found: 0,
            expected: SWEEP_AVGS.len(),
        })
    );
}

/// The comparison is by CONFIGURED AVERAGE, not by position, so a
/// reordered arm list cannot make a flat grid look monotone.
#[test]
fn the_check_orders_by_configured_average_not_by_position() {
    let mut arms = honest_grid();
    arms.reverse();
    assert_eq!(check_cdc_grid_fidelity(&arms), Ok(()));
}

#[test]
fn median_of_an_even_list_is_the_upper_middle() {
    // Deliberately unsorted, and NOT merely permuted around the
    // answer: `vec![4, 1, 3, 2]` was tried first and rejected,
    // because its raw (unsorted) element at index `len/2` is ALSO
    // 3 -- a coincidence that would leave a missing
    // `sort_unstable()` undetected. The reverse order used here
    // has raw index 2 == 2, which differs from the true median
    // (3), so a missing sort changes the result.
    assert_eq!(median(vec![4, 3, 2, 1]), 3);
    assert_eq!(median(Vec::new()), 0);
}

/// Process-unique scratch dir (matches `corpus.rs`'s and
/// `manifest_bytes.rs`'s test fixtures).
fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("granary-bench-sweep-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// The one genuine format limit (`Encode(BadGrainLen)`) is
/// distinguished from every harness-shaped refusal, and does NOT
/// collapse both into `Unrepresentable`. Direct unit test of
/// `manifest_status_for` — see
/// `an_over_cap_whole_file_grain_reports_its_real_byte_count_not_a_sentinel`
/// below for the same distinction proven through a real sweep.
#[test]
fn manifest_status_for_sorts_a_genuine_format_limit_from_harness_bugs() {
    let bad_grain_len = ManifestError::Encode(EncodeNodeError::BadGrainLen { len: 9_437_184 });
    match manifest_status_for(&bad_grain_len) {
        ManifestStatus::Unrepresentable(msg) => assert!(msg.contains("9437184"), "{msg}"),
        other => panic!("expected Unrepresentable for BadGrainLen, got {other:?}"),
    }

    // Every one of these is the harness feeding the encoder
    // garbage, not a frozen-format limit -- must NOT collapse into
    // `Unrepresentable`, or a corpus-ordering bug would silently
    // narrow the grid the same way a genuine over-cap file does.
    let harness_shaped = [
        ManifestError::MisorderedInput,
        ManifestError::Encode(EncodeNodeError::NotStrictlySorted),
        ManifestError::Encode(EncodeNodeError::SizeMismatch {
            size: 4096,
            sum: 8192,
        }),
        ManifestError::TooManyGrains { count: 5 },
    ];
    for e in &harness_shaped {
        match manifest_status_for(e) {
            ManifestStatus::HarnessError(_) => {}
            other => panic!("expected HarnessError for {e:?}, got {other:?}"),
        }
    }
}

/// EXECUTED, not merely modelled: a corpus-ordering bug reaching
/// `run_arm` (two nodes claiming the same path -- something
/// `corpus::load` itself would never emit, but `run_arm` takes a
/// `Corpus`, not only ones `load` produced) must classify as
/// `HarnessError`, not `Unrepresentable`. This proves
/// `manifest_terms` actually routes through `manifest_status_for`
/// end to end, not merely that the helper is correct in isolation
/// (the isolated unit test above cannot see whether the caller
/// wires it up).
#[test]
fn a_harness_shaped_manifest_error_reaches_run_arm_as_harness_error_not_unrepresentable() {
    let root = scratch("dup-path");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    std::fs::create_dir_all(&older_dir).expect("mkdir");
    std::fs::create_dir_all(&newer_dir).expect("mkdir");
    std::fs::write(newer_dir.join("a"), b"one").expect("write");

    let older = crate::corpus::load(&older_dir).expect("load older");
    let name = |s: &str| Name::new(s.as_bytes().to_vec()).expect("name");
    let newer = Corpus {
        root: newer_dir,
        nodes: vec![
            Node {
                components: vec![name("a")],
                kind: NodeKind::File {
                    exec: false,
                    len: 3,
                },
            },
            Node {
                components: vec![name("a")],
                kind: NodeKind::File {
                    exec: false,
                    len: 3,
                },
            },
        ],
        file_count: 2,
        file_bytes: 6,
    };
    let mut comp = GrainCompressor::new().expect("compressor");
    let m = run_arm(&older, &newer, Arm::WholeFile, &mut comp).expect("run_arm");
    match &m.manifest_status {
        ManifestStatus::HarnessError(_) => {}
        other => panic!("expected HarnessError, got {other:?}"),
    }
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// A real whole-file grain one byte over the frozen 8 MiB cap must
/// report the REAL byte count (8388609) in `manifest_status`, not
/// a `u32::MAX` (4294967295) sentinel — and it must classify as
/// `Unrepresentable` (a genuine format limit), not `HarnessError`.
#[test]
fn an_over_cap_whole_file_grain_reports_its_real_byte_count_not_a_sentinel() {
    let root = scratch("overcap");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    std::fs::create_dir_all(&older_dir).expect("mkdir");
    std::fs::create_dir_all(&newer_dir).expect("mkdir");
    let len = granary_core::manifest::GRAIN_UNPACKED_MAX as usize + 1;
    std::fs::write(newer_dir.join("huge"), vec![b'x'; len]).expect("write");

    let older = crate::corpus::load(&older_dir).expect("load older");
    let newer = crate::corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");
    let m = run_arm(&older, &newer, Arm::WholeFile, &mut comp).expect("run_arm");
    match &m.manifest_status {
        ManifestStatus::Unrepresentable(msg) => {
            assert!(
                msg.contains(&len.to_string()),
                "expected the real byte count {len} in the reason: {msg}"
            );
            assert!(
                !msg.contains("4294967295"),
                "must not contain the fabricated u32::MAX sentinel: {msg}"
            );
        }
        other => panic!("expected Unrepresentable, got {other:?}"),
    }
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// The record-shape contract (`sweep.rs`) had ZERO behavioral coverage: nulling
/// `cell_of`'s `FactorialCdc` arm left the whole suite green while every
/// factorial record would have carried null coordinates — the exact
/// unauditable-records shape the contract exists to forbid. This pins the record
/// shape through `run_arm`, the same path that measures: the factorial arm
/// carries its cell, the average-sweep arm carries its policy coordinates
/// (additive fields), and the tuple-less arms carry `None`, never fake
/// zeros.
#[test]
fn run_arm_records_carry_the_cell_coordinates() {
    let root = scratch("cell-coords");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    std::fs::create_dir_all(&older_dir).expect("mkdir");
    std::fs::create_dir_all(&newer_dir).expect("mkdir");
    std::fs::write(
        newer_dir.join("a"),
        granary_core::testkit::fill(31, 100_000),
    )
    .expect("write");
    let older = crate::corpus::load(&older_dir).expect("load older");
    let newer = crate::corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");

    let cell = GrainTuple::factorial_cell(16 << 10, NormalizationLevel::L2).expect("grid cell");
    let m = run_arm(&older, &newer, Arm::FactorialCdc(cell), &mut comp).expect("run_arm");
    assert_eq!(m.configured_min, Some(16 << 10));
    assert_eq!(m.configured_normalization, Some(2));

    let m3 = run_arm(&older, &newer, Arm::Cdc(GrainTuple::shipped()), &mut comp).expect("run_arm");
    assert_eq!(m3.configured_min, Some(MIN_GRAIN as u64));
    assert_eq!(m3.configured_normalization, Some(1));

    let wf = run_arm(&older, &newer, Arm::WholeFile, &mut comp).expect("run_arm");
    assert_eq!(wf.configured_min, None);
    assert_eq!(wf.configured_normalization, None);
    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// `paths_removed`'s subtraction must not panic if the "newer
/// nodes have distinct component vectors" invariant is ever
/// violated. `corpus::load` cannot produce this (no directory
/// holds two entries with the same name), so this constructs the
/// `Corpus` directly -- `retention` takes a `Corpus`, not only ones
/// `load` produced, and does not get to assume the invariant.
#[test]
fn paths_removed_saturates_instead_of_panicking_if_matched_exceeds_old_files() {
    let root = scratch("retention-overflow");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    std::fs::create_dir_all(&older_dir).expect("mkdir");
    std::fs::create_dir_all(&newer_dir).expect("mkdir");
    std::fs::write(older_dir.join("a"), b"x").expect("write");
    std::fs::write(newer_dir.join("a"), b"x").expect("write");

    let name = |s: &str| Name::new(s.as_bytes().to_vec()).expect("name");
    let older = Corpus {
        root: older_dir,
        nodes: vec![Node {
            components: vec![name("a")],
            kind: NodeKind::File {
                exec: false,
                len: 1,
            },
        }],
        file_count: 1,
        file_bytes: 1,
    };
    // Two node entries both claim path "a" -- the invariant
    // violation itself.
    let newer = Corpus {
        root: newer_dir,
        nodes: vec![
            Node {
                components: vec![name("a")],
                kind: NodeKind::File {
                    exec: false,
                    len: 1,
                },
            },
            Node {
                components: vec![name("a")],
                kind: NodeKind::File {
                    exec: false,
                    len: 1,
                },
            },
        ],
        file_count: 2,
        file_bytes: 2,
    };

    let r = retention(&older, &newer).expect("retention");
    assert_eq!(r.paths_removed, 0, "must saturate at 0, not panic");
    std::fs::remove_dir_all(&root).expect("cleanup");
}
