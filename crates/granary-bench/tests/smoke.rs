// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! End-to-end on a synthetic two-version corpus: load, sweep one arm,
//! measure retention. Record writing is gated on the production
//! controls and is therefore tested in `tests/controls.rs`, where a
//! real token exists.
//!
//! The frozen test below
//! (`a_two_version_sweep_measures_content_index_and_retention`) is kept
//! verbatim except for one line — its `store_manifest_bytes > 0`
//! assertion is vacuous (an empty corpus still reports 14 bytes, the
//! empty root node) and is replaced with an exact value. The
//! tests that follow strengthen the frozen smoke with corpora whose
//! answers are known BY CONSTRUCTION: every value is either computed by
//! hand from the fixture, or cross-checked against an independent
//! oracle (a direct `zstd::bulk::compress` call, or the frozen manifest
//! encoder invoked directly rather than through `sweep::run_arm`) —
//! never copied from the engine's own output.

#![expect(
    clippy::expect_used,
    reason = "the corpus-building helper sits outside #[test] fns (test code, standards rule 3)"
)]
#![expect(
    clippy::disallowed_methods,
    reason = "test scratch-dir naming; disallowed_methods has no allow-in-tests knob"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use granary_bench::chunk::Arm;
use granary_bench::compress::{GrainCompressor, ZSTD_LEVEL};
use granary_bench::corpus;
use granary_bench::manifest_bytes;
use granary_bench::sweep::{self, ManifestStatus};
use granary_bench::tuple::{GrainTuple, SWEEP_AVGS};
use granary_core::hash::GrainId;
use granary_core::manifest::GrainRef;
use granary_core::testkit;

fn build_version(root: &Path, extra: &[u8]) {
    fs::create_dir_all(root.join("bin")).expect("mkdir");
    fs::create_dir_all(root.join("lib")).expect("mkdir");
    let mut big = testkit::fill(77, 6 * 1024 * 1024);
    big.extend_from_slice(extra);
    fs::write(root.join("lib/libbig.dylib"), &big).expect("write");
    fs::write(root.join("bin/tool"), testkit::fill(78, 300_000)).expect("write");
    fs::write(root.join("README.md"), b"granary bench smoke\n").expect("write");
}

/// Independent oracle for one corpus's manifest under one arm: chunks
/// with the SAME production `Arm::cut_into` and encodes with the SAME
/// frozen `manifest_bytes::build`, but composed here directly rather
/// than through `sweep::run_arm`'s internal `scan`/`manifest_terms`.
/// This is what lets the tests below prove the ENGINE's own
/// novel/union arithmetic is correct, not merely replay its own
/// output — the chunker and the encoder are each independently and
/// exhaustively tested elsewhere (`tests/parity.rs`,
/// `manifest_bytes::tests`), so reusing them here is composing
/// already-trusted primitives, not trusting the thing under test.
fn independent_manifest(corpus: &corpus::Corpus, arm: Arm) -> manifest_bytes::ManifestNodes {
    let mut entries = Vec::new();
    let mut spans = Vec::new();
    for node in &corpus.nodes {
        let payload = match &node.kind {
            corpus::NodeKind::EmptyDir => manifest_bytes::Payload::EmptyDir,
            corpus::NodeKind::Symlink { target } => {
                manifest_bytes::Payload::Symlink(target.clone())
            }
            corpus::NodeKind::File { exec, .. } => {
                let data = corpus.read(node).expect("read fixture file");
                arm.cut_into(&data, &mut spans);
                let grains: Vec<GrainRef> = spans
                    .iter()
                    .filter_map(|s| {
                        data.get(s.offset..s.offset + s.len).map(|bytes| GrainRef {
                            id: GrainId::of(bytes),
                            unpacked_len: u32::try_from(s.len).unwrap_or(u32::MAX),
                        })
                    })
                    .collect();
                manifest_bytes::Payload::File {
                    exec: *exec,
                    size: data.len() as u64,
                    grains,
                }
            }
        };
        entries.push(manifest_bytes::Entry {
            components: node.components.clone(),
            payload,
        });
    }
    manifest_bytes::build(&entries).expect("independent manifest build")
}

/// Process-unique scratch dir per fixture.
fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("granary-bench-smoke-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

#[test]
fn a_two_version_sweep_measures_content_index_and_retention() {
    // Process-unique.
    let base = std::env::temp_dir().join(format!("granary-bench-smoke-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let older_dir = base.join("v1");
    let newer_dir = base.join("v2");
    build_version(&older_dir, b"");
    build_version(&newer_dir, b"one extra tail");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    assert_eq!(older.file_count, 3);

    let mut comp = GrainCompressor::new().expect("compressor");
    let arm = Arm::Cdc(GrainTuple::shipped());
    let m = sweep::run_arm(&older, &newer, arm, &mut comp).expect("sweep");
    assert_eq!(m.manifest_status, ManifestStatus::Exact);
    // The frozen `> 0` check here is vacuous (an empty corpus still
    // reports 14 bytes, the empty root node) — replaced with the exact
    // value from an independent oracle, applied to THIS test's own
    // corpus and arm rather than a separate fixture.
    let old_mf = independent_manifest(&older, arm);
    let new_mf = independent_manifest(&newer, arm);
    let mut union = old_mf.nodes.clone();
    for (id, len) in &new_mf.nodes {
        union.insert(*id, *len);
    }
    let expected_store_manifest_bytes: u64 = union.values().map(|&l| l as u64).sum();
    assert_eq!(
        m.store_manifest_bytes, expected_store_manifest_bytes,
        "store_manifest_bytes must equal the independent old+new manifest-node union: {m:#?}"
    );
    assert!(
        m.novel_stored_bytes > 0 && m.novel_stored_bytes < m.newer_bytes,
        "a 14-byte append must be neither free nor total: {m:#?}"
    );
    assert!(m.novel_grain_count >= 1);

    let r = sweep::retention(&older, &newer).expect("retention");
    assert_eq!(r.paths_common, 3);
    assert_eq!(r.paths_added, 0);
    assert!(
        r.path_identical_bytes > 0,
        "two of three files are unchanged"
    );

    // Whole-file dedup on a 6 MiB file is representable; the frozen cap
    // only bites above 8 MiB.
    let wf = sweep::run_arm(&older, &newer, Arm::WholeFile, &mut comp).expect("whole-file");
    assert_eq!(wf.manifest_status, ManifestStatus::Exact);

    fs::remove_dir_all(&base).expect("cleanup");
}

/// Ten of `ArmMetrics`'s seventeen fields
/// pinned exactly on a hand-computed fixed-block corpus — `arm`,
/// `kind`, `configured_avg`, `newer_bytes`, `novel_raw_bytes`,
/// `novel_grain_count`, `store_grain_count`, `manifest_status`,
/// `novel_stored_bytes`, `store_stored_bytes`. The other seven
/// (`max_clamped`, `coalesced_ranges`, `realized_mean_grain`,
/// `realized_median_grain`, `novel_manifest_bytes`,
/// `store_manifest_bytes`, `novel_by_class`) are each pinned through
/// `ArmMetrics` by a dedicated fixture elsewhere in this file — no
/// single hand-computed corpus exercises all seventeen meaningfully at
/// once. `novel_stored_bytes` is cross-checked against a DIRECT
/// `zstd::bulk::compress` call, not via `GrainCompressor` — checking it
/// against the very compressor under test would be circular.
///
/// Fixture (`Arm::Fixed(8)`, 8-byte grains):
///   older/a = A B                older/b = B C
///   newer/a = A E (E new)        newer/b = B F (F new)   newer/c = G (G new)
/// older grains {A,B,C}, 32 bytes; newer grains {A,E,B,F,G}, 40 bytes;
/// novel = {E,F,G}.
///
/// `E` and `F` are `EEEEEEE1` / `EEEEEEE2` — 8 bytes differing ONLY in
/// the last byte, not two visibly distinct grains — so a grain hashed
/// one byte short collides them into one
/// `GrainId`, which changes `novel_grain_count` (3 -> 2) and
/// `store_grain_count` (6 -> 5); the existing exact-value assertions
/// below catch that without a dedicated new assertion. `newer/c = G` is
/// present ONLY in the newer tree, so `older.bytes` (32) and
/// `newer.bytes` (40) differ — with equal totals, `assert_eq!(m.
/// newer_bytes, 32)` would still pass even if `newer_bytes` were
/// computed from the older tree.
#[test]
fn every_arm_metrics_field_is_pinned_on_a_hand_computed_fixed_block_corpus() {
    let root = scratch("fields");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(&older_dir).expect("mkdir");
    fs::create_dir_all(&newer_dir).expect("mkdir");

    let g_a = vec![b'A'; 8];
    let g_b = vec![b'B'; 8];
    let g_c = vec![b'C'; 8];
    let g_e = b"EEEEEEE1".to_vec();
    let g_f = b"EEEEEEE2".to_vec();
    let g_g = vec![b'G'; 8];

    let mut older_a = g_a.clone();
    older_a.extend_from_slice(&g_b);
    let mut older_b = g_b.clone();
    older_b.extend_from_slice(&g_c);
    let mut newer_a = g_a.clone();
    newer_a.extend_from_slice(&g_e);
    let mut newer_b = g_b.clone();
    newer_b.extend_from_slice(&g_f);
    let newer_c = g_g.clone();

    fs::write(older_dir.join("a"), &older_a).expect("write");
    fs::write(older_dir.join("b"), &older_b).expect("write");
    fs::write(newer_dir.join("a"), &newer_a).expect("write");
    fs::write(newer_dir.join("b"), &newer_b).expect("write");
    fs::write(newer_dir.join("c"), &newer_c).expect("write");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");
    let m = sweep::run_arm(&older, &newer, Arm::Fixed(8), &mut comp).expect("sweep");

    // `arm`, `kind` and `configured_avg` were never asserted through
    // `ArmMetrics` anywhere in this file — only via `sweep.rs`'s own
    // unit tests on the private `kind_of`/`configured_avg` helpers,
    // which cannot see whether `run_arm` actually wires them into the
    // report.
    assert_eq!(m.arm, "fixed-8", "{m:#?}");
    assert_eq!(m.kind, "fixed", "{m:#?}");
    assert_eq!(m.configured_avg, 8, "{m:#?}");

    assert_eq!(m.newer_bytes, 40, "{m:#?}");
    assert_eq!(m.novel_raw_bytes, 24, "{m:#?}");
    assert_eq!(m.novel_grain_count, 3, "{m:#?}");
    assert_eq!(m.store_grain_count, 6, "{m:#?}");
    assert_eq!(m.manifest_status, ManifestStatus::Exact);

    let expected_novel_stored: u64 = [&g_e, &g_f, &g_g]
        .iter()
        .map(|g| {
            zstd::bulk::compress(g, ZSTD_LEVEL)
                .expect("direct zstd")
                .len() as u64
        })
        .sum();
    assert_eq!(m.novel_stored_bytes, expected_novel_stored, "{m:#?}");

    let expected_store_stored: u64 = [&g_a, &g_b, &g_c, &g_e, &g_f, &g_g]
        .iter()
        .map(|g| {
            zstd::bulk::compress(g, ZSTD_LEVEL)
                .expect("direct zstd")
                .len() as u64
        })
        .sum();
    assert_eq!(m.store_stored_bytes, expected_store_stored, "{m:#?}");

    fs::remove_dir_all(&root).expect("cleanup");
}

/// `coalesced_ranges` pinned to an exact
/// integer on a corpus containing a repeat of a novel grain FOLLOWED BY
/// another novel grain — the only shape that exercises the
/// transparent-repeat rule end to end (through `ArmMetrics`, not just
/// the internal `novel_runs` helper `sweep.rs` already unit-tests
/// directly).
///
/// Newer file `f` = "NNNN" "NNNN" "MMMM" under `Fixed(4)`: spans
/// [N, N(repeat), M], older has no files so both N and M are novel. A
/// repeat must not break the run, and an adjacent-but-different novel
/// grain must not either: expected ranges = 1, not 2.
#[test]
fn coalesced_ranges_treats_a_repeated_novel_grain_as_transparent() {
    let root = scratch("ranges");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(&older_dir).expect("mkdir");
    fs::create_dir_all(&newer_dir).expect("mkdir");

    let mut content = Vec::new();
    content.extend_from_slice(&[b'N'; 4]);
    content.extend_from_slice(&[b'N'; 4]);
    content.extend_from_slice(&[b'M'; 4]);
    fs::write(newer_dir.join("f"), &content).expect("write");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");
    let m = sweep::run_arm(&older, &newer, Arm::Fixed(4), &mut comp).expect("sweep");

    assert_eq!(m.coalesced_ranges, 1, "{m:#?}");

    fs::remove_dir_all(&root).expect("cleanup");
}

/// `novel_by_class` pinned as a whole
/// vector, with DIFFERENT byte totals per class (equal-size fixtures
/// would make a class swap invisible), including a case that is
/// `exec` + an unknown extension (`.xyz`, falls through every table to
/// the exec fallback, per `FileClass::of`).
///
/// The original fixture
/// survived three mutants of the class-split/coalescing logic because
/// every file was both novel AND unique. Two additions close that:
/// `older/lib/archive.tar` carries the SAME 50 bytes as
/// `newer/lib/archive.tar`, so `archive` is HELD (present in the older
/// tree already) and its expected novel total drops to 0 — a mutant
/// that skipped the old-grain lookup for `Archive` specifically would
/// still report 50. `newer/share/dup1.dat` and `newer/src/dup2.rs`
/// carry IDENTICAL 7-byte content in two DIFFERENT classes — the same
/// novel grain, referenced twice; only its FIRST traversal occurrence
/// (`share/dup1.dat`, class `other`) may be counted, per the
/// transparent-repeat rule `coalesced_ranges_treats_a_repeated_novel_
/// grain_as_transparent` already proves for range counting — a mutant
/// that double-counted the repeat, or attributed it to the SECOND
/// occurrence's class (`text`), would move bytes between classes.
#[test]
fn novel_by_class_is_pinned_with_distinct_totals_including_exec_plus_unknown_extension() {
    let root = scratch("class");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(older_dir.join("lib")).expect("mkdir");
    fs::create_dir_all(newer_dir.join("lib")).expect("mkdir");
    fs::create_dir_all(newer_dir.join("src")).expect("mkdir");
    fs::create_dir_all(newer_dir.join("share")).expect("mkdir");
    fs::create_dir_all(newer_dir.join("bin")).expect("mkdir");

    // Held: identical content on both sides, so this grain is already in
    // the store and contributes 0 novel bytes to `archive`.
    fs::write(older_dir.join("lib/archive.tar"), vec![2u8; 50]).expect("write");
    fs::write(newer_dir.join("lib/archive.tar"), vec![2u8; 50]).expect("write");

    fs::write(newer_dir.join("lib/native.dylib"), vec![1u8; 100]).expect("write");
    fs::write(newer_dir.join("src/main.rs"), vec![3u8; 30]).expect("write");
    fs::write(newer_dir.join("share/misc.dat"), vec![4u8; 20]).expect("write");
    let tool = newer_dir.join("bin/tool.xyz");
    fs::write(&tool, vec![5u8; 10]).expect("write");
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).expect("chmod");
    // The same novel grain, referenced from two different classes
    // (`other` via `.dat`, `text` via `.rs`). Traversal order is
    // memcmp-sorted depth-first (`corpus.rs`), so `share/dup1.dat`
    // precedes `src/dup2.rs`; the repeat must be transparent.
    fs::write(newer_dir.join("share/dup1.dat"), vec![9u8; 7]).expect("write");
    fs::write(newer_dir.join("src/dup2.rs"), vec![9u8; 7]).expect("write");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");
    let m = sweep::run_arm(&older, &newer, Arm::WholeFile, &mut comp).expect("sweep");

    // native-binary = 100 (native.dylib) + 10 (exec .xyz) = 110.
    // archive = 0 (archive.tar is held, unchanged from the older tree).
    // text = 30 (main.rs); dup2.rs contributes 0 -- its grain's first
    // traversal occurrence is share/dup1.dat, counted under `other`.
    // other = 7 (dup1.dat, first occurrence) + 20 (misc.dat) = 27.
    assert_eq!(
        m.novel_by_class,
        vec![
            ("native-binary", 110u64),
            ("archive", 0u64),
            ("text", 30u64),
            ("other", 27u64),
        ],
        "{m:#?}"
    );

    fs::remove_dir_all(&root).expect("cleanup");
}

/// `realized_median_grain` and
/// `realized_mean_grain` on a distribution whose SORTED median differs
/// from the "id order" (`BTreeMap<GrainId,_>` iteration) middle —
/// otherwise a missing `sort_unstable()` in `sweep::median` is
/// invisible. `GrainId` order is a hash and cannot be predicted by
/// inspection, so the fixture's own claim is verified computationally
/// below, not assumed.
#[test]
fn median_and_mean_use_sorted_order_not_grain_id_order() {
    let items: [(Vec<u8>, u64); 5] = [
        (vec![0xA1; 3], 3),
        (vec![0xB2; 5], 5),
        (vec![0xC3; 9], 9),
        (vec![0xD4; 10], 10),
        (vec![0xE5; 21], 21),
    ];

    let mut by_id: Vec<(GrainId, u64)> = items
        .iter()
        .map(|(data, len)| (GrainId::of(data), *len))
        .collect();
    by_id.sort_by_key(|(id, _)| *id);
    let id_order_middle = by_id[by_id.len() / 2].1;

    let mut sorted_lens: Vec<u64> = items.iter().map(|(_, len)| *len).collect();
    sorted_lens.sort_unstable();
    let sorted_median = sorted_lens[sorted_lens.len() / 2];

    assert_ne!(
        id_order_middle, sorted_median,
        "fixture must actually distinguish id order from sorted order, or a missing sort is invisible"
    );

    #[expect(
        clippy::cast_precision_loss,
        reason = "grain lengths are tiny test literals; the result is a reported mean"
    )]
    let expected_mean = items.iter().map(|(_, l)| *l).sum::<u64>() as f64 / items.len() as f64;

    let root = scratch("median");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(&older_dir).expect("mkdir");
    fs::create_dir_all(&newer_dir).expect("mkdir");
    for (i, (data, _)) in items.iter().enumerate() {
        fs::write(newer_dir.join(format!("g{i}")), data).expect("write");
    }

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");
    let m = sweep::run_arm(&older, &newer, Arm::WholeFile, &mut comp).expect("sweep");

    assert_eq!(m.realized_median_grain, sorted_median, "{m:#?}");
    assert!(
        (m.realized_mean_grain - expected_mean).abs() < 1e-9,
        "{m:#?}"
    );

    fs::remove_dir_all(&root).expect("cleanup");
}

/// The dedup-bench cross-check's realized mean
/// is over EVERY chunk emitted; `realized_mean_grain` is over DISTINCT
/// grains. Comparing them compares two different statistics — on W1
/// that is a 6% gap against a 10% agreement band, so the verdict could
/// be decided by the choice of statistic. `realized_mean_span` is the
/// raw-to-raw counterpart.
///
/// The fixture is what makes the two differ: `dup-a` and `dup-b` hold
/// the SAME 10 bytes, so the unique-grain multiset is {10, 30} (mean
/// 20) while the span multiset is {10, 10, 30} (mean 16.67). Both
/// expectations are computed here from the fixture, never copied from
/// the engine.
#[test]
fn realized_mean_span_counts_every_span_not_distinct_grains() {
    let dup = vec![0x5A_u8; 10];
    let solo = vec![0x7C_u8; 30];

    let root = scratch("mean-span");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(&older_dir).expect("mkdir");
    fs::create_dir_all(&newer_dir).expect("mkdir");
    fs::write(newer_dir.join("dup-a"), &dup).expect("write");
    fs::write(newer_dir.join("dup-b"), &dup).expect("write");
    fs::write(newer_dir.join("solo"), &solo).expect("write");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");
    // Whole-file: one span per file, so the two multisets are exactly
    // the ones named above with no cutter behaviour in between.
    let m = sweep::run_arm(&older, &newer, Arm::WholeFile, &mut comp).expect("sweep");

    let distinct_mean = f64::from(10 + 30) / 2.0;
    let span_mean = f64::from(10 + 10 + 30) / 3.0;
    assert!(
        (distinct_mean - span_mean).abs() > 1e-9,
        "fixture must distinguish the two means, or the field is untested"
    );
    assert!(
        (m.realized_mean_grain - distinct_mean).abs() < 1e-9,
        "{m:#?}"
    );
    assert!((m.realized_mean_span - span_mean).abs() < 1e-9, "{m:#?}");

    fs::remove_dir_all(&root).expect("cleanup");
}

/// `novel_manifest_bytes` and
/// `store_manifest_bytes` pinned exactly, on a corpus with an
/// UNCHANGED SUBDIRECTORY — a flat corpus makes the set difference
/// trivially equal to the whole newer manifest, which would leave a
/// subtree-level identity bug invisible.
#[test]
fn manifest_bytes_are_pinned_exactly_with_an_unchanged_subdirectory() {
    let root = scratch("manifest");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(older_dir.join("keep")).expect("mkdir");
    fs::create_dir_all(newer_dir.join("keep")).expect("mkdir");

    fs::write(older_dir.join("keep/unchanged.txt"), b"hello world").expect("write");
    fs::write(newer_dir.join("keep/unchanged.txt"), b"hello world").expect("write");
    fs::write(older_dir.join("top.txt"), b"old-top").expect("write");
    fs::write(newer_dir.join("top.txt"), b"new-top-content").expect("write");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");

    let old_mf = independent_manifest(&older, Arm::WholeFile);
    let new_mf = independent_manifest(&newer, Arm::WholeFile);
    // Fixture sanity: the unchanged subdirectory must actually make the
    // two manifests share a node, or this corpus does not exercise what
    // it claims to.
    assert!(
        old_mf.nodes.keys().any(|id| new_mf.nodes.contains_key(id)),
        "fixture must share at least one manifest node"
    );
    let expected_novel: u64 = new_mf
        .nodes
        .iter()
        .filter(|(id, _)| !old_mf.nodes.contains_key(*id))
        .map(|(_, &len)| len as u64)
        .sum();
    let mut union = old_mf.nodes.clone();
    for (id, len) in &new_mf.nodes {
        union.insert(*id, *len);
    }
    let expected_store: u64 = union.values().map(|&l| l as u64).sum();

    let mut comp = GrainCompressor::new().expect("compressor");
    let m = sweep::run_arm(&older, &newer, Arm::WholeFile, &mut comp).expect("sweep");
    assert_eq!(m.manifest_status, ManifestStatus::Exact);
    assert_eq!(m.novel_manifest_bytes, expected_novel, "{m:#?}");
    assert_eq!(m.store_manifest_bytes, expected_store, "{m:#?}");

    fs::remove_dir_all(&root).expect("cleanup");
}

/// Every `Retention` field pinned exactly,
/// on a corpus with a removed path, an added path, a changed file, an
/// unchanged file, and a symlink — retention must not follow it.
#[test]
fn retention_fields_are_pinned_exactly_and_a_symlink_is_not_followed() {
    let root = scratch("retention");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(&older_dir).expect("mkdir");
    fs::create_dir_all(&newer_dir).expect("mkdir");

    fs::write(older_dir.join("removed.txt"), b"bye").expect("write");
    fs::write(older_dir.join("unchanged.txt"), b"same-content").expect("write");
    fs::write(older_dir.join("changed.txt"), b"old-value").expect("write");

    fs::write(newer_dir.join("unchanged.txt"), b"same-content").expect("write");
    fs::write(newer_dir.join("changed.txt"), b"new-value!!").expect("write");
    fs::write(newer_dir.join("added.txt"), b"brand-new").expect("write");
    // If the `NodeKind::File`-only guard in `retention()` were ever
    // dropped, `fs::read` would transparently follow this and add a
    // spurious matched/added path and 12 more `newer_bytes` — which
    // the exact assertions below would catch.
    symlink("unchanged.txt", newer_dir.join("link")).expect("symlink");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    let r = sweep::retention(&older, &newer).expect("retention");

    assert_eq!(r.paths_common, 2, "{r:#?}");
    assert_eq!(r.paths_added, 1, "{r:#?}");
    assert_eq!(r.paths_removed, 1, "{r:#?}");
    assert_eq!(r.path_identical_bytes, 12, "{r:#?}");
    assert_eq!(r.newer_bytes, 32, "{r:#?}");

    fs::remove_dir_all(&root).expect("cleanup");
}

/// An over-8-MiB file with
/// `Arm::WholeFile` — nothing else exercises the documented cap case
/// (the frozen smoke deliberately stays at 6 MiB to avoid it). Asserts
/// `Unrepresentable`, `novel_manifest_bytes == 0`, and that the CONTENT
/// terms are still produced (not zeroed out alongside the manifest
/// term).
#[test]
fn a_file_over_the_manifest_cap_is_unrepresentable_but_content_terms_are_produced() {
    let root = scratch("overcap");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(&older_dir).expect("mkdir");
    fs::create_dir_all(&newer_dir).expect("mkdir");

    let len = granary_core::manifest::GRAIN_UNPACKED_MAX as usize + 1;
    fs::write(newer_dir.join("huge"), testkit::fill(99, len)).expect("write");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");
    let m = sweep::run_arm(&older, &newer, Arm::WholeFile, &mut comp).expect("sweep");

    assert!(
        matches!(m.manifest_status, ManifestStatus::Unrepresentable(_)),
        "{:?}",
        m.manifest_status
    );
    assert_eq!(m.novel_manifest_bytes, 0, "{m:#?}");
    let expected_len = len as u64;
    assert_eq!(m.novel_raw_bytes, expected_len, "{m:#?}");
    assert_eq!(m.novel_grain_count, 1, "{m:#?}");
    assert!(
        m.novel_stored_bytes > 0,
        "content terms must still be produced: {m:#?}"
    );
    assert_eq!(m.newer_bytes, expected_len, "{m:#?}");

    fs::remove_dir_all(&root).expect("cleanup");
}

/// `Cdc(2 MiB)` asserting `max_clamped ==
/// true`, and `Cdc(shipped)` asserting `false` — through `ArmMetrics`
/// end to end (`GrainTuple`'s own `max_clamped` is already unit-tested
/// in `tuple.rs`; this proves `sweep::run_arm` wires it into the
/// report).
#[test]
fn max_clamped_flag_is_true_at_two_mib_and_false_at_shipped() {
    let root = scratch("clamp");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(&older_dir).expect("mkdir");
    fs::create_dir_all(&newer_dir).expect("mkdir");
    fs::write(older_dir.join("f"), testkit::fill(31, 4096)).expect("write");
    fs::write(newer_dir.join("f"), testkit::fill(32, 4096)).expect("write");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");

    let clamped = GrainTuple::from_avg(2 << 20).expect("grid point");
    let m_clamped = sweep::run_arm(&older, &newer, Arm::Cdc(clamped), &mut comp).expect("sweep");
    assert!(m_clamped.max_clamped(), "{m_clamped:#?}");

    let m_shipped =
        sweep::run_arm(&older, &newer, Arm::Cdc(GrainTuple::shipped()), &mut comp).expect("sweep");
    assert!(!m_shipped.max_clamped(), "{m_shipped:#?}");

    fs::remove_dir_all(&root).expect("cleanup");
}

/// The 61-outcome control suite proves RESYNC, not TUPLE FIDELITY: a
/// chunker secretly cutting every CDC arm at 8 KiB passes 61/61, and
/// so does one where
/// `cdc-128K` through `cdc-2M` all secretly cut at 128 KiB — exactly the
/// half of the grid the tie-break band and the W1 winner live in.
///
/// A saboteur's output is, by construction, the same measurement under a
/// different `configured_avg` label. So both saboteurs are reproduced
/// here EXACTLY: measured with the real chunker at the tuple the
/// saboteur substitutes, then relabelled — no hand-written numbers, and
/// nothing the refusal could be tuned to.
///
/// The honest measurement of the same corpus must pass, or the check
/// would be refusing real data rather than saboteurs.
#[test]
fn a_chunker_that_ignores_the_swept_tuple_is_refused() {
    let root = scratch("grid-fidelity");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(&older_dir).expect("mkdir");
    fs::create_dir_all(&newer_dir).expect("mkdir");
    // Large enough that the coarsest grid point (avg 2 MiB, min 1 MiB)
    // still cuts more than once; the older tree is left empty, which
    // halves the work without touching what is being checked.
    fs::write(newer_dir.join("blob"), testkit::fill(61, 24 * 1024 * 1024)).expect("write");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");

    let honest: Vec<sweep::ArmMetrics> = SWEEP_AVGS
        .into_iter()
        .map(|avg| {
            let t = GrainTuple::from_avg(avg).expect("grid point");
            sweep::run_arm(&older, &newer, Arm::Cdc(t), &mut comp).expect("sweep")
        })
        .collect();
    assert_eq!(
        sweep::check_cdc_grid_fidelity(&honest),
        Ok(()),
        "the real chunker must pass: {:#?}",
        honest
            .iter()
            .map(|m| (m.configured_avg, m.realized_mean_span))
            .collect::<Vec<_>>()
    );

    // Saboteur 1: every CDC arm secretly cuts at 8 KiB.
    let at_8k = honest.first().expect("the 8K point").clone();
    let all_at_8k: Vec<sweep::ArmMetrics> = honest
        .iter()
        .map(|h| sweep::ArmMetrics {
            arm: h.arm.clone(),
            configured_avg: h.configured_avg,
            max_policy: h.max_policy,
            ..at_8k.clone()
        })
        .collect();
    assert!(
        matches!(
            sweep::check_cdc_grid_fidelity(&all_at_8k),
            Err(sweep::GridFidelityError::SpanNotIncreasing { .. })
        ),
        "a grid that never varied the tuple must be refused"
    );

    // Saboteur 2, the arithmetically fatal one: 128K..2M all secretly
    // cut at 128 KiB — five points that would tie at the minimum and
    // publish 2 MiB (see `cost::tests::
    // a_flattened_coarse_half_of_the_grid_publishes_the_coarsest_point`).
    let flat_from = SWEEP_AVGS
        .iter()
        .position(|&a| a == 128 << 10)
        .expect("128K is on the grid");
    let at_128k = honest.get(flat_from).expect("the 128K point").clone();
    let coarse_half_flat: Vec<sweep::ArmMetrics> = honest
        .iter()
        .enumerate()
        .map(|(i, h)| {
            if i < flat_from {
                h.clone()
            } else {
                sweep::ArmMetrics {
                    arm: h.arm.clone(),
                    configured_avg: h.configured_avg,
                    max_policy: h.max_policy,
                    ..at_128k.clone()
                }
            }
        })
        .collect();
    match sweep::check_cdc_grid_fidelity(&coarse_half_flat) {
        Err(sweep::GridFidelityError::SpanNotIncreasing {
            finer_avg,
            coarser_avg,
            ..
        }) => {
            assert_eq!(finer_avg, (128 << 10) as u64);
            assert_eq!(coarser_avg, (256 << 10) as u64);
        }
        other => panic!("the fatal saboteur must be refused, got {other:?}"),
    }

    fs::remove_dir_all(&root).expect("cleanup");
}

/// The designated dedup-bench comparison is made
/// on the CDC-RELEVANT population (files >= `MIN_GRAIN`), because
/// 99.70% of W1's files by count are below it and become one whole-file
/// chunk in any implementation. The dedup-bench side of that split is
/// committed; the granary side existed nowhere in committed artefacts, so
/// the comparison was not computable from committed artefacts alone.
///
/// The fixture separates every quantity that could be conflated:
/// `small` sits ONE byte below the threshold (excluded), `at-min` sits
/// exactly ON it (included — the boundary is `>=`, matching the
/// external walker's `st.st_size >= min_grain`), and `dup` repeats
/// `at-min`'s content so raw chunks and unique chunks differ.
#[test]
fn the_cdc_relevant_split_is_the_files_at_or_above_min_grain_in_the_newer_tree() {
    let min_grain = granary_core::thresh::MIN_GRAIN;
    let at_min = testkit::fill(51, min_grain);
    let bigger = testkit::fill(52, 3 * 1024 * 1024);
    let small = testkit::fill(53, min_grain - 1);

    let root = scratch("cdc-relevant");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(&older_dir).expect("mkdir");
    fs::create_dir_all(&newer_dir).expect("mkdir");
    fs::write(newer_dir.join("at-min"), &at_min).expect("write");
    fs::write(newer_dir.join("dup"), &at_min).expect("write");
    fs::write(newer_dir.join("bigger"), &bigger).expect("write");
    fs::write(newer_dir.join("small"), &small).expect("write");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");

    // Whole-file first: one span per file, so every expectation below is
    // hand-computed from the fixture rather than from any cutter.
    let wf = sweep::run_arm(&older, &newer, Arm::WholeFile, &mut comp).expect("sweep");
    let c = &wf.cdc_relevant;
    assert_eq!(c.min_grain_bytes, min_grain as u64, "{c:#?}");
    assert_eq!(c.files, 3, "`small` is one byte short: {c:#?}");
    let expected_bytes = (2 * min_grain + 3 * 1024 * 1024) as u64;
    assert_eq!(c.bytes, expected_bytes, "{c:#?}");
    assert_eq!(c.raw_chunks, 3, "{c:#?}");
    assert_eq!(c.unique_chunks, 2, "`dup` repeats `at-min`: {c:#?}");
    #[expect(
        clippy::cast_precision_loss,
        reason = "fixture byte counts are tiny; the result is a mean"
    )]
    let expected_mean_span = expected_bytes as f64 / 3.0;
    #[expect(
        clippy::cast_precision_loss,
        reason = "fixture byte counts are tiny; the result is a mean"
    )]
    let expected_mean_grain = (min_grain + 3 * 1024 * 1024) as f64 / 2.0;
    assert!(
        (c.realized_mean_span - expected_mean_span).abs() < 1e-6,
        "{c:#?}"
    );
    assert!(
        (c.realized_mean_grain - expected_mean_grain).abs() < 1e-6,
        "{c:#?}"
    );
    // The whole-tree statistic includes `small` and is therefore a
    // DIFFERENT number — if it were not, this split would measure
    // nothing the record already carried.
    assert!(
        (wf.realized_mean_span - c.realized_mean_span).abs() > 1.0,
        "{wf:#?}"
    );

    // Now the arm the cross-check actually compares against, with the
    // expectation computed by cutting the same three files directly —
    // never copied from the engine.
    let arm = Arm::Cdc(GrainTuple::shipped());
    let m = sweep::run_arm(&older, &newer, arm, &mut comp).expect("sweep");
    let mut spans = Vec::new();
    let mut expected_raw = 0u64;
    let mut expected_bytes_cut = 0u64;
    let mut distinct: std::collections::BTreeMap<GrainId, u64> = std::collections::BTreeMap::new();
    for data in [&at_min, &at_min, &bigger] {
        arm.cut_into(data, &mut spans);
        for s in &spans {
            let bytes = data.get(s.offset..s.offset + s.len).expect("span in range");
            expected_raw += 1;
            expected_bytes_cut += s.len as u64;
            distinct.entry(GrainId::of(bytes)).or_insert(s.len as u64);
        }
    }
    assert!(expected_raw > 3, "the fixture must exercise real cutting");
    let c = &m.cdc_relevant;
    assert_eq!(c.raw_chunks, expected_raw, "{c:#?}");
    assert_eq!(c.bytes, expected_bytes_cut, "{c:#?}");
    assert_eq!(c.unique_chunks, distinct.len() as u64, "{c:#?}");
    #[expect(
        clippy::cast_precision_loss,
        reason = "fixture byte counts are tiny; the result is a mean"
    )]
    let expected_span = expected_bytes_cut as f64 / expected_raw as f64;
    #[expect(
        clippy::cast_precision_loss,
        reason = "fixture byte counts are tiny; the result is a mean"
    )]
    let expected_grain = distinct.values().sum::<u64>() as f64 / distinct.len().max(1) as f64;
    assert!(
        (c.realized_mean_span - expected_span).abs() < 1e-6,
        "{c:#?}"
    );
    assert!(
        (c.realized_mean_grain - expected_grain).abs() < 1e-6,
        "{c:#?}"
    );

    fs::remove_dir_all(&root).expect("cleanup");
}

/// `max_clamped: false` at the winner is a trap.
/// Whether `GRAIN_UNPACKED_MAX` constrains the choice cannot be read as
/// "it does if the winner's `max` is clamped": at a 1 MiB average
/// `max = min(8*avg, ceiling)` is EXACTLY the ceiling with no reduction,
/// so the flag reads `false` while the cap is binding (it is why
/// `cdc-2M` is clamped 16 MiB -> 8 MiB, and why W1's `whole-file` arm is
/// unrepresentable). The sweep's record must therefore distinguish "clamped
/// below the natural max" from "sitting exactly at the ceiling", through
/// `ArmMetrics` end to end.
///
/// The 1 MiB point is exercised here as a GRID POINT, not as the shipped
/// tuple: the shipped average is 256 KiB, whose 2 MiB max is clear of the
/// ceiling. The middle state this test pins is the reason the distinction
/// is kept.
#[test]
fn a_max_at_the_ceiling_is_distinguishable_from_a_max_clamped_to_it() {
    let root = scratch("ceiling");
    let older_dir = root.join("v1");
    let newer_dir = root.join("v2");
    fs::create_dir_all(&older_dir).expect("mkdir");
    fs::create_dir_all(&newer_dir).expect("mkdir");
    fs::write(older_dir.join("f"), testkit::fill(41, 4096)).expect("write");
    fs::write(newer_dir.join("f"), testkit::fill(42, 4096)).expect("write");

    let older = corpus::load(&older_dir).expect("load older");
    let newer = corpus::load(&newer_dir).expect("load newer");
    let mut comp = GrainCompressor::new().expect("compressor");
    let ceiling = granary_core::manifest::GRAIN_UNPACKED_MAX as usize;
    let mut policy_of = |avg: usize| {
        let t = GrainTuple::from_avg(avg).expect("grid point");
        sweep::run_arm(&older, &newer, Arm::Cdc(t), &mut comp)
            .expect("sweep")
            .max_policy
            .expect("a cdc arm carries a max policy")
    };

    // The middle state: nothing was reduced, and the cap still binds.
    let at_cap = policy_of(1 << 20);
    assert!(!at_cap.clamped, "{at_cap:#?}");
    assert!(
        at_cap.at_ceiling(),
        "1 MiB * 8 IS the ceiling — the record's `max_at_ceiling` flag \
         must not say otherwise: {at_cap:#?}"
    );
    assert_eq!(at_cap.max, ceiling, "{at_cap:#?}");
    assert_eq!(at_cap.unclamped, ceiling, "{at_cap:#?}");
    assert_eq!(at_cap.ceiling, ceiling, "{at_cap:#?}");

    // Genuinely clamped: 16 MiB reduced to the 8 MiB cap.
    let two_mib = policy_of(2 << 20);
    assert!(two_mib.clamped, "{two_mib:#?}");
    assert!(two_mib.at_ceiling(), "{two_mib:#?}");
    assert_eq!(two_mib.max, ceiling, "{two_mib:#?}");
    assert_eq!(two_mib.unclamped, 16 << 20, "{two_mib:#?}");

    // Neither: the cap is nowhere near this point.
    let eight_k = policy_of(8 << 10);
    assert!(!eight_k.clamped, "{eight_k:#?}");
    assert!(!eight_k.at_ceiling(), "{eight_k:#?}");
    assert_eq!(eight_k.max, 64 << 10, "{eight_k:#?}");
    assert_eq!(eight_k.unclamped, 64 << 10, "{eight_k:#?}");

    // The arms with no tuple have no policy at all — `false` and
    // "no such thing" must not look alike.
    let wf = sweep::run_arm(&older, &newer, Arm::WholeFile, &mut comp).expect("sweep");
    assert!(wf.max_policy.is_none(), "{wf:#?}");
    assert!(!wf.max_clamped(), "{wf:#?}");

    fs::remove_dir_all(&root).expect("cleanup");
}
