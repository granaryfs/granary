// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The measurement engine: one arm, one version pair, all the numbers
//! the pre-registered rule and the published curve need.
//!
//! Estimand (unchanged from the pilot, so the two are comparable):
//! the store is pre-loaded with the older version only, then the newer
//! version is republished. Novel = grain ids present in the newer tree
//! and absent from the older one, counted once.
//!
//! # The factorial's arms, datasets and record shape
//!
//! **Arms per pair: 31** — the 28 factorial cells (`tuple.rs`'s module doc)
//! plus three reference arms carried unchanged from the average sweep:
//! `fixed-256K` (the size-matched comparator at the fixed average; the
//! fixed arm has no `min` or normalization, so this one arm is the whole
//! fixed side), `fixed-4M` and `whole-file`.
//!
//! **Record shape:** the factorial's records MUST record the full tuple per
//! arm — a factorial whose records cannot show which cell produced them is
//! unauditable. The coordinates are additive fields; existing fields keep
//! their meaning.
//!
//! **Datasets**, unchanged and not chosen by result: W1 decides (deciding
//! pair 1.96.0 → 1.97.0, replication pair 1.95.0 → 1.96.0), W2 and W3
//! replicate. W3's generated files are all at least 2 MiB, above every
//! candidate floor, so it replicates the intra-file effects of `min` and
//! normalization but is silent on sub-floor gating. The per-file class
//! split below is reported for every arm and is never a decision input.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::PathBuf;

use granary_core::hash::GrainId;
use granary_core::manifest::{EncodeNodeError, GrainRef};
use granary_core::thresh::MIN_GRAIN;

use crate::chunk::{Arm, Span};
use crate::compress::GrainCompressor;
use crate::corpus::{Corpus, Node, NodeKind};
use crate::manifest_bytes::{self, Entry, ManifestError, ManifestNodes, Payload};
use crate::tuple::SWEEP_AVGS;

/// Pre-registered class tables.
const NATIVE_EXTS: [&[u8]; 5] = [b"dylib", b"so", b"o", b"a", b"bundle"];
/// See [`NATIVE_EXTS`].
const ARCHIVE_EXTS: [&[u8]; 7] = [b"rlib", b"rmeta", b"tar", b"gz", b"xz", b"zip", b"bc"];
/// See [`NATIVE_EXTS`].
const TEXT_EXTS: [&[u8]; 12] = [
    b"rs", b"md", b"json", b"toml", b"txt", b"html", b"css", b"js", b"h", b"c", b"py", b"sh",
];

/// Reported file classes. The split the metric demands ("CDC earns its
/// keep on large objects — the report must show that split rather than
/// bury it"), fixed before the objective was computed for any dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    /// Mach-O/ELF images, shared libraries, object files, and
    /// extensionless executables.
    NativeBinary,
    /// Archives and already-compressed containers.
    Archive,
    /// Source, docs, config, and other text.
    Text,
    /// Everything else.
    Other,
}

impl FileClass {
    /// Every class, in report order.
    pub const ALL: [Self; 4] = [Self::NativeBinary, Self::Archive, Self::Text, Self::Other];

    /// Stable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NativeBinary => "native-binary",
            Self::Archive => "archive",
            Self::Text => "text",
            Self::Other => "other",
        }
    }

    /// Classify by extension, falling back to the exec bit.
    #[must_use]
    pub fn of(node: &Node) -> Self {
        let exec = matches!(node.kind, NodeKind::File { exec: true, .. });
        let Some(last) = node.components.last() else {
            return Self::Other;
        };
        let bytes = last.as_bytes();
        let ext = match bytes.iter().rposition(|&b| b == b'.') {
            Some(dot) => bytes.get(dot + 1..).unwrap_or_default(),
            None => {
                return if exec {
                    Self::NativeBinary
                } else {
                    Self::Other
                };
            }
        };
        if NATIVE_EXTS.contains(&ext) {
            Self::NativeBinary
        } else if ARCHIVE_EXTS.contains(&ext) {
            Self::Archive
        } else if TEXT_EXTS.contains(&ext) {
            Self::Text
        } else if exec {
            Self::NativeBinary
        } else {
            Self::Other
        }
    }
}

/// Whether the arm's manifest could be measured exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestStatus {
    /// Measured with the frozen v1 encoder.
    Exact,
    /// Not expressible in the frozen format — reported, never modelled
    /// around. (Whole-file dedup on any file above the 8 MiB grain cap
    /// lands here, which is itself a finding.)
    Unrepresentable(String),
    /// The HARNESS fed the frozen encoder malformed input — a
    /// corpus-ordering bug, a size/grain-sum mismatch, a grain-count
    /// overflow. This is NOT a finding about the frozen format and
    /// must never be folded into [`Self::Unrepresentable`]: doing so
    /// would let a harness bug silently narrow the grid and shift the
    /// argmin, indistinguishable from a genuine over-cap file. See the
    /// private `manifest_status_for`, this module's sole classifier.
    HarnessError(String),
}

/// How one CDC arm's `max` relates to the frozen 8 MiB manifest cap.
///
/// Three states, and collapsing the last two is the trap this type
/// exists to close: `max` strictly below the ceiling, `max` AT the
/// ceiling because `MAX_AVG_RATIO * avg` happens to land there (nothing
/// reduced — `clamped` is `false` — yet the cap is binding), and `max`
/// at the ceiling BECAUSE it was reduced. The sweep's record has to
/// state whether `GRAIN_UNPACKED_MAX` constrains the choice; at a
/// 1 MiB average the answer is "yes" while `clamped` reads `false`.
/// (The shipped average is 256 KiB, whose `max` of 2 MiB is strictly
/// below the ceiling — the middle state is reachable only off the shipped
/// tuple, which is a reason to keep the distinction, not to drop it.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxPolicy {
    /// The tuple's max, as swept.
    pub max: usize,
    /// `MAX_AVG_RATIO * avg`, before the ceiling is applied.
    pub unclamped: usize,
    /// [`crate::tuple::GRAIN_MAX_CEILING`], the frozen manifest cap.
    pub ceiling: usize,
    /// Whether the ceiling REDUCED the policy max.
    pub clamped: bool,
}

impl MaxPolicy {
    /// Whether `max` sits at the frozen ceiling, reduced or not.
    #[must_use]
    pub const fn at_ceiling(&self) -> bool {
        self.max == self.ceiling
    }
}

/// The arm's realized distribution over the CDC-RELEVANT population of
/// the NEWER tree: the files at or above [`MIN_GRAIN`], where a
/// content-defined cutter can actually cut.
///
/// This block exists so the designated dedup-bench comparison is
/// computable from committed artefacts alone. The comparison is over this
/// population rather than the whole tree because most of W1's files sit
/// below a chunker's floor and become one whole-file chunk in ANY
/// implementation with that floor (99.70% by count at a 512 KiB
/// floor) — whole-tree agreement measures the
/// corpus's file-size distribution, not the chunkers. The dedup-bench side
/// of the split is committed as `cdc_relevant` in the cross-check record;
/// this is the granary side of the same population.
///
/// The threshold is the SHIPPED [`MIN_GRAIN`], not the arm's own `min`:
/// a per-arm threshold would make each arm's population a different set
/// of files, which is not a population any two arms could be compared
/// over.
///
/// In its default `legacy` mode the external cross-check uses a
/// different threshold: `bench/datasets/dedup-bench.config` configures
/// `fastcdc_min_block_size = 524288` while this side thresholds at
/// 128 KiB, so in that mode the two sides describe different
/// populations. Its `128k` mode reads `dedup-bench-128k.config`
/// (131072), which matches. The script reads its floor from the config,
/// not from Rust; no mechanical check binds the two thresholds.
/// **The matched-floor re-run has since been done** and, under
/// `dedup-bench-128k.config`, puts both sides on the shipped tuple
/// over the identical file population — and the disagreement SURVIVES it:
/// 17.73% raw-to-raw and 16.10% unique-to-unique against a 10% band,
/// INCONCLUSIVE on both axes (reproducible with
/// `scripts/bench/dedup-bench-crosscheck.sh`'s 128k mode).
/// Matching the populations was necessary, not sufficient.
#[derive(Debug, Clone, PartialEq)]
pub struct CdcRelevant {
    /// The population threshold, [`MIN_GRAIN`].
    pub min_grain_bytes: u64,
    /// Files in the newer tree at or above the threshold.
    pub files: u64,
    /// Their total bytes.
    pub bytes: u64,
    /// Every span the cutter emitted over them, duplicates included.
    pub raw_chunks: u64,
    /// Distinct grains among those spans.
    pub unique_chunks: u64,
    /// `bytes / raw_chunks` — the raw-to-raw statistic, and the granary side
    /// of the cross-check's raw-to-raw axis. Comparable with a cross-check
    /// result only at a MATCHED floor; the type doc names both floors, and
    /// what the matched-floor re-run found.
    pub realized_mean_span: f64,
    /// Mean length over DISTINCT grains. Comparable with the cross-check
    /// record's `cdc_relevant.realized_mean_unique` under the same
    /// same-floor caveat as [`Self::realized_mean_span`].
    pub realized_mean_grain: f64,
}

/// Everything one arm produced on one version pair.
#[derive(Debug, Clone)]
pub struct ArmMetrics {
    /// Arm label.
    pub arm: String,
    /// `cdc`, `fixed`, or `whole-file`.
    pub kind: &'static str,
    /// Configured average, or 0 for whole-file.
    pub configured_avg: u64,
    /// Configured floor (`min`), for the arms that have a tuple — explicit in
    /// every record (additive; the average-sweep fields keep their meaning).
    /// `None` for `fixed`/`whole-file`.
    pub configured_min: Option<u64>,
    /// Configured normalization level (0..=3), same rule as
    /// [`Self::configured_min`].
    pub configured_normalization: Option<u8>,
    /// How this arm's max relates to the frozen cap; `None` for the
    /// arms that have no tuple (`fixed`, `whole-file`).
    pub max_policy: Option<MaxPolicy>,
    /// Newer version's total file bytes.
    pub newer_bytes: u64,
    /// Raw novel bytes (pre-compression) — the pilot's axis.
    pub novel_raw_bytes: u64,
    /// Post-per-grain-zstd novel bytes — the metric's content term.
    pub novel_stored_bytes: u64,
    /// Distinct novel grains.
    pub novel_grain_count: u64,
    /// Exact novel manifest node bytes; 0 when unrepresentable.
    pub novel_manifest_bytes: u64,
    /// Post-zstd bytes of both versions' grains.
    pub store_stored_bytes: u64,
    /// Distinct grains across both versions.
    pub store_grain_count: u64,
    /// Exact manifest node bytes across both versions.
    pub store_manifest_bytes: u64,
    /// Maximal runs of novel grains in traversal order.
    pub coalesced_ranges: u64,
    /// Realized mean grain size in the newer tree, over DISTINCT
    /// grains — the pilot's statistic, and the one the cost rule uses.
    pub realized_mean_grain: f64,
    /// Realized mean span size in the newer tree, over EVERY span the
    /// cutter emitted, duplicates counted every time.
    ///
    /// This exists because the dedup-bench cross-check divides corpus bytes
    /// by every chunk emitted, and comparing that against
    /// [`Self::realized_mean_grain`] compares two different statistics — a 6%
    /// gap on W1 against a 10% agreement band, enough to decide the verdict
    /// by the choice of statistic. Both are reported; the cross-check
    /// compares raw to raw.
    pub realized_mean_span: f64,
    /// Realized median grain size in the newer tree.
    pub realized_median_grain: u64,
    /// Whether the manifest term is exact.
    pub manifest_status: ManifestStatus,
    /// Raw novel bytes by file class.
    pub novel_by_class: Vec<(&'static str, u64)>,
    /// The realized distribution restricted to the files a
    /// content-defined cutter can actually cut.
    pub cdc_relevant: CdcRelevant,
}

impl ArmMetrics {
    /// Whether the frozen cap REDUCED this arm's policy max. Derived
    /// from [`Self::max_policy`] rather than stored separately, so the
    /// flag and the three numbers behind it cannot disagree.
    #[must_use]
    pub fn max_clamped(&self) -> bool {
        self.max_policy.is_some_and(|p| p.clamped)
    }
}

/// Why a sweep could not complete.
#[derive(Debug)]
pub enum SweepError {
    /// Reading a corpus file failed.
    Io {
        /// Where.
        path: PathBuf,
        /// What.
        source: io::Error,
    },
    /// zstd failed.
    Compress(io::Error),
    /// A covariate self-check failed — the computation is reported
    /// invalid rather than published (C1's own negative case).
    Covariate(String),
}

impl fmt::Display for SweepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Compress(e) => write!(f, "zstd: {e}"),
            Self::Covariate(why) => write!(f, "covariate self-check: {why}"),
        }
    }
}

impl core::error::Error for SweepError {}

struct Scan {
    grains: BTreeMap<GrainId, (u64, u64)>,
    order: Vec<(FileClass, GrainId, u64)>,
    manifest: Result<ManifestNodes, ManifestError>,
    bytes: u64,
    /// The CDC-relevant accumulators, filled only on the NEWER scan —
    /// the cross-check's population is the newer tree
    /// (`cdc_split "$NEWER"` in `dedup-bench-crosscheck.sh`).
    cdc_files: u64,
    cdc_bytes: u64,
    cdc_raw_chunks: u64,
    cdc_grains: BTreeMap<GrainId, u64>,
}

/// Measure one arm on one version pair.
///
/// # Errors
/// [`SweepError`] on read or compression failure. A manifest the
/// frozen format cannot express is NOT an error — it is reported in
/// [`ArmMetrics::manifest_status`].
pub fn run_arm(
    older: &Corpus,
    newer: &Corpus,
    arm: Arm,
    comp: &mut GrainCompressor,
) -> Result<ArmMetrics, SweepError> {
    let old = scan(older, arm, comp, false)?;
    let new = scan(newer, arm, comp, true)?;

    let novel: BTreeSet<GrainId> = new
        .grains
        .keys()
        .filter(|id| !old.grains.contains_key(*id))
        .copied()
        .collect();

    let mut novel_raw = 0u64;
    let mut novel_stored = 0u64;
    for id in &novel {
        if let Some(&(raw, stored)) = new.grains.get(id) {
            novel_raw += raw;
            novel_stored += stored;
        }
    }

    let mut union = old.grains.clone();
    for (id, v) in &new.grains {
        union.insert(*id, *v);
    }
    let store_stored: u64 = union.values().map(|&(_, s)| s).sum();

    let (manifest_status, novel_manifest, store_manifest) = manifest_terms(&old, &new);
    let mut by_class: Vec<(&'static str, u64)> =
        FileClass::ALL.iter().map(|c| (c.label(), 0)).collect();
    let ids: Vec<GrainId> = new.order.iter().map(|(_, id, _)| *id).collect();
    let (first_novel, ranges) = novel_runs(&ids, &novel);
    for ((class, _, raw), &counted) in new.order.iter().zip(first_novel.iter()) {
        // `let` chain — stable in edition 2024 (see the note in `cost.rs`).
        if counted && let Some(slot) = by_class.iter_mut().find(|(l, _)| *l == class.label()) {
            slot.1 += raw;
        }
    }

    let lens: Vec<u64> = new.grains.values().map(|&(raw, _)| raw).collect();
    // `new.order` is every span the cutter emitted on the newer tree,
    // in traversal order, duplicates included — the multiset the
    // external cross-check averages over. `lens` above is the DISTINCT
    // one.
    let span_lens: Vec<u64> = new.order.iter().map(|&(_, _, len)| len).collect();
    let (configured_min, configured_normalization) = cell_of(arm);
    Ok(ArmMetrics {
        arm: arm.label(),
        kind: kind_of(arm),
        configured_avg: configured_avg(arm),
        configured_min,
        configured_normalization,
        max_policy: max_policy_of(arm),
        newer_bytes: new.bytes,
        novel_raw_bytes: novel_raw,
        novel_stored_bytes: novel_stored,
        novel_grain_count: novel.len() as u64,
        novel_manifest_bytes: novel_manifest,
        store_stored_bytes: store_stored,
        store_grain_count: union.len() as u64,
        store_manifest_bytes: store_manifest,
        coalesced_ranges: ranges,
        realized_mean_grain: mean(&lens),
        realized_mean_span: mean(&span_lens),
        realized_median_grain: median(lens),
        manifest_status,
        novel_by_class: by_class,
        cdc_relevant: CdcRelevant {
            min_grain_bytes: MIN_GRAIN as u64,
            files: new.cdc_files,
            bytes: new.cdc_bytes,
            raw_chunks: new.cdc_raw_chunks,
            unique_chunks: new.cdc_grains.len() as u64,
            realized_mean_span: per(new.cdc_bytes, new.cdc_raw_chunks),
            realized_mean_grain: per(
                new.cdc_grains.values().sum::<u64>(),
                new.cdc_grains.len() as u64,
            ),
        },
    })
}

/// Why a pair's measured grid may not be published.
#[derive(Debug, Clone, PartialEq)]
pub enum GridFidelityError {
    /// The record does not carry the whole pre-registered CDC grid, so
    /// the monotonicity check below would be weaker than it claims —
    /// or vacuous. An arm list that shrank is itself the defect.
    IncompleteGrid {
        /// CDC arms found.
        found: usize,
        /// CDC arms the grid has ([`SWEEP_AVGS`]).
        expected: usize,
    },
    /// Two adjacent grid points did not separate: the coarser point's
    /// realized mean span is not strictly greater than the finer one's.
    SpanNotIncreasing {
        /// The finer point's configured average.
        finer_avg: u64,
        /// Its realized mean span.
        finer_span: f64,
        /// The coarser point's configured average.
        coarser_avg: u64,
        /// Its realized mean span.
        coarser_span: f64,
    },
}

impl fmt::Display for GridFidelityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteGrid { found, expected } => write!(
                f,
                "the measured grid has {found} CDC arms, the pre-registered grid has {expected}"
            ),
            Self::SpanNotIncreasing {
                finer_avg,
                finer_span,
                coarser_avg,
                coarser_span,
            } => write!(
                f,
                "realized mean span did not increase from avg {finer_avg} \
                 ({finer_span}) to avg {coarser_avg} ({coarser_span}): the \
                 arms did not use the tuples they are labelled with"
            ),
        }
    }
}

impl core::error::Error for GridFidelityError {}

/// TUPLE FIDELITY: the CDC arms of one pair must actually have used the
/// tuples they are labelled with.
///
/// The 61-outcome control suite cannot see this. It proves RESYNC —
/// that a CDC arm recovers from a 1-byte prepend and a fixed arm does
/// not — and a cutter that ignores the swept tuple entirely resyncs
/// perfectly. Demonstrated with saboteur cutters through the real
/// suite: a chunker where every CDC arm secretly cuts at 8 KiB passes
/// 61/61, and so does one where `cdc-128K` through `cdc-2M` all secretly
/// cut at 128 KiB — exactly the half of the grid the tie-break band and
/// the W1 winner live in. The second is arithmetically fatal: with those
/// five points identical, every one of them sits at the minimum and the
/// tie-break publishes 2 MiB, with a genuine `ControlsPassed` token and
/// 61/61 in the record (see `cost::tests::
/// a_flattened_coarse_half_of_the_grid_publishes_the_coarsest_point`).
///
/// The assertion that does see it needs no new measurement — it uses
/// data already in every arm record: across the CDC grid, within a
/// pair, [`ArmMetrics::realized_mean_span`] must be STRICTLY
/// INCREASING. Verified true on all four measured pairs (W1 deciding
/// 8,970 -> 27,965; W1 replication 9,320 -> 33,633; W2 7,877 -> 18,079;
/// W3 11,992 -> 2,390,400), and both saboteurs flatten it.
///
/// It is enforced as a RECORD-WRITE REFUSAL, beside the CLI's
/// `refuse_harness_errors`, and deliberately NOT as an extra control outcome.
/// Three reasons: the property is about the arms actually PUBLISHED for the
/// measured trees, not about a chunker's behaviour on a synthetic control
/// buffer, so the artefact is where it belongs; a cross-arm invariant does
/// not fit `ControlOutcome`'s per-arm shape; and the controls are a
/// pre-registered, committed suite whose composition (61 outcomes, `3 *
/// all_arms() + 1`) is itself referenced by the published record — growing it
/// to launder a new check through the token would change what "the controls
/// passed" has meant since the suite was registered.
///
/// # Errors
/// [`GridFidelityError`] if the grid is incomplete or any adjacent pair
/// of points fails to separate.
pub fn check_cdc_grid_fidelity(measured: &[ArmMetrics]) -> Result<(), GridFidelityError> {
    let mut cdc: Vec<&ArmMetrics> = measured.iter().filter(|m| m.kind == "cdc").collect();
    if cdc.len() != SWEEP_AVGS.len() {
        return Err(GridFidelityError::IncompleteGrid {
            found: cdc.len(),
            expected: SWEEP_AVGS.len(),
        });
    }
    // By configured average, never by position: a reordered arm list
    // must not be able to make a flat grid look monotone.
    cdc.sort_by_key(|m| m.configured_avg);
    for pair in cdc.windows(2) {
        let [finer, coarser] = pair else { continue };
        if coarser.realized_mean_span <= finer.realized_mean_span {
            return Err(GridFidelityError::SpanNotIncreasing {
                finer_avg: finer.configured_avg,
                finer_span: finer.realized_mean_span,
                coarser_avg: coarser.configured_avg,
                coarser_span: coarser.realized_mean_span,
            });
        }
    }
    Ok(())
}

/// Walk a traversal order and mark the FIRST occurrence of each novel
/// grain, counting maximal runs of such positions — the range-GET count
/// a bin-packed store would serve.
///
/// Two rules, and the difference between them is the whole point:
/// a grain the older version already holds **breaks** the run (it lives
/// elsewhere in the store), while a REPEAT of a novel grain is
/// **transparent** (it is the same object, stored once, occupying no
/// separate space in a bin). Treating a repeat as a break would
/// overcount ranges on any tree with duplicate content and inflate the
/// request-count escalation.
fn novel_runs(order: &[GrainId], novel: &BTreeSet<GrainId>) -> (Vec<bool>, u64) {
    let mut seen: BTreeSet<GrainId> = BTreeSet::new();
    let mut first_novel = Vec::with_capacity(order.len());
    let mut ranges = 0u64;
    let mut in_run = false;
    for id in order {
        if !novel.contains(id) {
            in_run = false;
            first_novel.push(false);
            continue;
        }
        if !seen.insert(*id) {
            first_novel.push(false);
            continue;
        }
        if !in_run {
            ranges += 1;
        }
        in_run = true;
        first_novel.push(true);
    }
    (first_novel, ranges)
}

fn manifest_terms(old: &Scan, new: &Scan) -> (ManifestStatus, u64, u64) {
    match (&old.manifest, &new.manifest) {
        (Ok(o), Ok(n)) => {
            let novel: u64 = n
                .nodes
                .iter()
                .filter(|(id, _)| !o.nodes.contains_key(*id))
                .map(|(_, &len)| len as u64)
                .sum();
            let mut union = o.nodes.clone();
            for (id, len) in &n.nodes {
                union.insert(*id, *len);
            }
            let store: u64 = union.values().map(|&l| l as u64).sum();
            (ManifestStatus::Exact, novel, store)
        }
        (Err(e), _) | (_, Err(e)) => (manifest_status_for(e), 0, 0),
    }
}

/// Distinguish the ONE genuine frozen-format limit this harness can hit
/// (`Encode(BadGrainLen)` — a grain, or here a whole file, above the
/// 8 MiB cap; pinned by `manifest_bytes`'s
/// `a_grain_over_the_frozen_cap_is_refused`) from every other encoder
/// refusal, which means the harness itself fed the encoder malformed
/// input: bad component ordering, a size/grain-sum mismatch from a
/// corpus-ordering or buffer-reuse bug, or a grain count overflowing
/// `u32` (see `manifest_bytes`'s
/// `misordered_inputs_are_not_strictly_sorted_not_misordered_input`).
/// Matching bare `Err(_)` would fold both into "expected finding" and
/// silently narrow the grid on a harness bug, not just a genuine
/// over-cap file. Any `EncodeNodeError` variant this harness cannot
/// currently produce (e.g. `TooManyEntries`) falls to the harness-bug
/// side too: an unrecognised refusal is a bug to investigate, never a
/// silently-assumed format limit.
fn manifest_status_for(e: &ManifestError) -> ManifestStatus {
    match e {
        ManifestError::Encode(EncodeNodeError::BadGrainLen { .. }) => {
            ManifestStatus::Unrepresentable(e.to_string())
        }
        _ => ManifestStatus::HarnessError(e.to_string()),
    }
}

fn kind_of(arm: Arm) -> &'static str {
    match arm {
        // A factorial arm IS a cdc arm to every reader of records —
        // same cutter, same kind; the swept coordinates live in
        // `configured_min`/`configured_normalization`.
        Arm::Cdc(_) | Arm::FactorialCdc(_) => "cdc",
        Arm::Fixed(_) => "fixed",
        Arm::WholeFile => "whole-file",
    }
}

/// The swept cell coordinates, for the record — records that cannot
/// show which cell produced them are unauditable.
/// `None` for the arms that have no tuple — a missing coordinate and a
/// zero coordinate must not look alike, same rule as `max_policy_of`.
fn cell_of(arm: Arm) -> (Option<u64>, Option<u8>) {
    match arm {
        Arm::Cdc(t) | Arm::FactorialCdc(t) => (Some(t.min as u64), Some(t.normalization.as_u8())),
        Arm::Fixed(_) | Arm::WholeFile => (None, None),
    }
}

/// Only a CDC arm has a tuple, so only a CDC arm has a max policy.
fn max_policy_of(arm: Arm) -> Option<MaxPolicy> {
    match arm {
        Arm::Cdc(t) | Arm::FactorialCdc(t) => Some(MaxPolicy {
            max: t.max,
            unclamped: t.unclamped_max(),
            ceiling: crate::tuple::GRAIN_MAX_CEILING,
            clamped: t.max_clamped,
        }),
        Arm::Fixed(_) | Arm::WholeFile => None,
    }
}

fn configured_avg(arm: Arm) -> u64 {
    match arm {
        Arm::Cdc(t) | Arm::FactorialCdc(t) => t.avg as u64,
        Arm::Fixed(n) => n as u64,
        Arm::WholeFile => 0,
    }
}

fn scan(
    corpus: &Corpus,
    arm: Arm,
    comp: &mut GrainCompressor,
    keep_order: bool,
) -> Result<Scan, SweepError> {
    let mut out = Scan {
        grains: BTreeMap::new(),
        order: Vec::new(),
        manifest: Ok(ManifestNodes {
            root: GrainId::of(&[]),
            nodes: BTreeMap::new(),
        }),
        bytes: 0,
        cdc_files: 0,
        cdc_bytes: 0,
        cdc_raw_chunks: 0,
        cdc_grains: BTreeMap::new(),
    };
    let mut entries: Vec<Entry> = Vec::with_capacity(corpus.nodes.len());
    let mut spans: Vec<Span> = Vec::new();

    for node in &corpus.nodes {
        let payload = match &node.kind {
            NodeKind::EmptyDir => Payload::EmptyDir,
            NodeKind::Symlink { target } => Payload::Symlink(target.clone()),
            NodeKind::File { exec, .. } => {
                let data = corpus.read(node).map_err(|source| SweepError::Io {
                    path: corpus.path_of(node),
                    source,
                })?;
                out.bytes += data.len() as u64;
                // `>=`, matching the external walker's
                // `st.st_size >= min_grain`: a file exactly ON the
                // threshold is in the population on both sides.
                let cdc_relevant = keep_order && data.len() >= MIN_GRAIN;
                if cdc_relevant {
                    out.cdc_files += 1;
                    out.cdc_bytes += data.len() as u64;
                }
                arm.cut_into(&data, &mut spans);
                let grains = ingest(
                    &data,
                    &spans,
                    node,
                    comp,
                    keep_order,
                    cdc_relevant,
                    &mut out,
                )?;
                Payload::File {
                    exec: *exec,
                    size: data.len() as u64,
                    grains,
                }
            }
        };
        entries.push(Entry {
            components: node.components.clone(),
            payload,
        });
    }

    // The frozen encoder is the sole authority on what v1 can express.
    // No pre-filtering here: an over-cap grain reaches `build` with its
    // REAL length and the encoder reports it itself
    // (`manifest_status_for` sorts a genuine `BadGrainLen` from every
    // other refusal, which means the harness fed it something malformed).
    out.manifest = manifest_bytes::build(&entries);
    Ok(out)
}

/// Hash, compress and record one file's grains. Every span becomes a
/// `GrainRef` carrying its REAL unpacked length, even above the frozen
/// 8 MiB cap — fabricating a sentinel here would let a harness bug
/// (a dropped span, a bad ordering) masquerade as the same,
/// well-understood format limit the frozen encoder reports on its own.
fn ingest(
    data: &[u8],
    spans: &[Span],
    node: &Node,
    comp: &mut GrainCompressor,
    keep_order: bool,
    cdc_relevant: bool,
    out: &mut Scan,
) -> Result<Vec<GrainRef>, SweepError> {
    let class = FileClass::of(node);
    let mut refs = Vec::with_capacity(spans.len());
    for s in spans {
        let Some(bytes) = data.get(s.offset..s.offset + s.len) else {
            continue;
        };
        let id = GrainId::of(bytes);
        if let std::collections::btree_map::Entry::Vacant(slot) = out.grains.entry(id) {
            let clen = comp.compressed_len(bytes).map_err(SweepError::Compress)?;
            slot.insert((s.len as u64, clen as u64));
        }
        if keep_order {
            out.order.push((class, id, s.len as u64));
        }
        if cdc_relevant {
            out.cdc_raw_chunks += 1;
            out.cdc_grains.entry(id).or_insert(s.len as u64);
        }
        // A span over 4 GiB cannot be a real corpus file's grain (the
        // frozen cap is 8 MiB) and cannot fit `GrainRef::unpacked_len`
        // (`u32`) at all; saturate rather than drop the grain, so the
        // frozen encoder still sees, and reports, something.
        let len = u32::try_from(s.len).unwrap_or(u32::MAX);
        refs.push(GrainRef {
            id,
            unpacked_len: len,
        });
    }
    Ok(refs)
}

#[expect(
    clippy::cast_precision_loss,
    reason = "grain lengths are below 2^53; the result is a reported mean"
)]
fn mean(lens: &[u64]) -> f64 {
    if lens.is_empty() {
        return 0.0;
    }
    lens.iter().sum::<u64>() as f64 / lens.len() as f64
}

/// `total / count`, or 0 when nothing was counted — the same shape as
/// [`mean`], for accumulators kept as running totals rather than lists.
#[expect(
    clippy::cast_precision_loss,
    reason = "byte and chunk counts below 2^53; the result is a reported mean"
)]
fn per(total: u64, count: u64) -> f64 {
    if count == 0 {
        return 0.0;
    }
    total as f64 / count as f64
}

fn median(mut lens: Vec<u64>) -> u64 {
    if lens.is_empty() {
        return 0;
    }
    lens.sort_unstable();
    lens.get(lens.len() / 2).copied().unwrap_or(0)
}

/// Cross-version retention, arm-independent (the retention pre-check:
/// the achievable ratio is bounded by
/// `1 / novel-fraction`, so this is published for every dataset,
/// including excluded candidates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retention {
    /// Paths present in both versions.
    pub paths_common: u64,
    /// Paths only in the newer version.
    pub paths_added: u64,
    /// Paths only in the older version.
    pub paths_removed: u64,
    /// Bytes in newer files byte-identical to the same path in older.
    pub path_identical_bytes: u64,
    /// Total newer file bytes.
    pub newer_bytes: u64,
}

/// Measure retention for one version pair.
///
/// # Errors
/// [`SweepError::Io`] if a corpus file cannot be read.
pub fn retention(older: &Corpus, newer: &Corpus) -> Result<Retention, SweepError> {
    let mut old_files: BTreeMap<&Vec<granary_core::manifest::Name>, GrainId> = BTreeMap::new();
    for node in &older.nodes {
        if matches!(node.kind, NodeKind::File { .. }) {
            let data = older.read(node).map_err(|source| SweepError::Io {
                path: older.path_of(node),
                source,
            })?;
            old_files.insert(&node.components, GrainId::of(&data));
        }
    }
    let mut r = Retention {
        paths_common: 0,
        paths_added: 0,
        paths_removed: 0,
        path_identical_bytes: 0,
        newer_bytes: 0,
    };
    let mut matched = 0u64;
    for node in &newer.nodes {
        if !matches!(node.kind, NodeKind::File { .. }) {
            continue;
        }
        let data = newer.read(node).map_err(|source| SweepError::Io {
            path: newer.path_of(node),
            source,
        })?;
        r.newer_bytes += data.len() as u64;
        match old_files.get(&node.components) {
            Some(&old_id) => {
                r.paths_common += 1;
                matched += 1;
                if old_id == GrainId::of(&data) {
                    r.path_identical_bytes += data.len() as u64;
                }
            }
            None => r.paths_added += 1,
        }
    }
    r.paths_removed = (old_files.len() as u64).saturating_sub(matched);
    Ok(r)
}

#[expect(
    clippy::disallowed_methods,
    reason = "test scratch-dir naming; disallowed_methods has no allow-in-tests knob"
)]
#[cfg(test)]
mod tests;
