// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The registered covariates — explanatory, NEVER decision inputs: C1
//! (sub-floor size distribution) and C2 (intra-file change locality). They
//! exist so the sweep's headline number is explainable either way; neither
//! can change which cell the rule selects.
//!
//! THE BOUNDARY IS STRUCTURAL: `cost.rs` — the only module that selects
//! — does not import this module, and
//! `tests::the_decision_module_cannot_see_covariates` reads `cost.rs`'s
//! source and fails if the word `covariates` ever appears in it (the
//! same source-tripwire idiom as `tests/gen_w3_constants.rs`).
//! `LOCALITY_BOUNDARY` (0.25, registered) labels the READING grid
//! only; it is deliberately defined here, on the far side of that
//! boundary, so the selection code cannot reach it even by accident.
//!
//! COMPUTING EITHER COVARIATE ON A REAL DATASET CLOSES THE RULE'S
//! AMENDMENT WINDOW (`cost.rs`'s module doc) — computation closes it,
//! not commit. The CLI prints that fact on every covariate
//! invocation, unconditionally: a banner that tried to detect
//! "real" datasets would be a guard that can be defeated by a path
//! name.
//!
//! # The covariate definitions
//!
//! **C1 — sub-floor size distribution.** For the newer tree of each W1
//! pair and of W2: (a) a log2-bucket histogram (file count and bytes per
//! `[2^k, 2^(k+1))` bucket); (b) for each threshold `m` in the `min` grid
//! ∪ {512 KiB}: the count and total bytes of files with `size < m`, and
//! among those the **whole-file-novel bytes** — bytes of sub-`m` files
//! whose full-content blake3 matches no whole file anywhere in the older
//! tree (hash-based, so a renamed identical file counts as deduped, not
//! novel). C1(m) bounds what a floor of `m` can gate; it is computed from
//! the trees alone, before any chunking.
//!
//! **C2 — intra-file change locality.** Domain: regular, non-empty files
//! present at the SAME relative path in both trees of a pair with
//! differing content. Each is chunked, both versions, with the fixed
//! reference chunker `R` ([`C2_REFERENCE`]), and
//! `locality(f) = shared_bytes(f) / newer_size(f)`, where `shared_bytes`
//! sums the lengths of the newer version's R-grains whose blake3 appears
//! in the older version's R-grain hash set (set semantics: content stored
//! once serves any number of references). Reported: the byte-weighted
//! decile histogram; the split by file class; the split by newer size,
//! registered as `< 128 KiB / < 512 KiB / ≥ 512 KiB`; and the headline scalar —
//! **byte-weighted mean locality over the sub-512-KiB domain**. Beside it,
//! always: the bytes in newer-tree files with NO path match (the population
//! C2 cannot see), and of those the whole-file-deduped bytes (renames).
//! Unit honesty: [`C2_UNIT_NOTE`].
//!
//! As built, three departures from that text: the size split is a DISJOINT
//! partition `[0, 128 KiB)` / `[128 KiB, 512 KiB)` / `[512 KiB, ∞)`, where
//! the registered `< 512 KiB` row reads as cumulative (the cumulative
//! sub-512-KiB figure is the headline scalar, not a row);
//! `shared_bytes` counts EVERY newer R-grain whose hash is in the older
//! set, a repeated grain once per occurrence — set semantics apply to the
//! older side only; and non-emptiness is tested on the NEWER side only, so
//! a file empty in the older tree and non-empty in the newer one enters
//! the domain, at locality 0.
//!
//! **The reading grid**, keyed on the SELECTION so the report cannot pick
//! its interpretation after the fact. "Moved" means the decision selected a
//! cell other than the baseline `(128 KiB, L1)`; "high locality" means the
//! C2 headline exceeds [`LOCALITY_BOUNDARY`]. The grid applies only when the
//! move, if any, is a FLOOR move (the selected `min` below the baseline's); a move to a higher
//! floor, or a pure normalization move at the baseline floor, is reported
//! outside it, in prose. Every row stays subject to the escalations: any
//! move is an E7 recommendation to Adrian, a "stayed" row closes nothing
//! while any escalation is live, and under E1 neither row applies — the
//! covariates are then reported outside this grid.
//!
//! - moved lower, high locality — the lever is real and the mechanism
//!   understood; the format event lowers the floor (E7 to Adrian).
//! - moved lower, low locality — a lower floor won and locality does not
//!   explain it; the selection is adopted as decided (E7 to Adrian), and
//!   the report must name the mechanism it finds or state plainly that it
//!   cannot.
//! - stayed, high locality — recoverable bytes exist that no cell at
//!   `avg = 256 KiB` recovers; the floor stays, and the report names the
//!   finding for the compression-granularity question (sub-grain
//!   framing).
//! - stayed, low locality — sub-floor novelty is churn, not locality; the
//!   floor question closes as a measured non-decision, not re-opened
//!   without new workload evidence.

use std::collections::BTreeSet;

use granary_core::hash::GrainId;

use crate::chunk::{Arm, Span};
use crate::corpus::{Corpus, Node, NodeKind};
use crate::sweep::{FileClass, SweepError};
use crate::tuple::{FACTORIAL_MINS, GrainTuple, NormalizationLevel};

/// `LOCALITY_BOUNDARY`: the byte-weighted mean locality above
/// which the module doc's reading grid says "high locality". A LABELLING
/// convention for the report, never a decision input.
pub const LOCALITY_BOUNDARY: f64 = 0.25;

/// The C1 threshold grid: the factorial `min` grid plus 512 KiB (C1:
/// "each threshold `m` in the min grid ∪ {512 KiB}"). 512 KiB is the
/// floor the committed average-sweep records carry, not the shipped
/// 128 KiB `granary_core::thresh::MIN_GRAIN`, and this threshold does NOT
/// follow the shipped floor — a pre-registered covariate grid is a frozen
/// input, not a mirror of the current tuple.
#[must_use]
pub fn c1_thresholds() -> Vec<u64> {
    let mut t: Vec<u64> = FACTORIAL_MINS.iter().map(|&m| m as u64).collect();
    t.push(512 << 10);
    t
}

/// The reference chunker `R` for C2: fastcdc-v2020 at
/// `(min 256, avg 4 KiB, max 32 KiB, normalization 0)` — fixed,
/// deliberately NOT a grid cell; it measures locality at near-maximal
/// resolution and its own dedup performance is not an outcome. A
/// `const` item so the compile fails if it ever stops being legal.
pub const C2_REFERENCE: GrainTuple =
    match GrainTuple::new(256, 4 << 10, 32 << 10, NormalizationLevel::L0, false) {
        Ok(t) => t,
        Err(_) => panic!("the C2 reference chunker must be a legal tuple"),
    };

/// The C2 unit-honesty note, embedded verbatim in every C2 report:
/// the two quantities are related, not equal, and a reader must never
/// be allowed to compare them silently.
pub const C2_UNIT_NOTE: &str = "locality is shared RAW bytes before compression; \
the objective is post-zstd. They are related, not equal.";

/// One C1 threshold row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C1Threshold {
    /// The threshold `m` in bytes.
    pub threshold: u64,
    /// Files with `size < m` in the newer tree.
    pub files: u64,
    /// Their total bytes.
    pub bytes: u64,
    /// Among those, bytes of files whose full-content blake3 matches no
    /// whole file ANYWHERE in the older tree (rename = deduped, not
    /// novel). C1(m) bounds what a floor of `m` can gate.
    pub whole_file_novel_bytes: u64,
}

/// C1 — the sub-floor size distribution of one newer tree, computed
/// from the trees alone, before any chunking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C1 {
    /// Log2 buckets: `(k, files, bytes)` for sizes in `[2^k, 2^(k+1))`,
    /// ascending, empty buckets omitted.
    pub buckets: Vec<(u32, u64, u64)>,
    /// Zero-byte files — no log2 bucket exists for them, and hiding
    /// them would make the histogram's file total disagree with the
    /// walked total (the vacuity the negative test demands).
    pub empty_files: u64,
    /// One row per threshold in [`c1_thresholds`], same order.
    pub thresholds: Vec<C1Threshold>,
    /// Every regular file in the newer tree (the cross-check total).
    pub total_files: u64,
    /// Their total bytes.
    pub total_bytes: u64,
}

/// Compute C1 for one pair's newer tree.
///
/// # Errors
/// [`SweepError::Io`] if a corpus file cannot be read.
pub fn c1(older: &Corpus, newer: &Corpus) -> Result<C1, SweepError> {
    let mut old_whole: BTreeSet<GrainId> = BTreeSet::new();
    for node in &older.nodes {
        if matches!(node.kind, NodeKind::File { .. }) {
            let data = read(older, node)?;
            old_whole.insert(GrainId::of(&data));
        }
    }

    let thresholds = c1_thresholds();
    let mut rows: Vec<C1Threshold> = thresholds
        .iter()
        .map(|&threshold| C1Threshold {
            threshold,
            files: 0,
            bytes: 0,
            whole_file_novel_bytes: 0,
        })
        .collect();
    let mut buckets: Vec<(u32, u64, u64)> = Vec::new();
    let mut empty_files = 0u64;
    let mut total_files = 0u64;
    let mut total_bytes = 0u64;

    for node in &newer.nodes {
        if !matches!(node.kind, NodeKind::File { .. }) {
            continue;
        }
        let data = read(newer, node)?;
        let size = data.len() as u64;
        total_files += 1;
        total_bytes += size;
        if size == 0 {
            empty_files += 1;
        } else {
            let k = size.ilog2();
            match buckets.binary_search_by_key(&k, |&(bk, _, _)| bk) {
                Ok(i) => {
                    if let Some(b) = buckets.get_mut(i) {
                        b.1 += 1;
                        b.2 += size;
                    }
                }
                Err(i) => buckets.insert(i, (k, 1, size)),
            }
        }
        let novel = !old_whole.contains(&GrainId::of(&data));
        for row in &mut rows {
            // STRICT `<`, per C1's definition above. Note the
            // boundary asymmetry against the cutter: fastcdc returns a
            // whole file at `remaining <= min_size`, so a file of
            // EXACTLY the floor is one whole-file chunk to the cutter
            // but sits in the `>= floor` side of this row — C1(m) rows
            // concentrate at power-of-two file sizes accordingly.
            // Changing the comparison is a registration AMENDMENT
            // question, not a silent fix; recorded here so
            // the boundary reading is never accidental.
            if size < row.threshold {
                row.files += 1;
                row.bytes += size;
                if novel {
                    row.whole_file_novel_bytes += size;
                }
            }
        }
    }

    let c1 = C1 {
        buckets,
        empty_files,
        thresholds: rows,
        total_files,
        total_bytes,
    };
    validate_c1(&c1)?;
    Ok(c1)
}

/// C1's own negative test, run on every real computation: a threshold
/// list that omits 512 KiB, or a histogram whose bucket sums disagree
/// with the walked totals, FAILS the run rather than reporting.
fn validate_c1(c1: &C1) -> Result<(), SweepError> {
    let has_512k = c1.thresholds.iter().any(|r| r.threshold == 512 << 10);
    let bucket_files: u64 = c1.buckets.iter().map(|&(_, f, _)| f).sum();
    let bucket_bytes: u64 = c1.buckets.iter().map(|&(_, _, b)| b).sum();
    let files_agree = bucket_files + c1.empty_files == c1.total_files;
    let bytes_agree = bucket_bytes == c1.total_bytes;
    if has_512k && files_agree && bytes_agree {
        return Ok(());
    }
    Err(SweepError::Covariate(format!(
        "C1 self-check failed: threshold-512K={has_512k} files-agree={files_agree} \
         (buckets {bucket_files} + empty {} vs walked {}) bytes-agree={bytes_agree} \
         (buckets {bucket_bytes} vs walked {})",
        c1.empty_files, c1.total_files, c1.total_bytes
    )))
}

/// C2 — intra-file change locality for one pair.
#[derive(Debug, Clone, PartialEq)]
pub struct C2 {
    /// Files in the domain: regular, non-empty, same relative path in
    /// both trees, differing content.
    pub domain_files: u64,
    /// Their newer-side bytes.
    pub domain_bytes: u64,
    /// Byte-weighted decile histogram: bytes of domain files whose
    /// locality falls in `[i/10, (i+1)/10)`, the last bucket inclusive
    /// of 1.0.
    pub decile_bytes: [u64; 10],
    /// Byte-weighted mean locality per registered class, with the bytes
    /// behind each mean.
    pub by_class: Vec<(&'static str, f64, u64)>,
    /// Byte-weighted mean locality over the DISJOINT newer-size
    /// partition `[0, 128K)` / `[128K, 512K)` / `[512K, ∞)`, with the
    /// bytes behind each mean. The rows partition; they do not nest.
    /// The cumulative sub-512K aggregate is [`Self::headline_sub_512k`]
    /// — the middle row was once labelled `<512K`, which read as the
    /// headline's basis while covering only
    /// [128K, 512K), a ~3× population understatement in the one
    /// covariate whose subject is sub-floor behaviour.
    pub by_size: Vec<(&'static str, f64, u64)>,
    /// THE HEADLINE SCALAR: byte-weighted mean locality over the
    /// sub-512-KiB domain.
    pub headline_sub_512k: f64,
    /// Beside it, ALWAYS: bytes in newer-tree files with NO path match
    /// (the population C2 cannot see)…
    pub no_path_match_bytes: u64,
    /// …and of those, the whole-file-deduped bytes (renames: a
    /// full-content match to any older whole file).
    pub no_path_match_deduped_bytes: u64,
}

/// Compute C2 for one pair.
///
/// # Errors
/// [`SweepError::Io`] if a corpus file cannot be read.
pub fn c2(older: &Corpus, newer: &Corpus) -> Result<C2, SweepError> {
    let (old_by_path, old_whole) = index_older_side(older)?;

    let mut spans: Vec<Span> = Vec::new();
    let mut decile_bytes = [0u64; 10];
    let mut domain_files = 0u64;
    let mut domain_bytes = 0u64;
    let mut class_acc: Vec<(&'static str, u64, u64)> = FileClass::ALL
        .iter()
        .map(|c| (c.label(), 0u64, 0u64)) // (label, shared, bytes)
        .collect();
    let mut size_acc: [(u64, u64); 3] = [(0, 0); 3]; // (shared, bytes)
    let mut sub_512k_shared = 0u64;
    let mut sub_512k_bytes = 0u64;
    let mut no_path_match_bytes = 0u64;
    let mut no_path_match_deduped = 0u64;

    for node in &newer.nodes {
        if !matches!(node.kind, NodeKind::File { .. }) {
            continue;
        }
        let data = read(newer, node)?;
        let size = data.len() as u64;
        let Some(&(old_id, old_node)) = old_by_path.get(&node.components) else {
            no_path_match_bytes += size;
            if size > 0 && old_whole.contains(&GrainId::of(&data)) {
                no_path_match_deduped += size;
            }
            continue;
        };
        if size == 0 || old_id == GrainId::of(&data) {
            continue; // empty, or identical content: outside the domain
        }
        // Domain member: chunk BOTH versions with R.
        let old_data = read(older, old_node)?;
        let shared = shared_bytes(&old_data, &data, &mut spans);
        let locality = share(shared, size);
        domain_files += 1;
        domain_bytes += size;
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "locality is in [0,1]; the decile index is in 0..=10 by construction"
        )]
        let decile = ((locality * 10.0) as usize).min(9);
        if let Some(slot) = decile_bytes.get_mut(decile) {
            *slot += size;
        }
        let class = FileClass::of(node);
        if let Some(slot) = class_acc.iter_mut().find(|(l, _, _)| *l == class.label()) {
            slot.1 += shared;
            slot.2 += size;
        }
        let size_ix = if size < 128 << 10 {
            0
        } else if size < 512 << 10 {
            1
        } else {
            2
        };
        if let Some(slot) = size_acc.get_mut(size_ix) {
            slot.0 += shared;
            slot.1 += size;
        }
        if size < 512 << 10 {
            sub_512k_shared += shared;
            sub_512k_bytes += size;
        }
    }
    Ok(C2 {
        domain_files,
        domain_bytes,
        decile_bytes,
        by_class: class_acc
            .into_iter()
            .map(|(l, shared, bytes)| (l, share(shared, bytes), bytes))
            .collect(),
        by_size: vec![
            (
                "<128K",
                share_of(size_acc.first()),
                size_acc.first().map_or(0, |x| x.1),
            ),
            (
                // The DISJOINT middle partition, labelled as such —
                // `<512K` here understated the sub-512K population ~3×
                // against the cumulative headline.
                "128K..<512K",
                share_of(size_acc.get(1)),
                size_acc.get(1).map_or(0, |x| x.1),
            ),
            (
                ">=512K",
                share_of(size_acc.get(2)),
                size_acc.get(2).map_or(0, |x| x.1),
            ),
        ],
        headline_sub_512k: share(sub_512k_shared, sub_512k_bytes),
        no_path_match_bytes,
        no_path_match_deduped_bytes: no_path_match_deduped,
    })
}

/// The older side, one pass: per-path whole-file hash (for the domain
/// and rename tests) — R-grains are computed lazily per domain file.
type OldIndex<'a> =
    std::collections::BTreeMap<&'a Vec<granary_core::manifest::Name>, (GrainId, &'a Node)>;

fn index_older_side(older: &Corpus) -> Result<(OldIndex<'_>, BTreeSet<GrainId>), SweepError> {
    let mut old_by_path: OldIndex<'_> = std::collections::BTreeMap::new();
    let mut old_whole: BTreeSet<GrainId> = BTreeSet::new();
    for node in &older.nodes {
        if matches!(node.kind, NodeKind::File { .. }) {
            let data = read(older, node)?;
            let id = GrainId::of(&data);
            old_by_path.insert(&node.components, (id, node));
            old_whole.insert(id);
        }
    }
    Ok((old_by_path, old_whole))
}

/// C2's `shared_bytes(f)`: the newer version's R-grain lengths whose
/// blake3 appears in the older version's R-grain hash set — SET
/// semantics on the old side (content stored once serves any number of
/// references), every matching newer span counted at its length even
/// when repeated, because locality is a property of the newer bytes.
fn shared_bytes(old_data: &[u8], new_data: &[u8], spans: &mut Vec<Span>) -> u64 {
    Arm::Cdc(C2_REFERENCE).cut_into(old_data, spans);
    let mut old_grains: BTreeSet<GrainId> = BTreeSet::new();
    for s in spans.iter() {
        if let Some(bytes) = old_data.get(s.offset..s.offset + s.len) {
            old_grains.insert(GrainId::of(bytes));
        }
    }
    Arm::Cdc(C2_REFERENCE).cut_into(new_data, spans);
    let mut shared = 0u64;
    for s in spans.iter() {
        if let Some(bytes) = new_data.get(s.offset..s.offset + s.len)
            && old_grains.contains(&GrainId::of(bytes))
        {
            shared += s.len as u64;
        }
    }
    shared
}

fn share_of(acc: Option<&(u64, u64)>) -> f64 {
    acc.map_or(0.0, |&(shared, bytes)| share(shared, bytes))
}

fn read(corpus: &Corpus, node: &Node) -> Result<Vec<u8>, SweepError> {
    corpus.read(node).map_err(|source| SweepError::Io {
        path: corpus.path_of(node),
        source,
    })
}

#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts below 2^53; the result is a reported ratio"
)]
fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 / whole as f64
}

#[expect(
    clippy::disallowed_methods,
    reason = "test scratch-dir naming; disallowed_methods has no allow-in-tests knob"
)]
#[cfg(test)]
mod tests;
