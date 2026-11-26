// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The PRE-REGISTERED decision rule: the threshold is fixed from a written
//! cost model before datasets are chosen, by an outcome-independent rule.
//!
//! This module is the executable form of the rule — committed before
//! the OBJECTIVE was computed for any dataset, and the only thing
//! allowed to pick the tuple. The exact boundary: the deciding W1
//! pair's raw novelty was measured by the 2026-08-10 pilot, so this is
//! not blind.
//!
//! Objective, minimised: **republish bytes** — what a client pays to
//! move from version N to version N+1. That is spec §1's actual
//! promise, and it is the axis on which small and large grains trade
//! against each other:
//!
//! ```text
//! republish(t) = novel_stored_bytes(t)      // post-per-grain-zstd
//!              + novel_manifest_bytes(t)    // exact, frozen v1 encoder
//!              + novel_grain_count(t) * binmap_entry_bytes
//! ```
//!
//! Index bytes are IN the objective because the metric requires them and
//! because they are the term that grows without bound as grains shrink.
//! **But do not expect them to be the binding counterweight on W1.**
//! Measured on the deciding W1 pair:
//! the modelled binmap term is
//! **1.4488%** of the objective at the finest grid point (8 KiB) and
//! **0.5974%** at the one the average sweep chose (1 MiB); 96.4%-98.4% of
//! the objective is measured post-zstd bytes at every point. What actually
//! stops the runaway to small grains is the per-grain compression penalty
//! (+61.4% at 8 KiB vs +4.0% at 1 MiB), which lives inside
//! `novel_stored_bytes`.
//!
//! Two consequences, stated here rather than discovered later. On a
//! W1-shaped dataset both [`INDEX_SHARE_ESCALATION`] and
//! [`BINMAP_ENTRY_SENSITIVITY`] are close to unfirable, so their
//! silence is weak evidence, not a clean bill of health:
//!
//! - Index share at the winner measured **1.563%** against the 5%
//!   limit, and it FALLS as grains coarsen — so no winner the tie-break
//!   can produce on this dataset (1.77% at 64 KiB down to 1.56% at
//!   1 MiB) can trip it. The index is not tiny everywhere (4.05% at
//!   `fixed-8K`), but this lane only ever inspects the winner.
//! - The band `{0, 49, 98}` perturbs the objective by at most +/-1.45%
//!   (at 8 KiB; +/-0.60% at the winner) against a 2% tie-break band,
//!   and the lane compares TIE-BROKEN winners. Sweeping the entry size
//!   continuously on that pair: the raw grid minimum first moves at
//!   365 B, but the tie-broken winner holds until 3550 B — 72x nominal.
//!   The registered wrongness condition is "within 2x of 49 bytes", so
//!   this lane as built cannot see the error it was written for.
//!
//! They are kept because they cost nothing and because a future dataset
//! or a larger binmap entry could make them bite. (The figures above
//! are reconciled against the committed records.)
//!
//! # The factorial decision procedure
//!
//! [`decide_factorial`] chooses `(min, normalization)` at the fixed
//! `avg = 256 KiB` and `max = 2 MiB`, over the 28-cell grid stated in
//! `tuple.rs`'s module doc, on the objective above. **W1 decides, as a
//! dataset.** W2 and W3 are reported in full at every cell; if either's
//! factorial argmin differs from the selection, the disagreement is stated
//! prominently in the report, and W1 still decides. Across W1's two
//! pairs:
//!
//! 1. Per W1 pair, over the 28 cells at binmap entry 49, compute the band:
//!    the cells whose objective is within [`TIE_BREAK_TOLERANCE`] (2%) of
//!    that pair's factorial minimum. A cell whose objective is not fully
//!    measured on both pairs (control 4, `control.rs`'s module doc) does
//!    NOT enter any band, does NOT anchor any minimum, and invalidates the
//!    run — it is never silently dropped and never counted with a zero term.
//! 2. The admissible set **A** is the intersection of the two pairs' bands.
//!    **A empty → escalation E1, no selection**: the rule does not choose.
//! 3. **Incumbent-anchored selection.** If the baseline cell
//!    `(128 KiB, L1)` — the adopted tuple, this grid's incumbent — is in
//!    **A**, select it. Otherwise select from **A** by largest `min` first,
//!    then normalization nearest the incumbent L1 (order by `|level − 1|`,
//!    ties toward the higher level). Each cell is a unique
//!    `(min, normalization)`, so the selection is unique.
//! 4. Sensitivity: repeat steps 1–3 at binmap entry 0 and 98. If any replay
//!    selects a **different** cell, **or fails to select** (an empty
//!    intersection at that band point), → escalation E3. Treating a failed
//!    replay as "not different" would compare an absent result as a match.
//!    As built, each replay is compared with the nominal OUTCOME as an
//!    `Option<Cell>`: under E1 a replay that also fails to select matches
//!    the nominal "no selection" and adds no E3; a replay that selects
//!    where the nominal point did not, or the reverse, is E3.
//! 5. Apply the remaining escalations below. E2's argmin disjunct checks
//!    the pairs' argmins, not only the selected cell.
//!
//! Why the anchor: the selection feeds a format FREEZE, which keeps the
//! adopted value unless the evidence positively displaces it, so the
//! incumbent wins ties and the rule moves off it only when the baseline is
//! not even admissible. Without the anchor a flat landscape would fill
//! **A** with all 28 cells and let the preferences ALONE move the floor:
//! the residual order above picks `(256 KiB, L1)` from a full **A** — the
//! `min` moves, the level stays — and at `min = avg` the sub-average scan
//! region is empty, so the small files this sweep exists to serve would be
//! stored whole. (A lowest-normalization-first order would instead pick
//! `(256 KiB, L0)` and move both fields; the order above is the one
//! implemented, and it picks L1.)
//! The two pairs disagreeing about the argmin is handled (the
//! intersection shrinks), not escalated; only an empty intersection is.
//!
//! **Escalations.** Any one makes the output a recommendation for Adrian
//! rather than an automatic adoption; all are recorded machine-readably:
//!
//! - **E1** — empty admissible intersection (step 2), at nominal binmap 49.
//! - **E2** — grid edge: the selected cell's `min` is 4 KiB, OR either W1
//!   pair's factorial argmin sits at `min = 4 KiB` at nominal binmap 49 —
//!   the explorable bottom edge (fastcdc accepts floors down to 64 B, and
//!   no cell may be added after a result is seen, so a curve still
//!   descending at the edge is escalated, not chased). 256 KiB and
//!   normalization 0/3 are structural bounds, not edges.
//! - **E3** — the selection changes, or ceases to exist, at binmap entry 0
//!   or 98 (step 4).
//! - **E4** — the selected cell's steady-state index share exceeds
//!   [`INDEX_SHARE_ESCALATION`] (5%). As built, the share is
//!   `index / (index + store_stored_bytes)`, where `index` is the store's
//!   manifest bytes plus its grain count times 49 — a fraction of
//!   everything stored, index included, not of stored grain bytes alone —
//!   checked on EITHER pair and raised once per pair that exceeds it.
//! - **E5** — the selected cell's coalesced range count exceeds
//!   [`REQUEST_ESCALATION_FACTOR`] (4×) the baseline cell's on EITHER W1
//!   pair, the reference being the baseline cell measured in the same run.
//!   As built, when a pair's reference is unusable (the baseline cell
//!   reports zero coalesced ranges, or either cell is missing from the
//!   grid) the check is not silently passed: `RequestCountUncheckable` is
//!   raised instead, which is an escalation outside the E1–E7 list. Its
//!   `why` text is fixed — "the baseline cell reported zero coalesced
//!   ranges" — whatever the cause, and it names no pair.
//! - **E6** — the selected cell improves on the baseline cell's objective
//!   by more than [`BASELINE_DISPLACEMENT_ESCALATION`] (5%) on the
//!   deciding pair: the tripwire for the fixed-`avg` assumption.
//! - **E7** — the selected cell is not the baseline cell. Any displacement
//!   of the incumbent is a recommendation for Adrian, never an automatic
//!   re-freeze (step 3); it fires alongside whatever else applies.
//!
//! Control failures are not escalations: they invalidate the run, and no
//! decision output exists until the controls pass.
//!
//! As built, one reading the procedure above leaves open: a pair's argmin
//! (which E2's second disjunct reads) breaks exact objective ties toward
//! the smallest `min`, then the lowest level.
//!
//! **Change discipline.** The grid, this procedure and these escalation
//! conditions may not change at all, for any reason, once the amendment
//! window closes. The window closes the moment any number the rule defines
//! — a factorial arm or a covariate — is first COMPUTED on a registered
//! dataset (either W1 pair, W2 or W3), whenever or whether it is committed.

use granary_core::hash::GRAIN_ID_BINARY_LEN;

/// Per-grain binmap cost: grain id + bin ordinal `u32` + offset `u64` +
/// compressed length `u32`. Registered as a MODEL before the format froze;
/// the frozen shard entry matches it field for field at 49 B.
///
pub const BINMAP_ENTRY_BYTES: usize = GRAIN_ID_BINARY_LEN + 4 + 8 + 4;

/// The model is BOUND to the frozen format, not merely documented against it.
/// `granary_core::binmap::SHARD_ENTRY_LEN` is the entry the shard encoder
/// actually writes, and this crate already depends on that crate — so a format
/// amendment that moves the entry fails this build instead of leaving the
/// objective quietly measuring an index cost the format no longer has.
const _: () = assert!(BINMAP_ENTRY_BYTES == granary_core::binmap::SHARD_ENTRY_LEN);

/// Pre-registered sensitivity band on the modelled term: index free,
/// nominal, and double nominal. If the winner changes across the band,
/// the decision is flagged sensitivity-dependent and escalates rather
/// than being taken automatically.
pub const BINMAP_ENTRY_SENSITIVITY: [usize; 3] = [0, BINMAP_ENTRY_BYTES, 2 * BINMAP_ENTRY_BYTES];

/// Within this fraction of the minimum, prefer the LARGER grain: fewer
/// objects, less metadata pressure, more headroom under the frozen 8 MiB cap,
/// and a simpler bin layout. Declared before results.
pub const TIE_BREAK_TOLERANCE: f64 = 0.02;

/// Steady-state index share above which the choice escalates to a
/// human instead of being taken by the rule.
pub const INDEX_SHARE_ESCALATION: f64 = 0.05;

/// Coalesced-range count above this multiple of the shipped tuple's
/// escalates: a grain size that quadruples request count on a
/// per-request-priced object store is a cost the byte objective does
/// not see.
pub const REQUEST_ESCALATION_FACTOR: f64 = 4.0;

/// E6: a factorial winner improving on the baseline CELL by more than
/// this fraction on the deciding pair means the incumbent's fixed-`avg` slice
/// may not have contained the joint optimum — a floor or normalization
/// effect larger than the entire average sweep's 5.87% range. Adrian
/// decides whether the format event waits; the rule does not decide that
/// alone.
pub const BASELINE_DISPLACEMENT_ESCALATION: f64 = 0.05;

/// One measured grid point, reduced to the terms the rule uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Average grain size — the grid coordinate and the tie-break key.
    pub avg: usize,
    /// False when the point could not be measured end to end (e.g. its
    /// manifest is not expressible in the frozen format). Ineligible
    /// points are REPORTED, never chosen.
    pub eligible: bool,
    /// Post-per-grain-zstd bytes of grains new in the newer version.
    pub novel_stored_bytes: u64,
    /// Exact encoded bytes of manifest nodes new in the newer version.
    pub novel_manifest_bytes: u64,
    /// Count of grains new in the newer version.
    pub novel_grain_count: u64,
    /// Post-zstd bytes of the union of both versions' grains.
    pub store_stored_bytes: u64,
    /// Exact encoded bytes of the union of both versions' manifests.
    pub store_manifest_bytes: u64,
    /// Count of the union of both versions' grains.
    pub store_grain_count: u64,
    /// Maximal runs of consecutive novel grains in traversal order —
    /// the range-GET count a bin-packed store would serve.
    pub coalesced_ranges: u64,
}

impl Candidate {
    /// The objective, at one point of the sensitivity band.
    #[must_use]
    pub fn republish_bytes(&self, binmap_entry: usize) -> u64 {
        self.novel_stored_bytes
            .saturating_add(self.novel_manifest_bytes)
            .saturating_add(self.novel_grain_count.saturating_mul(binmap_entry as u64))
    }

    /// Steady-state index bytes (manifest + modelled binmap) as a
    /// fraction of everything the server stores.
    #[must_use]
    pub fn index_share(&self, binmap_entry: usize) -> f64 {
        let index = self
            .store_manifest_bytes
            .saturating_add(self.store_grain_count.saturating_mul(binmap_entry as u64));
        let total = index.saturating_add(self.store_stored_bytes);
        if total == 0 {
            return 0.0;
        }
        ratio(index, total)
    }
}

/// A condition the rule refuses to resolve on its own.
#[derive(Debug, Clone, PartialEq)]
pub enum Escalation {
    /// Steady-state index share exceeds [`INDEX_SHARE_ESCALATION`].
    IndexShare {
        /// Measured share.
        share: f64,
    },
    /// Range-GET count exceeds [`REQUEST_ESCALATION_FACTOR`] times the
    /// reference tuple's.
    RequestCount {
        /// Measured multiple of the reference.
        factor: f64,
    },
    /// A different grid point wins somewhere in the sensitivity band.
    SensitivityDependent {
        /// The binmap entry size at which the winner changes.
        binmap_entry: usize,
        /// The average that wins there instead.
        alt_avg: usize,
    },
    /// The winner sits at an end of the grid, so the optimum may lie
    /// outside it. The grid cannot be refined (half-octaves are not
    /// powers of two), so this is reported as edge-limited and never
    /// chased with post-hoc points.
    GridEdge {
        /// The winning average, which is `SWEEP_AVGS`' first or last.
        avg: usize,
    },
    /// A replication pair's argmin differs from the deciding pair's.
    /// Reported, never averaged away and never used to select the more
    /// favourable pair.
    ReplicationDisagreement {
        /// Which replication pair dissented.
        pair: String,
        /// The average it would have chosen.
        alt_avg: usize,
    },
    /// A replication pair produced no eligible candidate at all, so it
    /// could not replicate anything. Silence from a pair that failed to
    /// measure is not agreement.
    ReplicationUnmeasurable {
        /// Which replication pair could not be evaluated.
        pair: String,
    },
    /// The request-count check could not be performed: the shipped
    /// reference tuple is absent from the candidate set, ineligible, or
    /// reported zero ranges. An unperformed check must not read as a
    /// passed one.
    RequestCountUncheckable {
        /// Why the reference was unusable.
        why: &'static str,
    },
    // ---- Factorial escalations. The enum grows variants exactly as the
    // registered rule says it does; the average-sweep variants above keep
    // their meanings and their protocol. ------------------------------
    /// E1 — the admissible intersection is empty: the rule does not
    /// choose (decision step 2).
    EmptyAdmissibleIntersection {
        /// The band point (nominal 49).
        binmap_entry: usize,
    },
    /// E3 — a sensitivity replay selects a different cell than the nominal
    /// one, or fails to select where the nominal selected, at binmap 0 or 98
    /// (decision step 4). Under E1 a replay that also fails raises no E3.
    SelectionSensitivity {
        /// The replay's band point.
        binmap_entry: usize,
        /// What the replay produced; `None` = it failed to select.
        replay_selection: Option<Cell>,
    },
    /// E2, first disjunct — the SELECTED cell sits at the explorable
    /// bottom edge (`min = 4 KiB`).
    FloorEdgeSelected {
        /// The edge cell.
        cell: Cell,
    },
    /// E2, second disjunct — a pair's factorial ARGMIN sits at the
    /// bottom edge at nominal binmap 49, even if the selection is
    /// interior; the band point is the registered one.
    FloorEdgeArgmin {
        /// Which pair.
        pair: String,
        /// That pair's argmin cell.
        cell: Cell,
    },
    /// E4 — the selected cell's steady-state index share exceeds
    /// [`INDEX_SHARE_ESCALATION`] on a pair.
    CellIndexShare {
        /// Which pair.
        pair: String,
        /// Measured share.
        share: f64,
    },
    /// E5 — the selected cell's coalesced range count exceeds
    /// [`REQUEST_ESCALATION_FACTOR`] times the baseline cell's on a
    /// pair (references measured in the SAME run).
    CellRequestCount {
        /// Which pair.
        pair: String,
        /// Measured multiple.
        factor: f64,
    },
    /// E6 — the winner improves on the baseline cell by more than
    /// [`BASELINE_DISPLACEMENT_ESCALATION`] on the deciding pair.
    BaselineDisplacement {
        /// The measured improvement fraction.
        improvement: f64,
    },
    /// E7 — the selected cell is not the baseline cell. ANY displacement
    /// of the incumbent is a recommendation for Adrian, never an
    /// automatic re-freeze; fires alongside whatever else applies.
    IncumbentDisplaced {
        /// The selected cell.
        selected: Cell,
    },
}

/// What the rule concluded.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// A tuple was chosen; `escalations` may still be non-empty, in
    /// which case the choice is a recommendation for Adrian, not an
    /// automatic adoption.
    Chosen {
        /// Winning average grain size — the TIE-BREAK's answer, which is
        /// not necessarily the grid minimum. Compare with `argmin_avg`.
        avg: usize,
        /// Objective value at the nominal binmap entry size, at `avg`.
        republish_bytes: u64,
        /// The average that actually MINIMISES the objective, before the
        /// tie-break. Equal to `avg` when the winner is the minimum;
        /// different when [`TIE_BREAK_TOLERANCE`] promoted a coarser
        /// point. Recorded because a report that cannot see this field
        /// can say "minimises republish bytes" about a point that does
        /// not.
        argmin_avg: usize,
        /// The objective at `argmin_avg` — the grid minimum itself.
        argmin_republish_bytes: u64,
        /// How far the winner sits BELOW the tie-break cutoff
        /// `argmin_republish_bytes * (1 + TIE_BREAK_TOLERANCE)`: the
        /// margin by which the published answer survives. A move larger
        /// than this flips the decision to a finer point. Real-valued
        /// because the cutoff is — rounding it to an integer here would
        /// bake a presentation choice into the artefact.
        headroom_to_cutoff_bytes: f64,
        /// Conditions the rule refuses to resolve alone.
        escalations: Vec<Escalation>,
    },
    /// Every grid point was ineligible.
    NoEligibleCandidate,
}

/// Apply the rule. `grid_edges` are the first and last grid averages;
/// `reference_avg` is the shipped tuple's average — 256 KiB since the format
/// event, and read from `GrainTuple::shipped()` by the caller rather than
/// written down here — whose range count the request-count escalation is
/// measured against.
#[must_use]
pub fn choose(
    candidates: &[Candidate],
    grid_edges: (usize, usize),
    reference_avg: usize,
) -> Decision {
    let Some((minimum, winner)) = minimum_and_winner(candidates, BINMAP_ENTRY_BYTES) else {
        return Decision::NoEligibleCandidate;
    };

    let mut escalations = Vec::new();

    let share = winner.index_share(BINMAP_ENTRY_BYTES);
    if share > INDEX_SHARE_ESCALATION {
        escalations.push(Escalation::IndexShare { share });
    }

    match candidates.iter().find(|c| c.avg == reference_avg) {
        None => escalations.push(Escalation::RequestCountUncheckable {
            why: "the shipped reference tuple is not in the candidate set",
        }),
        Some(r) if !r.eligible => escalations.push(Escalation::RequestCountUncheckable {
            why: "the shipped reference tuple is ineligible",
        }),
        Some(r) if r.coalesced_ranges == 0 => {
            escalations.push(Escalation::RequestCountUncheckable {
                why: "the shipped reference tuple reported zero ranges",
            });
        }
        Some(r) => {
            let factor = ratio(winner.coalesced_ranges, r.coalesced_ranges);
            if factor > REQUEST_ESCALATION_FACTOR {
                escalations.push(Escalation::RequestCount { factor });
            }
        }
    }

    for entry in BINMAP_ENTRY_SENSITIVITY {
        // `let` chain — stable in edition 2024, which this workspace uses
        // (`Cargo.toml` `edition = "2024"`). Noted because it reads as
        // unstable syntax; it compiles clean on the pinned rustc 1.97.1.
        if let Some(alt) = argmin(candidates, entry)
            && alt.avg != winner.avg
        {
            escalations.push(Escalation::SensitivityDependent {
                binmap_entry: entry,
                alt_avg: alt.avg,
            });
        }
    }

    if winner.avg == grid_edges.0 || winner.avg == grid_edges.1 {
        escalations.push(Escalation::GridEdge { avg: winner.avg });
    }

    let republish_bytes = winner.republish_bytes(BINMAP_ENTRY_BYTES);
    let argmin_republish_bytes = minimum.republish_bytes(BINMAP_ENTRY_BYTES);
    Decision::Chosen {
        avg: winner.avg,
        republish_bytes,
        argmin_avg: minimum.avg,
        argmin_republish_bytes,
        headroom_to_cutoff_bytes: headroom(argmin_republish_bytes, republish_bytes),
        escalations,
    }
}

/// The full pre-registered decision: the rule on the DECIDING pair
/// (the registered rule names it in advance), plus a
/// [`Escalation::ReplicationDisagreement`] for every replication pair
/// whose own argmin differs.
///
/// Replication pairs never vote and are never averaged in — a
/// disagreement is surfaced, not resolved: the registered rule requires
/// this escalation, and without a mechanism to compute it the decision
/// would fall to hand-judgement after seeing the results.
#[must_use]
pub fn decide_with_replication(
    deciding: &[Candidate],
    replications: &[(String, Vec<Candidate>)],
    grid_edges: (usize, usize),
    reference_avg: usize,
) -> Decision {
    let mut decision = choose(deciding, grid_edges, reference_avg);
    let Decision::Chosen {
        avg, escalations, ..
    } = &mut decision
    else {
        return decision;
    };
    for (label, candidates) in replications {
        match argmin(candidates, BINMAP_ENTRY_BYTES) {
            Some(alt) if alt.avg != *avg => {
                escalations.push(Escalation::ReplicationDisagreement {
                    pair: label.clone(),
                    alt_avg: alt.avg,
                });
            }
            Some(_) => {}
            None => escalations.push(Escalation::ReplicationUnmeasurable {
                pair: label.clone(),
            }),
        }
    }
    decision
}

/// Minimise the objective, then apply the tie-break: among candidates
/// within [`TIE_BREAK_TOLERANCE`] of the minimum, the largest average
/// wins.
fn argmin(candidates: &[Candidate], binmap_entry: usize) -> Option<&Candidate> {
    minimum_and_winner(candidates, binmap_entry).map(|(_, winner)| winner)
}

/// The grid MINIMUM and the tie-break's WINNER, in that order — the two
/// are not the same point whenever [`TIE_BREAK_TOLERANCE`] promotes a
/// coarser grain, which is exactly the fact a result record has to
/// carry. Returned together from one function so no caller can compute
/// the pair from two different candidate sets.
///
/// Among equal minima the SMALLEST average is reported as the minimum:
/// deterministic, and the conservative direction, since the tie-break is
/// the only thing allowed to move the answer coarser.
fn minimum_and_winner(
    candidates: &[Candidate],
    binmap_entry: usize,
) -> Option<(&Candidate, &Candidate)> {
    let eligible: Vec<&Candidate> = candidates.iter().filter(|c| c.eligible).collect();
    let minimum = *eligible
        .iter()
        .min_by_key(|c| (c.republish_bytes(binmap_entry), c.avg))?;
    let cutoff = cutoff_of(minimum.republish_bytes(binmap_entry));
    let winner = eligible
        .into_iter()
        .filter(|c| {
            #[expect(
                clippy::cast_precision_loss,
                reason = "byte counts below 2^53; the tolerance is a 2% band, not an equality"
            )]
            let v = c.republish_bytes(binmap_entry) as f64;
            v <= cutoff
        })
        .max_by_key(|c| c.avg)?;
    Some((minimum, winner))
}

/// The tie-break cutoff: the largest objective value still eligible for
/// promotion to a coarser grain.
#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts below 2^53; the tolerance is a 2% band, not an equality"
)]
fn cutoff_of(best: u64) -> f64 {
    best as f64 * (1.0 + TIE_BREAK_TOLERANCE)
}

/// How far `chosen` sits below the tie-break cutoff derived from `best`.
/// Zero when the choice sits exactly on the cutoff; the full 2% band
/// when the choice IS the minimum.
#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts below 2^53; the result is a reported margin"
)]
fn headroom(best: u64, chosen: u64) -> f64 {
    cutoff_of(best) - chosen as f64
}

#[expect(
    clippy::cast_precision_loss,
    reason = "byte and object counts below 2^53; the result is a reported ratio"
)]
fn ratio(num: u64, den: u64) -> f64 {
    num as f64 / den as f64
}

#[cfg(test)]
mod tests;

// ===========================================================================
// The factorial decision rule, executable form — the registered, frozen
// procedure and escalations the module doc states.
// ===========================================================================

use core::fmt;

use crate::tuple::{BASELINE_CELL, FACTORIAL_LEVELS, FACTORIAL_MINS};

/// One factorial cell's coordinates: the swept axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cell {
    /// The floor.
    pub min: usize,
    /// Normalization level, 0..=3.
    pub level: u8,
}

impl Cell {
    /// The incumbent — the adopted tuple, kept as the rule's anchor.
    pub const BASELINE: Self = Self {
        min: BASELINE_CELL.min,
        level: BASELINE_CELL.normalization.as_u8(),
    };
}

/// One cell's measurement on one W1 pair, reduced to the terms the decision uses.
/// The same objective terms as [`Candidate`]; keyed by [`Cell`] instead
/// of by average, because the factorial's swept axes are the floor and
/// the normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellMeasure {
    /// Which cell.
    pub cell: Cell,
    /// Whether the frozen v1 encoder measured the manifest exactly.
    /// Anything else INVALIDATES the run (control 4) — a cell is
    /// never a band member with a zero term and never silently absent.
    pub manifest_exact: bool,
    /// Post-per-grain-zstd bytes of grains new in the newer version.
    pub novel_stored_bytes: u64,
    /// Exact encoded bytes of manifest nodes new in the newer version.
    pub novel_manifest_bytes: u64,
    /// Count of grains new in the newer version.
    pub novel_grain_count: u64,
    /// Post-zstd bytes of the union of both versions' grains.
    pub store_stored_bytes: u64,
    /// Exact encoded bytes of the union of both versions' manifests.
    pub store_manifest_bytes: u64,
    /// Count of the union of both versions' grains.
    pub store_grain_count: u64,
    /// Maximal runs of consecutive novel grains in traversal order.
    pub coalesced_ranges: u64,
}

impl CellMeasure {
    /// The objective at one binmap entry size — the same formula as
    /// [`Candidate::republish_bytes`], restated here because the two
    /// candidate types must not depend on each other.
    #[must_use]
    pub fn republish_bytes(&self, binmap_entry: usize) -> u64 {
        self.novel_stored_bytes
            .saturating_add(self.novel_manifest_bytes)
            .saturating_add(self.novel_grain_count.saturating_mul(binmap_entry as u64))
    }

    /// Steady-state index share, as [`Candidate::index_share`].
    #[must_use]
    pub fn index_share(&self, binmap_entry: usize) -> f64 {
        let index = self
            .store_manifest_bytes
            .saturating_add(self.store_grain_count.saturating_mul(binmap_entry as u64));
        let total = index.saturating_add(self.store_stored_bytes);
        if total == 0 {
            return 0.0;
        }
        ratio(index, total)
    }
}

/// One W1 pair's measured factorial grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairGrid {
    /// The pair label (e.g. `1.96.0->1.97.0`).
    pub label: String,
    /// The 28 cells' measurements.
    pub cells: Vec<CellMeasure>,
}

/// Why the run is INVALID and no decision output exists (control 4:
/// a cell that fails to measure is a control failure, never a band
/// exclusion). Structurally unreachable at `max = 2 MiB < 8 MiB` — the
/// encoder never refuses a grain — but registered so a future grid or
/// harness change cannot reintroduce the absent-as-measured shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactorialRunError {
    /// A registered cell has no measurement on a pair.
    MissingCell {
        /// Which pair.
        pair: String,
        /// Which cell.
        cell: Cell,
    },
    /// A cell appears more than once on a pair.
    DuplicateCell {
        /// Which pair.
        pair: String,
        /// Which cell.
        cell: Cell,
    },
    /// A cell's manifest term is not exact.
    UnmeasuredCell {
        /// Which pair.
        pair: String,
        /// Which cell.
        cell: Cell,
    },
    /// A cell outside the registered grid was measured. The
    /// registered-present / duplicate / exact checks alone would ADMIT
    /// an extra cell into the bands — a selection could then come from
    /// off the frozen grid.
    OffGridCell {
        /// Which pair.
        pair: String,
        /// Which cell.
        cell: Cell,
    },
}

impl fmt::Display for FactorialRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCell { pair, cell } => write!(
                f,
                "pair {pair}: cell (min {}, nc{}) was never measured — the run is invalid",
                cell.min, cell.level
            ),
            Self::DuplicateCell { pair, cell } => write!(
                f,
                "pair {pair}: cell (min {}, nc{}) was measured twice — the run is invalid",
                cell.min, cell.level
            ),
            Self::UnmeasuredCell { pair, cell } => write!(
                f,
                "pair {pair}: cell (min {}, nc{}) has no exact manifest term — the run \
                 is invalid (control 4: never a zero term, never a silent exclusion)",
                cell.min, cell.level
            ),
            Self::OffGridCell { pair, cell } => write!(
                f,
                "pair {pair}: cell (min {}, nc{}) is not on the registered grid — the \
                 run is invalid (no cell may be added, and an unregistered cell in \
                 the bands could be selected)",
                cell.min, cell.level
            ),
        }
    }
}

impl core::error::Error for FactorialRunError {}

/// One pair's band at one binmap entry size: the argmin and the cells
/// within [`TIE_BREAK_TOLERANCE`] of it (decision step 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairBand {
    /// The pair label.
    pub pair: String,
    /// The binmap entry size this band was computed at.
    pub binmap_entry: usize,
    /// The cell minimising the objective on this pair. Ties break to
    /// the smallest `min`, then the lowest level — deterministic, and
    /// the conservative direction (the incumbent anchor, not this, is
    /// what moves answers coarser).
    pub argmin: Cell,
    /// The objective at the argmin.
    pub argmin_republish_bytes: u64,
    /// Cells within the band, sorted by cell.
    pub members: Vec<Cell>,
}

/// One sensitivity replay (decision step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    /// The binmap entry size replayed at.
    pub binmap_entry: usize,
    /// What decision steps 1–3 produce there; `None` = empty intersection.
    pub selection: Option<Cell>,
}

/// The decision's output: bands, intersection, selection (or the E1 refusal),
/// replays, and every escalation — machine-readable, written into the
/// record's decision block.
#[derive(Debug, Clone, PartialEq)]
pub struct FactorialDecision {
    /// Both pairs' bands at nominal binmap 49.
    pub bands: Vec<PairBand>,
    /// The admissible set A: the intersection of the bands (decision step 2).
    pub intersection: Vec<Cell>,
    /// The selection at nominal 49; `None` means E1 fired and the rule
    /// refused to choose.
    pub selection: Option<Cell>,
    /// The replays at binmap 0 and 98.
    pub replays: Vec<Replay>,
    /// Every escalation that fired (E1–E7, or `RequestCountUncheckable`).
    /// ANY entry makes the output a recommendation, never an adoption.
    pub escalations: Vec<Escalation>,
}

/// Decision steps 1–3 at one binmap entry size: per-pair bands, intersection,
/// incumbent-anchored selection.
fn select_at(
    deciding: &PairGrid,
    replication: &PairGrid,
    binmap_entry: usize,
) -> (Vec<PairBand>, Vec<Cell>, Option<Cell>) {
    let bands: Vec<PairBand> = [deciding, replication]
        .iter()
        .map(|grid| band_of(grid, binmap_entry))
        .collect();
    let intersection: Vec<Cell> = bands
        .first()
        .map(|first| {
            first
                .members
                .iter()
                .filter(|c| bands.iter().all(|b| b.members.contains(c)))
                .copied()
                .collect()
        })
        .unwrap_or_default();
    let selection = if intersection.is_empty() {
        None
    } else if intersection.contains(&Cell::BASELINE) {
        // Decision step 3, the incumbent anchor: a freeze keeps the adopted
        // value unless the evidence positively displaces it. Without
        // this, a flat landscape would let preference alone move the
        // floor to 256 KiB — argmin-with-tiebreak is NOT this rule.
        Some(Cell::BASELINE)
    } else {
        // Largest `min` first; then normalization nearest the incumbent
        // L1 (|level - 1|), ties toward the higher level.
        intersection
            .iter()
            .max_by_key(|c| (c.min, core::cmp::Reverse(c.level.abs_diff(1)), c.level))
            .copied()
    };
    (bands, intersection, selection)
}

/// Decision step 1 for one pair: argmin (ties to smallest min, then lowest level)
/// and the 2% band around it, inclusive boundary (same float cutoff rule as
/// `cutoff_of`).
fn band_of(grid: &PairGrid, binmap_entry: usize) -> PairBand {
    // The grids are validated before any band is computed, so `cells`
    // is never empty here; the unwrap-free fold keeps that assumption
    // out of the code path anyway.
    let mut argmin: Option<(&CellMeasure, u64)> = None;
    for m in &grid.cells {
        let v = m.republish_bytes(binmap_entry);
        let better = match argmin {
            None => true,
            Some((best, bv)) => {
                (v, m.cell.min, m.cell.level) < (bv, best.cell.min, best.cell.level)
            }
        };
        if better {
            argmin = Some((m, v));
        }
    }
    let Some((best, best_v)) = argmin else {
        return PairBand {
            pair: grid.label.clone(),
            binmap_entry,
            argmin: Cell::BASELINE,
            argmin_republish_bytes: 0,
            members: Vec::new(),
        };
    };
    let cutoff = cutoff_of(best_v);
    let mut members: Vec<Cell> = grid
        .cells
        .iter()
        .filter(|m| {
            #[expect(
                clippy::cast_precision_loss,
                reason = "byte counts below 2^53; the tolerance is a 2% band"
            )]
            let v = m.republish_bytes(binmap_entry) as f64;
            v <= cutoff
        })
        .map(|m| m.cell)
        .collect();
    members.sort_unstable();
    PairBand {
        pair: grid.label.clone(),
        binmap_entry,
        argmin: best.cell,
        argmin_republish_bytes: best_v,
        members,
    }
}

/// Validate one pair's grid against the registered design: exactly the
/// 28 cells, each once, each with an exact manifest term.
fn validate_grid(grid: &PairGrid) -> Result<(), FactorialRunError> {
    let mut seen: Vec<Cell> = Vec::with_capacity(grid.cells.len());
    for m in &grid.cells {
        if !FACTORIAL_MINS.contains(&m.cell.min) || m.cell.level > 3 {
            return Err(FactorialRunError::OffGridCell {
                pair: grid.label.clone(),
                cell: m.cell,
            });
        }
        if seen.contains(&m.cell) {
            return Err(FactorialRunError::DuplicateCell {
                pair: grid.label.clone(),
                cell: m.cell,
            });
        }
        if !m.manifest_exact {
            return Err(FactorialRunError::UnmeasuredCell {
                pair: grid.label.clone(),
                cell: m.cell,
            });
        }
        seen.push(m.cell);
    }
    for min in FACTORIAL_MINS {
        for level in FACTORIAL_LEVELS {
            let cell = Cell {
                min,
                level: level.as_u8(),
            };
            if !seen.contains(&cell) {
                return Err(FactorialRunError::MissingCell {
                    pair: grid.label.clone(),
                    cell,
                });
            }
        }
    }
    Ok(())
}

fn find_cell(grid: &PairGrid, cell: Cell) -> Option<&CellMeasure> {
    grid.cells.iter().find(|m| m.cell == cell)
}

/// The full pre-registered factorial decision (steps 1–5 of the module
/// doc executed verbatim, then E1–E7). `deciding` is W1's deciding pair
/// (1.96.0→1.97.0), `replication` its replication pair (1.95.0→1.96.0);
/// both validated first — an invalid grid is a control-4 failure and NO
/// decision output exists.
///
/// # Errors
/// [`FactorialRunError`] when either grid is not the complete,
/// exactly-measured 28-cell factorial.
pub fn decide_factorial(
    deciding: &PairGrid,
    replication: &PairGrid,
) -> Result<FactorialDecision, FactorialRunError> {
    validate_grid(deciding)?;
    validate_grid(replication)?;

    let (bands, intersection, selection) = select_at(deciding, replication, BINMAP_ENTRY_BYTES);
    let mut escalations = Vec::new();

    // E1 — empty admissible intersection at nominal 49.
    if selection.is_none() {
        escalations.push(Escalation::EmptyAdmissibleIntersection {
            binmap_entry: BINMAP_ENTRY_BYTES,
        });
    }

    // Decision step 4 — sensitivity replays. A replay that selects a
    // DIFFERENT cell, or fails to select where the nominal selected, is E3;
    // the comparison is over `Option<Cell>` directly, so under E1 (nominal
    // None) a replay that also fails compares equal and raises no E3.
    let mut replays = Vec::new();
    for entry in [0usize, 2 * BINMAP_ENTRY_BYTES] {
        let (_, _, replay_selection) = select_at(deciding, replication, entry);
        if replay_selection != selection {
            escalations.push(Escalation::SelectionSensitivity {
                binmap_entry: entry,
                replay_selection,
            });
        }
        replays.push(Replay {
            binmap_entry: entry,
            selection: replay_selection,
        });
    }

    // E2 — grid edge, BOTH disjuncts: the selected cell's floor is
    // 4 KiB, or either pair's argmin floor is. The argmin half is
    // checked whether or not a cell was selected.
    if let Some(cell) = selection
        && cell.min == 4 << 10
    {
        escalations.push(Escalation::FloorEdgeSelected { cell });
    }
    for band in &bands {
        if band.argmin.min == 4 << 10 {
            escalations.push(Escalation::FloorEdgeArgmin {
                pair: band.pair.clone(),
                cell: band.argmin,
            });
        }
    }

    if let Some(cell) = selection {
        // E4 — index share, on EITHER pair (conservative: E4 does not
        // name a pair, and an escalation costs nothing).
        for grid in [deciding, replication] {
            if let Some(m) = find_cell(grid, cell) {
                let share = m.index_share(BINMAP_ENTRY_BYTES);
                if share > INDEX_SHARE_ESCALATION {
                    escalations.push(Escalation::CellIndexShare {
                        pair: grid.label.clone(),
                        share,
                    });
                }
            }
        }

        // E5 — request count vs the baseline cell's ranges measured in
        // the SAME run, per pair (the reference is the incumbent
        // cell in this run, pinned 740/741 as the reproduction
        // cross-check — control 1's job, not this rule's).
        for grid in [deciding, replication] {
            match (find_cell(grid, cell), find_cell(grid, Cell::BASELINE)) {
                (Some(sel), Some(base)) if base.coalesced_ranges > 0 => {
                    let factor = ratio(sel.coalesced_ranges, base.coalesced_ranges);
                    if factor > REQUEST_ESCALATION_FACTOR {
                        escalations.push(Escalation::CellRequestCount {
                            pair: grid.label.clone(),
                            factor,
                        });
                    }
                }
                _ => escalations.push(Escalation::RequestCountUncheckable {
                    why: "the baseline cell reported zero coalesced ranges",
                }),
            }
        }

        // E6 — baseline displacement on the DECIDING pair: the winner
        // improving on the baseline cell by more than 5% means the
        // fixed-avg slice may not have contained the joint optimum.
        if let (Some(sel), Some(base)) = (
            find_cell(deciding, cell),
            find_cell(deciding, Cell::BASELINE),
        ) {
            let sel_v = sel.republish_bytes(BINMAP_ENTRY_BYTES);
            let base_v = base.republish_bytes(BINMAP_ENTRY_BYTES);
            if base_v > 0 && sel_v < base_v {
                let improvement = ratio(base_v.saturating_sub(sel_v), base_v);
                if improvement > BASELINE_DISPLACEMENT_ESCALATION {
                    escalations.push(Escalation::BaselineDisplacement { improvement });
                }
            }
        }

        // E7 — ANY move off the incumbent is a recommendation for
        // Adrian, never an automatic re-freeze (decision step 3, E7).
        if cell != Cell::BASELINE {
            escalations.push(Escalation::IncumbentDisplaced { selected: cell });
        }
    }

    Ok(FactorialDecision {
        bands,
        intersection,
        selection,
        replays,
        escalations,
    })
}

/// The replication-dataset report (W2/W3, single pair — no selection
/// exists across one pair): the validated grid's bands at every
/// registered sensitivity point, so the replication report's verdict
/// ("does this dataset's argmin dissent?") is computable from the record
/// alone.
///
/// # Errors
/// [`FactorialRunError`] — control 4, exactly as [`decide_factorial`].
pub fn factorial_pair_bands(grid: &PairGrid) -> Result<Vec<PairBand>, FactorialRunError> {
    validate_grid(grid)?;
    Ok(BINMAP_ENTRY_SENSITIVITY
        .iter()
        .map(|&entry| band_of(grid, entry))
        .collect())
}
