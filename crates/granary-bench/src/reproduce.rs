// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Control 1 — the reproduction control, in process: the four arms
//! the factorial shares with the average sweep must reproduce their reference figures
//! FIELD-FOR-FIELD on every pair, or the run is INVALID and no record is
//! written. Never waived, never "re-baselined" to make a new number
//! pass.
//!
//! THE LABEL CORRESPONDENCE:
//! the baseline cell keeps the factorial label scheme (`cdc-min128K-nc1`)
//! and the control maps it to the average sweep's `cdc-256K` through
//! [`SHARED_ARMS`] — labels are nomenclature, not measurement. The
//! alternative (a legacy label on one cell) would make `cdc-256K` read as
//! a `min = 256 KiB` cell in a grid whose swept axis IS the floor, and
//! would break the two-cells-never-share-a-label rule's uniformity.
//! "Field-for-field" therefore means: every field of the committed arm
//! object EXCEPT `arm` — which is compared THROUGH the map, not exempted
//! — must be present in the fresh arm's rendering with an identical
//! canonical rendering. New fields are additive and ignored here.
//!
//! THE POPULATION RULE:
//! `cdc_relevant` is the one committed subtree whose values are
//! parameterized by a SHIPPED constant — its population is "files at or
//! above [`MIN_GRAIN`]", and the committed factorial records carry a
//! 512 KiB floor while the shipped [`MIN_GRAIN`] is 128 KiB. Comparing a
//! 512 KiB-floor subtree against a 128 KiB-floor subtree measures the
//! difference in floors, not measurement drift, so a strict rule would
//! fail every such pair and those records would be unreproducible. The rule:
//! when the committed and fresh `min_grain_bytes` are EQUAL, the
//! subtree is compared strictly like every other field; when they differ,
//! the fresh floor MUST be the shipped [`MIN_GRAIN`] (anything else is
//! emission drift — [`ReproError::CdcFloorNotShipped`]), the rest of the
//! subtree is definitionally incomparable (different populations) and is
//! skipped, and the move is RECORDED in the report
//! ([`ArmReproduction::population_moved`]) — never silently absorbed. The
//! control still refuses re-baselining; this is the one principled
//! exemption, it names its own trigger, and it closes itself the day a
//! baseline minted at the current floor is committed (equal floors shut
//! the door and restore full strictness).
//!
//! Comparison is at the CANONICAL RENDERING level (the one `Json` writer
//! both records went through), so float equality means "renders to the
//! same six decimals the committed record carries" — exactly what
//! byte-identical reproduction produces, with no epsilon to tune.

use std::fmt;
use std::path::Path;

use granary_core::thresh::MIN_GRAIN;

use crate::json::Json;
use crate::report::arm_json;
use crate::sweep::ArmMetrics;

/// The four shared arms: `(m4_label, committed_label)`.
pub const SHARED_ARMS: [(&str, &str); 4] = [
    ("cdc-min128K-nc1", "cdc-256K"),
    ("fixed-256K", "fixed-256K"),
    ("fixed-4M", "fixed-4M"),
    ("whole-file", "whole-file"),
];

/// Why the reproduction control could not PASS. Every variant
/// invalidates the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReproError {
    /// The committed baseline record could not be read.
    Io(String),
    /// The committed baseline record could not be parsed.
    Parse(String),
    /// The record parsed but is not shaped like an average-sweep record.
    Shape(String),
    /// The baseline has no pair with this label.
    MissingPair {
        /// The label looked for.
        pair: String,
    },
    /// The baseline pair has no arm with the committed label.
    MissingCommittedArm {
        /// Which pair.
        pair: String,
        /// The committed label looked for.
        arm: String,
    },
    /// The fresh measurement has no arm with the m4 label.
    MissingFreshArm {
        /// Which pair.
        pair: String,
        /// The m4 label looked for.
        arm: String,
    },
    /// A committed field is absent from the fresh rendering.
    MissingField {
        /// Which pair.
        pair: String,
        /// The m4 arm label.
        arm: String,
        /// The absent field.
        field: String,
    },
    /// The floor moved legitimately, but the population moved the
    /// WRONG WAY. Lowering the floor admits strictly more files, so
    /// `files` and `bytes` must not decrease (and raising it, not
    /// increase) — the one real invariant that survives the two
    /// populations being otherwise incomparable, and the only thing
    /// checked on this subtree while the rule's door is open.
    CdcPopulationNotMonotonic {
        /// Which pair.
        pair: String,
        /// The m4 arm label.
        arm: String,
        /// The subtree field that moved the wrong way.
        field: String,
        /// Committed floor → fresh floor.
        floors: (u64, u64),
        /// Committed value → fresh value.
        values: (u64, u64),
    },
    /// The committed and fresh `cdc_relevant` floors differ AND the
    /// fresh floor is not the shipped [`MIN_GRAIN`] — the emission
    /// itself drifted, which the population rule must never absorb.
    CdcFloorNotShipped {
        /// Which pair.
        pair: String,
        /// The m4 arm label.
        arm: String,
        /// The floor the fresh rendering carried.
        fresh: u64,
        /// The shipped constant it was required to carry.
        shipped: u64,
    },
    /// A committed field's value is not reproduced.
    Mismatch {
        /// Which pair.
        pair: String,
        /// The m4 arm label.
        arm: String,
        /// The field.
        field: String,
        /// The committed rendering.
        committed: String,
        /// The fresh rendering.
        fresh: String,
    },
}

impl fmt::Display for ReproError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "baseline record unreadable: {e}"),
            Self::Parse(e) => write!(f, "baseline record unparseable: {e}"),
            Self::Shape(e) => write!(f, "baseline record has the wrong shape: {e}"),
            Self::MissingPair { pair } => {
                write!(f, "the baseline record has no pair labelled `{pair}`")
            }
            Self::MissingCommittedArm { pair, arm } => {
                write!(f, "pair {pair}: no committed arm `{arm}` in the baseline")
            }
            Self::MissingFreshArm { pair, arm } => {
                write!(f, "pair {pair}: this run measured no arm `{arm}`")
            }
            Self::MissingField { pair, arm, field } => write!(
                f,
                "pair {pair}, arm {arm}: committed field `{field}` is absent \
                 from this run's record"
            ),
            Self::CdcPopulationNotMonotonic {
                pair,
                arm,
                field,
                floors,
                values,
            } => write!(
                f,
                "pair {pair}, arm {arm}: the cdc_relevant floor moved {} → {} \
                 but `{field}` moved {} → {}, the wrong way. Lowering the \
                 floor admits strictly MORE files; this population cannot be \
                 the same measurement re-thresholded. The run is INVALID.",
                floors.0, floors.1, values.0, values.1
            ),
            Self::CdcFloorNotShipped {
                pair,
                arm,
                fresh,
                shipped,
            } => write!(
                f,
                "pair {pair}, arm {arm}: `cdc_relevant.min_grain_bytes` is \
                 {fresh}, but the shipped MIN_GRAIN is {shipped} — the \
                 emission drifted; the population rule only spans a \
                 committed-vs-shipped constant move, never a drifted \
                 emission. The run is INVALID."
            ),
            Self::Mismatch {
                pair,
                arm,
                field,
                committed,
                fresh,
            } => write!(
                f,
                "pair {pair}, arm {arm}: `{field}` does not reproduce the \
                 committed figure — committed {committed}, measured {fresh}. \
                 The run is INVALID; restore comparability (toolchain, zstd, \
                 dataset bytes) and re-run. The control is never re-baselined."
            ),
        }
    }
}

impl core::error::Error for ReproError {}

/// What one passing check compared, for the record.
///
/// FIELDS ARE PRIVATE and the sole mint is [`check_reproduction`] — the
/// same sealing discipline `ControlsPassed` carries, applied here after
/// execution demonstrated the asymmetry: with public fields
/// a swallowed refusal could fabricate an empty "pass" and the record
/// asserted `passed: true` it never earned. A record's pass claim is
/// DERIVED from this evidence ([`Self::all_shared_arms_compared`]),
/// never asserted by a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairReproduction {
    /// The pair label.
    pair: String,
    /// Per-shared-arm comparison evidence.
    arms: Vec<ArmReproduction>,
}

/// One shared arm's comparison evidence. Fields private, same sealing
/// discipline as [`PairReproduction`] — the sole mint is
/// [`check_reproduction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmReproduction {
    /// The m4 label.
    m4_label: String,
    /// The committed average-sweep label it maps to.
    committed_label: String,
    /// Committed fields accounted for.
    fields_compared: usize,
    /// `Some((committed_floor, fresh_floor))` when the population rule
    /// fired: the committed `cdc_relevant` was minted under a different
    /// shipped `MIN_GRAIN` and the subtree was floor-checked instead of
    /// field-compared. `None` = equal floors, fully strict comparison.
    population_moved: Option<(u64, u64)>,
}

impl ArmReproduction {
    /// The m4 label.
    #[must_use]
    pub fn m4_label(&self) -> &str {
        &self.m4_label
    }

    /// The committed average-sweep label it maps to.
    #[must_use]
    pub fn committed_label(&self) -> &str {
        &self.committed_label
    }

    /// Committed fields accounted for.
    #[must_use]
    pub fn fields_compared(&self) -> usize {
        self.fields_compared
    }

    /// The recorded population move, if the rule fired (module doc).
    #[must_use]
    pub fn population_moved(&self) -> Option<(u64, u64)> {
        self.population_moved
    }
}

impl PairReproduction {
    /// The pair label.
    #[must_use]
    pub fn pair(&self) -> &str {
        &self.pair
    }

    /// Per-shared-arm comparison evidence.
    #[must_use]
    pub fn arms(&self) -> &[ArmReproduction] {
        &self.arms
    }

    /// Whether every shared arm was located and non-vacuously compared —
    /// the ONLY basis on which a record may claim the control passed.
    #[must_use]
    pub fn all_shared_arms_compared(&self) -> bool {
        self.arms.len() == SHARED_ARMS.len() && self.arms.iter().all(|a| a.fields_compared > 0)
    }
}

/// Check one measured pair against the committed baseline record.
///
/// # Errors
/// [`ReproError`] — any error invalidates the run; the caller must not
/// write a record.
pub fn check_reproduction(
    baseline_path: &Path,
    pair_label: &str,
    fresh: &[ArmMetrics],
) -> Result<PairReproduction, ReproError> {
    let text = std::fs::read_to_string(baseline_path)
        .map_err(|e| ReproError::Io(format!("{}: {e}", baseline_path.display())))?;
    let record = Json::parse(&text).map_err(|e| ReproError::Parse(e.to_string()))?;
    let pairs = record
        .get("pairs")
        .and_then(Json::items)
        .ok_or_else(|| ReproError::Shape("no `pairs` array".to_owned()))?;
    let pair = pairs
        .iter()
        .find(|p| p.get("label") == Some(&Json::s(pair_label)))
        .ok_or_else(|| ReproError::MissingPair {
            pair: pair_label.to_owned(),
        })?;
    let committed_arms = pair
        .get("arms")
        .and_then(Json::items)
        .ok_or_else(|| ReproError::Shape(format!("pair {pair_label} has no `arms` array")))?;

    let mut report = PairReproduction {
        pair: pair_label.to_owned(),
        arms: Vec::new(),
    };
    for (m4_label, committed_label) in SHARED_ARMS {
        let committed = committed_arms
            .iter()
            .find(|a| a.get("arm") == Some(&Json::s(committed_label)))
            .ok_or_else(|| ReproError::MissingCommittedArm {
                pair: pair_label.to_owned(),
                arm: committed_label.to_owned(),
            })?;
        let Json::Obj(committed_fields) = committed else {
            return Err(ReproError::Shape(format!(
                "pair {pair_label}, arm {committed_label}: not an object"
            )));
        };
        let fresh_arm = fresh.iter().find(|m| m.arm == m4_label).ok_or_else(|| {
            ReproError::MissingFreshArm {
                pair: pair_label.to_owned(),
                arm: m4_label.to_owned(),
            }
        })?;
        let rendered = arm_json(fresh_arm);
        let mut compared = 0usize;
        let mut population_moved = None;
        for (field, committed_value) in committed_fields {
            if field == "arm" {
                // Compared THROUGH the correspondence, not exempted:
                // the committed label is the lookup key above, and the
                // fresh label is the lookup key into `fresh` — both
                // sides already matched or we would not be here.
                compared += 1;
                continue;
            }
            let fresh_value = rendered
                .get(field)
                .ok_or_else(|| ReproError::MissingField {
                    pair: pair_label.to_owned(),
                    arm: m4_label.to_owned(),
                    field: field.clone(),
                })?;
            if field == "cdc_relevant"
                && let Some(moved) =
                    cdc_population_rule(pair_label, m4_label, committed_value, fresh_value)?
            {
                population_moved = Some(moved);
                compared += 1;
                continue;
            }
            let committed_text = committed_value.to_pretty();
            let fresh_text = fresh_value.to_pretty();
            if committed_text != fresh_text {
                return Err(ReproError::Mismatch {
                    pair: pair_label.to_owned(),
                    arm: m4_label.to_owned(),
                    field: field.clone(),
                    committed: committed_text.trim().to_owned(),
                    fresh: fresh_text.trim().to_owned(),
                });
            }
            compared += 1;
        }
        report.arms.push(ArmReproduction {
            m4_label: m4_label.to_owned(),
            committed_label: committed_label.to_owned(),
            fields_compared: compared,
            population_moved,
        });
    }
    Ok(report)
}

/// THE POPULATION RULE's floor arbitration for one arm (module doc).
/// `Ok(None)` = equal floors: the door is shut,
/// the caller compares the subtree strictly like every other field.
/// `Ok(Some((committed, fresh)))` = the floor legitimately moved with
/// the shipped constant: the caller records the move and skips the
/// definitionally incomparable remainder.
///
/// # Errors
/// [`ReproError::Shape`] when either floor is absent or not an unsigned
/// integer; [`ReproError::CdcFloorNotShipped`] when the floors differ
/// and the fresh one is not the shipped [`MIN_GRAIN`] — emission drift,
/// which the rule must never absorb.
fn cdc_population_rule(
    pair_label: &str,
    m4_label: &str,
    committed_value: &Json,
    fresh_value: &Json,
) -> Result<Option<(u64, u64)>, ReproError> {
    let floor_of = |v: &Json, side: &str| match v.get("min_grain_bytes") {
        Some(&Json::UInt(n)) => Ok(n),
        other => Err(ReproError::Shape(format!(
            "pair {pair_label}, arm {m4_label}: {side} \
             cdc_relevant.min_grain_bytes is {other:?}, not an unsigned \
             integer"
        ))),
    };
    let committed_floor = floor_of(committed_value, "committed")?;
    let fresh_floor = floor_of(fresh_value, "fresh")?;
    if committed_floor == fresh_floor {
        return Ok(None);
    }
    if fresh_floor != MIN_GRAIN as u64 {
        return Err(ReproError::CdcFloorNotShipped {
            pair: pair_label.to_owned(),
            arm: m4_label.to_owned(),
            fresh: fresh_floor,
            shipped: MIN_GRAIN as u64,
        });
    }
    // MONOTONICITY. Skipping the subtree is right — the two
    // populations are incomparable field-for-field — but "incomparable"
    // is not "unconstrained": the populations are NESTED. A lower floor
    // admits strictly more files, so `files` and `bytes` can only grow;
    // a higher floor, only shrink. Without this, ANY fresh subtree
    // passed as long as its floor was the shipped constant (an
    // all-zero population included — demonstrated by execution), which
    // left the milestone's own drift gate with nothing at all to say
    // about the one subtree it stops comparing.
    let grew = fresh_floor < committed_floor;
    for field in ["files", "bytes"] {
        let value_of = |v: &Json| match v.get(field) {
            Some(&Json::UInt(n)) => Ok(n),
            other => Err(ReproError::Shape(format!(
                "pair {pair_label}, arm {m4_label}: cdc_relevant.{field} is \
                 {other:?}, not an unsigned integer"
            ))),
        };
        let committed = value_of(committed_value)?;
        let fresh = value_of(fresh_value)?;
        if (grew && fresh < committed) || (!grew && fresh > committed) {
            return Err(ReproError::CdcPopulationNotMonotonic {
                pair: pair_label.to_owned(),
                arm: m4_label.to_owned(),
                field: field.to_owned(),
                floors: (committed_floor, fresh_floor),
                values: (committed, fresh),
            });
        }
    }
    Ok(Some((committed_floor, fresh_floor)))
}

#[expect(
    clippy::disallowed_methods,
    reason = "test scratch-dir naming; disallowed_methods has no allow-in-tests knob"
)]
#[cfg(test)]
mod tests;
