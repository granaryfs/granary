// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Candidate grain tuples and the pre-registered sweep grid.
//!
//! Every point on the grid is a tuple granary COULD ship: legal for
//! `fastcdc` 4.0.1 and expressible in the frozen v1 manifest. That is
//! how the metric's "evaluate at the shipped configuration"
//! rule is discharged for a milestone whose job is to CHOOSE the
//! shipped configuration — the sweep never proposes a point granary
//! could not adopt.
//!
//! # The factorial grid
//!
//! `min` in {4, 8, 16, 32, 64, 128, 256} KiB ([`FACTORIAL_MINS`]) crossed
//! with normalization in {0, 1, 2, 3} ([`FACTORIAL_LEVELS`]), at fixed
//! `avg = 256 KiB` and `max = 2 MiB`: **28 cells**, the baseline cell
//! `(128 KiB, 1)` being the adopted tuple. It is a factorial, not two
//! one-dimensional sweeps, because both levers act on the same population:
//! an input of length at most `min` is returned whole, and scanning from
//! `min` to `min(avg, len)` uses the hardened mask, so a file below the
//! average is scanned under it for its entire length — each normalization
//! level halves the per-byte cut probability there, and level 0 maximises
//! it. A low floor may pay off only at one level; the factorial is what
//! sees that interaction.
//!
//! **Legality of every cell:** `min` values 4,096–262,144 all lie in
//! fastcdc's 64..=1,048,576; `avg` 262,144 is in range and a power of two;
//! `max` 2,097,152 is in range and under the 8 MiB manifest ceiling; and
//! `min ≤ avg ≤ max` holds in every cell (the top of the `min` grid equals
//! `avg`).
//!
//! **Edges:** `min = 4 KiB` is a real edge — finer floors exist and are
//! unexplored, so a 4 KiB winner escalates (E2, `cost.rs`'s module doc).
//! `min = 256 KiB` is a structural ceiling (`min > avg` is not a legal
//! tuple), and {0, 1, 2, 3} is the complete normalization domain. **No
//! cell may be added to this grid after any new-dimension result has been
//! seen, for any reason.**

use core::fmt;

use fastcdc::v2020::{
    AVERAGE_MAX, AVERAGE_MIN, MAXIMUM_MAX, MAXIMUM_MIN, MINIMUM_MAX, MINIMUM_MIN, Normalization,
};
use granary_core::manifest::GRAIN_UNPACKED_MAX;
use granary_core::thresh::CHUNKER_SPEC;

/// Hard ceiling on any candidate `max`: the frozen v1 manifest refuses a
/// grain ref whose `unpacked_len` exceeds `GRAIN_UNPACKED_MAX` (the v1
/// manifest freeze; the decompression cap is the same 8 MiB). A larger
/// max is not a parameter choice, it is a format break — out of scope for the
/// sweep by construction, not by preference.
pub const GRAIN_MAX_CEILING: usize = GRAIN_UNPACKED_MAX as usize;

/// The grid's max/avg policy ratio: `max = MAX_AVG_RATIO * avg`, then
/// clamped to [`GRAIN_MAX_CEILING`]. Held constant across the grid so
/// the sweep varies ONE thing, and defined once so
/// [`GrainTuple::unclamped_max`] and [`GrainTuple::from_avg`] cannot
/// drift apart.
pub const MAX_AVG_RATIO: usize = 8;

/// The pre-registered sweep grid: one octave per step from 8 KiB to
/// 2 MiB. Fixed BEFORE any dataset was measured, and NO post-hoc point
/// may be added after a result has been seen, for any reason — a winner
/// at a grid edge is reported as edge-limited and escalates rather than
/// being chased.
pub const SWEEP_AVGS: [usize; 9] = [
    8 << 10,
    16 << 10,
    32 << 10,
    64 << 10,
    128 << 10,
    256 << 10,
    512 << 10,
    1 << 20,
    2 << 20,
];

/// The factorial's fixed average: the incumbent's `avg` — the `avg`
/// `BASELINE_CELL` is built from — not swept.
pub const FACTORIAL_AVG: usize = 256 << 10;

/// The factorial's fixed max: the incumbent's `8 × avg`, unclamped (2 MiB is under
/// the 8 MiB manifest ceiling), not swept.
pub const FACTORIAL_MAX: usize = 2 << 20;

/// The pre-registered `min` grid: octave spacing, 4 KiB to 256 KiB (=
/// `avg`, the structural ceiling — `min > avg` is not a legal fastcdc
/// tuple). Fixed as the module doc's grid BEFORE any new-dimension number
/// was computed; no cell may be added after any such result has been seen,
/// for any reason.
pub const FACTORIAL_MINS: [usize; 7] = [
    4 << 10,
    8 << 10,
    16 << 10,
    32 << 10,
    64 << 10,
    128 << 10,
    256 << 10,
];

/// The pre-registered normalization grid — the complete fastcdc
/// domain, so it has no explorable edges.
pub const FACTORIAL_LEVELS: [NormalizationLevel; 4] = [
    NormalizationLevel::L0,
    NormalizationLevel::L1,
    NormalizationLevel::L2,
    NormalizationLevel::L3,
];

/// The incumbent cell's floor: 128 KiB — the `min` of the adopted tuple, not swept.
/// The baseline cell `(BASELINE_MIN, BASELINE_LEVEL)` is the tuple the
/// format event ships unless the sweep positively displaces it
/// (the incumbent anchor).
pub const BASELINE_MIN: usize = 128 << 10;

/// The incumbent cell's normalization: LITERALLY `L1`, deliberately NOT
/// spelled `SHIPPED_NORMALIZATION`. The incumbent is the ADOPTED
/// tuple — a fixed value the rule anchors on and E7 fires against —
/// while the shipped constant follows whatever tuple a format event
/// ratifies. Kept apart, a non-L1 ratification cannot silently rewrite
/// the pre-registered incumbent, or any E7 reference to it.
pub const BASELINE_LEVEL: NormalizationLevel = NormalizationLevel::L1;

/// `FastCDC` v2020 normalization level, as our own total enum: the
/// tuple must be validatable without reaching for a fallible mapping
/// into the upstream type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizationLevel {
    /// No normalization.
    L0,
    /// The `fastcdc` crate's default level — what granary ships, and what it
    /// now threads explicitly through `with_level` rather than inheriting
    /// from `FastCDC::new` — the level is pinned with the frozen chunker tuple.
    L1,
    /// Stronger normalization.
    L2,
    /// Strongest normalization.
    L3,
}

impl NormalizationLevel {
    /// The wire/tuple representation recorded in `ChunkerSpec`.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::L0 => 0,
            Self::L1 => 1,
            Self::L2 => 2,
            Self::L3 => 3,
        }
    }

    /// Parse a recorded level; `None` for anything outside 0..=3.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::L0),
            1 => Some(Self::L1),
            2 => Some(Self::L2),
            3 => Some(Self::L3),
            _ => None,
        }
    }

    pub(crate) const fn to_fastcdc(self) -> Normalization {
        match self {
            Self::L0 => Normalization::Level0,
            Self::L1 => Normalization::Level1,
            Self::L2 => Normalization::Level2,
            Self::L3 => Normalization::Level3,
        }
    }
}

/// The normalization granary ships. Compile-time tripwire: if
/// `CHUNKER_SPEC.normalization` ever moves, this crate stops building
/// rather than silently sweeping a different chunker than core runs.
pub const SHIPPED_NORMALIZATION: NormalizationLevel = NormalizationLevel::L1;
const _: () = assert!(SHIPPED_NORMALIZATION.as_u8() == CHUNKER_SPEC.normalization);

/// A validated candidate chunker tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GrainTuple {
    /// Minimum grain size; inputs below it are never split.
    pub min: usize,
    /// Target average grain size (power of two — mask selection has no
    /// rounding ambiguity).
    pub avg: usize,
    /// Maximum grain size.
    pub max: usize,
    /// Normalization level.
    pub normalization: NormalizationLevel,
    /// True when the 8x-avg policy max was reduced to
    /// [`GRAIN_MAX_CEILING`]. The tuple stays shippable, but its
    /// max/avg ratio differs from the rest of the grid and every
    /// report must say so.
    pub max_clamped: bool,
}

/// Why a candidate tuple is not shippable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TupleError {
    /// `min` outside `fastcdc`'s accepted range.
    MinOutOfRange {
        /// The rejected value.
        min: usize,
    },
    /// `avg` outside `fastcdc`'s accepted range.
    AvgOutOfRange {
        /// The rejected value.
        avg: usize,
    },
    /// `max` outside `fastcdc`'s accepted range.
    MaxOutOfRange {
        /// The rejected value.
        max: usize,
    },
    /// `max` exceeds the frozen manifest grain cap.
    MaxOverManifestCeiling {
        /// The rejected value.
        max: usize,
        /// [`GRAIN_MAX_CEILING`].
        ceiling: usize,
    },
    /// `min <= avg <= max` violated.
    NotOrdered {
        /// Candidate minimum.
        min: usize,
        /// Candidate average.
        avg: usize,
        /// Candidate maximum.
        max: usize,
    },
    /// `avg` is not a power of two.
    AvgNotPowerOfTwo {
        /// The rejected value.
        avg: usize,
    },
}

impl fmt::Display for TupleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MinOutOfRange { min } => {
                write!(f, "min {min} outside {MINIMUM_MIN}..={MINIMUM_MAX}")
            }
            Self::AvgOutOfRange { avg } => {
                write!(f, "avg {avg} outside {AVERAGE_MIN}..={AVERAGE_MAX}")
            }
            Self::MaxOutOfRange { max } => {
                write!(f, "max {max} outside {MAXIMUM_MIN}..={MAXIMUM_MAX}")
            }
            Self::MaxOverManifestCeiling { max, ceiling } => write!(
                f,
                "max {max} exceeds the frozen manifest grain cap {ceiling}"
            ),
            Self::NotOrdered { min, avg, max } => {
                write!(f, "min {min} <= avg {avg} <= max {max} violated")
            }
            Self::AvgNotPowerOfTwo { avg } => write!(f, "avg {avg} is not a power of two"),
        }
    }
}

impl core::error::Error for TupleError {}

impl GrainTuple {
    /// Validate an explicit tuple.
    ///
    /// # Errors
    /// [`TupleError`] for any tuple `fastcdc` 4.0.1 would only
    /// `debug_assert!` on (it misbehaves data-dependently in release
    /// builds), plus granary's own manifest ceiling and
    /// power-of-two rule.
    pub const fn new(
        min: usize,
        avg: usize,
        max: usize,
        normalization: NormalizationLevel,
        max_clamped: bool,
    ) -> Result<Self, TupleError> {
        if min < MINIMUM_MIN || min > MINIMUM_MAX {
            return Err(TupleError::MinOutOfRange { min });
        }
        if avg < AVERAGE_MIN || avg > AVERAGE_MAX {
            return Err(TupleError::AvgOutOfRange { avg });
        }
        if max < MAXIMUM_MIN || max > MAXIMUM_MAX {
            return Err(TupleError::MaxOutOfRange { max });
        }
        if max > GRAIN_MAX_CEILING {
            return Err(TupleError::MaxOverManifestCeiling {
                max,
                ceiling: GRAIN_MAX_CEILING,
            });
        }
        if min > avg || avg > max {
            return Err(TupleError::NotOrdered { min, avg, max });
        }
        if !avg.is_power_of_two() {
            return Err(TupleError::AvgNotPowerOfTwo { avg });
        }
        Ok(Self {
            min,
            avg,
            max,
            normalization,
            max_clamped,
        })
    }

    /// The grid's tuple policy, applied to one average: `min = avg/2`,
    /// `max = 8*avg` clamped to [`GRAIN_MAX_CEILING`]. The ratios are
    /// granary's own shipped ratios — `min = avg/2`, `max = 8*avg`, which
    /// give 128 KiB / 256 KiB / 2 MiB at the shipped average — held
    /// constant across the grid so the sweep varies ONE thing.
    ///
    /// # Errors
    /// [`TupleError`] when the resulting tuple is not shippable — e.g.
    /// `avg = 4 MiB` gives `min = 2 MiB`, above `fastcdc`'s
    /// `MINIMUM_MAX` of 1 MiB.
    pub const fn from_avg(avg: usize) -> Result<Self, TupleError> {
        let min = avg / 2;
        let unclamped = avg * MAX_AVG_RATIO;
        let clamped = unclamped > GRAIN_MAX_CEILING;
        let max = if clamped {
            GRAIN_MAX_CEILING
        } else {
            unclamped
        };
        Self::new(min, avg, max, SHIPPED_NORMALIZATION, clamped)
    }

    /// The tuple granary ships today (`CHUNKER_SPEC`, a pinned format contract) — the
    /// reference point every ratio is reported against.
    #[must_use]
    pub const fn shipped() -> Self {
        Self {
            min: CHUNKER_SPEC.min,
            avg: CHUNKER_SPEC.avg,
            max: CHUNKER_SPEC.max,
            normalization: SHIPPED_NORMALIZATION,
            max_clamped: false,
        }
    }

    /// One factorial cell: `(min, normalization)` at the fixed
    /// `avg = 256 KiB`, `max = 2 MiB`. The max is a FIXED value
    /// here, not a ratio policy — it happens to equal
    /// `MAX_AVG_RATIO * avg`, which keeps [`Self::unclamped_max`]
    /// truthful — and 2 MiB is under the 8 MiB ceiling, so no cell
    /// is ever clamped.
    ///
    /// # Errors
    /// [`TupleError`] for a `(min, level)` outside what fastcdc 4.0.1
    /// accepts — every grid cell is legal (pinned in the tests), so an
    /// error here means a caller left the grid.
    pub const fn factorial_cell(min: usize, level: NormalizationLevel) -> Result<Self, TupleError> {
        Self::new(min, FACTORIAL_AVG, FACTORIAL_MAX, level, false)
    }

    /// The full 28-cell factorial grid, `min`-major, level-minor — the
    /// registered enumeration order. Every cell is legal (pinned by
    /// test), and the `if let Ok` cannot silently narrow the grid: the
    /// count-28 assertion in the tests is the guard.
    #[must_use]
    pub fn factorial_grid() -> Vec<Self> {
        let mut cells = Vec::with_capacity(FACTORIAL_MINS.len() * FACTORIAL_LEVELS.len());
        for min in FACTORIAL_MINS {
            for level in FACTORIAL_LEVELS {
                if let Ok(t) = Self::factorial_cell(min, level) {
                    cells.push(t);
                }
            }
        }
        cells
    }

    /// The policy max BEFORE [`GRAIN_MAX_CEILING`] is applied —
    /// `MAX_AVG_RATIO * avg`. Equal to [`Self::max`] except where the
    /// frozen cap reduced it.
    #[must_use]
    pub const fn unclamped_max(&self) -> usize {
        self.avg * MAX_AVG_RATIO
    }

    /// Short grid label, e.g. `1M` or `8K`.
    #[must_use]
    pub fn label(&self) -> String {
        si_label(self.avg)
    }
}

/// The incumbent: the adopted tuple, this grid's baseline cell.
/// The rule keeps it whenever it is admissible; any selection that
/// is not this cell is escalation E7. A `const` ITEM, not a function:
/// the initializer is evaluated at compile time, so the `panic!` arm is
/// a build failure if the cell ever stops being legal — there is no
/// runtime path to it.
pub const BASELINE_CELL: GrainTuple = match GrainTuple::factorial_cell(BASELINE_MIN, BASELINE_LEVEL)
{
    Ok(t) => t,
    Err(_) => panic!("the baseline cell must be a legal tuple"),
};

/// Render a power-of-two byte count as `8K` / `1M`, else as digits.
#[must_use]
pub fn si_label(n: usize) -> String {
    if n >= 1 << 20 && n.is_multiple_of(1 << 20) {
        format!("{}M", n >> 20)
    } else if n >= 1 << 10 && n.is_multiple_of(1 << 10) {
        format!("{}K", n >> 10)
    } else {
        format!("{n}")
    }
}

#[cfg(test)]
mod tests;
