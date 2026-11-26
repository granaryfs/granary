// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The contestants: content-defined chunking at a swept tuple, the
//! size-matched fixed-block control, and whole-file dedup.
//!
//! Chunking is always PER FILE — never across file boundaries — which
//! is what granary does and what the pilot measured.
//!
//! The CDC arm calls the same `fastcdc` 4.0.1 entry point
//! `granary_core::thresh` calls, with the tuple as a parameter instead
//! of a constant. `tests/parity.rs` is the tripwire: at the shipped
//! tuple this arm must yield byte-identical cut points to
//! `granary_core::thresh::grains`, or the sweep is measuring a
//! different chunker than granary ships.

use core::fmt;

use fastcdc::v2020::FastCDC;

use crate::tuple::{FACTORIAL_AVG, GrainTuple, SWEEP_AVGS, si_label};

/// One cut: a location within the file buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Byte offset within the file.
    pub offset: usize,
    /// Byte length; always non-zero.
    pub len: usize,
}

/// A chunking strategy under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm {
    /// Content-defined chunking at a candidate tuple.
    Cdc(GrainTuple),
    /// Content-defined chunking at one factorial cell — the same cutter as
    /// [`Self::Cdc`] (one match arm covers both), with a label that encodes
    /// the CELL (`cdc-min<floor>-nc<level>`) instead of the average, because
    /// on the factorial every cell shares one average and the swept
    /// coordinates are `(min, normalization)`. A separate variant rather than
    /// a label mode: the average sweep's arm list and labels must stay
    /// byte-identical (its committed records are the factorial's reproduction
    /// control), so nothing on the average-sweep side may learn a second
    /// labelling rule.
    FactorialCdc(GrainTuple),
    /// Fixed-size blocks. At `Fixed(t.avg)` this is the headline
    /// size-matched comparator (Zhu FAST'08 §5.4).
    ///
    /// HAZARD, not a guarded invariant: `Fixed(0)` never terminates.
    /// `cut_into`'s block loop advances `offset` by
    /// `block.min(data.len() - offset)`, which is 0 when `block == 0`,
    /// so it pushes zero-length spans forever — unbounded `Vec`
    /// growth, and a violation of [`Span`]'s own "always non-zero"
    /// doc. `Fixed(0)` is not reachable from [`all_arms`] (pinned in
    /// `tests::all_arms_never_yields_a_zero_sized_fixed_block`, below),
    /// and the controller has NOT authorised a runtime guard for a
    /// path that is unreachable in a frozen plan — so this is recorded
    /// here rather than defended in code.
    Fixed(usize),
    /// One grain per file — the degenerate baseline.
    WholeFile,
}

impl Arm {
    /// Stable label used in records and reports.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Cdc(t) => format!("cdc-{}", t.label()),
            // Encodes the FULL cell — two cells may never share a label
            // (`validate_factorial_arms` is the guard,
            // `factorial_arm_labels_encode_the_cell` the pin).
            Self::FactorialCdc(t) => {
                format!("cdc-min{}-nc{}", si_label(t.min), t.normalization.as_u8())
            }
            Self::Fixed(n) => format!("fixed-{}", si_label(n)),
            Self::WholeFile => "whole-file".to_owned(),
        }
    }

    /// The average grain size this arm targets; `usize::MAX` for
    /// whole-file, which has no size parameter.
    #[must_use]
    pub const fn avg_hint(self) -> usize {
        match self {
            Self::Cdc(t) | Self::FactorialCdc(t) => t.avg,
            Self::Fixed(n) => n,
            Self::WholeFile => usize::MAX,
        }
    }

    /// Cut `data` into `out` (cleared first). Empty input yields no
    /// spans for every arm — matching `granary_core::thresh::grains`.
    pub fn cut_into(self, data: &[u8], out: &mut Vec<Span>) {
        out.clear();
        if data.is_empty() {
            return;
        }
        match self {
            Self::Cdc(t) | Self::FactorialCdc(t) => {
                for c in
                    FastCDC::with_level(data, t.min, t.avg, t.max, t.normalization.to_fastcdc())
                {
                    out.push(Span {
                        offset: c.offset,
                        len: c.length,
                    });
                }
            }
            Self::Fixed(block) => {
                let mut offset = 0usize;
                while offset < data.len() {
                    let len = block.min(data.len() - offset);
                    out.push(Span { offset, len });
                    offset += len;
                }
            }
            Self::WholeFile => out.push(Span {
                offset: 0,
                len: data.len(),
            }),
        }
    }
}

/// The arm set, defined ONCE: both contestants at every grid point plus
/// the two global reference arms. The sweep and the positive control
/// must cover exactly the same arms — two independent list-builders
/// could drift, and a sweep arm the control never validated is the one
/// thing binding constraint 3 exists to prevent.
#[must_use]
pub fn all_arms() -> Vec<Arm> {
    let mut arms = Vec::with_capacity(2 * SWEEP_AVGS.len() + 2);
    for avg in SWEEP_AVGS {
        if let Ok(t) = GrainTuple::from_avg(avg) {
            arms.push(Arm::Cdc(t));
        }
        arms.push(Arm::Fixed(avg));
    }
    arms.push(Arm::Fixed(4 << 20));
    arms.push(Arm::WholeFile);
    arms
}

/// The factorial arm set, defined ONCE for the same reason
/// [`all_arms`] is: the sweep, the controls, and the reproduction
/// comparator must cover exactly the same 31 arms. 28 factorial CDC
/// cells in the registered enumeration order, then the three reference
/// arms carried unchanged from the average sweep: `fixed-256K` (the
/// one size-matched comparator — the fixed arm has no `min` or
/// normalization, so one arm is the whole fixed side), `fixed-4M`, and
/// `whole-file`.
#[must_use]
pub fn factorial_arms() -> Vec<Arm> {
    let grid = GrainTuple::factorial_grid();
    let mut arms = Vec::with_capacity(grid.len() + 3);
    for t in grid {
        arms.push(Arm::FactorialCdc(t));
    }
    arms.push(Arm::Fixed(FACTORIAL_AVG));
    arms.push(Arm::Fixed(4 << 20));
    arms.push(Arm::WholeFile);
    arms
}

/// Why an arm list is not the registered factorial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactorialArmsError {
    /// Not 31 arms.
    WrongCount {
        /// Arms found.
        found: usize,
    },
    /// Two arms share a label — an unauditable list (record shape: a factorial
    /// whose records cannot show which cell produced them).
    DuplicateLabel {
        /// The repeated label.
        label: String,
    },
    /// A factorial arm's tuple does not carry the registered FIXED
    /// coordinates (`avg = 256 KiB`, `max = 2 MiB`). The cell-set check
    /// below compares only `(min, normalization)` — the swept axes — so
    /// without this a `FactorialCdc` wrapping, say, a 1 MiB-average
    /// tuple would pass while measuring a different chunker than its
    /// label claims. (The label itself cannot lie: `Arm::label` derives
    /// it from the same tuple the cutter uses — asserting that would be
    /// a vacuous guard.)
    WrongFixedCoordinates {
        /// The offending arm's label.
        label: String,
    },
    /// The factorial cells present are not exactly the registered
    /// 28-cell grid.
    NotTheRegisteredGrid,
}

impl fmt::Display for FactorialArmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongCount { found } => {
                write!(f, "the factorial arm list has {found} arms, not 31")
            }
            Self::DuplicateLabel { label } => {
                write!(f, "two arms share the label `{label}`")
            }
            Self::WrongFixedCoordinates { label } => write!(
                f,
                "arm `{label}` does not carry the registered fixed avg/max"
            ),
            Self::NotTheRegisteredGrid => {
                f.write_str("the CDC cells are not the registered 28-cell grid")
            }
        }
    }
}

impl core::error::Error for FactorialArmsError {}

/// Validate a factorial arm list against the registered design before
/// anything is measured under it: 31 arms, all labels distinct, every
/// label describing its own tuple, and the CDC cells exactly the
/// registered grid. [`factorial_arms`] passes by construction (pinned
/// in tests); the point of a separate validator is that the CLI checks
/// the list it is ABOUT to measure with, so a future edit to the
/// builder cannot quietly narrow or transpose the grid.
///
/// # Errors
/// [`FactorialArmsError`] naming the first violation found.
pub fn validate_factorial_arms(arms: &[Arm]) -> Result<(), FactorialArmsError> {
    if arms.len() != 31 {
        return Err(FactorialArmsError::WrongCount { found: arms.len() });
    }
    let mut labels: Vec<String> = Vec::with_capacity(arms.len());
    for arm in arms {
        let label = arm.label();
        if labels.contains(&label) {
            return Err(FactorialArmsError::DuplicateLabel { label });
        }
        if let Arm::FactorialCdc(t) = arm
            && (t.avg != FACTORIAL_AVG || t.max != crate::tuple::FACTORIAL_MAX)
        {
            return Err(FactorialArmsError::WrongFixedCoordinates { label });
        }
        labels.push(label);
    }
    let mut cells: Vec<(usize, u8)> = arms
        .iter()
        .filter_map(|a| match a {
            Arm::FactorialCdc(t) => Some((t.min, t.normalization.as_u8())),
            _ => None,
        })
        .collect();
    cells.sort_unstable();
    let mut registered: Vec<(usize, u8)> = GrainTuple::factorial_grid()
        .iter()
        .map(|t| (t.min, t.normalization.as_u8()))
        .collect();
    registered.sort_unstable();
    if cells != registered {
        return Err(FactorialArmsError::NotTheRegisteredGrid);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
