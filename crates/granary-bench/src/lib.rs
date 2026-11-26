// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Grain-size benchmark harness (dev-only, never shipped).
//!
//! The harness answers ONE question: which `(min, avg, max)` grain
//! tuple should granary ship, given the measured trade — dedup improves
//! at small grains (ceiling 1.688 at 8 KiB vs 1.231 at 1 MiB) while
//! per-grain compression (+61.4% at 8 KiB vs +4.0% at 1 MiB) and index
//! bytes get worse. The chunk-size curve is the by-product.
//!
//! The decision rule is PRE-REGISTERED in [`cost`]. What that
//! rule is and is NOT blind to:
//! when it was fixed, the OBJECTIVE had not been computed for any dataset and the
//! dataset set predates all measurement, but the deciding W1 pair was
//! measured by the 2026-08-10 pilot, so this is not a blind design.
//! Nothing here may be tuned after seeing a result; the threshold was
//! fixed from a written cost model before any dataset was chosen.
//!
//! No wall clock, no ambient entropy: the run date and the harness git
//! sha arrive as CLI arguments (the determinism-seam rule applies workspace-wide).

pub mod chunk;
pub mod compress;
pub mod control;
pub mod corpus;
pub mod cost;
pub mod covariates;
pub mod json;
pub mod manifest_bytes;
pub mod report;
pub mod reproduce;
pub mod sweep;
pub mod tuple;
pub mod wallclock;
