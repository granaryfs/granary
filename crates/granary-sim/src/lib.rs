// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! deterministic sim harness (unpublished).

// `disallowed_types` is `allow` on the workspace line — legitimate
// `HashMap` use exists elsewhere — and only granary-core and
// granary-client opt in today. This crate opts in for the same reason:
// hash-map iteration order is ambient per-process state, and everything
// here is either the replayed path or the artifact it is replayed
// against.
#![deny(clippy::disallowed_types)]

pub mod decision_log;
pub mod fakes;
pub mod recovery;
pub mod rng;
pub mod scenario;
pub mod sched;
pub mod secure_random;
pub mod sync_runtime;
pub mod trace;
