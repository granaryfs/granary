// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The clock seam: the one way logic in this workspace learns the
//! time. PURE — a trait and nothing else, so
//! core keeps its no-wall-clocks property while callers that genuinely
//! need wall time (the CLI) implement it at the edge and callers that
//! need a REPLAY (the simulator) implement it with a pinned value.
//!
//! **ONE METHOD, AND NO TIMERS.** [`Clock`] answers `now()` and offers
//! no `sleep`, no `timeout`, no `sleep_until`, no deadline of any kind.
//! That is a decision, not an omission: nothing in the Phase 1 publish
//! path waits on time — the ONE-PROBE RULE
//! ([`crate::rootstore`], normative there) deliberately resolves an
//! ambiguous CAS with a single probe and no backoff loop — so a timer
//! method here would have no caller, and a seam with no caller cannot
//! be tested for the property that matters. Timers belong with
//! TTL refresh and jitter that spreads client polls: granary-client's hint-first
//! head discovery (crate granary-client, module head.rs) is this
//! seam's first production consumer of `now()` for anything beyond
//! minting a timestamp field — its head poll reads a `Clock` to judge a
//! persisted hint's freshness against a jittered TTL. (Not an intra-doc
//! link: that module lives in a different crate, which this one may not
//! depend on.)
//!
//! **This is why the simulator needs no virtual-timer machinery.** With
//! no waits to virtualize, scenario interleaving cannot come from a
//! clock and does not: the sim owns a seeded poll loop and chooses which
//! runnable task to poll next. A virtual timer
//! wheel would order nothing that the scheduler does not already order,
//! and a replay that depended on one would depend on the timer's
//! ordering rules as well as on the seed.

use crate::sheaf::Timestamp;

/// The time, as the formats' own timestamp type.
///
/// `Send + Sync` because a clock is shared by reference across the
/// tasks one scenario drives; the trait is dyn-compatible (no `async`,
/// no generics), unlike the storage seams.
pub trait Clock: Send + Sync {
    /// The current time, as the format's own timestamp type
    /// ([`crate::sheaf::Timestamp`], which [`crate::root`] re-exports —
    /// the same value that lands in a root's `timestamp` field and in
    /// the `writer_uuid` preimage).
    ///
    /// Implementations must be free of side effects a caller can
    /// observe: two publishes handed the same clock reading must be
    /// able to produce the same bytes.
    fn now(&self) -> Timestamp;
}

#[cfg(test)]
mod tests;
