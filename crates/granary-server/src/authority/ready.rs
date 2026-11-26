// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Making an adopted log ready to serve: what the start owes every log
//! it recovers, and initialise owes a log it keeps.

use granary_core::decisionlog::DecisionLog;
use granary_core::root::VolumeName;

use super::gate::{Fence, FenceCell, LogCall, LogGate};

/// What making a log ready owes it, from its classification: where its
/// committed prefix ends, how long a tail follows it, and whether the
/// prefix holds a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Readiness {
    committed_len: usize,
    tail_len: usize,
    has_records: bool,
}

impl Readiness {
    pub(crate) const fn new(committed_len: usize, tail_len: usize, has_records: bool) -> Self {
        Self {
            committed_len,
            tail_len,
            has_records,
        }
    }

    /// Make `volume`'s log ready: a tail is truncated to the committed
    /// length; then a log holding records is re-synced (a committed
    /// survivor is made durable again before it is served), and a log
    /// with an envelope and no record runs `complete_namespace`, so its
    /// first append follows a durable name. Every call is gated, and
    /// every error fences.
    ///
    /// # Cancellation safety
    /// As [`LogGate::fencing`]: dropped once a call has begun, it fences.
    ///
    /// # Errors
    /// The [`Fence`] the engine carries.
    pub(crate) async fn make_ready<L: DecisionLog>(
        self,
        log: &L,
        gate: &LogGate,
        fence: &FenceCell,
        volume: &VolumeName,
    ) -> Result<(), Fence> {
        if self.tail_len > 0 {
            // Every length here is a slice's, and no platform this builds
            // for has a `usize` wider than the seam's `u64`.
            let len = u64::try_from(self.committed_len).unwrap_or(u64::MAX);
            gate.fencing(fence, LogCall::Truncate, Some(volume), || {
                log.truncate(volume, len)
            })
            .await?;
        }
        if self.has_records {
            gate.fencing(fence, LogCall::Resync, Some(volume), || log.resync(volume))
                .await
        } else {
            gate.fencing(fence, LogCall::CompleteNamespace, Some(volume), || {
                log.complete_namespace(volume)
            })
            .await
        }
    }
}
