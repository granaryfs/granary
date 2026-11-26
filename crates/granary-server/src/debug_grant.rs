// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Protected publication and demand-driven application of debug grants.
//! Local verbs run before runtime or subscriber construction and acknowledge
//! publication; the reader applies grants through the capture handle.
//! The core codec owns persistent syntax; verbs own issuance and narrowing.
//! Incarnations are immutable secure draws. The demand reader owns capture
//! application and bounded revision history; its cached state performs no I/O.
//! Reader and capture share a grant clock whose failure permanently disables
//! activation. Production clock support requires Linux's suspend-inclusive time.

pub(crate) mod cli;
pub(crate) mod clock;
mod incarnation;
pub(crate) mod reader;
mod verbs;

pub(crate) use incarnation::ServerIncarnation;

pub use cli::run_debug_grant_command_line;

#[cfg(test)]
mod tests;

use crate::diagnostics::{CaptureEntry, CaptureHandle, CaptureRevision, CaptureSlot};
use crate::enrollment::ReaderStartError;
use crate::sink::LossyStderr;
use granary_core::debug_grant::{DebugGrant, Incarnation};
use granary_core::secure_random::{EntropyUnavailable, SecureRandom};
use std::path::Path;
use tracing::Subscriber;
use tracing_subscriber::EnvFilter;

pub(crate) mod events;

/// Startup-owned incarnation and clock shared by capture and the demand reader.
/// Construct inside the serving runtime, before installing the subscriber.
#[derive(Clone, Debug)]
pub struct DebugGrantHost {
    incarnation: ServerIncarnation,
    clock: clock::GrantClock,
}

impl DebugGrantHost {
    /// Read the immutable incarnation shared with the grant reader.
    #[must_use]
    pub fn incarnation(&self) -> Incarnation {
        self.incarnation.value()
    }

    /// Draw one secure incarnation and sample the production grant clock.
    ///
    /// # Errors
    /// Returns an entropy failure rather than reusing or inventing a token.
    pub fn new(random: &mut dyn SecureRandom) -> Result<Self, EntropyUnavailable> {
        Ok(Self {
            incarnation: ServerIncarnation::draw(random)?,
            clock: clock::GrantClock::production(),
        })
    }

    #[cfg(test)]
    pub(crate) fn injected(
        random: &mut dyn SecureRandom,
        clock: std::sync::Arc<dyn granary_core::clock::Clock>,
    ) -> Result<Self, EntropyUnavailable> {
        Ok(Self {
            incarnation: ServerIncarnation::draw(random)?,
            clock: clock::GrantClock::injected(clock),
        })
    }

    #[cfg(test)]
    pub(crate) fn test_clock(&self) -> clock::GrantClock {
        self.clock.clone()
    }

    /// Compose the immutable ceiling, lossy sink and grant-aware capture clock.
    pub fn subscriber(
        &self,
        ceiling: EnvFilter,
        sink: LossyStderr,
        authenticated_requests: bool,
    ) -> (CaptureHandle, impl Subscriber + Send + Sync) {
        CaptureHandle::subscriber_with_grant_clock(
            ceiling,
            sink,
            authenticated_requests,
            self.clock.clone(),
        )
    }

    /// Announce the bound listener, current incarnation and restart reset policy.
    pub fn ready(&self, addr: std::net::SocketAddr) {
        tracing::info!(addr = %addr, incarnation = %self.incarnation,
            debug_grant_restart = "reset", debug_grant_activation = self.clock.failure().map_or("clock-supported", clock::ClockFailure::as_str),
            "listening");
    }

    pub(crate) fn open(
        &self,
        path: &Path,
        accept_unsupported: bool,
        capture: CaptureHandle,
    ) -> Result<reader::DebugGrantReader, ReaderStartError> {
        reader::DebugGrantReader::open(
            path,
            accept_unsupported,
            self.incarnation.clone(),
            self.clock.clone(),
            capture,
        )
    }
}

/// A bounded local copy. The observed and accepted records carry complete decoded
/// metadata; accepted is history, while only effective denotes live capture.
/// Grant metadata and effective capture revision are sampled together. Counters
/// are separately sampled, saturating process totals. No event history is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugGrantSnapshot {
    /// The process's immutable expected incarnation.
    pub incarnation: Incarnation,
    /// `unread`, `applied` or `disabled`; unread never means missing.
    pub state: &'static str,
    /// Fixed refusal, expiry or unsupported-profile code.
    pub reason: Option<&'static str>,
    /// Issued-at lead measured on future-issued refusal, rounded up to seconds
    /// and saturated at 18446744073709551615. Cached observation preserves it.
    pub future_issued_lead_secs: Option<u64>,
    /// Last decoded record, including the received incarnation on stale refusal.
    pub observed: Option<DebugGrant>,
    /// Last accepted record; may be expired, suspended or retired.
    pub accepted: Option<DebugGrant>,
    /// Current scope, DEBUG/kind, deadline and remaining budget, if effective.
    pub effective: Option<CaptureEntry>,
    /// Last allocated capture slot, retained for diagnosis after disablement.
    pub slot: Option<CaptureSlot>,
    /// Capture revision sampled with grant metadata.
    pub capture_revision: CaptureRevision,
    /// Highest authentic file revision observed for this incarnation.
    pub high_revision: u64,
    /// Highest authentic generation observed for this incarnation.
    pub high_generation: u64,
    /// Highest retired generation; restoration cannot replenish its allowance.
    pub retired_generation: u64,
    /// Reader failures, stalls and application totals.
    pub reader_counters: reader::ReaderCounters,
    /// Admission, suppression, expiry, queue loss and malformed-record totals.
    pub capture_counters: crate::diagnostics::CaptureCounters,
}
