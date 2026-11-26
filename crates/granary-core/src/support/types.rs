// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
//! Value types for the documented support profiles; none perform I/O.
use super::{Result, require};
use crate::{
    authority_answer::VolumeStatus, debug_grant::GrantScope, enrollment::PrincipalId,
    sheaf::Timestamp,
};
use std::collections::BTreeMap;
/// Validated authority profile tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityProfile {
    SingleProcess,
}
/// Controls in wire order: submission rate/burst, byte rate/burst, occupancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportControls(pub [u64; 5]);
impl SupportControls {
    /// Values in the documented order.
    #[must_use]
    pub fn tuple(self) -> (u64, u64, u64, u64, u64) {
        let [
            submission_rate,
            submission_burst,
            byte_rate,
            byte_burst,
            cap,
        ] = self.0;
        (
            submission_rate,
            submission_burst,
            byte_rate,
            byte_burst,
            cap,
        )
    }
    pub(super) fn validate(self) -> Result<()> {
        let [
            submission_rate,
            submission_burst,
            byte_rate,
            byte_burst,
            cap,
        ] = self.0;
        // These are v1 accept-set bounds, independent of deployment defaults.
        require(self.0.into_iter().all(|n| n > 0), "controls")?;
        require(byte_burst >= 268_435_456 && cap <= 7, "controls")?;
        require(
            u32::try_from(submission_burst.div_ceil(submission_rate)).is_ok()
                && u32::try_from(byte_burst.div_ceil(byte_rate)).is_ok(),
            "controls",
        )
    }
}
/// Absent log or an exact authority-status value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeView {
    NoLog,
    Log(VolumeStatus),
}
impl VolumeView {
    pub(super) fn status(&self) -> Option<&VolumeStatus> {
        match self {
            Self::NoLog => None,
            Self::Log(v) => Some(v),
        }
    }
}
/// Terminal state at the observation's selection point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalState {
    Fenced,
    Stopped,
}
/// Fixed enrollment refusal codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    Missing,
    Unreadable,
    Unprotected,
    Oversize,
    Corrupt,
    Directory,
    Stalled,
}
/// The state the last completed refresh reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotState {
    /// A set was read.
    Ok {
        /// Its principal records, active and retired.
        principals: usize,
        /// Its enrolled credentials.
        credentials: usize,
    },
    /// No set could be read.
    Unavailable(UnavailableReason),
}

/// The reader's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SnapshotCounters {
    /// Lookups answered `unavailable(missing)`.
    pub missing: u64,
    /// Lookups answered `unavailable(unreadable)`.
    pub unreadable: u64,
    /// Lookups answered `unavailable(unprotected)`.
    pub unprotected: u64,
    /// Lookups answered `unavailable(oversize)`.
    pub oversize: u64,
    /// Lookups answered `unavailable(corrupt)`.
    pub corrupt: u64,
    /// Lookups answered `unavailable(directory)`.
    pub directory: u64,
    /// Lookups answered `unavailable(stalled)`.
    pub stalled: u64,
    /// Refreshes that read and decoded a new set.
    pub reloads: u64,
    /// Refreshes that did not produce a set, for any reason.
    pub reload_failures: u64,
}

/// The reader's status, as a value: what the last completed refresh found,
/// that refresh's sequence number (the start counter's value, not a time),
/// and the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentSnapshot {
    /// The last completed refresh's verdict.
    pub state: SnapshotState,
    /// The last completed refresh's sequence number.
    pub sequence: u64,
    /// The counters.
    pub counters: SnapshotCounters,
}

/// Saturating process counters; repeated cached content verdicts count refusals,
/// while applications and retirements count transitions only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReaderCounters {
    pub refreshes: u64,
    pub reloads: u64,
    pub refusals: u64,
    pub unreadable: u64,
    pub stalled: u64,
    pub applications: u64,
    pub retirements: u64,
}

/// Separately sampled, saturating capture counters. Queued means local acceptance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureCounters {
    /// Attempts admitted by scope and budget, before formatting or final expiry.
    pub admitted: u64,
    /// Matching events suppressed by exhausted budgets.
    pub budget_suppressed: u64,
    /// Attempts refused by budget, replacement contention or expiry.
    pub suppressed: u64,
    /// Matching attempts refused by a latched or newly observed expiry.
    pub expiry_suppressed: u64,
    /// Slots whose expiry has been observed, counted once per slot.
    pub expired: u64,
    /// Attempts suppressed rather than waiting for a replacement's write guard.
    pub contention: u64,
    /// Events with missing, malformed or unsupported fields.
    pub malformed: u64,
    /// Fields or encoded records that exceed their bounds.
    pub oversize: u64,
    /// DEBUG lines accepted by the local queue.
    pub queued: u64,
    /// DEBUG lines refused by the local queue.
    pub sink_drops: u64,
}

/// Closed refusal registry; numeric encoding is explicitly assigned by the codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefusalReason {
    NotFound,
    UnknownTarget,
    AlreadyExists,
    AddressMismatch,
    VerifyFailed,
    LayoutInvalid,
    BadRange,
    ExtentTooWide,
    BadRequest,
    MethodNotAllowed,
    TooLarge,
    Internal,
    Unavailable,
    NoPrincipal,
    NotEnrolled,
    RateLimited,
    AuthorityManaged,
    InvalidCandidate,
    NoLog,
    UnknownVolume,
    StaleBase,
    OperationBound,
    NotDecided,
    EpochMismatch,
    VolumeDamaged,
    Fenced,
    Stopped,
    EnrollmentUnavailable,
}
/// Process totals and bounded retained principal rows.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RefusalSnapshot {
    pub totals: BTreeMap<RefusalReason, u64>,
    pub principals: BTreeMap<PrincipalId, BTreeMap<RefusalReason, u64>>,
}
/// Effective DEBUG authenticated-request capture; kind and level have one v1 value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportCapture {
    pub slot: u64,
    pub scope: GrantScope,
    pub remaining_lines: u64,
    pub remaining_bytes: u64,
    pub deadline: Option<Timestamp>,
    pub lease: Option<u64>,
}
