// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use granary_core::authlog::{Epoch, OPERATION_MAX};
use granary_core::authority_answer::{
    Bound, Head, LAST_CANDIDATE_SEQ, Position, Receipt, VolumeStatus,
};
use granary_core::hash::GrainId;
use granary_core::root::{self, ROOT_MAX_BYTES, VolumeName};
use std::sync::Arc;

/// Maximum candidate history accepted for one epoch and operation.
pub const OWNED_CANDIDATES_MAX: usize = 128;

/// Invalid local request; no request has been sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError(pub(super) &'static str);
impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for RequestError {}

pub(super) fn volume_name(volume: &str) -> Result<VolumeName, RequestError> {
    VolumeName::from_bytes(volume.as_bytes()).map_err(|_| RequestError("invalid volume name"))
}

/// Strictly decoded candidate, retaining the exact signed bytes and their digest.
/// Signature and chain verification belong to the caller and authority.
#[derive(Debug, Clone)]
pub struct OwnedCandidate {
    pub(super) volume: VolumeName,
    pub(super) bytes: Arc<[u8]>,
    pub(super) id: GrainId,
    pub(super) seq: u64,
}
impl OwnedCandidate {
    /// Decode bounded candidate bytes without re-encoding or checking signatures.
    ///
    /// # Errors
    /// Refuses bad volume grammar, excess size, malformed roots, a foreign
    /// volume or a sequence outside the authority's candidate range.
    pub fn new(volume: &str, bytes: Arc<[u8]>) -> Result<Self, RequestError> {
        let volume = volume_name(volume)?;
        if bytes.len() as u64 > ROOT_MAX_BYTES {
            return Err(RequestError("candidate exceeds root cap"));
        }
        let doc =
            root::decode_root(&bytes).map_err(|_| RequestError("invalid candidate encoding"))?;
        if doc.volume != volume {
            return Err(RequestError("candidate volume mismatch"));
        }
        if doc.seq == 0 || doc.seq > LAST_CANDIDATE_SEQ {
            return Err(RequestError("invalid candidate sequence"));
        }
        // In v1, root::decode_root accepts only canonical bytes: decode_header
        // checks the fixed-width fields, exact presence/reserved tags and the
        // encoding::open_envelope magic/type/version; decode_root pins signature
        // algorithms and lengths, preserves slot order, and uses Cursor::finish
        // to reject trailing bytes. Re-encoding any accepted document therefore
        // reproduces its input, so re-encoding before hashing is an equivalent
        // mutation today. Hash the original bytes to keep identity independent
        // of the encoder if the format's accepted encodings ever change.
        let id = GrainId::of(&bytes);
        Ok(Self {
            volume,
            bytes,
            id,
            seq: doc.seq,
        })
    }
    /// Exact bytes whose digest identifies this candidate.
    #[must_use]
    pub fn bytes(&self) -> &Arc<[u8]> {
        &self.bytes
    }
    /// Digest of the exact supplied bytes.
    #[must_use]
    pub fn id(&self) -> GrainId {
        self.id
    }
    /// Root sequence carried by the signed candidate.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }
}

/// An immutable submission plus the caller's owned candidate history.
/// History provenance and completeness are the caller's responsibility.
#[derive(Debug, Clone)]
pub struct PublishRequest {
    pub(super) volume: VolumeName,
    pub(super) epoch: Epoch,
    pub(super) operation: Vec<u8>,
    pub(super) candidate: OwnedCandidate,
    pub(super) owned: Vec<OwnedCandidate>,
}
impl PublishRequest {
    /// Bind a candidate and bounded history to one volume, epoch and operation.
    ///
    /// # Errors
    /// Refuses bad volume grammar, operation length outside 1–255, foreign
    /// candidates, excess or duplicate history, or history missing the submission.
    pub fn new(
        volume: &str,
        epoch: Epoch,
        operation: &[u8],
        candidate: OwnedCandidate,
        owned: Vec<OwnedCandidate>,
    ) -> Result<Self, RequestError> {
        let volume = volume_name(volume)?;
        if operation.is_empty() || operation.len() > OPERATION_MAX {
            return Err(RequestError("invalid operation length"));
        }
        if owned.len() > OWNED_CANDIDATES_MAX {
            return Err(RequestError("owned candidate history exceeds cap"));
        }
        if candidate.volume != volume || owned.iter().any(|c| c.volume != volume) {
            return Err(RequestError("owned candidate volume mismatch"));
        }
        if !owned
            .iter()
            .any(|c| c.id == candidate.id && c.bytes == candidate.bytes)
        {
            return Err(RequestError("submitted candidate missing from history"));
        }
        for (n, c) in owned.iter().enumerate() {
            if owned
                .iter()
                .skip(n.saturating_add(1))
                .any(|other| other.id == c.id)
            {
                return Err(RequestError("duplicate owned candidate"));
            }
        }
        Ok(Self {
            volume,
            epoch,
            operation: operation.to_vec(),
            candidate,
            owned,
        })
    }
    /// Submitted candidate, including its original bytes.
    #[must_use]
    pub fn candidate(&self) -> &OwnedCandidate {
        &self.candidate
    }
    /// Requested authority epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
    /// Exact operation identity sent on the wire.
    #[must_use]
    pub fn operation(&self) -> &[u8] {
        &self.operation
    }
    /// Volume named by the authenticated request URL.
    #[must_use]
    pub fn volume(&self) -> &str {
        self.volume.as_str()
    }
}

/// A landed receipt checked against the submitted candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedLanded {
    pub(super) receipt: Receipt,
    pub(super) head: Option<Head>,
}
impl CheckedLanded {
    /// Request-relative receipt. This is protocol evidence, not a signed receipt.
    #[must_use]
    pub fn receipt(&self) -> Receipt {
        self.receipt
    }
    /// Diagnostic head; the caller must verify the chain independently.
    #[must_use]
    pub fn head(&self) -> Option<Head> {
        self.head
    }
}
/// A decision checked against an owned candidate and the sent epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedDecision {
    pub(super) position: Position,
    pub(super) candidate_id: GrainId,
}
impl CheckedDecision {
    /// Log position, whose entry sequence is independent of the root sequence.
    #[must_use]
    pub fn position(&self) -> Position {
        self.position
    }
    /// Checked candidate identifier.
    #[must_use]
    pub fn candidate_id(&self) -> GrainId {
        self.candidate_id
    }
}
/// A checked lost answer; the occupant's root sequence is inferred only
/// under the conforming-authority assumption. The chain still needs verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedLost {
    pub(super) decision: CheckedDecision,
    pub(super) occupant: GrainId,
    pub(super) head: Option<Head>,
}
impl CheckedLost {
    /// Decision for the submitted candidate.
    #[must_use]
    pub fn decision(&self) -> CheckedDecision {
        self.decision
    }
    /// Occupant reported at the submitted candidate's root sequence.
    #[must_use]
    pub fn occupant(&self) -> GrainId {
        self.occupant
    }
    /// Diagnostic head, requiring independent chain verification.
    #[must_use]
    pub fn head(&self) -> Option<Head> {
        self.head
    }
}
/// Binding checked against the caller's owned history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedBound {
    pub(super) bound: Bound,
}
impl CheckedBound {
    /// Reported earlier decision for an owned candidate.
    #[must_use]
    pub fn bound(&self) -> Bound {
        self.bound
    }
}
/// Validated conflict; this request wrote nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckedConflict {
    /// Diagnostic verified head reported by the peer.
    StaleBase(Head),
    /// Earlier durable decision, matched to owned history.
    OperationBound(CheckedBound),
    /// Another operation's open decision; its candidate need not be owned.
    NotDecided(Position, GrainId),
    /// Different current epoch and an optional diagnostic head.
    EpochMismatch(Epoch, Option<Head>),
    /// The authority could not verify the volume chain.
    VolumeDamaged,
}
/// Decoded status observation. It never proves a publish write or trusted head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedStatus {
    pub(super) observation: VolumeStatus,
}
impl CheckedStatus {
    /// Snapshot of authority diagnostics, with no landing or chain proof.
    #[must_use]
    pub fn observation(&self) -> VolumeStatus {
        self.observation
    }
}

/// Identified publish admission or rule refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishRefusal {
    /// 400 bad-request.
    BadRequest,
    /// 400 invalid-candidate.
    InvalidCandidate,
    /// 400 missing-reference.
    MissingReference,
    /// 400 invalid-reference.
    InvalidReference,
    /// 413 publish-work-limit.
    PublishWorkLimit,
    /// 403 no-principal.
    NoPrincipal,
    /// 403 not-enrolled.
    NotEnrolled,
    /// 404 unknown-target.
    UnknownTarget,
    /// 404 no-log.
    NoLog,
    /// 404 unknown-volume.
    UnknownVolume,
    /// 405 method-not-allowed.
    MethodNotAllowed,
    /// 413 too-large.
    TooLarge,
}
/// Identified status refusal; reads have no principal or rate refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusRefusal {
    /// 400 bad-request.
    BadRequest,
    /// 404 unknown-target.
    UnknownTarget,
    /// 404 no-log.
    NoLog,
    /// 404 unknown-volume.
    UnknownVolume,
    /// 405 method-not-allowed.
    MethodNotAllowed,
    /// 413 too-large.
    TooLarge,
}
/// Identified publish service response, with distinct per-request evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceReason {
    /// Reply loss or load refusal: no no-write proof.
    Unavailable,
    /// Pre-engine admission failure for this request only.
    EnrollmentUnavailable,
    /// Fence may have followed a durable write.
    Fenced,
    /// Stopping may have followed a durable write.
    Stopped,
}
/// Identified status service response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusServiceReason {
    /// Temporarily unavailable.
    Unavailable,
    /// Authority fenced.
    Fenced,
    /// Authority stopped.
    Stopped,
}
/// Checked evidence from exactly one publish call. It releases no retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishResponse {
    /// Durable decision and the submitted root landed.
    Landed(CheckedLanded),
    /// Durable decision with another reported occupant.
    Lost(CheckedLost),
    /// Durable new decision; landing remains uncertain.
    Accepted(CheckedDecision),
    /// Durable open decision; landing remains uncertain.
    Open(CheckedDecision),
    /// This request wrote nothing; binding may report a prior decision.
    Conflict(CheckedConflict),
    /// This request wrote nothing.
    Refused(PublishRefusal),
    /// This request wrote nothing; earlier submissions are unaffected.
    RateLimited,
    /// Only enrollment admission failure supplies this request's no-write proof.
    ServiceUnavailable(ServiceReason),
    /// 500 internal supplies no write proof.
    Internal,
}
/// Whether a checked status answer identifies authority endpoint configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityConfiguration {
    /// Any checked answer other than unknown-target.
    Configured,
    /// The authority target is not implemented.
    UnknownTarget,
}
/// Status observation or identified refusal. Never publish-write evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusResponse {
    /// Strictly decoded diagnostic snapshot.
    Observed(CheckedStatus),
    /// Identified read refusal.
    Refused(StatusRefusal),
    /// Identified service state.
    ServiceUnavailable(StatusServiceReason),
    /// 500 internal.
    Internal,
}

/// The failed response check, independent of its diagnostic wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolErrorKind {
    MissingToken,
    InvalidResponse,
}
/// Identification retained for an unusable peer response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    pub(super) status: u16,
    pub(super) kind: ProtocolErrorKind,
    pub(super) token: Option<String>,
    pub(super) reason: String,
}
impl ProtocolError {
    /// The response check that failed.
    #[must_use]
    pub fn kind(&self) -> ProtocolErrorKind {
        self.kind
    }
    /// Observed HTTP status.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }
    /// Observed error field, when bounded and token-shaped; diagnostic only.
    #[must_use]
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }
    #[cfg(test)]
    pub(crate) fn reword(mut self, reason: &str) -> Self {
        self.reason = reason.to_owned();
        self
    }
    /// Named violated protocol check.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}
impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "authority response {} {:?}: {}",
            self.status, self.token, self.reason
        )
    }
}
impl std::error::Error for ProtocolError {}
/// Failure to send or receive a response; supplies no write proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError(pub(super) String);
#[cfg(test)]
impl From<&str> for TransportError {
    fn from(reason: &str) -> Self {
        Self(reason.to_owned())
    }
}
impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for TransportError {}
/// A call with no usable authority evidence. Every variant is uncertain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    /// Invalid local request.
    Request(RequestError),
    /// Transport failure.
    Transport(TransportError),
    /// Whole-call deadline expired.
    Elapsed,
    /// Invalid or unidentified peer response.
    Backend(ProtocolError),
}
impl std::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(e) => e.fmt(f),
            Self::Transport(e) => e.fmt(f),
            Self::Elapsed => f.write_str("authority call elapsed"),
            Self::Backend(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for AuthorityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(e) => Some(e),
            Self::Transport(e) => Some(e),
            Self::Backend(e) => Some(e),
            Self::Elapsed => None,
        }
    }
}

impl PublishResponse {
    /// Validated wire identification: status and registered error token.
    #[must_use]
    pub fn identification(&self) -> (u16, Option<&'static str>) {
        match self {
            Self::Landed(_) | Self::Lost(_) => (200, None),
            Self::Accepted(_) | Self::Open(_) => (202, None),
            Self::Conflict(c) => (
                409,
                Some(match c {
                    CheckedConflict::StaleBase(_) => "stale-base",
                    CheckedConflict::OperationBound(_) => "operation-bound",
                    CheckedConflict::NotDecided(..) => "not-decided",
                    CheckedConflict::EpochMismatch(..) => "epoch-mismatch",
                    CheckedConflict::VolumeDamaged => "volume-damaged",
                }),
            ),
            Self::Refused(r) => match r {
                PublishRefusal::BadRequest => (400, Some("bad-request")),
                PublishRefusal::InvalidCandidate => (400, Some("invalid-candidate")),
                PublishRefusal::MissingReference => (400, Some("missing-reference")),
                PublishRefusal::InvalidReference => (400, Some("invalid-reference")),
                PublishRefusal::PublishWorkLimit => (413, Some("publish-work-limit")),
                PublishRefusal::NoPrincipal => (403, Some("no-principal")),
                PublishRefusal::NotEnrolled => (403, Some("not-enrolled")),
                PublishRefusal::UnknownTarget => (404, Some("unknown-target")),
                PublishRefusal::NoLog => (404, Some("no-log")),
                PublishRefusal::UnknownVolume => (404, Some("unknown-volume")),
                PublishRefusal::MethodNotAllowed => (405, Some("method-not-allowed")),
                PublishRefusal::TooLarge => (413, Some("too-large")),
            },
            Self::RateLimited => (429, Some("rate-limited")),
            Self::ServiceUnavailable(reason) => (
                503,
                Some(match reason {
                    ServiceReason::Unavailable => "unavailable",
                    ServiceReason::EnrollmentUnavailable => "enrollment-unavailable",
                    ServiceReason::Fenced => "fenced",
                    ServiceReason::Stopped => "stopped",
                }),
            ),
            Self::Internal => (500, Some("internal")),
        }
    }
    /// Whether this response proves this request wrote no authority record.
    /// It never classifies an earlier submission or releases retention.
    #[must_use]
    pub fn request_wrote_nothing(&self) -> bool {
        matches!(
            self,
            Self::Conflict(_)
                | Self::Refused(_)
                | Self::RateLimited
                | Self::ServiceUnavailable(ServiceReason::EnrollmentUnavailable)
        )
    }
}
impl StatusResponse {
    /// Classify checked answers only; transport and protocol errors have no classification.
    #[must_use]
    pub const fn authority_configuration(&self) -> AuthorityConfiguration {
        match self {
            Self::Refused(StatusRefusal::UnknownTarget) => AuthorityConfiguration::UnknownTarget,
            _ => AuthorityConfiguration::Configured,
        }
    }

    /// Validated wire identification.
    #[must_use]
    pub fn identification(&self) -> (u16, Option<&'static str>) {
        match self {
            Self::Observed(_) => (200, None),
            Self::Refused(r) => match r {
                StatusRefusal::BadRequest => (400, Some("bad-request")),
                StatusRefusal::UnknownTarget => (404, Some("unknown-target")),
                StatusRefusal::NoLog => (404, Some("no-log")),
                StatusRefusal::UnknownVolume => (404, Some("unknown-volume")),
                StatusRefusal::MethodNotAllowed => (405, Some("method-not-allowed")),
                StatusRefusal::TooLarge => (413, Some("too-large")),
            },
            Self::ServiceUnavailable(reason) => (
                503,
                Some(match reason {
                    StatusServiceReason::Unavailable => "unavailable",
                    StatusServiceReason::Fenced => "fenced",
                    StatusServiceReason::Stopped => "stopped",
                }),
            ),
            Self::Internal => (500, Some("internal")),
        }
    }
}
