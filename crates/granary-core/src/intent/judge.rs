// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The agreement between an intent answer's status, token, media type and
//! body, and the request that drew it. The result
//! is a class the caller acts on, never a raw status: a validated refusal that
//! recorded no mutation, an outcome that may have been recorded, and a
//! disagreement that is a backend error are different things to do next. Each
//! class also says whether the request may be sent again unchanged
//! ([`Verdict::resend`]).

use super::{
    Error, INSTANCE_LEN, MEDIA_READBACK, MEDIA_RECEIPT, Readback, Receipt, ReceiptState,
    WRITER_LEN, decode_readback, decode_receipt,
};
use crate::hash::GrainId;
use crate::root::{RootDoc, VolumeName};

const TOKEN_SUPERSEDED: &str = "intent-superseded";
const TOKEN_BOUND: &str = "intent-bound";
const TOKEN_QUOTA: &str = "intent-quota";
const TOKEN_STOPPED: &str = "stopped";
const TOKEN_FENCED: &str = "fenced";
const TOKEN_UNAVAILABLE: &str = "unavailable";
const TOKEN_ENROLLMENT_UNAVAILABLE: &str = "enrollment-unavailable";
const TOKEN_RATE_LIMITED: &str = "rate-limited";
const TOKEN_TOO_LARGE: &str = "too-large";
const TOKEN_METHOD_NOT_ALLOWED: &str = "method-not-allowed";
const TOKEN_UNKNOWN_VOLUME: &str = "unknown-volume";
const TOKEN_UNKNOWN_TARGET: &str = "unknown-target";
const TOKEN_NOT_ENROLLED: &str = "not-enrolled";
const TOKEN_NO_PRINCIPAL: &str = "no-principal";
const TOKEN_INVALID_CANDIDATE: &str = "invalid-candidate";
const TOKEN_BAD_REQUEST: &str = "bad-request";
const TOKEN_CHANGED: &str = "intent-changed";
const TOKEN_EPOCH_EXHAUSTED: &str = "intent-epoch-exhausted";
const TOKEN_CURSOR_CHANGED: &str = "intent-cursor-changed";
const TOKEN_ABSENT: &str = "intent-absent";

/// What a client knows of the response it is judging. The media type is the
/// response's `Content-Type` field value exactly as received: a value with
/// parameters, or in another case, is not the expected media type, and a
/// response with no such field or more than one has none to pass.
#[derive(Debug, Clone, Copy)]
pub struct Reply<'a> {
    /// The HTTP status.
    pub status: u16,
    /// The response media type, if any, byte for byte.
    pub media_type: Option<&'a str>,
    /// The `Granary-Error` field value, if any.
    pub token: Option<&'a str>,
    /// The response content, as framed.
    pub body: &'a [u8],
}

/// The identity of a registration the client sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterRequest {
    /// The writer identity.
    pub writer: [u8; WRITER_LEN],
    /// Authority-issued ownership epoch.
    pub epoch: u64,
    /// The instance token of the sending process.
    pub instance: [u8; INSTANCE_LEN],
    /// The generation sent.
    pub generation: u64,
    /// The `GrainId` of the prepared root's exact bytes as sent.
    pub root_id: GrainId,
}

/// The identity of a release the client sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseRequest {
    /// The writer identity.
    pub writer: [u8; WRITER_LEN],
    /// Authority-issued ownership epoch.
    pub epoch: u64,
    /// The instance token of the sending process.
    pub instance: [u8; INSTANCE_LEN],
    /// The generation released: everything at or below it.
    pub generation: u64,
}

/// A validated refusal that no retransmission can change: the request was
/// judged and no mutation was recorded, so the client retains its prepared
/// state and request evidence and surfaces the refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `400` + `bad-request`.
    BadRequest,
    /// `400` + `invalid-candidate`: the prepared root failed strict decoding,
    /// named another volume or failed its signature.
    InvalidPreparedRoot,
    /// `403` + `no-principal`.
    NoPrincipal,
    /// `403` + `not-enrolled`.
    NotEnrolled,
    /// `404` + `unknown-volume`: the authority does not serve the volume.
    UnknownVolume,
    /// `405` + `method-not-allowed`.
    MethodNotAllowed,
    /// `413` + `too-large`.
    TooLarge,
}

/// Why an answer proves nothing about whether the request was recorded. The
/// client sends the request again unchanged, within its retransmit horizon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownCause {
    /// `500`.
    Internal,
    /// `503` + `unavailable`.
    Unavailable,
    /// `503` + `fenced`.
    Fenced,
    /// `503` + `stopped`.
    Stopped,
    /// Another `5xx`, or a `503` with no token the table names.
    Other(u16),
}

/// A disagreement between the answer and the request or the protocol. It is a
/// backend error: never a success, never a rebase, nothing released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disagreement {
    /// A status the table has no row for, for this operation.
    UnexpectedStatus(u16),
    /// A status the table has, with a token absent or not that row's.
    TokenMismatch(u16),
    /// A `Granary-Error` field on a `2xx`.
    TokenOnSuccess,
    /// A row that carries a body whose media type is absent or another body's.
    WrongMediaType,
    /// An intent media type on a row that carries no intent body.
    UnexpectedIntentBody,
    /// The body failed its strict decode.
    Body(Error),
    /// The receipt names another writer than the request.
    ReceiptWriter,
    /// The receipt's instance token is not the one the row needs: the
    /// request's on an answer that accepted it or reports a same-epoch overtake.
    ReceiptInstance,
    /// Receipt ownership epoch fails the required equality or forward relation.
    ReceiptEpoch,
    /// Grant does not bind the exact ownership request bytes.
    GrantRequestId,
    /// The state/root snapshot differs where equality is required, or is
    /// unchanged where a changed snapshot is required.
    ReceiptState,
    /// The receipt's generation is not the one the row needs.
    ReceiptGeneration,
    /// The receipt's root id is not the one the row needs.
    ReceiptRootId,
}

impl Disagreement {
    /// The stable name of this disagreement with the expected response.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::UnexpectedStatus(_) => "unexpected-status",
            Self::TokenMismatch(_) => "token-mismatch",
            Self::TokenOnSuccess => "token-on-success",
            Self::WrongMediaType => "wrong-media-type",
            Self::UnexpectedIntentBody => "unexpected-intent-body",
            Self::Body(_) => "body",
            Self::ReceiptWriter => "receipt-writer",
            Self::ReceiptEpoch => "receipt-epoch",
            Self::GrantRequestId => "grant-request-id",
            Self::ReceiptInstance => "receipt-instance",
            Self::ReceiptState => "receipt-state",
            Self::ReceiptGeneration => "receipt-generation",
            Self::ReceiptRootId => "receipt-root-id",
        }
    }
}

/// Whether a request may be sent again unchanged, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resend {
    /// Never: the answer is final, or a defect, or a fence.
    Never,
    /// Now, subject to the client's own backoff and its retransmit horizon.
    Unchanged,
    /// Once the `Retry-After` the answer carried, or the client's own backoff
    /// if longer, has elapsed.
    AfterDelay,
}

/// What a client does when no answer was judged at all: no reply, a timeout,
/// a broken connection, or a `REFUSED_STREAM` reset. Intent mutations are
/// idempotent on their exact request bytes, so the request goes again unchanged.
pub const RESEND_AFTER_TRANSPORT_FAILURE: Resend = Resend::Unchanged;

/// The class of an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict<T> {
    /// A proven `200`: the request's receipt or ownership grant, or the readback.
    Accepted(T),
    /// `409` + `intent-superseded` under a strictly newer E: the instance is fenced;
    /// the receipt reports the row as recorded.
    Superseded(Receipt),
    /// `409` + `intent-bound`: the client has a defect and surfaces it.
    Bound(Receipt),
    /// Same epoch/token has already overtaken this registration; informational.
    Overtaken(Receipt),
    /// Conditional selection or an absent acquisition's row changed.
    Changed(Receipt),
    /// Ownership no longer exists; fence owned requests.
    Absent,
    /// Absent acquisition used a stale principal/volume cursor.
    CursorChanged,
    /// No more ownership epochs can be allocated.
    EpochExhausted,
    /// `409` + `intent-quota`: no row was created or reopened; there is no
    /// intent body.
    OverQuota,
    /// A validated refusal no retransmission can change.
    Refused(Refusal),
    /// `429` + `rate-limited`: a timing answer, not a refusal. Nothing was
    /// registered, and the request goes again unchanged after the delay.
    RateLimited,
    /// `404` + `unknown-target`: the server does not implement intents, and a
    /// client that needs one refuses to start with a named error.
    NotImplemented,
    /// `503` + `enrollment-unavailable`: the request did not reach the
    /// authority engine; send it again unchanged.
    EnrollmentUnavailable,
    /// The request may have been recorded; send it again unchanged.
    Unknown(UnknownCause),
    /// The answer disagrees with the protocol or the request.
    Backend(Disagreement),
}

impl<T> Verdict<T> {
    /// Whether the request may be sent again unchanged. Only an answer that
    /// proves nothing about the request (a `5xx`, an unavailable enrollment)
    /// and a `429` allow it; every validated `4xx` and every fence is final.
    #[must_use]
    pub const fn resend(&self) -> Resend {
        match self {
            Self::EnrollmentUnavailable | Self::Unknown(_) => Resend::Unchanged,
            Self::RateLimited => Resend::AfterDelay,
            Self::Accepted(_)
            | Self::Superseded(_)
            | Self::Bound(_)
            | Self::Overtaken(_)
            | Self::Changed(_)
            | Self::Absent
            | Self::CursorChanged
            | Self::EpochExhausted
            | Self::OverQuota
            | Self::Refused(_)
            | Self::NotImplemented
            | Self::Backend(_) => Resend::Never,
        }
    }
}

#[derive(Clone, Copy)]
enum Write<'r> {
    Register(&'r RegisterRequest),
    Release(&'r ReleaseRequest),
}

#[derive(Clone, Copy)]
enum Op<'r> {
    Write(Write<'r>),
    Readback,
    Ownership(&'r super::Ownership),
}

impl Op<'_> {
    const fn success_media(self) -> &'static str {
        match self {
            Self::Write(_) => MEDIA_RECEIPT,
            Self::Readback => MEDIA_READBACK,
            Self::Ownership(_) => super::MEDIA_GRANT,
        }
    }
    const fn is_acquire(self) -> bool {
        matches!(
            self,
            Self::Ownership(super::Ownership {
                mode: super::OwnershipMode::Acquire { .. },
                ..
            })
        )
    }

    const fn writes(self) -> bool {
        matches!(self, Self::Write(_) | Self::Ownership(_))
    }
}

/// Byte-exact: no parameters, no case folding, as the transport that fetched
/// the answer compares it.
fn media_is(media_type: Option<&str>, expected: &str) -> bool {
    media_type == Some(expected)
}

fn is_intent_media(media_type: Option<&str>) -> bool {
    [
        super::MEDIA_REGISTER,
        super::MEDIA_RELEASE,
        super::MEDIA_OWNERSHIP,
        super::MEDIA_GRANT,
        MEDIA_RECEIPT,
        MEDIA_READBACK,
    ]
    .iter()
    .any(|m| media_is(media_type, m))
}

fn writer_matches(rec: &Receipt, writer: [u8; WRITER_LEN]) -> Result<(), Disagreement> {
    if rec.writer == writer {
        Ok(())
    } else {
        Err(Disagreement::ReceiptWriter)
    }
}

/// The receipt's instance token is the request's (`same`) or another's.
fn instance_is(
    rec: &Receipt,
    instance: [u8; INSTANCE_LEN],
    same: bool,
) -> Result<(), Disagreement> {
    if (rec.instance == instance) == same {
        Ok(())
    } else {
        Err(Disagreement::ReceiptInstance)
    }
}

fn epoch_is(rec: &Receipt, epoch: u64) -> Result<(), Disagreement> {
    if rec.epoch == epoch {
        Ok(())
    } else {
        Err(Disagreement::ReceiptEpoch)
    }
}

fn generation_is(ok: bool) -> Result<(), Disagreement> {
    if ok {
        Ok(())
    } else {
        Err(Disagreement::ReceiptGeneration)
    }
}

/// A receipt for the request's own row: this writer, epoch and token, live at
/// this generation. It yields the root id the row holds. A receipt for
/// generation N is never proof of another generation.
fn own_live_row(req: &RegisterRequest, rec: &Receipt) -> Result<GrainId, Disagreement> {
    writer_matches(rec, req.writer)?;
    epoch_is(rec, req.epoch)?;
    instance_is(rec, req.instance, true)?;
    let ReceiptState::Live { prepared_root_id } = rec.state else {
        return Err(Disagreement::ReceiptState);
    };
    generation_is(rec.generation == req.generation)?;
    Ok(prepared_root_id)
}

/// A `200` to a registration: the row is this instance's, live at this
/// generation, holding the bytes sent.
fn registered(req: &RegisterRequest, rec: &Receipt) -> Result<(), Disagreement> {
    if own_live_row(req, rec)? == req.root_id {
        Ok(())
    } else {
        Err(Disagreement::ReceiptRootId)
    }
}

/// A `409` `intent-bound`: this instance's live row at this generation holds
/// other bytes than the request's.
fn register_bound(req: &RegisterRequest, rec: &Receipt) -> Result<(), Disagreement> {
    if own_live_row(req, rec)? == req.root_id {
        Err(Disagreement::ReceiptRootId)
    } else {
        Ok(())
    }
}

/// A `409` `intent-superseded` to a registration: newer ownership fences at
/// any generation. The same epoch requires the same token and a live G>g
/// or released G>=g; that overtake is informational.
fn register_superseded(req: &RegisterRequest, rec: &Receipt) -> Result<(), Disagreement> {
    writer_matches(rec, req.writer)?;
    if rec.epoch < req.epoch {
        return Err(Disagreement::ReceiptEpoch);
    }
    let beaten = if rec.epoch == req.epoch {
        instance_is(rec, req.instance, true)?;
        match rec.state {
            ReceiptState::Live { .. } => rec.generation > req.generation,
            ReceiptState::Released => rec.generation >= req.generation,
        }
    } else {
        true
    };
    generation_is(beaten)
}

/// A `200` to a release: the row is this instance's, released, at the
/// released generation or above (a release of g releases everything at or
/// below g, and the row records the higher of g and what it held).
fn released(req: &ReleaseRequest, rec: &Receipt) -> Result<(), Disagreement> {
    writer_matches(rec, req.writer)?;
    epoch_is(rec, req.epoch)?;
    instance_is(rec, req.instance, true)?;
    if rec.state != ReceiptState::Released {
        return Err(Disagreement::ReceiptState);
    }
    generation_is(rec.generation >= req.generation)
}

/// A `409` `intent-superseded` to a release requires strictly newer ownership,
/// whatever the generation or token. E/T are installed together: a different
/// token at the same epoch is a backend disagreement.
fn release_superseded(req: &ReleaseRequest, rec: &Receipt) -> Result<(), Disagreement> {
    writer_matches(rec, req.writer)?;
    if rec.epoch < req.epoch {
        return Err(Disagreement::ReceiptEpoch);
    }
    if rec.epoch == req.epoch {
        instance_is(rec, req.instance, true)?;
        return Err(Disagreement::ReceiptEpoch);
    }
    Ok(())
}

fn receipt_of(body: &[u8]) -> Result<Receipt, Disagreement> {
    decode_receipt(body).map_err(Disagreement::Body)
}

/// A `409` row that carries a recorded receipt, checked against the request.
fn conflict<T>(
    reply: &Reply<'_>,
    check: impl FnOnce(&Receipt) -> Result<(), Disagreement>,
    class: impl FnOnce(Receipt) -> Verdict<T>,
) -> Verdict<T> {
    if !media_is(reply.media_type, MEDIA_RECEIPT) {
        return Verdict::Backend(Disagreement::WrongMediaType);
    }
    let rec = match receipt_of(reply.body) {
        Ok(rec) => rec,
        Err(d) => return Verdict::Backend(d),
    };
    match check(&rec) {
        Ok(()) => class(rec),
        Err(d) => Verdict::Backend(d),
    }
}

/// Every row that carries no intent body.
fn bodyless<T>(op: Op<'_>, status: u16, token: Option<&str>) -> Verdict<T> {
    let mismatch = Verdict::Backend(Disagreement::TokenMismatch(status));
    match status {
        400 => match token {
            Some(TOKEN_BAD_REQUEST) => Verdict::Refused(Refusal::BadRequest),
            Some(TOKEN_INVALID_CANDIDATE) if matches!(op, Op::Write(Write::Register(_))) => {
                Verdict::Refused(Refusal::InvalidPreparedRoot)
            }
            _ => mismatch,
        },
        403 => match token {
            Some(TOKEN_NO_PRINCIPAL) => Verdict::Refused(Refusal::NoPrincipal),
            Some(TOKEN_NOT_ENROLLED) => Verdict::Refused(Refusal::NotEnrolled),
            _ => mismatch,
        },
        404 => match token {
            Some(TOKEN_UNKNOWN_TARGET) => Verdict::NotImplemented,
            Some(TOKEN_UNKNOWN_VOLUME) => Verdict::Refused(Refusal::UnknownVolume),
            _ => mismatch,
        },
        405 => match token {
            Some(TOKEN_METHOD_NOT_ALLOWED) => Verdict::Refused(Refusal::MethodNotAllowed),
            _ => mismatch,
        },
        409 if op.writes() => match token {
            Some(TOKEN_QUOTA) if matches!(op, Op::Write(Write::Register(_))) || op.is_acquire() => {
                Verdict::OverQuota
            }
            Some(TOKEN_ABSENT) if !op.is_acquire() => Verdict::Absent,
            Some(TOKEN_CURSOR_CHANGED) if op.is_acquire() => Verdict::CursorChanged,
            Some(TOKEN_EPOCH_EXHAUSTED) if matches!(op, Op::Ownership(_)) => {
                Verdict::EpochExhausted
            }
            _ => mismatch,
        },
        413 if op.writes() => match token {
            Some(TOKEN_TOO_LARGE) => Verdict::Refused(Refusal::TooLarge),
            _ => mismatch,
        },
        429 => match token {
            Some(TOKEN_RATE_LIMITED) => Verdict::RateLimited,
            _ => mismatch,
        },
        500 => Verdict::Unknown(UnknownCause::Internal),
        503 => match token {
            Some(TOKEN_ENROLLMENT_UNAVAILABLE) => Verdict::EnrollmentUnavailable,
            Some(TOKEN_UNAVAILABLE) => Verdict::Unknown(UnknownCause::Unavailable),
            Some(TOKEN_FENCED) => Verdict::Unknown(UnknownCause::Fenced),
            Some(TOKEN_STOPPED) => Verdict::Unknown(UnknownCause::Stopped),
            _ => Verdict::Unknown(UnknownCause::Other(503)),
        },
        501..=599 => Verdict::Unknown(UnknownCause::Other(status)),
        other => Verdict::Backend(Disagreement::UnexpectedStatus(other)),
    }
}

fn judge<'a, T>(
    op: Op<'_>,
    reply: &Reply<'a>,
    accept: impl FnOnce(&'a [u8]) -> Result<T, Disagreement>,
) -> Verdict<T> {
    if (200..300).contains(&reply.status) && reply.token.is_some() {
        return Verdict::Backend(Disagreement::TokenOnSuccess);
    }
    if reply.status == 200 {
        if !media_is(reply.media_type, op.success_media()) {
            return Verdict::Backend(Disagreement::WrongMediaType);
        }
        return match accept(reply.body) {
            Ok(value) => Verdict::Accepted(value),
            Err(d) => Verdict::Backend(d),
        };
    }
    if reply.status == 409 {
        match (op, reply.token) {
            (Op::Write(Write::Register(req)), Some(TOKEN_SUPERSEDED)) => {
                return conflict(
                    reply,
                    |rec| register_superseded(req, rec),
                    |rec| {
                        if rec.epoch == req.epoch && rec.instance == req.instance {
                            Verdict::Overtaken(rec)
                        } else {
                            Verdict::Superseded(rec)
                        }
                    },
                );
            }
            (Op::Write(Write::Release(req)), Some(TOKEN_SUPERSEDED)) => {
                return conflict(
                    reply,
                    |rec| release_superseded(req, rec),
                    Verdict::Superseded,
                );
            }
            (Op::Write(Write::Register(req)), Some(TOKEN_BOUND)) => {
                return conflict(reply, |rec| register_bound(req, rec), Verdict::Bound);
            }
            (Op::Ownership(req), Some(token @ (TOKEN_CHANGED | TOKEN_SUPERSEDED))) => {
                return conflict(
                    reply,
                    |rec| ownership_conflict(req, rec, token),
                    |rec| {
                        if token == TOKEN_CHANGED {
                            Verdict::Changed(rec)
                        } else {
                            Verdict::Superseded(rec)
                        }
                    },
                );
            }
            _ => {}
        }
    }
    let verdict = bodyless(op, reply.status, reply.token);
    if !matches!(verdict, Verdict::Backend(_)) && is_intent_media(reply.media_type) {
        return Verdict::Backend(Disagreement::UnexpectedIntentBody);
    }
    verdict
}

/// Classify the answer to a registration.
#[must_use]
pub fn judge_register(req: &RegisterRequest, reply: &Reply<'_>) -> Verdict<Receipt> {
    judge(Op::Write(Write::Register(req)), reply, |body| {
        let rec = receipt_of(body)?;
        registered(req, &rec)?;
        Ok(rec)
    })
}

/// Classify the answer to a release.
#[must_use]
pub fn judge_release(req: &ReleaseRequest, reply: &Reply<'_>) -> Verdict<Receipt> {
    judge(Op::Write(Write::Release(req)), reply, |body| {
        let rec = receipt_of(body)?;
        released(req, &rec)?;
        Ok(rec)
    })
}

/// Classify the answer to a readback for `volume`. `verify` is the caller's
/// signature step ([`decode_readback`]).
#[must_use]
pub fn judge_readback<'a>(
    reply: &Reply<'a>,
    volume: &VolumeName,
    verify: impl FnMut(&RootDoc, &[u8]) -> bool,
) -> Verdict<Readback<'a>> {
    judge(Op::Readback, reply, |body| {
        decode_readback(body, volume, verify).map_err(Disagreement::Body)
    })
}

fn ownership_conflict(
    req: &super::Ownership,
    rec: &Receipt,
    token: &str,
) -> Result<(), Disagreement> {
    writer_matches(rec, req.writer)?;
    match req.mode {
        super::OwnershipMode::Acquire { .. } => {
            if token == TOKEN_CHANGED {
                Ok(())
            } else {
                Err(Disagreement::TokenMismatch(409))
            }
        }
        super::OwnershipMode::Takeover {
            expected_epoch,
            generation,
            state,
            ..
        } => {
            if token == TOKEN_SUPERSEDED {
                if rec.epoch <= expected_epoch {
                    Err(Disagreement::ReceiptEpoch)
                } else {
                    Ok(())
                }
            } else {
                epoch_is(rec, expected_epoch)?;
                if rec.generation != generation || rec.state != state {
                    Ok(())
                } else {
                    Err(Disagreement::ReceiptState)
                }
            }
        }
    }
}

/// Classify an acquisition or conditional-transfer reply against the exact
/// ownership request bytes sent. Q is their [`GrainId`], never a reconstruction.
///
/// # Errors
/// Returns the strict [`super::decode_ownership`] error for malformed local
/// request bytes before judging any reply. These errors are not server verdicts.
pub fn judge_ownership(
    request_bytes: &[u8],
    reply: &Reply<'_>,
) -> Result<Verdict<super::Grant>, Error> {
    let req = super::decode_ownership(request_bytes)?;
    let request_id = GrainId::of(request_bytes);
    Ok(judge(Op::Ownership(&req), reply, |body| {
        let grant = super::decode_grant(body).map_err(Disagreement::Body)?;
        if grant.request_id != request_id {
            return Err(Disagreement::GrantRequestId);
        }
        let rec = grant.receipt;
        writer_matches(&rec, req.writer)?;
        instance_is(&rec, req.instance, true)?;
        let (epoch_ok, generation, state) = match req.mode {
            super::OwnershipMode::Acquire { observed_cursor } => (
                observed_cursor.checked_add(1) == Some(rec.epoch),
                0,
                ReceiptState::Released,
            ),
            super::OwnershipMode::Takeover {
                expected_epoch,
                generation,
                state,
                ..
            } => (rec.epoch > expected_epoch, generation, state),
        };
        if !epoch_ok {
            return Err(Disagreement::ReceiptEpoch);
        }
        generation_is(rec.generation == generation)?;
        if rec.state != state {
            return Err(Disagreement::ReceiptState);
        }
        Ok(grant)
    }))
}
