// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Request-relative authority evidence over an immutable credential pool.
//! Each call sends once, plus at most one resend when the client stack proves
//! the first request was unsent. A response never releases a retained submission;
//! observations and later refusals never settle an earlier unanswered call.
//! Share one `Arc<HttpStore>` per exact base, trust, network context and loaded
//! credential generation. Rotation constructs a fresh store. Stable principal
//! continuity is explicit caller configuration, never inferred from certificates.

use crate::http_store::{
    CT_ROOT, GRANARY_ERROR, HttpStore, RetryPolicy, is_token_shaped, seam_deadline, under_deadline,
};
use granary_core::authority_answer::{self as codec, Bound, Position, PublishAnswer};
use granary_core::root::ROOT_MAX_BYTES;
use granary_core::rootstore::{RootStoreError, format_hint_body};
use hyper::{
    HeaderMap, Method, Response,
    body::{Body, Bytes},
    header::CONTENT_TYPE,
};
use std::future::Future;
use std::time::Duration;

mod types;
pub use types::{
    AuthorityConfiguration, AuthorityError, CheckedBound, CheckedConflict, CheckedDecision,
    CheckedLanded, CheckedLost, CheckedStatus, OWNED_CANDIDATES_MAX, OwnedCandidate, ProtocolError,
    ProtocolErrorKind, PublishRefusal, PublishRequest, PublishResponse, RequestError,
    ServiceReason, StatusRefusal, StatusResponse, StatusServiceReason, TransportError,
};

const ANSWER_MEDIA: &str = "application/vnd.granary.authority-answer.v1";
const STATUS_MEDIA: &str = "application/vnd.granary.volume-status.v1";
fn transport(error: &RootStoreError) -> AuthorityError {
    AuthorityError::Transport(TransportError(error.to_string()))
}
fn backend(status: u16, headers: &HeaderMap, reason: impl Into<String>) -> AuthorityError {
    backend_kind(status, headers, ProtocolErrorKind::InvalidResponse, reason)
}
fn backend_kind(
    status: u16,
    headers: &HeaderMap,
    kind: ProtocolErrorKind,
    reason: impl Into<String>,
) -> AuthorityError {
    AuthorityError::Backend(ProtocolError {
        status,
        kind,
        token: headers
            .get(GRANARY_ERROR)
            .and_then(|v| v.to_str().ok())
            .filter(|token| is_token_shaped(token))
            .map(str::to_owned),
        reason: reason.into(),
    })
}
fn identification(status: u16, headers: &HeaderMap) -> Result<Option<&str>, AuthorityError> {
    let mut tokens = headers.get_all(GRANARY_ERROR).iter();
    let first = tokens.next();
    if tokens.next().is_some() {
        return Err(backend(status, headers, "duplicate error token"));
    }
    if (200..300).contains(&status) {
        if first.is_some() {
            return Err(backend(status, headers, "success carries error token"));
        }
        return Ok(None);
    }
    let first = first.ok_or_else(|| {
        backend_kind(
            status,
            headers,
            ProtocolErrorKind::MissingToken,
            "missing error token",
        )
    })?;
    let token = first
        .to_str()
        .map_err(|_| backend(status, headers, "invalid error token"))?;
    Ok(Some(token))
}
fn media(status: u16, headers: &HeaderMap, expected: &str) -> Result<(), AuthorityError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    if values.next().map(hyper::header::HeaderValue::as_bytes) != Some(expected.as_bytes())
        || values.next().is_some()
    {
        return Err(backend(status, headers, "answer media type mismatch"));
    }
    Ok(())
}
pub(crate) fn answer_tuple(answer: PublishAnswer) -> (u16, Option<&'static str>) {
    match answer {
        PublishAnswer::Landed { .. } | PublishAnswer::Lost { .. } => (200, None),
        PublishAnswer::Accepted { .. } | PublishAnswer::Open { .. } => (202, None),
        PublishAnswer::StaleBase(_) => (409, Some("stale-base")),
        PublishAnswer::OperationBound(_) => (409, Some("operation-bound")),
        PublishAnswer::NotDecided { .. } => (409, Some("not-decided")),
        PublishAnswer::EpochMismatch { .. } => (409, Some("epoch-mismatch")),
        PublishAnswer::VolumeDamaged => (409, Some("volume-damaged")),
    }
}

/// Validate decoded fields against the same immutable request sent on the wire.
pub(crate) fn check_answer(
    request: &PublishRequest,
    answer: PublishAnswer,
) -> Result<PublishResponse, &'static str> {
    let epoch = |position: Position| {
        if position.epoch == request.epoch {
            Ok(())
        } else {
            Err("position epoch mismatch")
        }
    };
    let decision = |position: Position, candidate_id| {
        epoch(position)?;
        if candidate_id != request.candidate.id {
            return Err("candidate id mismatch");
        }
        Ok(CheckedDecision {
            position,
            candidate_id,
        })
    };
    Ok(match answer {
        PublishAnswer::Landed { receipt, head } => {
            epoch(receipt.position)?;
            if receipt.stored_id != request.candidate.id {
                return Err("stored id mismatch");
            }
            if receipt.root_seq != request.candidate.seq {
                return Err("landed root sequence mismatch");
            }
            PublishResponse::Landed(CheckedLanded { receipt, head })
        }
        PublishAnswer::Lost {
            position,
            candidate_id,
            occupant,
            head,
        } => PublishResponse::Lost(CheckedLost {
            decision: decision(position, candidate_id)?,
            occupant,
            head,
        }),
        PublishAnswer::Accepted {
            position,
            candidate_id,
        } => PublishResponse::Accepted(decision(position, candidate_id)?),
        PublishAnswer::Open {
            position,
            candidate_id,
        } => PublishResponse::Open(decision(position, candidate_id)?),
        PublishAnswer::StaleBase(head) => {
            PublishResponse::Conflict(CheckedConflict::StaleBase(head))
        }
        PublishAnswer::OperationBound(bound) => {
            let (position, id) = match bound {
                Bound::Open {
                    position,
                    candidate_id,
                } => (position, candidate_id),
                Bound::Landed(receipt) => (receipt.position, receipt.stored_id),
            };
            epoch(position)?;
            let owned = request
                .owned
                .iter()
                .find(|c| c.id == id)
                .ok_or("binding not owned")?;
            if let Bound::Landed(receipt) = bound
                && receipt.root_seq != owned.seq
            {
                return Err("bound root sequence mismatch");
            }
            PublishResponse::Conflict(CheckedConflict::OperationBound(CheckedBound { bound }))
        }
        PublishAnswer::NotDecided {
            position,
            candidate_id,
        } => {
            epoch(position)?;
            PublishResponse::Conflict(CheckedConflict::NotDecided(position, candidate_id))
        }
        PublishAnswer::EpochMismatch { epoch, head } => {
            if epoch == request.epoch {
                return Err("unchanged mismatch epoch");
            }
            PublishResponse::Conflict(CheckedConflict::EpochMismatch(epoch, head))
        }
        PublishAnswer::VolumeDamaged => PublishResponse::Conflict(CheckedConflict::VolumeDamaged),
    })
}

fn checked_bytes(
    request: &PublishRequest,
    status: u16,
    headers: &HeaderMap,
    token: Option<&str>,
    bytes: &[u8],
) -> Result<PublishResponse, AuthorityError> {
    let answer = codec::decode(bytes)
        .map_err(|e| backend(status, headers, format!("answer decode: {e}")))?;
    if answer_tuple(answer) != (status, token) {
        return Err(backend(status, headers, "kind/status/token mismatch"));
    }
    check_answer(request, answer).map_err(|reason| backend(status, headers, reason))
}

/// Validate one complete authority answer without I/O. Simulation and HTTP
/// use the same request-relative checks; this never constructs unchecked proof.
/// # Errors
/// Excess size, malformed bytes or mismatched identification/identity.
pub fn validate_publish_answer(
    request: &PublishRequest,
    status: u16,
    token: Option<&str>,
    bytes: &[u8],
) -> Result<PublishResponse, AuthorityError> {
    let mut headers = HeaderMap::new();
    if let Some(token) = token {
        let value = hyper::header::HeaderValue::from_str(token)
            .map_err(|_| backend(status, &headers, "invalid token"))?;
        headers.insert(GRANARY_ERROR, value);
    }
    let token = identification(status, &headers)?;
    if matches!(status, 200 | 202 | 409) {
        if bytes.len() > codec::MAX_BYTES {
            return Err(backend(status, &headers, "answer exceeds cap"));
        }
        checked_bytes(request, status, &headers, token, bytes)
    } else {
        identified_publish_response(status, token)
            .ok_or_else(|| backend(status, &headers, "unexpected publish status/token"))
    }
}

/// Validate a complete canonical status observation. It is never landing proof.
/// # Errors
/// Malformed or oversized status bytes.
pub fn validate_status_observation(bytes: &[u8]) -> Result<StatusResponse, AuthorityError> {
    let observation =
        codec::decode_status(bytes).map_err(|e| backend(200, &HeaderMap::new(), e.to_string()))?;
    Ok(StatusResponse::Observed(CheckedStatus { observation }))
}

pub(crate) fn fuzz_validate(request: &PublishRequest, data: &[u8]) {
    let Some((&high, rest)) = data.split_first() else {
        return;
    };
    let Some((&low, rest)) = rest.split_first() else {
        return;
    };
    let Some((&field, bytes)) = rest.split_first() else {
        return;
    };
    let status = u16::from_be_bytes([high, low]);
    let mut headers = HeaderMap::new();
    let tokens = [
        "stale-base",
        "operation-bound",
        "not-decided",
        "epoch-mismatch",
        "volume-damaged",
        "unknown",
        "unavailable",
    ];
    if let Some(token) = usize::from(field & 7)
        .checked_sub(1)
        .and_then(|n| tokens.get(n))
    {
        headers.insert(
            GRANARY_ERROR,
            hyper::header::HeaderValue::from_static(token),
        );
    }
    if field & 8 != 0 {
        headers.append(
            GRANARY_ERROR,
            hyper::header::HeaderValue::from_static("volume-damaged"),
        );
    }
    headers.insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(if field & 16 == 0 {
            ANSWER_MEDIA
        } else {
            "text/plain"
        }),
    );
    if bytes.len() > codec::MAX_BYTES {
        return;
    }
    let Ok(token) = identification(status, &headers) else {
        return;
    };
    if media(status, &headers, ANSWER_MEDIA).is_err() {
        return;
    }
    let _ = checked_bytes(request, status, &headers, token, bytes);
}

async fn publish_response<B>(
    store: &HttpStore,
    request: &PublishRequest,
    response: Response<B>,
) -> Result<PublishResponse, AuthorityError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let (parts, body) = response.into_parts();
    let status = parts.status.as_u16();
    let headers = &parts.headers;
    let token = identification(status, headers)?;
    if matches!(status, 200 | 202 | 409) {
        media(status, headers, ANSWER_MEDIA)?;
        let bytes = store
            .authority_body(body, codec::MAX_BYTES)
            .await
            .map_err(|e| backend(status, headers, format!("incomplete answer body: {e}")))?
            .ok_or_else(|| backend(status, headers, "answer exceeds cap"))?;
        return checked_bytes(request, status, headers, token, &bytes);
    }
    // Error text is diagnostic only. Dropping it avoids both parsing and draining.
    identified_publish_response(status, token)
        .ok_or_else(|| backend(status, headers, "unexpected publish status/token"))
}
fn identified_publish_response(status: u16, token: Option<&str>) -> Option<PublishResponse> {
    match (status, token) {
        (400, Some("bad-request")) => Some(PublishResponse::Refused(PublishRefusal::BadRequest)),
        (400, Some("invalid-candidate")) => {
            Some(PublishResponse::Refused(PublishRefusal::InvalidCandidate))
        }
        (400, Some("missing-reference")) => {
            Some(PublishResponse::Refused(PublishRefusal::MissingReference))
        }
        (400, Some("invalid-reference")) => {
            Some(PublishResponse::Refused(PublishRefusal::InvalidReference))
        }
        (413, Some("publish-work-limit")) => {
            Some(PublishResponse::Refused(PublishRefusal::PublishWorkLimit))
        }
        (403, Some("no-principal")) => Some(PublishResponse::Refused(PublishRefusal::NoPrincipal)),
        (403, Some("not-enrolled")) => Some(PublishResponse::Refused(PublishRefusal::NotEnrolled)),
        (404, Some("unknown-target")) => {
            Some(PublishResponse::Refused(PublishRefusal::UnknownTarget))
        }
        (404, Some("no-log")) => Some(PublishResponse::Refused(PublishRefusal::NoLog)),
        (404, Some("unknown-volume")) => {
            Some(PublishResponse::Refused(PublishRefusal::UnknownVolume))
        }
        (405, Some("method-not-allowed")) => {
            Some(PublishResponse::Refused(PublishRefusal::MethodNotAllowed))
        }
        (413, Some("too-large")) => Some(PublishResponse::Refused(PublishRefusal::TooLarge)),
        (429, Some("rate-limited")) => Some(PublishResponse::RateLimited),
        (503, Some("unavailable")) => Some(PublishResponse::ServiceUnavailable(
            ServiceReason::Unavailable,
        )),
        (503, Some("enrollment-unavailable")) => Some(PublishResponse::ServiceUnavailable(
            ServiceReason::EnrollmentUnavailable,
        )),
        (503, Some("fenced")) => Some(PublishResponse::ServiceUnavailable(ServiceReason::Fenced)),
        (503, Some("stopped")) => Some(PublishResponse::ServiceUnavailable(ServiceReason::Stopped)),
        (500, Some("internal")) => Some(PublishResponse::Internal),
        _ => None,
    }
}

async fn status_response<B>(
    store: &HttpStore,
    response: Response<B>,
) -> Result<StatusResponse, AuthorityError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let (parts, body) = response.into_parts();
    let status = parts.status.as_u16();
    let headers = &parts.headers;
    let token = identification(status, headers)?;
    if status == 200 {
        media(status, headers, STATUS_MEDIA)?;
        let bytes = store
            .authority_body(body, codec::STATUS_V1_MAX)
            .await
            .map_err(|e| backend(status, headers, format!("incomplete status body: {e}")))?
            .ok_or_else(|| backend(status, headers, "status exceeds cap"))?;
        let observation = codec::decode_status(&bytes)
            .map_err(|e| backend(status, headers, format!("status decode: {e}")))?;
        return Ok(StatusResponse::Observed(CheckedStatus { observation }));
    }
    match (status, token) {
        (400, Some("bad-request")) => Ok(StatusResponse::Refused(StatusRefusal::BadRequest)),
        (404, Some("unknown-target")) => Ok(StatusResponse::Refused(StatusRefusal::UnknownTarget)),
        (404, Some("no-log")) => Ok(StatusResponse::Refused(StatusRefusal::NoLog)),
        (404, Some("unknown-volume")) => Ok(StatusResponse::Refused(StatusRefusal::UnknownVolume)),
        (405, Some("method-not-allowed")) => {
            Ok(StatusResponse::Refused(StatusRefusal::MethodNotAllowed))
        }
        (413, Some("too-large")) => Ok(StatusResponse::Refused(StatusRefusal::TooLarge)),
        (503, Some("unavailable")) => Ok(StatusResponse::ServiceUnavailable(
            StatusServiceReason::Unavailable,
        )),
        (503, Some("fenced")) => Ok(StatusResponse::ServiceUnavailable(
            StatusServiceReason::Fenced,
        )),
        (503, Some("stopped")) => Ok(StatusResponse::ServiceUnavailable(
            StatusServiceReason::Stopped,
        )),
        (500, Some("internal")) => Ok(StatusResponse::Internal),
        _ => Err(backend(status, headers, "unexpected status status/token")),
    }
}
async fn probe_response<B>(
    store: &HttpStore,
    response: Response<B>,
) -> Result<Option<Vec<u8>>, RootStoreError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let (parts, body) = response.into_parts();
    let status = parts.status.as_u16();
    let token = identification(status, &parts.headers)
        .map_err(|e| RootStoreError::Backend(e.to_string()))?;
    match (status, token) {
        (200, None) => {
            media(status, &parts.headers, CT_ROOT)
                .map_err(|e| RootStoreError::Backend(e.to_string()))?;
            store
                .authority_body(body, usize::try_from(ROOT_MAX_BYTES).unwrap_or(usize::MAX))
                .await?
                .map(Some)
                .ok_or_else(|| RootStoreError::RefusedResponse {
                    reason: "root probe exceeds cap".to_owned(),
                    kind: granary_core::rootstore::RefusalKind::OverCap,
                })
        }
        (404, Some("not-found")) => Ok(None),
        _ => Err(RootStoreError::Backend(format!(
            "root probe: unexpected status {status} {:?}",
            token.filter(|token| is_token_shaped(token))
        ))),
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
async fn deadline<T>(
    budget: Duration,
    call: impl Future<Output = Result<T, AuthorityError>>,
) -> Result<T, AuthorityError> {
    // Keep the authority result inside the shared deadline; the outer error
    // can only mean that the wait elapsed.
    under_deadline("authority", budget, async { Ok(call.await) })
        .await
        .map_err(|_| AuthorityError::Elapsed)?
}
impl HttpStore {
    /// Send one immutable publish submission, validating evidence against it.
    /// The deadline covers connect, headers and the complete bounded body.
    ///
    /// # Errors
    /// Request construction, transport, elapsed deadline or invalid peer evidence.
    /// All network failures and invalid evidence leave the submission uncertain.
    ///
    /// # Cancellation safety
    /// Dropping the future drops only the client's wait. The authority may still
    /// decide the submission; the caller must retain it as uncertain.
    pub async fn publish_once(
        &self,
        request: &PublishRequest,
    ) -> Result<PublishResponse, AuthorityError> {
        let budget = seam_deadline(request.candidate.bytes.len() as u64);
        deadline(budget, async {
            let mut req = self
                .authority_request(
                    request.volume(),
                    "/publish",
                    Method::POST,
                    Bytes::from_owner(request.candidate.bytes.clone()),
                )
                .map_err(|e| transport(&e))?;
            req.headers_mut().insert(
                CONTENT_TYPE,
                hyper::header::HeaderValue::from_static(CT_ROOT),
            );
            for (name, bytes) in [
                ("granary-epoch", request.epoch.to_bytes().as_slice()),
                ("granary-operation", request.operation()),
            ] {
                let value = hyper::header::HeaderValue::from_str(&hex(bytes))
                    .map_err(|_| AuthorityError::Request(RequestError("invalid request header")))?;
                req.headers_mut().insert(name, value);
            }
            let response = self
                .send(req, "POST publish", RetryPolicy::Never)
                .await
                .map_err(|e| transport(&e))?;
            publish_response(self, request, response).await
        })
        .await
    }
    /// Read one diagnostic authority snapshot. This never settles publish writes.
    ///
    /// # Errors
    /// Bad volume, transport, elapsed whole-call deadline or invalid peer evidence.
    ///
    /// # Cancellation safety
    /// Dropping the future stops this wait and supplies no publish-write evidence.
    pub async fn status_once(&self, volume: &str) -> Result<StatusResponse, AuthorityError> {
        types::volume_name(volume).map_err(AuthorityError::Request)?;
        deadline(seam_deadline(0), async {
            let req = self
                .authority_request(volume, "/status", Method::GET, Bytes::new())
                .map_err(|e| transport(&e))?;
            let response = self
                .send(req, "GET status", RetryPolicy::Never)
                .await
                .map_err(|e| transport(&e))?;
            status_response(self, response).await
        })
        .await
    }
    /// Fetch exact capped root bytes with one send, plus at most one resend of a
    /// request the client stack proved unsent, or an identified absence.
    /// An absent root never proves that a publish submission wrote nothing.
    ///
    /// # Errors
    /// Invalid volume/sequence, transport, framing, excess size, deadline or an
    /// unidentified/unexpected response. This call never resends except for that
    /// provably-unsent case.
    ///
    /// # Cancellation safety
    /// Dropping the future ends the read; it supplies no publish-write evidence.
    pub async fn probe_root_once(
        &self,
        volume: &str,
        seq: u64,
    ) -> Result<Option<Vec<u8>>, RootStoreError> {
        types::volume_name(volume).map_err(|e| RootStoreError::InvalidVolume {
            reason: e.to_string(),
        })?;
        if seq == 0 || seq == u64::MAX {
            return Err(RootStoreError::Backend(
                "invalid probe root sequence".to_owned(),
            ));
        }
        let req = self.authority_request(
            volume,
            &format!("/root/{}", format_hint_body(seq)),
            Method::GET,
            Bytes::new(),
        )?;
        under_deadline("GET root probe", seam_deadline(ROOT_MAX_BYTES), async {
            let response = self.send(req, "GET root probe", RetryPolicy::Never).await?;
            probe_response(self, response).await
        })
        .await
    }
}

#[cfg(test)]
mod tests;
