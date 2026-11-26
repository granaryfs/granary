// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Single-attempt intent HTTP operations. The coordinator owns all retries.

use crate::http_store::{HttpStore, RetryPolicy, seam_deadline};
use granary_core::intent::{self, Grant, OwnershipMode, Receipt, Reply, Verdict};
use granary_core::retained_submission::Scope;
use granary_core::root::{RootDoc, VolumeName};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use hyper::{Method, body::Bytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentTransportError {
    InvalidRequest,
    Transport,
    Deadline,
    Backend,
}
impl std::fmt::Display for IntentTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "intent invalid request",
            Self::Transport => "intent transport uncertainty",
            Self::Deadline => "intent attempt deadline",
            Self::Backend => "intent backend disagreement",
        })
    }
}
impl std::error::Error for IntentTransportError {}

/// Owned response bytes, rejudged against the retained request on completion.
#[derive(Clone)]
pub struct IntentReply {
    pub(crate) scope: Option<Scope>,
    pub(crate) volume: Option<VolumeName>,
    pub(crate) status: u16,
    pub(crate) media_type: Option<String>,
    pub(crate) token: Option<String>,
    pub(crate) body: Vec<u8>,
    pub(crate) retry_after: Option<String>,
}
impl std::fmt::Debug for IntentReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntentReply")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}
impl IntentReply {
    /// Construct raw simulated transport bytes. Completion still judges the
    /// answer against the durable request and checks its scope and volume.
    #[cfg(feature = "overlay-fault-tests")]
    #[must_use]
    pub fn test_response(scope: Scope, volume: VolumeName, reply: Reply<'_>) -> Self {
        Self {
            scope: Some(scope),
            volume: Some(volume),
            status: reply.status,
            media_type: reply.media_type.map(str::to_owned),
            token: reply.token.map(str::to_owned),
            body: reply.body.to_vec(),
            retry_after: None,
        }
    }
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    #[must_use]
    pub fn retry_after(&self) -> Option<&str> {
        self.retry_after.as_deref()
    }
    pub(crate) fn matches_scope(&self, scope: &Scope, volume: &VolumeName) -> bool {
        self.scope.as_ref() == Some(scope) && self.volume.as_ref() == Some(volume)
    }

    /// Judge every readback row against the configured volume and signer.
    #[must_use]
    pub fn readback(
        &self,
        volume: &VolumeName,
        verify: impl FnMut(&RootDoc, &[u8]) -> bool,
    ) -> Verdict<intent::Readback<'_>> {
        intent::judge_readback(&self.borrowed(), volume, verify)
    }

    pub(crate) fn borrowed(&self) -> Reply<'_> {
        Reply {
            status: self.status,
            media_type: self.media_type.as_deref(),
            token: self.token.as_deref(),
            body: &self.body,
        }
    }
    /// # Errors
    /// Malformed local ownership request bytes.
    pub fn ownership(&self, request: &[u8]) -> Result<Verdict<Grant>, intent::Error> {
        intent::judge_ownership(request, &self.borrowed())
    }
    #[must_use]
    pub fn registration(&self, request: &intent::RegisterRequest) -> Verdict<Receipt> {
        intent::judge_register(request, &self.borrowed())
    }
    #[must_use]
    pub fn release(&self, request: &intent::ReleaseRequest) -> Verdict<Receipt> {
        intent::judge_release(request, &self.borrowed())
    }
}

fn single(headers: &hyper::HeaderMap, name: &str) -> Result<Option<String>, IntentTransportError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .map(|v| v.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| IntentTransportError::Backend)?;
    if values.next().is_some() {
        return Err(IntentTransportError::Backend);
    }
    Ok(value)
}

fn metadata(status: u16, headers: &hyper::HeaderMap) -> Result<IntentReply, IntentTransportError> {
    // A generic server failure carries no mutation proof. Missing or duplicate
    // identification becomes absent judge input rather than an invented refusal.
    let field = |name| {
        let value = single(headers, name);
        if status >= 500 {
            Ok(value.unwrap_or(None))
        } else {
            value
        }
    };
    if status < 500 && single(headers, CACHE_CONTROL.as_str())?.as_deref() != Some("no-store") {
        return Err(IntentTransportError::Backend);
    }
    Ok(IntentReply {
        scope: None,
        volume: None,
        status,
        media_type: field(CONTENT_TYPE.as_str())?,
        token: field("granary-error")?,
        retry_after: field(RETRY_AFTER.as_str())?,
        body: vec![],
    })
}

impl HttpStore {
    #[expect(
        clippy::too_many_arguments,
        reason = "one bounded attempt receives independent scope, endpoint, method, media and body operands"
    )]
    async fn intent_once(
        &self,
        scope: &Scope,
        volume: &VolumeName,
        tail: &str,
        method: Method,
        body: &[u8],
        media: Option<&'static str>,
        cap: usize,
    ) -> Result<IntentReply, IntentTransportError> {
        if scope.digest().is_err() || !self.intent_scope_matches(scope) {
            return Err(IntentTransportError::InvalidRequest);
        }
        let result = tokio::time::timeout(seam_deadline(cap as u64), async {
            let mut request = self
                .authority_request(volume.as_str(), tail, method, Bytes::copy_from_slice(body))
                .map_err(|_| IntentTransportError::InvalidRequest)?;
            if let Some(media) = media {
                request
                    .headers_mut()
                    .insert(CONTENT_TYPE, hyper::header::HeaderValue::from_static(media));
            }
            let response = self
                .send(request, "intent", RetryPolicy::Never)
                .await
                .map_err(|_| IntentTransportError::Transport)?;
            let (parts, body) = response.into_parts();
            let mut reply = metadata(parts.status.as_u16(), &parts.headers)?;
            reply.scope = Some(scope.clone());
            reply.volume = Some(volume.clone());
            if reply.status >= 500 {
                return Ok(reply);
            }
            reply.body = self
                .authority_body(body, cap)
                .await
                .map_err(|_| IntentTransportError::Transport)?
                .ok_or(IntentTransportError::Backend)?;
            Ok(reply)
        })
        .await;
        result.map_err(|_| IntentTransportError::Deadline)?
    }

    /// Read one authenticated diagnostic snapshot; no ownership is inferred.
    /// # Errors
    /// Framing, bounds, transport or attempt deadline failures.
    /// # Cancellation safety
    /// Cancellation supplies no mutation evidence.
    pub async fn intent_readback_once(
        &self,
        scope: &Scope,
        volume: &VolumeName,
        mut verify: impl FnMut(&RootDoc, &[u8]) -> bool,
    ) -> Result<IntentReply, IntentTransportError> {
        let reply = self
            .intent_once(
                scope,
                volume,
                "/intent",
                Method::GET,
                &[],
                None,
                intent::READBACK_MAX_BYTES,
            )
            .await?;
        if matches!(
            intent::judge_readback(&reply.borrowed(), volume, &mut verify),
            Verdict::Backend(_)
        ) {
            return Err(IntentTransportError::Backend);
        }
        Ok(reply)
    }

    async fn ownership_once(
        &self,
        scope: &Scope,
        volume: &VolumeName,
        bytes: &[u8],
        acquire: bool,
    ) -> Result<IntentReply, IntentTransportError> {
        let request =
            intent::decode_ownership(bytes).map_err(|_| IntentTransportError::InvalidRequest)?;
        if matches!(request.mode, OwnershipMode::Acquire { .. }) != acquire {
            return Err(IntentTransportError::InvalidRequest);
        }
        let reply = self
            .intent_once(
                scope,
                volume,
                "/intent/ownership",
                Method::POST,
                bytes,
                Some(intent::MEDIA_OWNERSHIP),
                intent::GRANT_MAX_BYTES,
            )
            .await?;
        if matches!(reply.ownership(bytes), Ok(Verdict::Backend(_)) | Err(_)) {
            return Err(IntentTransportError::Backend);
        }
        Ok(reply)
    }

    /// Send retained absent-row acquisition bytes once.
    /// # Errors
    /// Invalid local request, framing, transport or request-relative disagreement.
    /// # Cancellation safety
    /// The acquisition may have committed; retain the exact bytes.
    pub async fn intent_acquire_once(
        &self,
        scope: &Scope,
        volume: &VolumeName,
        bytes: &[u8],
    ) -> Result<IntentReply, IntentTransportError> {
        self.ownership_once(scope, volume, bytes, true).await
    }
    /// Send retained conditional-transfer bytes once.
    /// # Errors
    /// Invalid local request, framing, transport or request-relative disagreement.
    /// # Cancellation safety
    /// The transfer may have committed; retain the exact selection and consent.
    pub async fn intent_takeover_once(
        &self,
        scope: &Scope,
        volume: &VolumeName,
        bytes: &[u8],
    ) -> Result<IntentReply, IntentTransportError> {
        self.ownership_once(scope, volume, bytes, false).await
    }
    /// Send an exact prepared-root registration once.
    /// # Errors
    /// Invalid local request, framing, transport or request-relative disagreement.
    /// # Cancellation safety
    /// The registration may have committed; retain the exact request.
    pub async fn intent_register_once(
        &self,
        scope: &Scope,
        volume: &VolumeName,
        bytes: &[u8],
        verify: impl FnMut(&RootDoc, &[u8]) -> bool,
    ) -> Result<IntentReply, IntentTransportError> {
        let request = intent::decode_register(bytes, volume, verify)
            .map_err(|_| IntentTransportError::InvalidRequest)?;
        let identity = intent::RegisterRequest {
            writer: request.writer,
            epoch: request.epoch,
            instance: request.instance,
            generation: request.generation,
            root_id: request.root_id(),
        };
        let reply = self
            .intent_once(
                scope,
                volume,
                "/intent",
                Method::POST,
                bytes,
                Some(intent::MEDIA_REGISTER),
                intent::RECEIPT_MAX_BYTES,
            )
            .await?;
        if matches!(reply.registration(&identity), Verdict::Backend(_)) {
            return Err(IntentTransportError::Backend);
        }
        Ok(reply)
    }
    /// Release through the highest possibly sent generation once.
    /// # Errors
    /// Invalid local request, framing, transport or request-relative disagreement.
    /// # Cancellation safety
    /// The release may have committed; retain exact request evidence.
    pub async fn intent_release_once(
        &self,
        scope: &Scope,
        volume: &VolumeName,
        bytes: &[u8],
    ) -> Result<IntentReply, IntentTransportError> {
        let request =
            intent::decode_release(bytes).map_err(|_| IntentTransportError::InvalidRequest)?;
        let identity = intent::ReleaseRequest {
            writer: request.writer,
            epoch: request.epoch,
            instance: request.instance,
            generation: request.generation,
        };
        let reply = self
            .intent_once(
                scope,
                volume,
                "/intent/release",
                Method::POST,
                bytes,
                Some(intent::MEDIA_RELEASE),
                intent::RECEIPT_MAX_BYTES,
            )
            .await?;
        if matches!(reply.release(&identity), Verdict::Backend(_)) {
            return Err(IntentTransportError::Backend);
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn transport_metadata_refuses_cacheable_and_duplicate_proofs_but_preserves_generic_5xx() {
        let mut valid = hyper::HeaderMap::new();
        valid.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        valid.insert(CONTENT_TYPE, HeaderValue::from_static(intent::MEDIA_GRANT));
        assert!(metadata(200, &valid).is_ok());
        let mut missing = valid.clone();
        missing.remove(CACHE_CONTROL);
        assert_eq!(
            metadata(200, &missing).unwrap_err(),
            IntentTransportError::Backend
        );
        let mut duplicate = valid.clone();
        duplicate.append(CONTENT_TYPE, HeaderValue::from_static(intent::MEDIA_GRANT));
        assert_eq!(
            metadata(200, &duplicate).unwrap_err(),
            IntentTransportError::Backend
        );
        let mut unknown = hyper::HeaderMap::new();
        unknown.append("granary-error", HeaderValue::from_static("first"));
        unknown.append("granary-error", HeaderValue::from_static("second"));
        let reply = metadata(502, &unknown).unwrap();
        let request = intent::Ownership {
            writer: [1; 16],
            instance: [2; 16],
            mode: OwnershipMode::Acquire { observed_cursor: 0 },
        };
        assert!(matches!(
            reply.ownership(&intent::encode_ownership(request).unwrap()),
            Ok(Verdict::Unknown(_))
        ));
        assert_eq!((reply.token, reply.body.len()), (None, 0));
    }
}
