// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The one in-process authority shared by writable mount and daemon fixtures.

use super::{PublishedTree, remote_handle, vol};
#[cfg(test)]
use crate::SyncRuntime as _;
use crate::authority_transport::{AuthorityError, StatusRefusal, StatusResponse};
use crate::writable_start::WritableAuthority;
use crate::{
    AuthorityTransport, IntentReply, IntentTransportError, MountMetrics, PendingIntent,
    PublishRequest, PublishResponse, validate_publish_answer, validate_status_observation,
};
use granary_core::authority_answer::{self, Head, Position, PublishAnswer, VolumeStatus};
use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::intent::{self, Grant, Receipt, ReceiptState};
use granary_core::overlay_ownership::Operation;
use granary_core::retained_submission::Scope;
use granary_core::root::{RootDoc, Timestamp, VolumeName};
use granary_core::rootstore::{RootStore, RootStoreError};
use object_store::memory::InMemory;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
#[cfg_attr(
    test,
    expect(
        clippy::struct_excessive_bools,
        reason = "the paired fixtures toggle independent transport fault controls"
    )
)]
pub(crate) struct AuthorityState {
    pub(crate) grants: BTreeMap<GrainId, Grant>,
    pub(crate) calls: [u64; 4],
    /// Runtime facades minted from this authority.
    pub(crate) runtime_facades: usize,
    /// Every bin range read, as `(bin digest, offset, length)`.
    pub(crate) ranges: Vec<([u8; DIGEST_LEN], u64, u32)>,
    pub(crate) cursor: u64,
    pub(crate) row: Option<Receipt>,
    pub(crate) root: Vec<u8>,
    pub(crate) sends: Vec<Vec<u8>>,
    pub(crate) publications: Vec<Vec<u8>>,
    pub(crate) tick: u64,
    /// Fail the next metadata or bin range read once, as an unavailable store.
    pub(crate) fail_next_read: bool,
    /// How the next bin range read fails once, leaving metadata reads served.
    pub(crate) next_range_fault: Option<RangeFault>,
    /// The store error a root read at each seq answers; every other seq is
    /// served.
    pub(crate) root_fault: BTreeMap<u64, RootStoreError>,
    /// The store error a head probe answers while set.
    pub(crate) probe_fault: Option<RootStoreError>,
    /// While set, a probe that would make `probes` exceed it waits, uncounted,
    /// until it is cleared or raised.
    pub(crate) probe_limit: Option<usize>,
    /// Polls blocked by the probe limit.
    #[cfg(test)]
    pub(crate) probe_waits: usize,
    /// Refuse this many publications as rate limited before answering any.
    pub(crate) publish_refusals: usize,
    #[cfg(test)]
    pub(crate) publish_timeouts: usize,
    /// Answer this many publications `503 unavailable`, each after the
    /// delay, before answering any other way.
    #[cfg(test)]
    pub(crate) publish_unavailable: Option<(usize, std::time::Duration)>,
    /// Refuse every publication as an invalid candidate.
    pub(crate) reject_publications: bool,
    /// Hold the next publication this long before it reaches the store.
    pub(crate) publish_delay: Option<std::time::Duration>,
    /// Hold the next publication's reply this long after it reaches the store.
    pub(crate) reply_delay: Option<std::time::Duration>,
    /// How many times the head was probed.
    pub(crate) probes: usize,
    /// How many numbered roots were read.
    pub(crate) root_reads: usize,
    /// Serve this many engine registrations, then answer every later one
    /// as unavailable; `None` serves them all.
    pub(crate) registrations_served: Option<usize>,
    /// Move the wall tick this far after every read of it, by any clone of
    /// the clock. The clock then advances with the number of reads, not with
    /// elapsed time: a retry's backoff has passed when the engine checks it
    /// only if the reads between computing and checking it add up to at
    /// least that backoff.
    pub(crate) tick_per_read: u64,
    /// Answer the next intent registration with this `Retry-After` value.
    #[cfg(test)]
    pub(crate) intent_retry_after: Option<u64>,
    /// Hold the next intent retry wait for this wall-clock duration.
    #[cfg(test)]
    pub(crate) intent_wait_delay: Option<std::time::Duration>,
    /// Run intent waits on the monotonic clock while the wall tick is frozen.
    #[cfg(test)]
    pub(crate) intent_wait_frozen: bool,
    /// Reject acquires over an existing row and takeovers with a stale selection.
    #[cfg(test)]
    pub(crate) ownership_strict: bool,
    /// Apply a competing authority change after readback, as Acquire is judged.
    #[cfg(test)]
    pub(crate) ownership_acquire_race: Option<AcquireRace>,
    /// Store this many ownership grants before dropping their replies.
    #[cfg(test)]
    pub(crate) ownership_lost_grants: u32,
    /// Refuse this many ownership requests with 403 `no-principal` once the
    /// lost grants have been applied, even if a recorded grant matches.
    #[cfg(test)]
    pub(crate) ownership_refusals: u32,
    /// Block the poll that answers the next Register for this duration.
    #[cfg(test)]
    pub(crate) intent_reply_block: Option<std::time::Duration>,
    /// Delay one recovery release before the authority decides it.
    #[cfg(test)]
    pub(crate) release_delay: Option<std::time::Duration>,
    /// Apply one recovery release but lose its reply at the transport.
    #[cfg(test)]
    pub(crate) release_lost_reply: bool,
    /// Override the next readback's protocol answer.
    pub(crate) next_readback_rule: Option<&'static str>,
    /// Start and elapsed duration of the last intent retry wait that ran.
    #[cfg(test)]
    pub(crate) intent_wait_observed: Option<(tokio::time::Instant, std::time::Duration)>,
    /// Apply engine registrations but lose each reply at the transport.
    pub(crate) lose_registration_replies: bool,
    /// How the authority answers a Release.
    pub(crate) release_answer: ReleaseAnswer,
    /// Run once as the next Release is answered, before its reply returns.
    pub(crate) on_release: Option<Box<dyn FnOnce() + Send>>,
    /// How many publications were answered `stale-base`.
    pub(crate) stale_bases: usize,
    /// Last root sequence this authority landed.
    pub(crate) head_seq: u64,
    /// Exact request identities of accepted registrations, in acceptance order.
    pub(crate) registration_requests: Vec<GrainId>,
}
/// What changes between readback and the next Acquire.
#[cfg(test)]
pub(crate) enum AcquireRace {
    Insert(Receipt),
    AdvanceCursor,
}

/// How the authority answers a Release.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "fault answers are selected by the shared authority's test-target consumers"
    )
)]
pub(crate) enum ReleaseAnswer {
    /// It releases the row.
    #[default]
    Released,
    /// Another owner's newer epoch holds the row.
    Superseded,
    /// No row is held for this writer.
    Absent,
    /// It refuses the Release without a fence.
    Refused(u16, &'static str),
    /// It is unavailable.
    Unavailable,
    /// It rate-limits the Release for this many seconds.
    #[cfg(test)]
    RateLimited(u64),
}
/// How a bin range read fails.
#[derive(Clone, Copy)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "range faults are selected by the shared authority's test-target consumers"
    )
)]
pub(crate) enum RangeFault {
    /// As an unavailable store.
    Unavailable,
    /// With bytes altered after the read, as a frame that does not verify.
    Corrupt,
    /// As a refused answer, as a store or proxy answering another extent.
    Refused,
}
#[derive(Default)]
pub(crate) struct RangeReadPause {
    armed: std::sync::atomic::AtomicBool,
    pub(crate) entered: (Mutex<bool>, std::sync::Condvar),
    released: Mutex<bool>,
    release: tokio::sync::Notify,
}
impl RangeReadPause {
    #[cfg(test)]
    pub(crate) fn armed() -> Arc<Self> {
        let pause = Arc::new(Self::default());
        pause.arm();
        pause
    }
    #[cfg(test)]
    pub(crate) fn unarmed() -> Arc<Self> {
        Arc::new(Self::default())
    }
    #[cfg(test)]
    pub(crate) fn arm(&self) {
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(test)]
    pub(crate) fn is_entered(&self) -> bool {
        *self.entered.0.lock().unwrap()
    }
    #[must_use]
    #[cfg(test)]
    pub(crate) fn wait_entered_timeout(&self, timeout: std::time::Duration) -> bool {
        let (lock, cvar) = &self.entered;
        let (seen, _) = cvar
            .wait_timeout_while(lock.lock().unwrap(), timeout, |seen| !*seen)
            .unwrap();
        *seen
    }
    #[must_use]
    #[cfg(test)]
    pub(crate) fn wait_entered(&self) -> bool {
        self.wait_entered_timeout(std::time::Duration::from_secs(10))
    }
    #[cfg(test)]
    pub(crate) fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release.notify_waiters();
    }
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture mutex is unpoisoned while its generated range read is paused"
    )]
    pub(crate) async fn wait_for_release(&self) {
        if !self.armed.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let notified = self.release.notified();
        {
            let (lock, cvar) = &self.entered;
            let mut seen = lock.lock().unwrap();
            *seen = true;
            cvar.notify_all();
        }
        if *self.released.lock().unwrap() {
            return;
        }
        notified.await;
    }
}
#[derive(Clone)]
pub struct Authority {
    mem: Arc<InMemory>,
    scope: Scope,
    state: Arc<Mutex<AuthorityState>>,
    rule: &'static str,
    metrics: Option<crate::ClientMetrics>,
    publish: bool,
    range_pause: Option<Arc<RangeReadPause>>,
}

#[cfg(test)]
struct IntentWaitObservation {
    state: Arc<Mutex<AuthorityState>>,
    started: tokio::time::Instant,
}

#[cfg(test)]
impl Drop for IntentWaitObservation {
    fn drop(&mut self) {
        let now = crate::SyncRuntime::now(&crate::TokioSyncRuntime);
        let elapsed = now.checked_duration_since(self.started).unwrap_or_default();
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .intent_wait_observed = Some((self.started, elapsed));
    }
}
impl std::fmt::Debug for Authority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Authority").finish_non_exhaustive()
    }
}
impl MountMetrics for Authority {
    fn client_metrics(&self) -> Option<&crate::ClientMetrics> {
        self.metrics.as_ref()
    }
}
impl RootStore for Authority {
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before a generated root write"
    )]
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        if self.publish {
            return remote_handle(&self.mem).put_root(volume, seq, bytes).await;
        }
        self.state.lock().unwrap().calls[3] += 1;
        panic!("startup must not publish")
    }
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before a generated root read"
    )]
    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        {
            let mut state = self.state.lock().unwrap();
            state.root_reads += 1;
            if let Some(error) = state.root_fault.get(&seq) {
                return Err(error.clone());
            }
        }
        remote_handle(&self.mem).get_root(volume, seq).await
    }
    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        self.list_head(async { remote_handle(&self.mem).max_seq(volume).await })
            .await
    }
    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.list_head(async { remote_handle(&self.mem).max_seq_above(volume, floor).await })
            .await
    }
    async fn read_hint(
        &self,
        volume: &str,
        token: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
        if self.rule == "no_head" {
            Ok(granary_core::rootstore::HintRead::Missing)
        } else {
            remote_handle(&self.mem).read_hint(volume, token).await
        }
    }
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before a generated hint write"
    )]
    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        if self.publish {
            return remote_handle(&self.mem).write_hint(volume, seq).await;
        }
        self.state.lock().unwrap().calls[3] += 1;
        panic!("startup must not update hint")
    }
}
impl BinStore for Authority {
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before a generated bin write"
    )]
    async fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        if self.publish {
            return remote_handle(&self.mem).put_bin(digest, bytes).await;
        }
        self.state.lock().unwrap().calls[3] += 1;
        panic!("startup must not upload")
    }
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before a generated metadata write"
    )]
    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        if self.publish {
            return remote_handle(&self.mem).put_meta(volume, id, bytes).await;
        }
        self.state.lock().unwrap().calls[3] += 1;
        panic!("startup must not upload metadata")
    }
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before a generated metadata read"
    )]
    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        if std::mem::take(&mut self.state.lock().unwrap().fail_next_read) {
            return Err(RootStoreError::Unavailable {
                operation: "GET meta",
                status: 503,
            });
        }
        remote_handle(&self.mem).get_meta(volume, id).await
    }
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before a generated range read"
    )]
    async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        let fault = {
            let mut state = self.state.lock().unwrap();
            state.ranges.push((*digest, offset, length));
            let fault = state.next_range_fault.take();
            if std::mem::take(&mut state.fail_next_read)
                || matches!(fault, Some(RangeFault::Unavailable))
            {
                return Err(RootStoreError::Unavailable {
                    operation: "GET bin",
                    status: 503,
                });
            }
            if matches!(fault, Some(RangeFault::Refused)) {
                return Err(RootStoreError::RefusedResponse {
                    reason: "a range answer of another extent".to_owned(),
                    kind: granary_core::rootstore::RefusalKind::Extent,
                });
            }
            fault
        };
        if let Some(pause) = &self.range_pause {
            pause.wait_for_release().await;
        }
        let mut bytes = remote_handle(&self.mem)
            .get_bin_range(digest, offset, length)
            .await?;
        if matches!(fault, Some(RangeFault::Corrupt))
            && let Some(last) = bytes.last_mut()
        {
            *last ^= 0xff;
        }
        Ok(bytes)
    }
}
impl Authority {
    #[cfg(test)]
    pub(crate) fn new(tree: &PublishedTree, state: &Arc<Mutex<AuthorityState>>) -> Self {
        Self::with_scope_and_rule(tree, None, state, "valid")
    }
    pub(crate) fn with_scope_and_rule(
        tree: &PublishedTree,
        scope: Option<Scope>,
        state: &Arc<Mutex<AuthorityState>>,
        rule: &'static str,
    ) -> Self {
        Self {
            mem: Arc::clone(&tree.mem),
            scope: scope.unwrap_or_else(|| Scope {
                authority_base: b"https://fixture.invalid".to_vec(),
                pins: vec![],
                credential_context: b"fixture".to_vec(),
            }),
            state: Arc::clone(state),
            rule,
            metrics: None,
            publish: false,
            range_pause: None,
        }
    }
    #[cfg(test)]
    pub(crate) fn with_metrics(mut self, metrics: crate::ClientMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }
    pub(crate) fn with_publication(mut self) -> Self {
        self.publish = true;
        self
    }
    #[cfg(test)]
    pub(crate) fn with_range_pause(mut self, pause: Arc<RangeReadPause>) -> Self {
        self.range_pause = Some(pause);
        self
    }
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before a generated head probe"
    )]
    async fn list_head(
        &self,
        listing: impl Future<Output = Result<Option<u64>, RootStoreError>>,
    ) -> Result<Option<u64>, RootStoreError> {
        loop {
            {
                let mut state = self.state.lock().unwrap();
                if state.probe_limit.is_none_or(|limit| state.probes < limit) {
                    state.probes += 1;
                    if let Some(error) = &state.probe_fault {
                        return Err(error.clone());
                    }
                    break;
                }
                #[cfg(test)]
                {
                    state.probe_waits += 1;
                }
            }
            crate::SyncRuntime::sleep(
                &crate::TokioSyncRuntime,
                std::time::Duration::from_millis(10),
            )
            .await;
        }
        if self.rule == "no_head" {
            Ok(None)
        } else {
            listing.await
        }
    }
    pub(crate) fn reply(
        &self,
        status: u16,
        token: Option<&str>,
        media: Option<&str>,
        body: Vec<u8>,
    ) -> IntentReply {
        IntentReply {
            scope: Some(self.scope.clone()),
            volume: Some(vol("v")),
            status,
            token: token.map(str::to_owned),
            media_type: media.map(str::to_owned),
            body,
            retry_after: None,
        }
    }
    #[expect(
        clippy::unwrap_used,
        reason = "encode a checked receipt from the fixture's authority row"
    )]
    fn superseded(&self, receipt: Receipt) -> IntentReply {
        self.reply(
            409,
            Some("intent-superseded"),
            Some(intent::MEDIA_RECEIPT),
            intent::encode_receipt(receipt).unwrap(),
        )
    }
    /// Answer a Release as `state.release_answer` says.
    #[expect(
        clippy::unwrap_used,
        reason = "decode and encode only requests produced by the checked fixture engine"
    )]
    pub(crate) fn release_receipt(
        &self,
        state: &mut AuthorityState,
        request: &PendingIntent,
    ) -> IntentReply {
        let decoded = intent::decode_release(request.bytes()).unwrap();
        let receipt = Receipt {
            writer: decoded.writer,
            epoch: decoded.epoch,
            instance: decoded.instance,
            generation: decoded.generation,
            state: ReceiptState::Released,
        };
        match state.release_answer {
            ReleaseAnswer::Released => {
                state.row = Some(receipt);
                state.root.clear();
                self.reply(
                    200,
                    None,
                    Some(intent::MEDIA_RECEIPT),
                    intent::encode_receipt(receipt).unwrap(),
                )
            }
            ReleaseAnswer::Superseded => {
                let successor = Receipt {
                    epoch: decoded.epoch + 1,
                    ..receipt
                };
                self.superseded(successor)
            }
            ReleaseAnswer::Absent => self.reply(409, Some("intent-absent"), None, vec![]),
            ReleaseAnswer::Refused(status, token) => self.reply(status, Some(token), None, vec![]),
            ReleaseAnswer::Unavailable => self.reply(503, Some("unavailable"), None, vec![]),
            #[cfg(test)]
            ReleaseAnswer::RateLimited(seconds) => {
                let mut response = self.reply(429, Some("rate-limited"), None, vec![]);
                response.retry_after = Some(seconds.to_string());
                response
            }
        }
    }
    #[expect(
        clippy::unwrap_used,
        reason = "decode and encode only requests produced by the checked fixture engine"
    )]
    pub(crate) fn register_receipt(
        &self,
        state: &mut AuthorityState,
        request: &PendingIntent,
        verify: impl FnMut(&RootDoc, &[u8]) -> bool,
    ) -> IntentReply {
        let decoded = intent::decode_register(request.bytes(), request.volume(), verify).unwrap();
        let receipt = Receipt {
            writer: decoded.writer,
            epoch: decoded.epoch,
            instance: decoded.instance,
            generation: decoded.generation,
            state: ReceiptState::Live {
                prepared_root_id: decoded.root_id(),
            },
        };
        state.row = Some(receipt);
        state.root = decoded.root.to_vec();
        state
            .registration_requests
            .push(GrainId::of(request.bytes()));
        self.reply(
            200,
            None,
            Some(intent::MEDIA_RECEIPT),
            intent::encode_receipt(receipt).unwrap(),
        )
    }
}
impl WritableAuthority for Authority {
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before a runtime facade is minted"
    )]
    fn read_facade(&self) -> Self {
        self.state.lock().unwrap().runtime_facades += 1;
        self.clone()
    }
    #[expect(
        clippy::unwrap_used,
        reason = "encode the fixture authority's fixed checked status answer"
    )]
    async fn writable_status(&self, _: &VolumeName) -> Result<StatusResponse, AuthorityError> {
        self.state.lock().unwrap().calls[0] += 1;
        Ok(match self.rule {
            "unknown_target" => StatusResponse::Refused(StatusRefusal::UnknownTarget),
            "unknown_volume" => StatusResponse::Refused(StatusRefusal::UnknownVolume),
            "no_log" => StatusResponse::Refused(StatusRefusal::NoLog),
            "status_unavailable" => StatusResponse::Internal,
            "status_invalid" => StatusResponse::Refused(StatusRefusal::BadRequest),
            _ => crate::validate_status_observation(
                &granary_core::authority_answer::encode_status(
                    granary_core::authority_answer::VolumeStatus {
                        epoch: granary_core::authlog::Epoch::from_bytes([1; 16]),
                        head: None,
                        open: None,
                    },
                )
                .unwrap(),
            )
            .unwrap(),
        })
    }
    #[expect(
        clippy::unwrap_used,
        reason = "encode the fixture authority's in-memory checked readback"
    )]
    async fn writable_readback(
        &self,
        _: &Scope,
        _: &VolumeName,
        _: &[u8; 32],
    ) -> Result<IntentReply, IntentTransportError> {
        let mut state = self.state.lock().unwrap();
        state.calls[1] += 1;
        let rule = state.next_readback_rule.take().unwrap_or(self.rule);
        Ok(match rule {
            "family_missing" => self.reply(404, Some("unknown-target"), None, vec![]),
            "family_volume" => self.reply(404, Some("unknown-volume"), None, vec![]),
            "family_access" => self.reply(403, Some("no-principal"), None, vec![]),
            "family_invalid" => self.reply(200, None, Some(intent::MEDIA_READBACK), vec![]),
            #[cfg(test)]
            "family_scope" => IntentReply {
                scope: None,
                ..self.reply(
                    200,
                    None,
                    Some(intent::MEDIA_READBACK),
                    intent::encode_readback(state.cursor, &[]).unwrap(),
                )
            },
            "family_unavailable" => self.reply(503, Some("unavailable"), None, vec![]),
            "accepted_without_rows" => self.reply(
                200,
                None,
                Some(intent::MEDIA_READBACK),
                intent::encode_readback(state.cursor, &[]).unwrap(),
            ),
            _ => {
                let rows: Vec<_> = state
                    .row
                    .into_iter()
                    .filter(|row| matches!(row.state, ReceiptState::Live { .. }))
                    .map(|row| intent::ReadbackRow {
                        writer: row.writer,
                        epoch: row.epoch,
                        generation: row.generation,
                        root: state.root.as_slice(),
                    })
                    .collect();
                self.reply(
                    200,
                    None,
                    Some(intent::MEDIA_READBACK),
                    intent::encode_readback(state.cursor, &rows).unwrap(),
                )
            }
        })
    }
    #[expect(
        clippy::unwrap_used,
        reason = "decode and encode only requests produced by the checked fixture engine"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "fault hooks stay at their grant lookup and persistence boundaries"
    )]
    async fn writable_send(
        &self,
        _: &Scope,
        request: &PendingIntent,
        public: &[u8; 32],
    ) -> Result<IntentReply, IntentTransportError> {
        #[cfg(test)]
        if request.operation() == Operation::Release {
            let delay = self.state.lock().unwrap().release_delay.take();
            if let Some(delay) = delay {
                crate::TokioSyncRuntime.sleep(delay).await;
            }
        }
        let mut state = self.state.lock().unwrap();
        state.calls[2] += 1;
        state.sends.push(request.bytes().to_vec());
        if (self.rule == "acquire_missing" && request.operation() == Operation::Ownership)
            || (self.rule == "register_missing" && request.operation() == Operation::Register)
        {
            return Ok(self.reply(404, Some("unknown-target"), None, vec![]));
        }
        if self.rule == "always_lost" {
            return Err(IntentTransportError::Transport);
        }
        #[cfg(test)]
        if request.operation() == Operation::Register
            && let Some(seconds) = state.intent_retry_after.take()
        {
            let mut reply = self.reply(503, Some("unavailable"), None, vec![]);
            reply.retry_after = Some(seconds.to_string());
            return Ok(reply);
        }
        match request.operation() {
            Operation::Ownership => {
                #[cfg(test)]
                if state.ownership_refusals > 0 && state.ownership_lost_grants == 0 {
                    state.ownership_refusals -= 1;
                    return Ok(self.reply(403, Some("no-principal"), None, vec![]));
                }
                let decoded = intent::decode_ownership(request.bytes()).unwrap();
                #[cfg(test)]
                if let intent::OwnershipMode::Acquire { .. } = decoded.mode {
                    match state.ownership_acquire_race.take() {
                        Some(AcquireRace::Insert(row)) => {
                            state.cursor = row.epoch;
                            state.row = Some(row);
                        }
                        Some(AcquireRace::AdvanceCursor) => state.cursor += 1,
                        None => {}
                    }
                }
                // A takeover grant cannot be replayed after its row is evicted.
                if state.row.is_none()
                    && matches!(decoded.mode, intent::OwnershipMode::Takeover { .. })
                {
                    return Ok(self.reply(409, Some("intent-absent"), None, vec![]));
                }
                let request_id = GrainId::of(request.bytes());
                if let Some(grant) = state.grants.get(&request_id) {
                    return Ok(self.reply(
                        200,
                        None,
                        Some(intent::MEDIA_GRANT),
                        intent::encode_grant(*grant).unwrap(),
                    ));
                }
                #[cfg(test)]
                if self.rule == "superseded_succession"
                    && let intent::OwnershipMode::Takeover { expected_epoch, .. } = decoded.mode
                    && let Some(row) = state.row
                    && row.epoch > expected_epoch
                {
                    return Ok(self.superseded(row));
                }
                #[cfg(test)]
                if state.ownership_strict
                    && let Some(row) = state.row
                {
                    let conflict = match decoded.mode {
                        intent::OwnershipMode::Acquire { .. } => Some("intent-changed"),
                        intent::OwnershipMode::Takeover {
                            expected_epoch,
                            generation,
                            state: expected,
                            ..
                        } => {
                            if row.epoch != expected_epoch {
                                Some("intent-superseded")
                            } else if (row.generation, row.state) != (generation, expected) {
                                Some("intent-changed")
                            } else {
                                None
                            }
                        }
                    };
                    if let Some(token) = conflict {
                        return Ok(self.reply(
                            409,
                            Some(token),
                            Some(intent::MEDIA_RECEIPT),
                            intent::encode_receipt(row).unwrap(),
                        ));
                    }
                }
                #[cfg(test)]
                if state.ownership_strict
                    && let intent::OwnershipMode::Acquire { observed_cursor } = decoded.mode
                    && observed_cursor != state.cursor
                {
                    return Ok(self.reply(409, Some("intent-cursor-changed"), None, vec![]));
                }
                state.cursor += 1;
                let prior = state.row;
                let receipt = Receipt {
                    writer: decoded.writer,
                    epoch: state.cursor,
                    instance: decoded.instance,
                    generation: prior.map_or(0, |row| row.generation),
                    state: prior.map_or(ReceiptState::Released, |row| row.state),
                };
                state.row = Some(receipt);
                let grant = Grant {
                    request_id,
                    receipt,
                };
                state.grants.insert(request_id, grant);
                #[cfg(test)]
                if state.ownership_lost_grants > 0 {
                    state.ownership_lost_grants -= 1;
                    return Err(IntentTransportError::Transport);
                }
                if self.rule == "lost_grant" && state.calls[2] == 1 {
                    return Err(IntentTransportError::Transport);
                }
                Ok(self.reply(
                    200,
                    None,
                    Some(intent::MEDIA_GRANT),
                    intent::encode_grant(grant).unwrap(),
                ))
            }
            Operation::Register => {
                let reply = self.register_receipt(&mut state, request, |doc, prefix| {
                    doc.sigs.iter().any(|signature| {
                        granary_store::crypto::verify(public, prefix, &signature.sig).is_ok()
                    })
                });
                #[cfg(test)]
                let delay = state.intent_reply_block.take();
                drop(state);
                #[cfg(test)]
                if let Some(delay) = delay {
                    super::block_for_test(delay);
                }
                Ok(reply)
            }
            Operation::Release => {
                let reply = self.release_receipt(&mut state, request);
                #[cfg(test)]
                if std::mem::take(&mut state.release_lost_reply) {
                    return Err(IntentTransportError::Transport);
                }
                Ok(reply)
            }
        }
    }
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before its deterministic wait"
    )]
    async fn writable_wait(&self, milliseconds: u64) {
        #[cfg(test)]
        let observation = IntentWaitObservation {
            state: self.state.clone(),
            started: crate::SyncRuntime::now(&crate::TokioSyncRuntime),
        };
        #[cfg(test)]
        if self.state.lock().unwrap().intent_wait_frozen {
            crate::TokioSyncRuntime
                .sleep(std::time::Duration::from_millis(milliseconds))
                .await;
            return;
        }
        #[cfg(test)]
        let delay = self.state.lock().unwrap().intent_wait_delay.take();
        #[cfg(test)]
        if let Some(delay) = delay {
            crate::TokioSyncRuntime.sleep(delay).await;
        }
        self.state.lock().unwrap().tick += milliseconds;
        #[cfg(test)]
        drop(observation);
    }
}
impl crate::SyncRemote for Authority {
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before a generated registration"
    )]
    async fn register_once(
        &self,
        request: &PendingIntent,
        trusted: &granary_store::crypto::TrustedKeys,
    ) -> Result<IntentReply, IntentTransportError> {
        let mut state = self.state.lock().unwrap();
        state.calls[2] += 1;
        state.sends.push(request.bytes().to_vec());
        if let Some(served) = &mut state.registrations_served {
            if *served == 0 {
                return Ok(self.reply(503, Some("unavailable"), None, vec![]));
            }
            *served -= 1;
        }
        let reply = self.register_receipt(&mut state, request, |doc, prefix| {
            granary_store::crypto::check_signatures(doc, prefix, trusted).is_ok()
        });
        if state.lose_registration_replies {
            Err(IntentTransportError::Transport)
        } else {
            Ok(reply)
        }
    }
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture authority state is unpoisoned before a generated release"
    )]
    async fn release_once(
        &self,
        request: &PendingIntent,
    ) -> Result<IntentReply, IntentTransportError> {
        let mut state = self.state.lock().unwrap();
        state.calls[2] += 1;
        state.sends.push(request.bytes().to_vec());
        let reply = self.release_receipt(&mut state, request);
        let hook = state.on_release.take();
        drop(state);
        if let Some(hook) = hook {
            hook();
        }
        Ok(reply)
    }
}
#[derive(Clone)]
pub(crate) struct Time(pub(crate) Arc<Mutex<AuthorityState>>);
impl granary_core::clock::Clock for Time {
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture tick remains in the timestamp's representable range"
    )]
    fn now(&self) -> Timestamp {
        let tick = {
            let mut state = self.0.lock().unwrap();
            let tick = state.tick + 1000;
            state.tick += state.tick_per_read;
            tick
        };
        Timestamp {
            secs: i64::try_from(tick / 1000).unwrap(),
            nanos: u32::try_from(tick % 1000).unwrap() * 1_000_000,
        }
    }
}
pub(crate) struct Entropy(pub(crate) u8);
impl granary_core::secure_random::SecureRandom for Entropy {
    fn fill(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        bytes.fill(self.0);
        self.0 += 1;
        Ok(())
    }
}
impl AuthorityTransport for Authority {
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture store and authority codec receive only generated valid values"
    )]
    async fn publish_once(
        &self,
        request: &PublishRequest,
    ) -> Result<PublishResponse, AuthorityError> {
        let store = remote_handle(&self.mem);
        let candidate = request.candidate();
        let delay = self.state.lock().unwrap().publish_delay.take();
        if let Some(delay) = delay {
            crate::SyncRuntime::sleep(&crate::TokioSyncRuntime, delay).await;
        }
        #[cfg(test)]
        {
            let unavailable = {
                let mut state = self.state.lock().unwrap();
                match &mut state.publish_unavailable {
                    Some((left, delay)) if *left > 0 => {
                        *left -= 1;
                        let delay = *delay;
                        state.publications.push(candidate.bytes().to_vec());
                        Some(delay)
                    }
                    _ => None,
                }
            };
            if let Some(delay) = unavailable {
                crate::SyncRuntime::sleep(&crate::TokioSyncRuntime, delay).await;
                return validate_publish_answer(request, 503, Some("unavailable"), &[]);
            }
        }
        {
            let mut state = self.state.lock().unwrap();
            state.publications.push(candidate.bytes().to_vec());
            #[cfg(test)]
            if state.publish_timeouts > 0 {
                state.publish_timeouts -= 1;
                return Err(AuthorityError::Elapsed);
            }
            if state.publish_refusals > 0 {
                state.publish_refusals -= 1;
                return validate_publish_answer(request, 429, Some("rate-limited"), &[]);
            }
            if state.reject_publications {
                return validate_publish_answer(request, 400, Some("invalid-candidate"), &[]);
            }
        }
        let head = store.max_seq(request.volume()).await.unwrap().unwrap();
        let (status, token, answer) = if head >= candidate.seq() {
            self.state.lock().unwrap().stale_bases += 1;
            let root = store
                .get_root(request.volume(), head)
                .await
                .unwrap()
                .unwrap();
            (
                409,
                Some("stale-base"),
                PublishAnswer::StaleBase(Head::new(Some((head, GrainId::of(&root))))),
            )
        } else {
            store
                .put_root(
                    request.volume(),
                    candidate.seq(),
                    candidate.bytes().to_vec(),
                )
                .await
                .unwrap();
            self.state.lock().unwrap().head_seq = candidate.seq();
            (
                200,
                None,
                PublishAnswer::Landed {
                    receipt: authority_answer::Receipt {
                        position: Position {
                            epoch: request.epoch(),
                            entry_seq: 1,
                        },
                        root_seq: candidate.seq(),
                        stored_id: candidate.id(),
                    },
                    head: None,
                },
            )
        };
        let reply_delay = self.state.lock().unwrap().reply_delay.take();
        if let Some(delay) = reply_delay {
            crate::SyncRuntime::sleep(&crate::TokioSyncRuntime, delay).await;
        }
        validate_publish_answer(
            request,
            status,
            token,
            &authority_answer::encode(answer).unwrap(),
        )
    }
    #[expect(
        clippy::unwrap_used,
        reason = "the fixture store and authority codec receive only generated valid values"
    )]
    async fn status_once(&self, volume: &str) -> Result<StatusResponse, AuthorityError> {
        let store = remote_handle(&self.mem);
        let head = match store.max_seq(volume).await.unwrap() {
            Some(seq) => {
                let root = store.get_root(volume, seq).await.unwrap().unwrap();
                Some(Head::new(Some((seq, GrainId::of(&root)))))
            }
            None => None,
        };
        validate_status_observation(
            &authority_answer::encode_status(VolumeStatus {
                epoch: granary_core::authlog::Epoch::from_bytes([1; 16]),
                head,
                open: None,
            })
            .unwrap(),
        )
    }
    async fn probe_root_once(
        &self,
        volume: &str,
        seq: u64,
    ) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.get_root(volume, seq).await
    }
}
