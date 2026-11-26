// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Sealed construction and retained submission with short mediator transactions.

use super::{
    Arc, AtomicBool, Clock, CommitCapture, CommitDrive, CoordinationError, Duration, FloorWake,
    GrainId, GrainSource, LandedProof, LocalContent, MonotonicClock, Mutex, Notify, OverlayIo,
    Phase, Reply, RetainedCommit, RuntimeRng, SAVE_MARGIN, Submission, SyncContent, SyncEngine,
    SyncOptions, SyncProjectionQueue, SyncRemote, SyncRuntime, bounded, refused,
    terminal_non_landing,
};
use crate::{
    AuthorityTransport, CommitResult, PublicationHandle, PublicationJournal, PublicationOutcome,
    PublicationResult, PublicationStoreError, PublicationStoreErrorKind, PublishResponse,
    RecoveryDelay, RecoveryError, RecoveryIntent, RecoveryParts, ServiceReason,
    http_store::seam_deadline, recovery::MAX_UNAVAILABLE_EXEMPTIONS,
};
use granary_core::{
    grainsource::GrainSourceError,
    retained_submission::{Candidate, Evidence, FrozenIntent, RequestIdentity, Role, Scope},
    rng::Rng as _,
    root::VolumeName,
    secure_random::SecureRandom,
};
use granary_store::bounds::ROOT_MAX_BYTES;
use std::sync::atomic::AtomicUsize;
use tracing::Instrument as _;

const OUTAGE_WINDOW: Duration = Duration::from_mins(31);
const MIN_OUTAGE_POLL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Waited {
    Latched,
    LaneRetained,
    Construct,
}

struct Journal<'a, P: OverlayIo, R, S, C, M, E> {
    engine: &'a Arc<SyncEngine<P, R, S, C, M, E>>,
    lane: &'a RetainedCommit,
    deadline: tokio::time::Instant,
    drive: CommitDrive,
    conflict: super::reporting::Conflict,
    /// A merge ran and its candidate is not saved yet.
    merged: bool,
}

fn outage_window_active(lane: &RetainedCommit, now: tokio::time::Instant) -> bool {
    lane.observation.lock().is_ok_and(|state| {
        state
            .outage_started
            .is_some_and(|started| now.duration_since(started) < OUTAGE_WINDOW)
    })
}

/// One holder of the commit driver; the driver is free once every holder
/// has dropped, and the last one to drop wakes a caller waiting for it.
pub(super) struct DriverGuard {
    holders: Arc<AtomicUsize>,
    released: Arc<Notify>,
}
impl DriverGuard {
    /// A second holder of a driver the caller already holds, for work that
    /// must keep the driver after the caller stops waiting.
    pub(super) fn share(holders: &Arc<AtomicUsize>, released: &Arc<Notify>) -> Self {
        holders.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self {
            holders: Arc::clone(holders),
            released: Arc::clone(released),
        }
    }
}
impl Drop for DriverGuard {
    fn drop(&mut self) {
        if self
            .holders
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.released.notify_waiters();
        }
    }
}
#[expect(
    clippy::needless_pass_by_value,
    reason = "map_err consumes the failed transaction's owned error"
)]
fn journal_error(error: CoordinationError) -> PublicationStoreError {
    PublicationStoreError {
        path: "journal".into(),
        kind: match &error {
            CoordinationError::Overlay(crate::OverlayError::Conflict) => {
                PublicationStoreErrorKind::Conflict
            }
            CoordinationError::CommitFenced { .. } => PublicationStoreErrorKind::Fenced,
            CoordinationError::Refused("SyncCommitRebaseUnavailable") => {
                PublicationStoreErrorKind::Unavailable
            }
            CoordinationError::Refused("SyncCommitRebaseManifest") => {
                PublicationStoreErrorKind::Corrupt
            }
            _ => PublicationStoreErrorKind::Refused,
        },
        reason: error.to_string(),
    }
}
impl<P, R, S, C, M, E> GrainSource for Journal<'_, P, R, S, C, M, E>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + granary_core::rootstore::RootStore + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    fn has(&self, id: &GrainId) -> bool {
        LocalContent(self.engine.content.as_ref()).has(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        // Recovery fetches missing objects asynchronously through its transport.
        LocalContent(self.engine.content.as_ref()).get(id)
    }
}
impl<P, R, S, C, M, E> PublicationJournal for Journal<'_, P, R, S, C, M, E>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + granary_core::rootstore::RootStore + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    fn check_dispatch_deadline(&self, root_bytes: u64) -> Result<(), RecoveryError> {
        let start = match self.drive {
            CommitDrive::Start(_) => true,
            CommitDrive::Background(_) => false,
            CommitDrive::Direct(_) | CommitDrive::Mount(_) => return Ok(()),
        };
        let now = self.engine.runtime.now();
        if !start && !outage_window_active(self.lane, now) {
            return Ok(());
        }
        let seam = seam_deadline(root_bytes);
        let floor = if start { seam + SAVE_MARGIN } else { seam };
        #[cfg(test)]
        let floor = if start {
            self.engine
                .start_dispatch_floor
                .get()
                .copied()
                .unwrap_or(floor)
        } else {
            floor
        };
        if self.deadline.saturating_duration_since(now) < floor {
            return Err(RecoveryError::Refused("SyncDeadline"));
        }
        Ok(())
    }

    fn check_dispatch_deadline_at_cap(&self) -> bool {
        matches!(self.drive, CommitDrive::Start(_))
    }

    fn retry(&mut self, attempt: u32, reason: crate::RetryReason) {
        let unavailable = self
            .lane
            .observation
            .lock()
            .is_ok_and(|mut state| std::mem::take(&mut state.retry_unavailable));
        let reason = if unavailable && reason != crate::RetryReason::Conflict {
            crate::RetryReason::Unavailable
        } else {
            reason
        };
        self.engine.metrics.record_retry(reason);
        crate::observe::op_retry(crate::OperationKind::Commit, attempt, reason);
        #[cfg(test)]
        self.engine
            .commit_retries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(reason);
    }
    fn unavailable_window_open(&mut self, record: &Submission) -> bool {
        let now = self.engine.runtime.now();
        self.lane.observation.lock().is_ok_and(|mut state| {
            let started = *state.outage_started.get_or_insert(now);
            if now.duration_since(started) >= OUTAGE_WINDOW {
                return false;
            }
            // Even a drive interrupted after saving the exemption must wait.
            let jitter = RuntimeRng(self.engine.runtime.as_ref()).below(30_001);
            let next_poll = now + MIN_OUTAGE_POLL + Duration::from_millis(jitter);
            state.next_poll = Some((
                next_poll,
                PublicationHandle {
                    scope: record.scope.clone(),
                    volume: record.volume.clone(),
                    publication_id: record.publication_id,
                },
            ));
            state.retry_unavailable = true;
            true
        })
    }
    fn commit_attempts(
        &mut self,
        publication: [u8; 16],
    ) -> Result<Option<u64>, PublicationStoreError> {
        self.engine
            .local(|local| {
                Ok(Some(
                    local
                        .commit_progress(self.lane.serial, publication)?
                        .attempts,
                ))
            })
            .map_err(journal_error)
    }
    fn load(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        self.engine
            .local(|local| {
                let record = local.commit_record(self.lane.serial, self.lane.publication)?;
                if record.scope != *scope || record.volume != *volume {
                    return Err(refused("SyncCommitScope"));
                }
                Ok(Some(record))
            })
            .map_err(journal_error)
    }
    fn begin(&mut self, _: &Submission) -> Result<(), PublicationStoreError> {
        Err(journal_error(refused("SyncCommitAlreadyRetained")))
    }
    async fn rebase_manifest(
        &mut self,
        frozen: &FrozenIntent,
        parent: Option<GrainId>,
        seq: u64,
    ) -> Result<GrainId, PublicationStoreError> {
        self.engine
            .fault(
                "sync.commit",
                "before_rebase",
                self.lane.serial,
                None,
                "none",
            )
            .await
            .map_err(journal_error)?;
        // A projected lane's residual is copied in one short acquisition and
        // built off the executor; writes since the last attempt join it.
        let anchors = if self.lane.projected {
            let snapshot = self
                .engine
                .local(|local| {
                    local.residual_snapshot(
                        self.lane.serial,
                        self.lane.boundary,
                        self.lane.publication,
                    )
                })
                .map_err(journal_error)?;
            let anchors = self
                .engine
                .runtime
                .blocking(move || snapshot.anchors())
                .await
                .map_err(|_| journal_error(refused("SyncMaterializationLost")))?
                .map_err(|error| journal_error(error.into()))?;
            Some(anchors)
        } else {
            None
        };
        let merged = self
            .engine
            .merge_commit_manifest(
                frozen,
                &self.lane.entries,
                parent,
                seq,
                self.deadline,
                super::rebase::MergePurpose::Attempt(self.conflict.clone(), anchors),
            )
            .await
            .map_err(journal_error)?;
        self.merged = true;
        Ok(merged)
    }

    async fn replace(
        &mut self,
        generation: u64,
        record: &Submission,
    ) -> Result<(), PublicationStoreError> {
        if matches!(record.phase, Phase::AwaitingAnswer { .. }) {
            self.engine
                .fault(
                    "sync.commit",
                    "before_submit",
                    self.lane.serial,
                    None,
                    "none",
                )
                .await
                .map_err(journal_error)?;
        }
        self.engine
            .verify_commit_record(record, &self.lane.entries, self.deadline, &self.conflict)
            .await
            .map_err(journal_error)?;
        let rebased = std::mem::take(&mut self.merged);
        self.engine
            .local(|local| {
                local.check_commit_lane(self.lane.serial)?;
                if record.publication_id != self.lane.publication {
                    return Err(refused("SyncCommitIdentity"));
                }
                if matches!(record.phase, Phase::AwaitingAnswer { .. }) {
                    let progress =
                        local.commit_progress(self.lane.serial, self.lane.publication)?;
                    let attempt = progress
                        .attempts
                        .checked_add(1)
                        .ok_or_else(|| refused("SyncCommitExhausted"))?;
                    local.overlay_transaction(|t| {
                        t.record_commit_attempt(self.lane.boundary, self.lane.publication, attempt)
                    })?;
                }
                local.publication_transaction(|j| j.replace(generation, record))
            })
            .map_err(journal_error)?;
        // The first ready save after a merge makes the rebased candidate
        // durable; the ready saves that follow come from probes.
        if rebased && matches!(record.phase, Phase::Ready) {
            self.engine
                .fault(
                    "sync.commit",
                    "after_rebase",
                    self.lane.serial,
                    None,
                    "none",
                )
                .await
                .map_err(journal_error)?;
        }
        Ok(())
    }
}

impl<P, R, S, C, M, E> SyncEngine<P, R, S, C, M, E>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + AuthorityTransport + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    #[cfg(test)]
    pub(crate) fn commit_retry_reasons(&self) -> Vec<crate::RetryReason> {
        self.commit_retries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    #[cfg(test)]
    pub(crate) async fn rebase_commit_manifest(
        self: &Arc<Self>,
        lane: &RetainedCommit,
        frozen: &FrozenIntent,
        parent: Option<GrainId>,
        seq: u64,
    ) -> Result<GrainId, PublicationStoreError> {
        Journal {
            engine: self,
            lane,
            deadline: lane.deadline,
            drive: CommitDrive::Direct(RecoveryIntent::Continue),
            conflict: super::reporting::Conflict::default(),
            merged: false,
        }
        .rebase_manifest(frozen, parent, seq)
        .await
    }

    #[cfg(test)]
    pub(crate) async fn replace_commit_record(
        self: &Arc<Self>,
        lane: &RetainedCommit,
        generation: u64,
        record: &Submission,
    ) -> Result<(), PublicationStoreError> {
        Journal {
            engine: self,
            lane,
            deadline: lane.deadline,
            drive: CommitDrive::Direct(RecoveryIntent::Continue),
            conflict: super::reporting::Conflict::default(),
            merged: false,
        }
        .replace(generation, record)
        .await
    }

    /// Seal, materialize, accept and sign a complete candidate using the captured
    /// base and persisted writer. Dropping this wait leaves supervised construction
    /// running; `recover_commit` selects its retained result without recapturing.
    /// # Errors
    /// Entropy, admission, capacity, object acceptance or durable retention.
    pub fn construct_commit(
        self: &Arc<Self>,
        options: SyncOptions,
        secure: &mut (impl SecureRandom + ?Sized),
    ) -> impl std::future::Future<Output = Result<RetainedCommit, CoordinationError>> + Send + 'static
    {
        self.construct_commit_inner(options, secure, false)
    }

    pub(crate) fn construct_latched(
        self: &Arc<Self>,
        options: SyncOptions,
        secure: &mut (impl SecureRandom + ?Sized),
    ) -> impl std::future::Future<Output = Result<RetainedCommit, CoordinationError>> + Send + 'static
    {
        self.construct_commit_inner(options, secure, true)
    }

    fn construct_commit_inner(
        self: &Arc<Self>,
        options: SyncOptions,
        secure: &mut (impl SecureRandom + ?Sized),
        latched: bool,
    ) -> impl std::future::Future<Output = Result<RetainedCommit, CoordinationError>> + Send + 'static
    {
        use tracing::instrument::WithSubscriber as _;
        let identities = commit_identities(secure);
        let span = identities
            .as_ref()
            .ok()
            .and_then(|(_, _, id)| *id)
            .map_or_else(tracing::Span::none, |id| {
                crate::operation_span(crate::OperationKind::Commit, &id)
            });
        let engine = self.clone();
        async move {
            let (publication, operation, operation_id) = identities?;
            let worker = engine.clone();
            // Supervised construction reports its own failure, so the report
            // survives a caller that stopped waiting.
            let report = |error: &CoordinationError| {
                crate::observe::op_failed(
                    crate::OperationKind::Commit,
                    super::super::failure_class(error),
                );
            };
            let owner = Arc::new(super::ConstructionOwner {
                operation,
                serial: std::sync::OnceLock::new(),
            });
            let lost = owner.clone();
            let unmonitored = owner.clone();
            let monitor = engine.clone();
            let runtime = engine.runtime.clone();
            let (sender, receiver) = tokio::sync::oneshot::channel();
            // A detached monitor joins the construction, so a task lost after
            // its caller stopped waiting still releases what it opened.
            drop(engine.runtime.spawn(async move {
                let construction = runtime.spawn(async move {
                    let result = worker
                        .construct_owned(options, publication, &owner, operation_id, latched)
                        .await;
                    #[cfg(test)]
                    worker.disarm_retention_panics();
                    if let Err(error) = &result {
                        let mutations_closed = latched
                            && matches!(
                                error,
                                CoordinationError::Overlay(crate::OverlayError::MutationsClosed)
                            );
                        if !mutations_closed {
                            report(error);
                            // Best effort: an unrecorded refusal is retried sooner.
                            let _ = worker.local(|local| {
                                local.note_capacity_refusal(error);
                                Ok(())
                            });
                        }
                    }
                    result
                });
                let result = construction.await.unwrap_or_else(|_| {
                    monitor.release_lost_construction(&lost);
                    let error = refused("SyncSupervisorLost");
                    report(&error);
                    Err(error)
                });
                // Nothing holds the engine once the result is delivered.
                drop(monitor);
                let _ = sender.send(result);
            }));
            // A lost monitor is answered as its join-error arm would answer.
            receiver.await.unwrap_or_else(|_| {
                engine.release_lost_construction(&unmonitored);
                let error = refused("SyncSupervisorLost");
                report(&error);
                Err(error)
            })
        }
        .instrument(span)
        .with_current_subscriber()
    }

    async fn construct_owned(
        self: &Arc<Self>,
        options: SyncOptions,
        publication: [u8; 16],
        owner: &super::ConstructionOwner,
        operation_id: Option<crate::CorrelationId>,
        latched: bool,
    ) -> Result<RetainedCommit, CoordinationError> {
        let capture = self
            .begin_commit_inner(options, true, Some(owner), latched)
            .await?;
        let result = self
            .construct_candidate(
                &capture,
                options.workspace_bytes,
                publication,
                owner.operation,
            )
            .await;
        match result {
            Ok((record, mapped)) => {
                self.retain_commit_mapped(capture, &record, Some(Arc::new(mapped)), operation_id)
                    .await
            }
            Err(error) => {
                self.discard_commit(capture)?;
                Err(error)
            }
        }
    }

    async fn construct_candidate(
        self: &Arc<Self>,
        capture: &CommitCapture,
        budget: u64,
        publication: [u8; 16],
        operation: [u8; 16],
    ) -> Result<(Submission, std::collections::BTreeSet<GrainId>), CoordinationError> {
        #[cfg(test)]
        self.retention_panics(super::super::RetentionPanic::Constructing);
        let boundary = capture
            .snapshot
            .as_deref()
            .ok_or_else(|| refused("SyncCommitCapture"))?;
        let mut queue = SyncProjectionQueue::default();
        queue.reserve(boundary)?;
        let reply = Arc::new(Reply {
            sender: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            cancellation: Notify::new(),
            metrics: self.metrics.clone(),
            observed: false,
        });
        let (mut accepted, _) = self
            .accept_boundary(boundary, budget, &reply, capture.deadline, &queue, true)
            .await?;
        let mapped = accepted
            .accepted
            .take_complete()
            .map_err(|_| refused("SyncCommitBinmap"))?;
        let writer = self.local(|local| Ok(local.writer_uuid()))?;
        let mut doc = accepted.accepted.doc;
        doc.writer_uuid = writer;
        let prefix = granary_core::root::signing_prefix_of(&doc)
            .map_err(|_| refused("SyncCommitSignature"))?;
        doc.sigs.push(granary_core::root::RootSig {
            key_id: self.key.key_id(),
            sig: self.key.sign(&prefix),
        });
        let bytes =
            granary_core::root::encode_root(&doc).map_err(|_| refused("SyncCommitSignature"))?;
        let record = self
            .initial_submission(bytes, capture.deadline, publication, operation)
            .await?;
        Ok((record, mapped))
    }

    /// Read the closed journal through the commit's bounded whole-tree capture.
    /// The comparison needs neither a retained boundary nor remote custody.
    pub(crate) async fn replayed_manifest(
        self: &Arc<Self>,
        options: SyncOptions,
    ) -> Result<GrainId, CoordinationError> {
        self.local(|local| {
            if !local.mutations_closed() {
                return Err(refused("WritableRecoveryRequired"));
            }
            local.check_finish_obligations()
        })?;
        let capture = self.begin_commit_inner(options, true, None, false).await?;
        let manifest = self
            .replayed_manifest_inner(&capture, options.workspace_bytes)
            .await;
        self.discard_commit(capture)?;
        manifest
    }

    /// Return the signing key after a mount-less comparison so the unchanged
    /// finish path can attach after registering the selected root.
    pub(crate) fn into_comparison_key(
        self: Arc<Self>,
    ) -> Option<granary_store::crypto::SigningKey> {
        Arc::into_inner(self).map(|engine| engine.key)
    }

    async fn replayed_manifest_inner(
        self: &Arc<Self>,
        capture: &CommitCapture,
        budget: u64,
    ) -> Result<GrainId, CoordinationError> {
        let boundary = capture
            .snapshot
            .clone()
            .ok_or_else(|| refused("SyncCommitCapture"))?;
        let deadline = capture.deadline;
        let reply = Reply {
            sender: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            cancellation: Notify::new(),
            metrics: self.metrics.clone(),
            observed: false,
        };
        let engine = self.clone();
        self.runtime
            .blocking(move || engine.materialized_manifest(&boundary, budget, &reply, deadline))
            .await
            .map_err(|_| refused("SyncMaterializationLost"))?
    }

    /// A retained submission whose one candidate is `root`, signed by the
    /// persisted writer, under the publication epoch the authority reports.
    pub(super) async fn initial_submission(
        &self,
        root: Vec<u8>,
        deadline: tokio::time::Instant,
        publication: [u8; 16],
        operation: [u8; 16],
    ) -> Result<Submission, CoordinationError> {
        let doc =
            granary_core::root::decode_root(&root).map_err(|_| refused("SyncCommitSignature"))?;
        let scope = self.local(|local| Ok(local.snapshot().scope.clone()))?;
        let status = bounded(
            self.runtime.as_ref(),
            deadline,
            crate::bootstrap_publication(self.remote.as_ref(), &doc.volume),
        )
        .await?
        .map_err(|_| refused("SyncCommitBootstrap"))?;
        let request = RequestIdentity {
            epoch: status.observation().epoch.to_bytes(),
            operation,
        };
        Ok(Submission {
            generation: 1,
            publication_id: publication,
            scope,
            volume: doc.volume,
            frozen: FrozenIntent {
                writer_identity: doc.writer_uuid,
                min_prefix_bits: 0,
                initial_root: root.clone(),
            },
            current: Some(request),
            candidates: vec![Candidate {
                number: 1,
                role: Role::Active,
                request,
                seq: doc.seq,
                id: GrainId::of(&root),
                root,
                evidence: Evidence::default(),
            }],
            phase: Phase::Ready,
            last_response: None,
            unavailable_exemptions: 0,
        })
    }

    /// Continue retained submission, including rebase, then read back, refresh
    /// and replace the base before reopening syncs. Cancellation preserves the
    /// lane and exact journal-before-send evidence. Pending/budget exhaustion
    /// never admits a sync or invents an acknowledgement.
    /// # Errors
    /// Deadline, retained evidence, authority, content or local persistence.
    pub async fn drive_commit(
        self: &Arc<Self>,
        lane: &RetainedCommit,
        secure: &mut (dyn SecureRandom + Send),
        delay: &mut (dyn RecoveryDelay + Send),
        intent: RecoveryIntent,
        options: SyncOptions,
    ) -> Result<PublicationResult, CoordinationError> {
        self.drive_commit_for(lane, secure, delay, CommitDrive::Direct(intent), options)
            .await
    }

    pub(crate) async fn drive_commit_for(
        self: &Arc<Self>,
        lane: &RetainedCommit,
        secure: &mut (dyn SecureRandom + Send),
        delay: &mut (dyn RecoveryDelay + Send),
        drive: CommitDrive,
        options: SyncOptions,
    ) -> Result<PublicationResult, CoordinationError> {
        self.commit_driver
            .compare_exchange(
                0,
                1,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map_err(|_| refused("SyncCommitInFlight"))?;
        // Whatever this drive settled wakes a caller waiting on the lane,
        // once the driver below is released.
        let _wake = FloorWake(&self.floor_changed);
        let _driver = DriverGuard {
            holders: Arc::clone(&self.commit_driver),
            released: Arc::clone(&self.floor_changed),
        };
        let mut observation = super::reporting::Observation::new(self, lane, secure);
        let result = self
            .drive_commit_inner(lane, secure, delay, drive, options, &observation.conflict)
            .instrument(observation.span())
            .await;
        observation.span().in_scope(|| {
            if matches!(
                &result,
                Err(CoordinationError::Refused("SyncCommitRebaseUnavailable")
                    | CoordinationError::Recovery(crate::RecoveryError::Journal(
                        PublicationStoreError {
                            kind: PublicationStoreErrorKind::Unavailable,
                            ..
                        }
                    )))
            ) && self
                .local(|local| {
                    Ok(local
                        .commit_progress(lane.serial, lane.publication)?
                        .attempts)
                })
                .is_ok_and(|attempts| attempts > 0)
                && let Ok(mut state) = lane.observation.lock()
            {
                state.retry_unavailable = true;
            }
        });
        observation.finish(&result);
        result.map(|(result, _)| result)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the poll gate, bounded drive and retained settlement are ordered under one driver holder"
    )]
    async fn drive_commit_inner(
        self: &Arc<Self>,
        lane: &RetainedCommit,
        secure: &mut (dyn SecureRandom + Send),
        delay: &mut (dyn RecoveryDelay + Send),
        drive: CommitDrive,
        options: SyncOptions,
        conflict: &super::reporting::Conflict,
    ) -> Result<(PublicationResult, Option<CommitResult>), CoordinationError> {
        let outage_pending = |handle| {
            Ok((
                PublicationResult::new(
                    handle,
                    PublicationOutcome::Pending,
                    Some(PublishResponse::ServiceUnavailable(
                        ServiceReason::Unavailable,
                    )),
                    true,
                    None,
                ),
                None,
            ))
        };
        if let Ok(state) = lane.observation.lock()
            && let Some((next_poll, handle)) = &state.next_poll
            && self.runtime.now() < *next_poll
        {
            return outage_pending(handle.clone());
        }
        let record = self.local(|local| local.commit_record(lane.serial, lane.publication))?;
        let deadline = self.deadline(options)?.min(lane.deadline);
        let handle = PublicationHandle {
            scope: record.scope.clone(),
            volume: record.volume.clone(),
            publication_id: record.publication_id,
        };
        let now = self.runtime.now();
        if matches!(drive, CommitDrive::Mount(_))
            && deadline.saturating_duration_since(now) < seam_deadline(ROOT_MAX_BYTES)
            && record.unavailable_exemptions < MAX_UNAVAILABLE_EXEMPTIONS
            && outage_window_active(lane, now)
        {
            return outage_pending(handle);
        }
        let writer = self.local(|local| Ok(local.writer_uuid()))?;
        self.verify_commit_record(&record, &lane.entries, deadline, conflict)
            .await
            .map_err(|error| self.commit_error(error, lane))?;
        let attempts_at_start = if record.is_complete() {
            // Landing readback can resume after the attempt frames have been retired.
            0
        } else {
            self.local(|local| {
                Ok(local
                    .commit_progress(lane.serial, lane.publication)?
                    .attempts)
            })?
        };
        let intent = match drive {
            CommitDrive::Direct(intent)
            | CommitDrive::Mount(intent)
            | CommitDrive::Start(intent)
            | CommitDrive::Background(intent) => intent,
        };
        let mut journal = Journal {
            engine: self,
            lane,
            deadline,
            drive,
            conflict: conflict.clone(),
            merged: false,
        };
        let parts = RecoveryParts {
            transport: self.remote.as_ref(),
            journal: &mut journal,
            publisher_keys: &self.trusted,
            signer: &self.key,
            secure,
            clock: self.wall.as_ref(),
            delay,
        };
        let mut result = bounded(
            self.runtime.as_ref(),
            deadline,
            Box::pin(crate::recovery::resume_store_publication(
                parts, &handle, intent, writer,
            )),
        )
        .await?
        .map_err(|error| match error {
            RecoveryError::Refused("SyncDeadline") => refused("SyncDeadline"),
            error => CoordinationError::Recovery(error),
        })
        .map_err(|error| self.commit_error(error, lane))?;
        if let PublicationOutcome::Landed(done) = &result.outcome {
            let doc = granary_core::root::decode_root(&done.root)
                .map_err(|_| refused("SyncCommitSignature"))?;
            let mut entries = lane.entries.clone();
            let engine = self.clone();
            let manifest_root = doc.manifest_root;
            entries = self
                .runtime
                .blocking(move || {
                    let content = engine
                        .content
                        .with_deadline(engine.runtime.clone(), deadline);
                    build_landed_entries(manifest_root, &entries, &content)
                })
                .await
                .map_err(|_| refused("SyncMaterializationLost"))??;
            self.finish_landed_commit(
                lane,
                LandedProof {
                    boundary_seq: lane.boundary,
                    landed_root: done.id,
                    landed_seq: done.seq,
                    captured_entries: lane.entries.clone(),
                    entries,
                },
                SyncOptions {
                    deadline: Some(deadline),
                    ..options
                },
            )
            .await?;
            return Ok((result, Some(CommitResult::Ok)));
        }
        let retained = self.local(|local| local.commit_record(lane.serial, lane.publication))?;
        if result.admission_error().is_none()
            && !crate::recovery::deferred_answer_pending(&retained)
            && crate::recovery::charged_attempts(
                self.local(|local| {
                    Ok(local
                        .commit_progress(lane.serial, lane.publication)?
                        .attempts)
                })?,
                attempts_at_start,
                &retained,
            ) >= u64::from(crate::recovery::DISPATCH_ATTEMPTS)
        {
            result.outcome = PublicationOutcome::Exhausted;
        }
        let terminal = if result.outcome == PublicationOutcome::Exhausted {
            self.local(|local| local.exhaust_commit(lane.serial, lane.boundary, lane.publication))?;
            Some(CommitResult::Exhausted)
        } else if terminal_non_landing(&retained) {
            self.finish_rejected_commit(lane)?;
            Some(CommitResult::Failed)
        } else {
            None
        };
        Ok((result, terminal))
    }

    /// Wait for the first live commit state. A held lane refuses immediately;
    /// a latched store refuses as closed to mutations. Otherwise, wait for
    /// journal or staging pressure, quiescence without open write handles, or
    /// maximum age from the first dirty record, then construct and drive one
    /// commit cycle.
    /// # Errors
    /// `SyncCommitInFlight` for a held lane, `MutationsClosed` for a latched
    /// store, or deadline, readiness, capacity, authority, content or local
    /// persistence failures from construction and driving.
    pub async fn coalesce_commit(
        self: &Arc<Self>,
        options: SyncOptions,
        secure: &mut (dyn SecureRandom + Send),
    ) -> Result<PublicationResult, CoordinationError> {
        match self.live_wait(options).await? {
            Waited::Construct => {}
            Waited::LaneRetained => return Err(refused("SyncCommitInFlight")),
            Waited::Latched => return Err(crate::OverlayError::MutationsClosed.into()),
        }
        let lane = self.construct_commit(options, secure).await?;
        let mut delay = RuntimeSeams(self.runtime.as_ref());
        self.drive_commit(&lane, secure, &mut delay, RecoveryIntent::Continue, options)
            .await
    }

    pub(super) async fn live_wait(
        &self,
        options: SyncOptions,
    ) -> Result<Waited, CoordinationError> {
        loop {
            let floor = self.floor_changed.notified();
            tokio::pin!(floor);
            floor.as_mut().enable();
            let wake = self.coalesce_wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            #[cfg(test)]
            if let Some(hook) = self
                .before_live_read
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                hook();
            }
            let now = self.runtime.now();
            let state = self.local(|local| local.live_state(&options, now))?;
            #[cfg(test)]
            if let Some(hook) = self
                .after_live_read
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                hook();
            }
            match state {
                crate::writable_store::sync_engine::LiveState::Latched => {
                    return Ok(Waited::Latched);
                }
                crate::writable_store::sync_engine::LiveState::LaneHeld => {
                    return Ok(Waited::LaneRetained);
                }
                crate::writable_store::sync_engine::LiveState::Ready => {
                    return Ok(Waited::Construct);
                }
                crate::writable_store::sync_engine::LiveState::WaitUntil(Some(deadline)) => {
                    use std::future::Future as _;
                    let mut timer =
                        std::pin::pin!(self.runtime.sleep(deadline.saturating_duration_since(now)));
                    std::future::poll_fn(|cx| {
                        if floor.as_mut().poll(cx).is_ready()
                            || wake.as_mut().poll(cx).is_ready()
                            || self.runtime.now() >= deadline
                            || timer.as_mut().poll(cx).is_ready()
                        {
                            std::task::Poll::Ready(())
                        } else {
                            std::task::Poll::Pending
                        }
                    })
                    .await;
                }
                crate::writable_store::sync_engine::LiveState::Clean
                | crate::writable_store::sync_engine::LiveState::WaitUntil(None) => {
                    use std::future::Future as _;
                    std::future::poll_fn(|cx| {
                        if floor.as_mut().poll(cx).is_ready() || wake.as_mut().poll(cx).is_ready() {
                            std::task::Poll::Ready(())
                        } else {
                            std::task::Poll::Pending
                        }
                    })
                    .await;
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn live_wait_for_test(
        &self,
        options: SyncOptions,
    ) -> Result<&'static str, CoordinationError> {
        Ok(match self.live_wait(options).await? {
            Waited::Latched => "latched",
            Waited::LaneRetained => "lane_retained",
            Waited::Construct => "construct",
        })
    }
}

/// A commit's publication and operation identities and its correlation id.
pub(super) type CommitIdentities = ([u8; 16], [u8; 16], Option<crate::CorrelationId>);

/// Draw a commit's identities; a correlation id that cannot be drawn is
/// reported and goes without.
pub(super) fn commit_identities(
    secure: &mut (impl SecureRandom + ?Sized),
) -> Result<CommitIdentities, CoordinationError> {
    let mut publication = [0; 16];
    let mut operation = [0; 16];
    secure
        .fill(&mut publication)
        .map_err(|_| refused("IntentEntropyUnavailable"))?;
    secure
        .fill(&mut operation)
        .map_err(|_| refused("IntentEntropyUnavailable"))?;
    let operation_id = if let Ok(id) = crate::CorrelationId::draw(secure) {
        Some(id)
    } else {
        crate::observe::op_failed(
            crate::OperationKind::Session,
            crate::FailureClass::Unavailable,
        );
        None
    };
    Ok((publication, operation, operation_id))
}

pub(crate) struct RuntimeSeams<'a, E>(pub(crate) &'a E);
impl<E: SyncRuntime> RecoveryDelay for RuntimeSeams<'_, E> {
    fn jitter(&mut self, ceiling: Duration) -> Duration {
        use granary_core::rng::Rng as _;
        let bound = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(RuntimeRng(self.0).below(bound.saturating_add(1)))
    }
    fn wait(
        &mut self,
        duration: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(self.0.sleep(duration))
    }
}

pub(crate) fn build_landed_entries(
    root: GrainId,
    entries: &[crate::OverlayEntry],
    source: &impl SyncContent,
) -> Result<Vec<crate::OverlayEntry>, CoordinationError> {
    granary_core::manifest::validate_dir_tree(&root, &|id| source.get(id).ok())
        .map_err(|_| refused("SyncCommitManifest"))?;
    let index: std::collections::BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (entry.path.as_slice(), entry))
        .collect();
    crate::writable_store::capture::overlay_base_entries(
        source,
        root,
        &|path, kind| {
            index
                .get(path)
                .filter(|old| std::mem::discriminant(&old.kind) == std::mem::discriminant(kind))
                .map_or(0, |old| old.inode)
        },
        &mut |size, grains| {
            let payload = granary_core::manifest::node::file_payload(size, grains)
                .map_err(|_| refused("SyncCommitManifest"))?;
            source.remember_payload(GrainId::of(&payload), size, grains)
        },
        &|| refused("SyncCommitNamespace"),
    )
}

#[cfg(test)]
mod tests;
