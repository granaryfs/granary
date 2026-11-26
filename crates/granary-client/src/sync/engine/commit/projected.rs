// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A projected sync registers like any sync, then holds the commit lane from
//! before admission reopens, so no other capture runs before its candidate.

use super::super::{FloorWake, SyncWaiter, workspace_error};
use super::{
    Arc, AtomicBool, Clock, CommitCapture, CoordinationError, GrainId, MonotonicClock, Mutex,
    Notify, OverlayIo, Reply, RetainedCommit, SyncContent, SyncEngine, SyncOptions, SyncRemote,
    SyncRuntime, WritableStore, refused,
};
use crate::{
    AuthorityTransport, BoundaryCapture, PublicationOutcome, RecoveryIntent, SyncBoundary,
    SyncTarget,
};
use granary_core::secure_random::SecureRandom;
use std::collections::BTreeSet;
use tokio::sync::oneshot;

type Answer = oneshot::Receiver<Result<(), CoordinationError>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resumed {
    Open,
    Ended { landed: bool },
    Latched,
}

/// A projected sync whose registration completed, retained under the commit
/// lane it closed. Its boundary context is its seal's own, with the
/// projection as the candidate's entries, never the live namespace.
#[derive(Debug)]
pub(crate) struct ProjectedCapture {
    pub(crate) serial: u64,
    pub(crate) capture: BoundaryCapture,
    /// The signed prepared root, its candidate's bytes.
    pub(crate) root: Vec<u8>,
    pub(crate) accepted: Arc<crate::AcceptedSyncProjection>,
    /// Every id the acceptance's complete binmap resolves.
    pub(crate) mapped: Option<Arc<BTreeSet<GrainId>>>,
    /// The lane's graph charge, with its residual replacement reserve.
    pub(crate) charge: u64,
    pub(crate) deadline: tokio::time::Instant,
}

impl<P, R, S, C, M, E> SyncEngine<P, R, S, C, M, E>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    /// Once every earlier capture has completed and no lane is held, seal one
    /// file or directory and register the projection of what it sealed, then
    /// close the commit lane before admission reopens. Its reply is private:
    /// it records no fsync. `None`: the seal found nothing owed.
    /// # Errors
    /// Deadline, capacity, registration or local persistence. A refusal after
    /// the seal leaves its request retained for reconciliation and, unless
    /// local state is poisoned, the lane open and its reservations released;
    /// a poisoned store keeps the lane closed.
    #[cfg(test)]
    pub(crate) async fn prepare_projected(
        self: &Arc<Self>,
        seal: impl FnOnce(&mut WritableStore<P>) -> Result<Option<SyncBoundary>, CoordinationError>
        + Send
        + 'static,
        options: SyncOptions,
    ) -> Result<Option<ProjectedCapture>, CoordinationError> {
        let deadline = self.deadline(options)?;
        // Admission once no lane is held and every earlier capture has
        // completed; the wait holds nothing completion needs.
        let admission = loop {
            let wake = self.floor_changed.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            if let Some(admission) = self.drained_admission(deadline).await? {
                break admission;
            }
            self.runtime
                .timeout_at(deadline, wake)
                .await
                .map_err(|_| refused("SyncDeadline"))?;
        };
        let (reply, answer) = self.private_reply();
        self.prepare_admitted(admission, seal, options, deadline, &reply, answer)
            .await
    }

    /// A projected seal's own reply, which records no fsync, and its answer.
    fn private_reply(&self) -> (Arc<Reply>, Answer) {
        let (sender, answer) = oneshot::channel();
        let reply = Arc::new(Reply {
            sender: Mutex::new(Some(sender)),
            cancelled: AtomicBool::new(false),
            cancellation: Notify::new(),
            metrics: self.metrics.clone(),
            observed: false,
        });
        (reply, answer)
    }

    /// Admission, if no lane is held and every earlier capture has
    /// completed, before and after it is acquired.
    async fn drained_admission(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<Option<tokio::sync::MutexGuard<'_, ()>>, CoordinationError> {
        if !self.local(drained)? {
            return Ok(None);
        }
        let admission = self
            .runtime
            .timeout_at(deadline, self.admission.lock())
            .await
            .map_err(|_| refused("SyncDeadline"))?;
        // A preparation whose operation was lost holds its seal's
        // reservations until its supervisor disposes of them under admission.
        let disposed = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?
            .preparing
            .is_none();
        Ok((disposed && self.local(drained)?).then_some(admission))
    }

    /// Seal and register under `admission`, then close the lane before
    /// admission drops. Its preparation, registration and closed lane are
    /// keyed to `reply`, so a lost supervisor can release them.
    async fn prepare_admitted(
        self: &Arc<Self>,
        admission: tokio::sync::MutexGuard<'_, ()>,
        seal: impl FnOnce(&mut WritableStore<P>) -> Result<Option<SyncBoundary>, CoordinationError>
        + Send
        + 'static,
        options: SyncOptions,
        deadline: tokio::time::Instant,
        reply: &Arc<Reply>,
        answer: Answer,
    ) -> Result<Option<ProjectedCapture>, CoordinationError> {
        let _wake = FloorWake(&self.floor_changed);
        let Some(prepared) = self
            .seal_prepared(seal, options, reply, deadline, true)
            .await?
        else {
            return Ok(None);
        };
        // The lane holds what its candidate's entries cost, as a restart
        // charges them, not what the live namespace cost at the seal.
        let charge = self.local(|local| {
            let wanted = crate::overlay_store::commit_graph_charge_of(
                prepared.accepted.projection().entries(),
            )
            .ok_or_else(|| refused("SyncGraphOverflow"))?;
            if wanted > options.workspace_bytes {
                return Err(workspace_error(
                    &self.volume,
                    wanted,
                    options.workspace_bytes,
                ));
            }
            match wanted.checked_sub(prepared.charge) {
                Some(more) => local.reserve_engine_graph(more)?,
                None => local.release_engine_graph(prepared.charge.saturating_sub(wanted))?,
            }
            Ok(wanted)
        });
        let held = *charge.as_ref().unwrap_or(&prepared.charge);
        // Preparing a registration refuses a closed lane, so the lane closes
        // after it, and before any other capture can take admission.
        let closed = self.close_for_construction(None, false, options.workspace_bytes);
        let serial = closed.as_ref().ok().copied();
        self.state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?
            .projected = Some((serial, held, reply.clone()));
        drop(admission);
        if let Err(error) = self.settle(&prepared, reply, deadline).await {
            // Poisoned local state refuses the cancellation and keeps the
            // lane closed; the settlement's error is the one reported.
            let _ = self.cancel_projected(serial, held);
            return Err(error);
        }
        let answered = self
            .runtime
            .timeout_at(deadline, answer)
            .await
            .map_err(|_| refused("SyncDeadline"))
            .and_then(|answer| answer.map_err(|_| refused("SyncCancelled"))?);
        match closed.and_then(|serial| answered.and(charge).map(|charge| (serial, charge))) {
            Ok((serial, charge)) => Ok(Some(ProjectedCapture {
                serial,
                capture: prepared
                    .accepted
                    .boundary()
                    .commit_capture(prepared.accepted.projection().entries().to_vec()),
                root: prepared.root,
                accepted: prepared.accepted,
                mapped: prepared.mapped,
                charge,
                deadline,
            })),
            Err(error) => {
                self.cancel_projected(serial, held)?;
                Err(error)
            }
        }
    }

    /// Release a projected capture that recorded no boundary.
    /// # Errors
    /// A durable boundary, a foreign lane, poison or persistence.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "disposition consumes the one-shot capture capability"
    )]
    pub(crate) fn discard_projected(
        &self,
        capture: ProjectedCapture,
    ) -> Result<(), CoordinationError> {
        self.cancel_projected(Some(capture.serial), capture.charge)
    }

    /// The seal belongs to its completion, which has disposed of it: the
    /// lane is cancelled with no snapshot of its own.
    fn cancel_projected(&self, serial: Option<u64>, charge: u64) -> Result<(), CoordinationError> {
        if let Some(serial) = serial {
            return self.cancel_construction(serial, None, charge);
        }
        // A released projected lane wakes a shutdown draining the engine.
        let _wake = FloorWake(&self.floor_changed);
        self.local(|local| local.release_projected_commit(charge))?;
        self.state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?
            .projected = None;
        Ok(())
    }

    /// Release what a lost publication's `reply` still owns: its
    /// preparation or registration, then the lane it holds closed until the
    /// lane's candidate is retained. Admission spans the cleanup, so no other
    /// projected seal reserves before this one's reservations are released.
    /// # Errors
    /// The first of the two releases' failures.
    async fn fail_published(&self, reply: &Arc<Reply>) -> Result<(), CoordinationError> {
        let _admission = self.admission.lock().await;
        let failure = self.fail_supervisor(reply).await;
        let projected = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| refused("SyncStatePoisoned"))?;
            if state
                .projected
                .as_ref()
                .is_some_and(|(_, _, waiting)| Arc::ptr_eq(reply, waiting))
            {
                state.projected.take()
            } else {
                None
            }
        };
        let cancelled = match projected {
            Some((serial, charge, _)) => self.cancel_projected(serial, charge),
            None => Ok(()),
        };
        failure.and(cancelled)
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
    /// Start a supervised published sync of `target`; callers only own this
    /// cancellation-safe waiter, which answers once its own landing is
    /// installed. For harnesses and embedders: the caller chooses the
    /// entropy its publication identities are drawn from, where a mount's
    /// published profile draws them from the operating system's.
    #[must_use]
    pub fn publish_sync(
        self: &Arc<Self>,
        target: SyncTarget,
        options: SyncOptions,
        secure: impl SecureRandom + Send + 'static,
    ) -> SyncWaiter {
        self.sync_published(
            move |local| local.overlay_transaction(|t| t.seal_sync(target)).map(Some),
            options,
            secure,
        )
    }

    /// Publish what one file or directory sync seals: drive any lane
    /// retained before it to its install, then register its projection,
    /// retain that signed root as the lane's candidate, drive it and install
    /// its landing. The call succeeds only on its own landing, installed
    /// before its deadline, and its one reply records the fsync. The call
    /// runs supervised: a caller that stops waiting leaves its lane either
    /// retained, with its evidence, or released.
    /// # Errors
    /// The waiter answers deadline, capacity, registration, publication,
    /// install or local persistence; a fenced mount answers with its fence.
    pub(crate) fn sync_published(
        self: &Arc<Self>,
        seal: impl FnOnce(&mut WritableStore<P>) -> Result<Option<SyncBoundary>, CoordinationError>
        + Send
        + 'static,
        options: SyncOptions,
        mut secure: impl SecureRandom + Send + 'static,
    ) -> SyncWaiter {
        let (supervised, waiter) = self.observed_reply();
        let (private, answer) = self.private_reply();
        let engine = self.clone();
        let runtime = self.runtime.clone();
        drop(self.runtime.spawn(async move {
            let operation_engine = engine.clone();
            let operation_reply = private.clone();
            let operation = runtime.spawn(async move {
                Box::pin(operation_engine.publish(
                    seal,
                    options,
                    &mut secure,
                    &operation_reply,
                    answer,
                ))
                .await
            });
            let result = match operation.await {
                Ok(result) => result,
                Err(_) => Err(engine
                    .fail_published(&private)
                    .await
                    .err()
                    .unwrap_or_else(|| refused("SyncSupervisorLost"))),
            };
            // Nothing holds the engine once the reply is delivered.
            drop(engine);
            supervised.deliver(result);
        }));
        waiter
    }

    async fn publish(
        self: &Arc<Self>,
        seal: impl FnOnce(&mut WritableStore<P>) -> Result<Option<SyncBoundary>, CoordinationError>
        + Send
        + 'static,
        options: SyncOptions,
        secure: &mut (dyn SecureRandom + Send),
        reply: &Arc<Reply>,
        answer: Answer,
    ) -> Result<(), CoordinationError> {
        let deadline = self.deadline(options)?;
        let options = SyncOptions {
            deadline: Some(deadline),
            ..options
        };
        let (publication, operation, operation_id) = super::driver::commit_identities(secure)?;
        // A lane retained before this call lands and installs first; losing
        // admission to another lane takes that one over too.
        let admission = loop {
            // Enabled before the takeover's last check, so a lane retained
            // after it still wakes this wait.
            let wake = self.floor_changed.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            self.take_over(
                options,
                deadline,
                super::CommitDrive::Mount(RecoveryIntent::ExplicitRecovery),
                secure,
            )
            .await?;
            if let Some(admission) = self.drained_admission(deadline).await? {
                break admission;
            }
            self.runtime
                .timeout_at(deadline, wake)
                .await
                .map_err(|_| refused("SyncDeadline"))?;
        };
        let Some(capture) = self
            .prepare_admitted(admission, seal, options, deadline, reply, answer)
            .await?
        else {
            return Ok(());
        };
        let lane = self
            .retain_projected(capture, publication, operation, operation_id)
            .await?;
        self.drive_own(&lane, options, deadline, secure).await?;
        // An install observed after the deadline is not this call's success.
        if self.runtime.now() >= deadline {
            return Err(refused("SyncDeadline"));
        }
        Ok(())
    }

    /// Drive a lane retained before this call, an earlier caller's or one
    /// recovered after a restart, to its install under this call's
    /// deadline, recovering whatever probe or rebase it was left in. Answers
    /// once no lane is held. Another lane's driver, or a lane still under
    /// construction, is waited for holding nothing.
    pub(crate) async fn take_over(
        self: &Arc<Self>,
        options: SyncOptions,
        deadline: tokio::time::Instant,
        drive: super::CommitDrive,
        secure: &mut (dyn SecureRandom + Send),
    ) -> Result<(), CoordinationError> {
        self.take_over_inner(options, deadline, drive, secure, false)
            .await
            .map(|_| ())
    }

    pub(crate) async fn take_over_latched(
        self: &Arc<Self>,
        options: SyncOptions,
        deadline: tokio::time::Instant,
        secure: &mut (dyn SecureRandom + Send),
    ) -> Result<Resumed, CoordinationError> {
        self.take_over_inner(
            options,
            deadline,
            super::CommitDrive::Background(RecoveryIntent::ExplicitRecovery),
            secure,
            true,
        )
        .await
    }

    async fn take_over_inner(
        self: &Arc<Self>,
        options: SyncOptions,
        deadline: tokio::time::Instant,
        drive: super::CommitDrive,
        secure: &mut (dyn SecureRandom + Send),
        latched: bool,
    ) -> Result<Resumed, CoordinationError> {
        let mut held_landings = None;
        loop {
            let wake = self.floor_changed.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            let serial = match self.read_live_admission(latched)? {
                crate::writable_store::sync_engine::LiveAdmission::Latched => {
                    return Ok(Resumed::Latched);
                }
                crate::writable_store::sync_engine::LiveAdmission::Held { serial, landings } => {
                    held_landings.get_or_insert(landings);
                    if latched {
                        // A retry may act only on answers newer than this resume.
                        self.take_answered();
                    }
                    serial
                }
                crate::writable_store::sync_engine::LiveAdmission::Open { landings } => {
                    return Ok(held_landings.map_or(Resumed::Open, |held| Resumed::Ended {
                        landed: held != landings,
                    }));
                }
            };
            match self.recover_commit(options) {
                Ok(lane) => {
                    #[cfg(test)]
                    if latched
                        && let Some(hook) = self
                            .before_live_commit_drive
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                    {
                        hook();
                    }
                    if let Some(result) = self
                        .drive_or_wait(
                            &lane.with_deadline(deadline),
                            drive,
                            SyncOptions {
                                deadline: Some(deadline),
                                ..options
                            },
                            secure,
                        )
                        .await?
                    {
                        self.landed(&result)?;
                        continue;
                    }
                }
                Err(CoordinationError::Refused("SyncCommitConstructionPending")) => {}
                // A lane that settled since the check above is no error.
                Err(error) => {
                    #[cfg(test)]
                    if let Some(hook) = self
                        .after_recover_error
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                    {
                        hook();
                    }
                    match self.read_live_admission(latched)? {
                        crate::writable_store::sync_engine::LiveAdmission::Latched => {
                            return Ok(Resumed::Latched);
                        }
                        crate::writable_store::sync_engine::LiveAdmission::Open { landings } => {
                            return Ok(Resumed::Ended {
                                landed: held_landings.is_some_and(|held| held != landings),
                            });
                        }
                        crate::writable_store::sync_engine::LiveAdmission::Held {
                            serial: current,
                            ..
                        } if current == serial => return Err(error),
                        crate::writable_store::sync_engine::LiveAdmission::Held { .. } => continue,
                    }
                }
            }
            self.runtime
                .timeout_at(deadline, wake)
                .await
                .map_err(|_| refused("SyncDeadline"))?;
        }
    }

    fn read_live_admission(
        &self,
        latched: bool,
    ) -> Result<crate::writable_store::sync_engine::LiveAdmission, CoordinationError> {
        self.local(|local| {
            if latched {
                local.live_admission()
            } else {
                local.sync_admission()
            }
        })
    }

    /// Drive this call's own lane to its install. Another driver may hold
    /// it: this call waits for that driver, holding nothing, and its
    /// landing is this call's, since the lane holds this call's capture.
    async fn drive_own(
        self: &Arc<Self>,
        lane: &RetainedCommit,
        options: SyncOptions,
        deadline: tokio::time::Instant,
        secure: &mut (dyn SecureRandom + Send),
    ) -> Result<(), CoordinationError> {
        loop {
            let wake = self.floor_changed.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            if !self.holds(lane)? {
                // Another driver ended the lane: installed, or fenced.
                return self.local(|local| local.sync_admission_open().map(|_| ()));
            }
            if let Some(result) = self
                .drive_or_wait(
                    lane,
                    super::CommitDrive::Mount(RecoveryIntent::Continue),
                    options,
                    secure,
                )
                .await?
            {
                return self.landed(&result);
            }
            self.runtime
                .timeout_at(deadline, wake)
                .await
                .map_err(|_| refused("SyncDeadline"))?;
        }
    }

    /// One drive of `lane`; `None` when another driver holds it, or ended it
    /// between this call's selection and its drive. The caller's next check
    /// then sees the lane installed or fenced.
    async fn drive_or_wait(
        self: &Arc<Self>,
        lane: &RetainedCommit,
        drive: super::CommitDrive,
        options: SyncOptions,
        secure: &mut (dyn SecureRandom + Send),
    ) -> Result<Option<crate::PublicationResult>, CoordinationError> {
        let mut delay = super::driver::RuntimeSeams(self.runtime.as_ref());
        match Box::pin(self.drive_commit_for(lane, secure, &mut delay, drive, options)).await {
            Ok(result) => Ok(Some(result)),
            Err(CoordinationError::Refused("SyncCommitInFlight")) => Ok(None),
            Err(error) if !self.holds(lane)? => {
                drop(error);
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Whether `lane` is still the engine's retained lane.
    fn holds(&self, lane: &RetainedCommit) -> Result<bool, CoordinationError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?
            .commit
            .as_ref()
            .is_some_and(|retained| retained.publication == lane.publication))
    }

    /// A drive's outcome as this call's answer: only a landing succeeds.
    fn landed(&self, result: &crate::PublicationResult) -> Result<(), CoordinationError> {
        if matches!(result.outcome, PublicationOutcome::Landed(_)) {
            return Ok(());
        }
        if let Some(error) = result.admission_error() {
            return Err(error);
        }
        // Preserve any fence established by the drive before treating the
        // remaining outcomes as unresolved.
        self.local(|local| local.sync_admission_open())?;
        Err(refused("SyncCommitUnresolved"))
    }

    /// Retain a projected capture's signed root as its lane's candidate,
    /// with the boundary that records its selection.
    async fn retain_projected(
        self: &Arc<Self>,
        capture: ProjectedCapture,
        publication: [u8; 16],
        operation: [u8; 16],
        operation_id: Option<crate::CorrelationId>,
    ) -> Result<RetainedCommit, CoordinationError> {
        let prepared = self
            .initial_submission(
                capture.root.clone(),
                capture.deadline,
                publication,
                operation,
            )
            .await
            .and_then(|record| {
                let selection = capture.accepted.selection()?;
                let instance = self.local(|local| Ok(local.snapshot().instance))?;
                Ok((record, selection, instance))
            });
        let (record, selection, instance) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                self.discard_projected(capture)?;
                return Err(error);
            }
        };
        let commit = CommitCapture {
            serial: capture.serial,
            instance,
            capture: capture.capture,
            charge: capture.charge,
            deadline: capture.deadline,
            snapshot: None,
            selection: crate::BoundarySelection::Projected(selection),
        };
        self.retain_commit_mapped(commit, &record, capture.mapped, operation_id)
            .await
    }
}

fn drained<P: OverlayIo>(local: &mut WritableStore<P>) -> Result<bool, CoordinationError> {
    Ok(local.sync_admission_open()? && local.sync_queue_empty())
}
