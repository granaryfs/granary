// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Engine transactions end before object callbacks and transport attempts.

use super::{CoordinationError, PendingIntent, WritableStore, refused};
use crate::{AcceptedSyncProjection, OverlayIo, RejectionProof, SyncBoundary, VerifiedSyncPayload};
use granary_core::{clock::Clock, root};
use granary_store::crypto::{SigningKey, TrustedKeys};

impl<P: OverlayIo> WritableStore<P> {
    pub(crate) fn report_commit_fenced(
        &self,
        class: crate::FailureClass,
    ) -> Result<(), CoordinationError> {
        let overlay = self
            .overlay
            .as_ref()
            .ok_or_else(|| refused("IntentReplayPending"))?;
        overlay.report_commit_fenced(class);
        Ok(())
    }
    pub(crate) fn report_commit_outcome(
        &mut self,
        result: crate::CommitResult,
        duration: Option<std::time::Duration>,
        failure: Option<crate::FailureClass>,
        retained: bool,
    ) -> Result<(), CoordinationError> {
        if let Some(class) = failure {
            crate::observe::op_failed(crate::OperationKind::Commit, class);
            if retained {
                self.report_commit_fenced(class)?;
            }
        }
        if let Some(metrics) = &self.metrics {
            metrics.set_available(crate::MetricsGroup::Commit, true);
            metrics.record_commit_sample(result, duration);
        }
        self.observe_commit(result);
        Ok(())
    }
    pub(crate) fn fence_commit_conflict(&mut self) -> CoordinationError {
        self.commit_conflict = true;
        CoordinationError::Fenced {
            recorded_generation: None,
        }
    }
    fn fence_commit_boundary(&mut self, publication: [u8; 16]) -> CoordinationError {
        self.commit_conflict = true;
        self.fenced_publication = Some(publication);
        CoordinationError::CommitFenced { publication }
    }
    /// Discard a boundary interrupted before retained submission admission. The
    /// journal-before-send contract makes absence of its publication durable
    /// no-send evidence; a matching retained record or landing refuses.
    /// # Errors
    /// Retained submission, foreign/multiple boundaries, custody or persistence.
    pub fn reconcile_unsubmitted_commit(&mut self) -> Result<(), CoordinationError> {
        self.check()?;
        if self.engine_attached {
            return Err(refused("SyncCommitInFlight"));
        }
        let record = self
            .store
            .publications(self.config.euid)?
            .load(&self.config.scope, &self.config.volume)?;
        let commits = self.recovery_commits()?;
        let [
            crate::RecoveryCommit::Boundary {
                index,
                publication_id,
                ..
            },
        ] = commits.as_slice()
        else {
            return Err(refused("SyncCommitRecoveryRequired"));
        };
        if self
            .overlay_transaction(|t| t.commit_progress(*publication_id))?
            .is_some_and(|progress| progress.fenced)
        {
            return Err(self.fence_commit_boundary(*publication_id));
        }
        if record.as_ref().is_some_and(|record| {
            record.publication_id == *publication_id
                || (!record.is_complete() && !crate::sync::terminal_non_landing(record))
        }) {
            return Err(refused("SyncCommitUnresolved"));
        }
        if let Some(record) = record.filter(crate::sync::terminal_non_landing) {
            self.archive_proven_non_landing(&record, 0)?;
        }
        self.overlay_transaction(|t| t.replace_rejected(*index, *publication_id))
    }
    /// Reconcile a durable terminal refusal before startup registration. Unknown
    /// or accepted submissions refuse; no overlay effects are absorbed.
    /// # Errors
    /// Missing/foreign evidence, possible landing, custody or persistence.
    pub fn reconcile_commit_rejection(&mut self) -> Result<(), CoordinationError> {
        self.check()?;
        let record = self
            .store
            .publications(self.config.euid)?
            .load(&self.config.scope, &self.config.volume)?
            .ok_or_else(|| refused("SyncCommitNotRetained"))?;
        if !crate::sync::terminal_non_landing(&record) {
            return Err(refused("SyncCommitUnresolved"));
        }
        let commits = self.recovery_commits()?;
        if commits.is_empty() {
            self.archive_proven_non_landing(&record, 0)?;
            return Ok(());
        }
        let [
            crate::RecoveryCommit::Boundary {
                index,
                candidate,
                publication_id,
                ..
            },
        ] = commits.as_slice()
        else {
            return Err(refused("SyncCommitRecoveryRequired"));
        };
        if *publication_id != record.publication_id {
            return self.reconcile_unsubmitted_commit();
        }
        if *candidate != granary_core::hash::GrainId::of(&record.frozen.initial_root) {
            return Err(refused("SyncCommitIdentity"));
        }
        self.strip_proven_non_landing(*index, *publication_id)
    }
    /// Admitted commit evidence, whole-tree and projected alike: a landing
    /// installs either image and a rejection strips either boundary.
    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "the transaction facade requires a higher-ranked lifetime; a method pointer does not compile"
    )]
    pub(crate) fn recovery_commits(
        &mut self,
    ) -> Result<Vec<crate::RecoveryCommit>, CoordinationError> {
        #[cfg(test)]
        super::shared::record_transaction();
        let permission = if self.recovery_released() {
            self.released_recovery_permission()?
        } else {
            self.permission()?
        };
        self.overlay_transaction_with(permission, |t| t.recovery_commits())
    }
    pub(crate) fn check_sync_base(&self, bytes: &[u8], seq: u64) -> Result<(), CoordinationError> {
        self.check()?;
        let base = self
            .overlay
            .as_ref()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .sync_base()?;
        if base != (granary_core::hash::GrainId::of(bytes), seq) {
            return Err(refused("SyncBaseBinding"));
        }
        Ok(())
    }
    pub(crate) fn attach_sync_engine(&mut self) -> Result<(), CoordinationError> {
        self.check()?;
        if self.engine_attached || !self.capture_queue.is_empty() {
            return Err(refused("SyncEngineAlreadyAttached"));
        }
        if self.carrier.pending.iter().any(|p| !p.context.is_empty()) {
            return Err(refused("SyncRecoveryRequired"));
        }
        let retained = self
            .store
            .publications(self.config.euid)?
            .load(&self.config.scope, &self.config.volume)?;
        let commits = self.recovery_commits()?;
        let boundaries: Vec<_> = commits
            .iter()
            .filter_map(|c| {
                if let crate::RecoveryCommit::Boundary {
                    index,
                    candidate,
                    publication_id,
                    ..
                } = c
                {
                    Some((*index, *candidate, *publication_id))
                } else {
                    None
                }
            })
            .collect();
        for (_, _, publication) in &boundaries {
            if self
                .overlay_transaction(|t| t.commit_progress(*publication))?
                .is_some_and(|progress| progress.fenced)
            {
                return Err(self.fence_commit_boundary(*publication));
            }
        }
        match (boundaries.as_slice(), retained.as_ref()) {
            ([], None) => {}
            ([], Some(r)) if r.is_complete() || crate::sync::terminal_non_landing(r) => {}
            ([(boundary, candidate, publication)], Some(r))
                if *publication == r.publication_id
                    && *candidate == granary_core::hash::GrainId::of(&r.frozen.initial_root) =>
            {
                if crate::sync::terminal_non_landing(r) {
                    self.strip_proven_non_landing(*boundary, *publication)?;
                } else {
                    if self.carrier.phase != granary_core::overlay_ownership::Phase::Serving
                        && self.carrier.phase != granary_core::overlay_ownership::Phase::OwnedStart
                    {
                        return Err(refused("SyncRecoveryRequired"));
                    }
                    // Service remains closed until the retained submission has
                    // landed and its readback/refresh/replacement have finished.
                    self.commit_serial = self
                        .commit_serial
                        .checked_add(1)
                        .ok_or_else(|| refused("SyncCommitExhausted"))?;
                    self.commit_lane = Some(self.commit_serial);
                }
            }
            _ => return Err(refused("SyncCommitRecoveryRequired")),
        }
        if self.carrier.phase != granary_core::overlay_ownership::Phase::Serving
            && !(self.carrier.phase == granary_core::overlay_ownership::Phase::OwnedStart
                && self.commit_lane.is_some())
        {
            return Err(refused("SyncRecoveryRequired"));
        }
        self.engine_attached = true;
        Ok(())
    }

    /// Clear the attachment of an engine that has ended, so another may
    /// attach to this same store: only with no commit lane, no capture
    /// queued, no context retained and nothing owing completion, the state
    /// an engine leaves once its work is done. Answers whether it detached.
    pub(crate) fn detach_sync_engine(&mut self) -> bool {
        if self.commit_lane.is_some()
            || !self.capture_queue.is_empty()
            || self.carrier.pending.iter().any(|p| !p.context.is_empty())
            || !self.sync_queue_empty()
        {
            return false;
        }
        self.engine_attached = false;
        true
    }

    pub(crate) fn sync_admission_open(&self) -> Result<bool, CoordinationError> {
        self.check()?;
        Ok(self.commit_lane.is_none())
    }

    pub(crate) fn live_admission(&self) -> Result<LiveAdmission, CoordinationError> {
        self.check()?;
        if self.mutations_closed {
            Ok(LiveAdmission::Latched)
        } else {
            Ok(self.lane_admission())
        }
    }

    pub(crate) fn sync_admission(&self) -> Result<LiveAdmission, CoordinationError> {
        self.check()?;
        Ok(self.lane_admission())
    }

    fn lane_admission(&self) -> LiveAdmission {
        match self.commit_lane {
            Some(serial) => LiveAdmission::Held {
                serial,
                landings: self.commit_landings,
            },
            None => LiveAdmission::Open {
                landings: self.commit_landings,
            },
        }
    }

    pub(crate) fn recovered_commit(
        &mut self,
    ) -> Result<
        (
            u64,
            u64,
            bool,
            Vec<crate::OverlayEntry>,
            granary_core::retained_submission::Submission,
        ),
        CoordinationError,
    > {
        self.recovered_commit_inner(true)
    }

    fn recovered_commit_inner(
        &mut self,
        live_entries: bool,
    ) -> Result<
        (
            u64,
            u64,
            bool,
            Vec<crate::OverlayEntry>,
            granary_core::retained_submission::Submission,
        ),
        CoordinationError,
    > {
        let serial = self
            .commit_lane
            .ok_or_else(|| refused("SyncCommitNotRetained"))?;
        let scope = self.config.scope.clone();
        let volume = self.config.volume.clone();
        let record = self
            .publication_transaction(|j| j.load(&scope, &volume))?
            .ok_or_else(|| refused("SyncCommitNotRetained"))?;
        let commits = self.recovery_commits()?;
        let (boundary, candidate, selection) = commits
            .iter()
            .find_map(|c| {
                if let crate::RecoveryCommit::Boundary {
                    index,
                    candidate,
                    publication_id,
                    selection,
                    ..
                } = c
                    && *publication_id == record.publication_id
                {
                    Some((*index, *candidate, *selection))
                } else {
                    None
                }
            })
            .ok_or_else(|| refused("SyncCommitRecoveryRequired"))?;
        let entries = if live_entries {
            let overlay = self
                .overlay
                .as_mut()
                .ok_or_else(|| refused("IntentReplayPending"))?;
            match selection {
                crate::BoundarySelection::Tree => {
                    overlay.commit_entries(boundary, record.publication_id)?
                }
                // A projected candidate is rebuilt from its selection, never from
                // the whole prefix; a boundary that does not bind it is evidence of
                // corruption, not a reason to fall back.
                crate::BoundarySelection::Projected(_) => {
                    if candidate != granary_core::hash::GrainId::of(&record.frozen.initial_root) {
                        return Err(refused("SyncProjectedBinding"));
                    }
                    overlay
                        .projected_commit_entries(boundary, record.publication_id)
                        .map_err(|error| match error {
                            crate::OverlayError::Refused(_) => refused("SyncProjectedBinding"),
                            error => error.into(),
                        })?
                }
            }
        } else {
            Vec::new()
        };
        let projected = matches!(selection, crate::BoundarySelection::Projected(_));
        Ok((serial, boundary, projected, entries, record))
    }

    pub(crate) fn recovered_landing_commit(
        &mut self,
        stored: &[u8],
    ) -> Result<
        (
            u64,
            u64,
            bool,
            Vec<crate::OverlayEntry>,
            granary_core::retained_submission::Submission,
        ),
        CoordinationError,
    > {
        if self.stored_landing(stored)?.is_none() {
            return Err(refused("SyncCommitLandingBinding"));
        }
        self.recovered_commit_inner(false)
    }

    /// A copy of what the lane's residual is built from, for a rebase to
    /// build off the mediator.
    pub(crate) fn residual_snapshot(
        &mut self,
        serial: u64,
        boundary: u64,
        publication: [u8; 16],
    ) -> Result<crate::overlay_store::ResidualSnapshot, CoordinationError> {
        self.check_commit_lane(serial)?;
        let overlay = self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?;
        Ok(overlay.residual_snapshot(boundary, publication)?)
    }

    pub(crate) fn close_sync_admission(&mut self) -> Result<u64, CoordinationError> {
        self.check()?;
        if self.commit_lane.is_some() {
            return Err(refused("SyncCommitInFlight"));
        }
        self.commit_serial = self
            .commit_serial
            .checked_add(1)
            .ok_or_else(|| refused("SyncCommitExhausted"))?;
        self.commit_lane = Some(self.commit_serial);
        Ok(self.commit_serial)
    }

    pub(crate) fn close_sync_admission_unless_latched(&mut self) -> Result<u64, CoordinationError> {
        if self.mutations_closed {
            return Err(crate::OverlayError::MutationsClosed.into());
        }
        self.close_sync_admission()
    }

    pub(crate) fn check_commit_lane(&self, serial: u64) -> Result<(), CoordinationError> {
        self.check()?;
        if self.commit_lane != Some(serial) {
            return Err(refused("SyncCommitContext"));
        }
        Ok(())
    }

    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "the transaction facade requires a higher-ranked lifetime; a method pointer does not compile"
    )]
    pub(crate) fn cancel_unsent_commit(
        &mut self,
        serial: u64,
        snapshot: Option<&SyncBoundary>,
        charge: u64,
    ) -> Result<(), CoordinationError> {
        self.check_commit_lane(serial)?;
        if !self
            .overlay_transaction(|t| t.recovery_commits())?
            .is_empty()
        {
            return Err(refused("SyncCommitUnresolved"));
        }
        if let Some(snapshot) = snapshot {
            self.release_sync_boundary(snapshot)?;
        }
        self.release_projected_commit(charge)?;
        self.commit_lane = None;
        Ok(())
    }

    /// Reserve a projected lane's graph charge, as a whole-tree capture
    /// charges its entries, with the bound its residual replacement can add
    /// to the journal from this cursor until that lane ends.
    pub(crate) fn reserve_projected_commit(
        &mut self,
        budget: u64,
    ) -> Result<u64, CoordinationError> {
        let overlay = self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?;
        let charge = overlay.commit_graph_charge()?;
        if charge > budget {
            return Err(crate::sync::workspace_error(
                &self.carrier.volume,
                charge,
                budget,
            ));
        }
        let result = overlay.reserve_projected();
        self.retain_overlay_bundle(result.as_ref().err());
        result?;
        if let Err(error) = self.reserve_engine_graph(charge) {
            self.release_projected_commit(0)?;
            return Err(error);
        }
        Ok(charge)
    }

    /// Release a lane's graph charge and any projected replacement bound.
    pub(crate) fn release_projected_commit(
        &mut self,
        charge: u64,
    ) -> Result<(), CoordinationError> {
        self.overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .release_projected();
        self.release_engine_graph(charge)
    }

    /// Records a commit construction refused for room at any step, so the
    /// coalescer backs off instead of retrying it. Returns whether it was recorded.
    pub(crate) fn note_capacity_refusal(&mut self, error: &CoordinationError) -> bool {
        if matches!(
            error,
            CoordinationError::Overlay(
                crate::OverlayError::NoSpace
                    | crate::OverlayError::Refused("OverlayCapacityExhausted")
            ) | CoordinationError::Refused("SyncWorkspaceExhausted")
        ) && let Some(overlay) = &mut self.overlay
        {
            let recorded = overlay.note_capacity_refusal();
            self.retain_overlay_bundle(None);
            recorded
        } else {
            false
        }
    }

    pub(crate) fn capture_commit(
        &mut self,
        serial: u64,
        budget: u64,
        snapshot: bool,
    ) -> Result<(crate::BoundaryCapture, u64, Option<SyncBoundary>), CoordinationError> {
        self.check_commit_lane(serial)?;
        if !self.sync_queue_empty() {
            return Err(refused("SyncCommitDrainPending"));
        }
        let charge = self
            .overlay
            .as_ref()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .commit_graph_charge()?;
        if charge > budget {
            return Err(crate::sync::workspace_error(
                &self.carrier.volume,
                charge,
                budget,
            ));
        }
        self.reserve_engine_graph(charge)?;
        match self.overlay_transaction(|t| {
            let capture = t.capture_boundary()?;
            let seal = if snapshot {
                Some(t.seal_commit()?)
            } else {
                None
            };
            Ok((capture, seal))
        }) {
            Ok((capture, seal)) => Ok((capture, charge, seal)),
            Err(error) => {
                self.release_engine_graph(charge)?;
                Err(error)
            }
        }
    }

    pub(crate) fn retain_commit(
        &mut self,
        serial: u64,
        capture: crate::BoundaryCapture,
        record: &granary_core::retained_submission::Submission,
        selection: crate::BoundarySelection,
    ) -> Result<u64, CoordinationError> {
        self.check_commit_lane(serial)?;
        if record.scope != self.config.scope || record.volume != self.config.volume {
            return Err(refused("SyncCommitScope"));
        }
        granary_core::retained_submission::validate(record)
            .map_err(|_| refused("SyncCommitRecord"))?;
        let candidate = granary_core::hash::GrainId::of(&record.frozen.initial_root);
        let boundary = self.overlay_transaction(|t| match selection {
            crate::BoundarySelection::Tree => {
                t.record_boundary(capture, candidate, record.publication_id)
            }
            crate::BoundarySelection::Projected(selected) => {
                t.record_projected_boundary(capture, candidate, record.publication_id, selected)
            }
        })?;
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        if self
            .faults
            .sync_point("sync.commit", "boundary_recorded", serial, None, "none")
            .is_some()
        {
            return Err(refused("SyncInjectedFault"));
        }
        self.publication_transaction(|j| j.begin(record))?;
        Ok(boundary)
    }

    pub(crate) fn commit_record(
        &mut self,
        serial: u64,
        publication: [u8; 16],
    ) -> Result<granary_core::retained_submission::Submission, CoordinationError> {
        self.check_commit_lane(serial)?;
        let scope = self.config.scope.clone();
        let volume = self.config.volume.clone();
        let record = self
            .publication_transaction(|j| j.load(&scope, &volume))?
            .ok_or_else(|| refused("SyncCommitNotRetained"))?;
        if record.publication_id != publication {
            return Err(refused("SyncCommitIdentity"));
        }
        Ok(record)
    }

    pub(crate) fn commit_progress(
        &mut self,
        serial: u64,
        publication: [u8; 16],
    ) -> Result<granary_core::overlay_journal::CommitProgress, CoordinationError> {
        self.check_commit_lane(serial)?;
        let progress = self
            .overlay_transaction(|t| t.commit_progress(publication))?
            .ok_or_else(|| refused("SyncCommitRecoveryRequired"))?;
        if progress.fenced {
            return Err(self.fence_commit_boundary(publication));
        }
        Ok(progress)
    }

    fn strip_proven_non_landing(
        &mut self,
        boundary: u64,
        publication: [u8; 16],
    ) -> Result<(), CoordinationError> {
        let scope = self.config.scope.clone();
        let volume = self.config.volume.clone();
        let record = self
            .publication_transaction(|j| j.load(&scope, &volume))?
            .ok_or_else(|| refused("SyncCommitNotRetained"))?;
        if record.publication_id != publication {
            return Err(refused("SyncCommitIdentity"));
        }
        let progress = self
            .overlay_transaction(|t| t.commit_progress(publication))?
            .ok_or_else(|| refused("SyncCommitRecoveryRequired"))?;
        if progress.fenced {
            return Err(self.fence_commit_boundary(publication));
        }
        let attempts = progress.attempts;
        let proof = self.archive_proven_non_landing(&record, attempts)?;
        self.overlay_transaction(|t| t.replace_rejected_with_proof(boundary, publication, proof))?;
        if !self.engine_attached {
            self.report_commit_outcome(
                crate::CommitResult::Failed,
                None,
                Some(crate::FailureClass::Refused),
                true,
            )?;
        }
        Ok(())
    }

    pub(super) fn archive_proven_non_landing(
        &mut self,
        record: &granary_core::retained_submission::Submission,
        attempts: u64,
    ) -> Result<RejectionProof, CoordinationError> {
        let proof = crate::NoWriteProof::from_submission(record, attempts)
            .ok_or_else(|| refused("SyncCommitUnresolved"))?;
        let proof = RejectionProof::NoWrite(proof);
        self.archive_rejection(record, &proof)?;
        Ok(proof)
    }

    pub(crate) fn archive_rejection(
        &mut self,
        record: &granary_core::retained_submission::Submission,
        proof: &RejectionProof,
    ) -> Result<(), CoordinationError> {
        let faults = self.faults.clone();
        self.publication_transaction(|journal| {
            journal.abandon(
                &record.scope,
                &record.volume,
                record.publication_id,
                crate::AbandonAcknowledgement::Proven(proof, &faults),
            )
        })?;
        Ok(())
    }

    pub(crate) fn exhaust_commit(
        &mut self,
        serial: u64,
        boundary: u64,
        publication: [u8; 16],
    ) -> Result<(), CoordinationError> {
        self.check_commit_lane(serial)?;
        self.overlay_transaction(|t| t.record_commit_fence(boundary, publication))?;
        self.fence_commit_boundary(publication);
        Ok(())
    }

    /// Journal the verified stored landing, unless a recovered lane already
    /// holds it.
    pub(crate) fn record_landed_commit(
        &mut self,
        serial: u64,
        proof: &crate::LandedProof,
    ) -> Result<(), CoordinationError> {
        self.check_commit_lane(serial)?;
        self.overlay_transaction(|t| {
            let landed = t.recovery_commits()?.into_iter().any(|c| matches!(c,
                crate::RecoveryCommit::Landed { boundary_seq, root, seq, .. }
                if boundary_seq == proof.boundary_seq && root == proof.landed_root && seq == proof.landed_seq));
            if !landed { t.record_landed(proof)?; }
            Ok(())
        })
    }

    pub(crate) fn install_commit_base(
        &mut self,
        serial: u64,
        proof: crate::LandedProof,
    ) -> Result<crate::ViewChange, CoordinationError> {
        self.check_commit_lane(serial)?;
        let receipt = granary_core::intent::decode_receipt(&self.carrier.current)
            .map_err(|_| refused("SyncCommitRefresh"))?;
        if receipt.state
            != (granary_core::intent::ReceiptState::Live {
                prepared_root_id: proof.landed_root,
            })
        {
            return Err(refused("SyncCommitRefresh"));
        }
        let result = self
            .record_landed_commit(serial, &proof)
            .and_then(|()| {
                self.overlay_transaction(|t| {
                    t.record_landed_refresh(receipt.generation, proof.landed_root)?;
                    Ok(())
                })
            })
            .and_then(|()| {
                #[cfg(any(test, feature = "overlay-fault-tests"))]
                if self
                    .faults
                    .sync_point("sync.commit", "before_replace", serial, None, "none")
                    .is_some()
                {
                    return Err(refused("SyncInjectedFault"));
                }
                self.overlay_transaction(|t| t.replace_landed(proof))
            });
        if matches!(
            result,
            Err(CoordinationError::Overlay(crate::OverlayError::Conflict))
        ) {
            self.fence_commit_conflict();
            return result;
        }
        let change = result?;
        self.commit_landings = self.commit_landings.wrapping_add(1);
        if self.carrier.phase == granary_core::overlay_ownership::Phase::OwnedStart {
            let mut next = self.carrier.clone();
            next.phase = granary_core::overlay_ownership::Phase::Serving;
            self.persist(next)?;
        }
        self.commit_lane = None;
        self.engine_attached = true;
        Ok(change)
    }

    pub(crate) fn finish_non_landing(
        &mut self,
        serial: u64,
        boundary: u64,
        publication: [u8; 16],
    ) -> Result<(), CoordinationError> {
        self.check_commit_lane(serial)?;
        self.strip_proven_non_landing(boundary, publication)?;
        self.commit_lane = None;
        Ok(())
    }

    pub(crate) fn reserve_engine_graph(&mut self, bytes: u64) -> Result<(), CoordinationError> {
        self.check()?;
        let result = self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .reserve_engine_graph(bytes);
        self.retain_overlay_bundle(result.as_ref().err());
        Ok(result?)
    }

    pub(crate) fn release_engine_graph(&mut self, bytes: u64) -> Result<(), CoordinationError> {
        let result = self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .release_engine_graph(bytes);
        self.retain_overlay_bundle(result.as_ref().err());
        Ok(result?)
    }

    /// Flush the exact seal, sign accepted closure with persisted W, then retain
    /// the exact registration. No object provider is called in this transaction.
    pub(crate) fn sign_sync_registration(
        &mut self,
        accepted: &AcceptedSyncProjection,
        payloads: Vec<VerifiedSyncPayload>,
        key: &SigningKey,
        trusted: &TrustedKeys,
        clock: &impl Clock,
    ) -> Result<(PendingIntent, Vec<u8>), CoordinationError> {
        self.check()?;
        self.overlay_transaction(|t| t.flush_sync_boundary(accepted.boundary()))?;
        let mut doc = accepted.accepted.doc.clone();
        let (parent, seq) = accepted.boundary().base();
        if doc.volume != self.config.volume
            || doc.parent != Some(parent)
            || doc.seq
                != seq
                    .checked_add(1)
                    .ok_or_else(|| refused("SyncBaseOverflow"))?
        {
            return Err(refused("SyncPreparedBase"));
        }
        doc.writer_uuid = self.writer_uuid();
        let prefix = root::signing_prefix_of(&doc).map_err(|_| refused("SyncPreparedRoot"))?;
        doc.sigs.push(root::RootSig {
            key_id: key.key_id(),
            sig: key.sign(&prefix),
        });
        let bytes = root::encode_root(&doc).map_err(|_| refused("SyncPreparedRoot"))?;
        let request = self.prepare_sync_registration(
            &bytes,
            accepted.boundary().clone(),
            payloads,
            clock,
            |doc, prefix| granary_store::crypto::check_signatures(doc, prefix, trusted).is_ok(),
        )?;
        Ok((request, bytes))
    }

    /// Persist local caller failure before dropping volatile floors. Pending
    /// exact network bytes and attempt/answer evidence remain for reconciliation.
    pub(crate) fn fail_sync_registration(
        &mut self,
        request: &PendingIntent,
        boundary: &SyncBoundary,
    ) -> Result<(), CoordinationError> {
        let generation =
            granary_core::intent::decode_register(request.bytes(), request.volume(), |_, _| true)
                .map_err(|_| refused("IntentRegister"))?
                .generation;
        let queued = self
            .capture_queue
            .get(&generation)
            .ok_or_else(|| refused("SyncCallerNotRetained"))?;
        if queued.boundary.as_ref().map(SyncBoundary::id) != Some(boundary.id()) {
            return Err(refused("SyncCallerBinding"));
        }
        let index = self.locate(request)?;
        let mut next = self.carrier.clone();
        next.pending
            .get_mut(index)
            .ok_or_else(|| refused("IntentRequestNotRetained"))?
            .context
            .clear();
        if let Err(error) = self.persist(next) {
            self.poisoned = true;
            // Poison is the durable-uncertainty fence; no shrink may proceed.
            self.release_sync_boundary(boundary)?;
            self.capture_queue.remove(&generation);
            return Err(error);
        }
        // Only bound engine captures with a persisted caller disposition may
        // retain content admission after leaving the capture queue. Prune
        // settled generations so this volatile provenance stays bounded.
        self.failed_sync_registrations.retain(|generation| {
            self.carrier.pending.iter().any(|pending| {
                !pending.terminal && pending.generation().is_ok_and(|g| g == *generation)
            })
        });
        self.failed_sync_registrations.insert(generation);
        self.release_sync_boundary(boundary)?;
        self.capture_queue.remove(&generation);
        Ok(())
    }

    pub(crate) fn fail_sync_preparation(
        &mut self,
        boundary: &SyncBoundary,
    ) -> Result<(), CoordinationError> {
        let request = self
            .capture_queue
            .values()
            .find(|queued| {
                queued
                    .boundary
                    .as_ref()
                    .is_some_and(|queued| queued.id() == boundary.id())
            })
            .map(|queued| queued.request.clone());
        if let Some(request) = request {
            self.fail_sync_registration(&request, boundary)
        } else {
            self.release_sync_boundary(boundary)
        }
    }

    pub(crate) fn retry_delay(
        &self,
        request: &PendingIntent,
        clock: &impl Clock,
    ) -> Result<std::time::Duration, CoordinationError> {
        let pending = self
            .carrier
            .pending
            .get(self.locate(request)?)
            .ok_or_else(|| refused("IntentRequestNotRetained"))?;
        Ok(std::time::Duration::from_millis(
            pending.eligible.saturating_sub(super::now(clock)?),
        ))
    }

    /// [`Self::prepare_release`], the retained request expiring `remaining`
    /// from now on `clock` as well as within `bound`.
    /// # Errors
    /// As [`Self::prepare_release`], or a deadline past the clock's range.
    pub(crate) fn prepare_release_within(
        &mut self,
        clock: &impl Clock,
        bound: std::time::Duration,
        remaining: std::time::Duration,
    ) -> Result<PendingIntent, CoordinationError> {
        let remaining =
            u64::try_from(remaining.as_millis()).map_err(|_| refused("IntentDeadlineOverflow"))?;
        let deadline = super::now(clock)?
            .checked_add(remaining)
            .ok_or_else(|| refused("IntentDeadlineOverflow"))?;
        self.prepare_release(clock, bound, Some(deadline))
    }

    pub(crate) fn sync_request_answered(
        &self,
        request: &PendingIntent,
    ) -> Result<bool, CoordinationError> {
        Ok(self
            .carrier
            .pending
            .get(self.locate(request)?)
            .ok_or_else(|| refused("IntentRequestNotRetained"))?
            .terminal)
    }

    /// No capture still owes completion work. A Register whose context is
    /// empty owns no capture, terminal or not: a failed caller's retained
    /// request waits for reconciliation, and a lane's own Register is gated by
    /// that lane. The context term is an equivalent mutant while an engine is
    /// attached, named rather than chased: attachment refuses any context and
    /// each clear leaves the queue in the same acquisition. The one queue exit
    /// that keeps a context, a failed caller whose disposition did not
    /// persist, poisons the store, so `check` refuses any seal or capture the
    /// drain would admit.
    pub(crate) fn sync_queue_empty(&self) -> bool {
        self.capture_queue.is_empty()
            && !self.carrier.pending.iter().any(|p| {
                p.operation == granary_core::overlay_ownership::Operation::Register
                    && !p.context.is_empty()
            })
    }

    /// Full local obligations, independently of coalescence and scan cleanliness.
    pub(crate) fn check_finish_obligations(&mut self) -> Result<(), CoordinationError> {
        self.check()?;
        let requests = self.carrier.pending.iter().any(|p| !p.terminal);
        let contexts = self.carrier.pending.iter().any(|p| !p.context.is_empty());
        let captures = !self.capture_queue.is_empty();
        let held = self.has_open_write_handles();
        let retained = self.publication_unsettled()?;
        let lane = self.commit_lane.is_some();
        #[cfg(test)]
        let (requests, contexts, captures, held, retained, lane) = (
            requests || FINISH_DEBT.get() == "request",
            contexts || FINISH_DEBT.get() == "context",
            captures || FINISH_DEBT.get() == "capture",
            held || FINISH_DEBT.get() == "handle",
            retained || FINISH_DEBT.get() == "retained",
            lane || FINISH_DEBT.get() == "lane",
        );
        if requests || contexts || captures || held || retained || lane {
            return Err(refused("WritableRecoveryRequired"));
        }
        self.overlay
            .as_ref()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .check_finish_obligations()?;
        Ok(())
    }

    pub(crate) fn check_finish_namespace(&self) -> Result<(), CoordinationError> {
        let equivalent = self
            .overlay
            .as_ref()
            .is_some_and(crate::OverlayStore::initial_state_ready);
        #[cfg(test)]
        let equivalent = equivalent && FINISH_DEBT.get() != "namespace";
        if !equivalent {
            return Err(refused("WritableRecoveryRequired"));
        }
        Ok(())
    }

    /// All obligations and exact publication evidence precede normalization.
    pub(crate) fn normalize_finished(&mut self, published: bool) -> Result<(), CoordinationError> {
        self.check_finish_obligations()?;
        #[cfg(test)]
        let published = published && FINISH_DEBT.get() != "publication";
        if !published {
            return Err(refused("WritableRecoveryRequired"));
        }
        let result = self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .normalize_same_base(&self.store);
        self.retain_overlay_bundle(result.as_ref().err());
        Ok(result?)
    }

    pub(crate) fn finish_normalization_required(&mut self) -> Result<bool, CoordinationError> {
        self.check()?;
        Ok(self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .normalization_required()?)
    }

    /// Publication evidence is bound to the carrier's exact signed root.
    pub(crate) fn finish_publication_proved(&mut self) -> Result<bool, CoordinationError> {
        self.check()?;
        let root = &self.carrier.root;
        if root.is_empty()
            || self
                .shutdown_base()
                .is_some_and(|(base, _)| base == granary_core::hash::GrainId::of(root))
        {
            return Ok(true);
        }
        Ok(self
            .store
            .publications(self.config.euid)?
            .load(&self.config.scope, &self.config.volume)?
            .is_some_and(|record| record.is_complete() && record.frozen.initial_root == *root))
    }

    /// Whether this store holds nothing that an adoption of another
    /// writer's head would lose or race: no commit lane, no lease or stage
    /// handle, no capture owing completion, every retained request terminal,
    /// and a clean overlay, on a store no shutdown has closed.
    /// # Errors
    /// The store's own refusal: poison, a fence or a commit conflict.
    pub(crate) fn adoption_ready(&mut self) -> Result<bool, CoordinationError> {
        self.check()?;
        Ok(self.commit_lane.is_none()
            && !self.has_open_write_handles()
            && self.sync_queue_empty()
            && self.carrier.pending.iter().all(|pending| pending.terminal)
            && !self.mutations_closed
            && self
                .overlay
                .as_mut()
                .is_some_and(crate::OverlayStore::adoption_clean))
    }

    /// Replace the clean overlay with a header-only journal on the published
    /// head `root` at `seq`, whose base entries are `entries`.
    /// # Errors
    /// Readiness, an unclean journal, custody or persistence failure.
    pub(crate) fn replace_adopted(
        &mut self,
        root: granary_core::hash::GrainId,
        seq: u64,
        entries: Vec<crate::OverlayEntry>,
    ) -> Result<crate::ViewChange, CoordinationError> {
        self.overlay_transaction(|overlay| overlay.replace_adopted(root, seq, entries))
    }

    /// A registration request on this store's carrier, for engine state a
    /// test holds.
    #[cfg(test)]
    pub(crate) fn pending_register_for_test(&self) -> PendingIntent {
        self.pending(
            granary_core::overlay_ownership::Operation::Register,
            Vec::new(),
        )
    }

    /// Hold one of the states an adoption waits for, as the store's own
    /// paths would leave it, without the overlay work that would come with
    /// it.
    #[cfg(test)]
    pub(crate) fn hold_adoption_for_test(&mut self, hold: AdoptionHold) {
        use granary_core::overlay_ownership::Operation;
        match hold {
            AdoptionHold::CommitLane => self.commit_lane = Some(self.commit_serial + 1),
            AdoptionHold::CaptureQueue => {
                let request = self.pending(Operation::Register, Vec::new());
                self.capture_queue.insert(
                    u64::MAX,
                    super::capture::QueuedCapture {
                        request,
                        files: Vec::new(),
                        boundary: None,
                    },
                );
            }
            // A failed caller's registration of the registered root at the
            // next generation, retained for reconciliation: readiness admits
            // it, and it owns no capture.
            AdoptionHold::Registration => {
                let receipt = granary_core::intent::decode_receipt(&self.carrier.current)
                    .expect("a current receipt");
                let generation = self.carrier.sent + 1;
                let body = granary_core::intent::encode_register(
                    &self.carrier.writer,
                    receipt.epoch,
                    &self.config.instance,
                    generation,
                    &self.carrier.root,
                )
                .expect("the registered root encodes");
                self.failed_sync_registrations.insert(generation);
                self.carrier
                    .pending
                    .push(granary_core::overlay_ownership::Pending {
                        operation: Operation::Register,
                        body,
                        context: Vec::new(),
                        first: 0,
                        expires: u64::MAX,
                        eligible: 0,
                        attempts: 0,
                        terminal: false,
                        answered: false,
                        answer: Vec::new(),
                    });
            }
        }
    }

    pub(crate) fn has_open_write_handles(&self) -> bool {
        !self.object_leases.is_empty()
            || self
                .overlay
                .as_ref()
                .is_some_and(crate::OverlayStore::has_open_stage_handles)
    }

    pub(crate) fn install_coalescer(
        &mut self,
        clock: crate::overlay_store::CoalesceClock,
    ) -> std::sync::Arc<tokio::sync::Notify> {
        let wake = self.coalesce_wake.clone();
        if let Some(overlay) = &mut self.overlay {
            overlay.install_coalescer(Some(clock.clone()), wake.clone());
        }
        self.coalesce_clock = Some(clock);
        wake
    }

    pub(crate) fn coalesce_state(
        &mut self,
        options: &crate::SyncOptions,
        now: tokio::time::Instant,
    ) -> Result<CoalesceState, CoordinationError> {
        self.check()?;
        let has_open_write_handles = self.has_open_write_handles();
        let overlay = self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?;
        let Some((first_at, last_at, commit_requested)) = overlay.active_dirty_span(now) else {
            return Ok(CoalesceState::Clean);
        };
        // A commit refused for room is retried after a long backoff, or
        // sooner on the wake of whatever frees room.
        if let Some(retry_at) = overlay.capacity_retry_at(now, super::CAPACITY_RETRY_DELAY)
            && now < retry_at
        {
            return Ok(CoalesceState::WaitUntil(Some(retry_at)));
        }
        if commit_requested {
            return Ok(CoalesceState::Ready);
        }
        let quiesce_at = (!has_open_write_handles)
            .then(|| last_at.checked_add(options.quiesce_delay))
            .flatten();
        let max_age_at = first_at.checked_add(options.max_coalesce_delay);
        let earliest = match (quiesce_at, max_age_at) {
            (Some(q), Some(m)) => Some(q.min(m)),
            (Some(q), None) => Some(q),
            (None, Some(m)) => Some(m),
            (None, None) => None,
        };
        if earliest.is_some_and(|at| now >= at) {
            Ok(CoalesceState::Ready)
        } else {
            Ok(CoalesceState::WaitUntil(earliest))
        }
    }

    pub(crate) fn live_state(
        &mut self,
        options: &crate::SyncOptions,
        now: tokio::time::Instant,
    ) -> Result<LiveState, CoordinationError> {
        self.check()?;
        if self.mutations_closed {
            return Ok(LiveState::Latched);
        }
        if self.commit_lane.is_some() {
            return Ok(LiveState::LaneHeld);
        }
        Ok(match self.coalesce_state(options, now)? {
            CoalesceState::Clean => LiveState::Clean,
            CoalesceState::Ready => LiveState::Ready,
            CoalesceState::WaitUntil(deadline) => LiveState::WaitUntil(deadline),
        })
    }
}

/// A state an adoption waits for, held alone by a test.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdoptionHold {
    /// A closed commit lane.
    CommitLane,
    /// A capture that owes completion.
    CaptureQueue,
    /// A retained registration not yet terminal.
    Registration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoalesceState {
    Clean,
    Ready,
    WaitUntil(Option<tokio::time::Instant>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveAdmission {
    Latched,
    Held { serial: u64, landings: u64 },
    Open { landings: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveState {
    Latched,
    LaneHeld,
    Clean,
    Ready,
    WaitUntil(Option<tokio::time::Instant>),
}

pub(crate) fn generation(request: &PendingIntent) -> Result<u64, CoordinationError> {
    Ok(
        granary_core::intent::decode_register(request.bytes(), request.volume(), |_, _| true)
            .map_err(|_| refused("IntentRegister"))?
            .generation,
    )
}

#[cfg(test)]
std::thread_local! {
    pub(crate) static FINISH_DEBT: std::cell::Cell<&'static str> = const { std::cell::Cell::new("") };
}
