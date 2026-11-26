// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Short local facades cannot replace owned components or export readiness grants.

use super::{
    BundleOverlay, BundleRefusal, CoordinationError, OverlayEntry, OverlayError, OverlayIo,
    OverlayReadiness, OverlayStore, OwnershipStatus, Store, WritableStore, refused,
};
use crate::overlay_store::{
    CaptureToken, CapturedFile, CapturedPart, CapturedRange, OverlayCursor, OverlayDirectoryQuery,
    OverlayPage, OverlayQuery, OverlayQueryEntry, OverlaySummary, RecoveryCommit,
    RegisteredCapture, SyncBoundary, SyncTarget,
};
use granary_core::hash::GrainId;
use granary_core::overlay_journal::{Location, Record};

pub struct WritableOverlay<'a, P: OverlayIo> {
    pub(super) overlay: &'a mut OverlayStore<P>,
    pub(super) bundle_overlay: &'a mut Result<BundleOverlay, BundleRefusal>,
    pub(super) range_cache: &'a mut crate::overlay_store::verified_range::VerifiedRangeCache,
    pub(super) store: &'a mut Store,
    pub(super) permission: OwnershipStatus,
    pub(super) poisoned: &'a mut bool,
    pub(super) sync_admission_open: bool,
    pub(super) mutations_closed: bool,
}
impl<P: OverlayIo> std::fmt::Debug for WritableOverlay<'_, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WritableOverlay").finish_non_exhaustive()
    }
}
impl<P: OverlayIo> WritableOverlay<'_, P> {
    /// Observe live namespace length, fresh charges and cap in one local read.
    /// # Errors
    /// Readiness, custody or accounting failure.
    pub fn observation(
        &mut self,
    ) -> Result<crate::overlay_store::OverlayObservation, OverlayError> {
        self.run(|o, s, p| o.observation(s, p))
    }
    /// Materialize the pinned file from authenticated, already local objects.
    /// # Errors
    /// Readiness, custody, cap, missing/corrupt content or persistence failure.
    pub fn copy_up(&mut self, at: Location) -> Result<u64, OverlayError> {
        self.check_mutations_open()?;
        self.run(|o, s, p| o.copy_up_local(s, p, at))
    }
    /// Read a clean file through the same local authenticated source as copy-up.
    /// # Errors
    /// Readiness, invalid routing, missing/corrupt content or custody failure.
    pub fn read_base(
        &mut self,
        path: &[granary_core::manifest::Name],
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        self.run_cached(|o, s, p, memo| o.read_base_local(s, p, path, offset, length, memo))
    }
    /// Read the current shared stage, including a held detached object.
    /// # Errors
    /// Readiness, inaccessible stage, custody or persistence failure.
    pub fn read_stage(
        &mut self,
        stage: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        self.run(|o, s, p| o.read_stage(s, p, stage, offset, length))
    }
    /// Drop one stage hold without retiring evidence or acknowledging sync.
    /// # Errors
    /// Poison, custody, a missing stage or a hold already released.
    pub fn close_stage(&mut self, stage: u64) -> Result<(), OverlayError> {
        self.run(|o, s, _| o.close_stage(s, stage))
    }
    pub(crate) fn seal_commit(&mut self) -> Result<SyncBoundary, OverlayError> {
        if self.sync_admission_open {
            return Err(OverlayError::PendingBoundary);
        }
        self.run(|o, s, p| o.seal_sync(s, p, SyncTarget::Tree))
            .map(SyncBoundary::for_complete_commit)
    }
    pub(crate) fn replace_rejected(
        &mut self,
        boundary: u64,
        publication: [u8; 16],
    ) -> Result<(), OverlayError> {
        self.invalidate_clean_content()?;
        self.run(|o, s, p| o.replace_rejected(s, p, boundary, publication))
    }
    /// Seal the commit prefix after sync admission has closed and drained.
    /// # Errors
    /// Readiness, custody or a pending orphan/capture.
    pub fn capture_boundary(&mut self) -> Result<crate::BoundaryCapture, OverlayError> {
        self.run(OverlayStore::capture_boundary)
    }
    /// Retain the sealed boundary before any submission can be dispatched.
    /// # Errors
    /// Stale capture or local persistence failure.
    pub fn record_boundary(
        &mut self,
        capture: crate::BoundaryCapture,
        candidate: GrainId,
        publication: [u8; 16],
    ) -> Result<u64, OverlayError> {
        self.run(|o, s, p| o.record_boundary(s, p, capture, candidate, publication))
    }
    /// Retain a projected boundary, with the file its candidate selected,
    /// before any submission can be dispatched.
    /// # Errors
    /// Stale capture or local persistence failure.
    pub fn record_projected_boundary(
        &mut self,
        capture: crate::BoundaryCapture,
        candidate: GrainId,
        publication: [u8; 16],
        selection: Option<granary_core::overlay_journal::ProjectedSelection>,
    ) -> Result<u64, OverlayError> {
        self.run(|o, s, p| {
            o.record_projected_boundary(s, p, capture, candidate, publication, selection)
        })
    }
    /// Read the publication's admitted dispatch count and fence after replay.
    /// # Errors
    /// Custody, replay or persistence failure.
    pub fn commit_progress(
        &mut self,
        publication: [u8; 16],
    ) -> Result<Option<granary_core::overlay_journal::CommitProgress>, OverlayError> {
        self.run(|o, s, p| o.commit_progress(s, p, publication))
    }
    /// # Errors
    /// Boundary binding, attempt order, capacity or persistence failure.
    pub fn record_commit_attempt(
        &mut self,
        boundary: u64,
        publication: [u8; 16],
        attempt: u64,
    ) -> Result<u64, OverlayError> {
        self.run(|o, s, p| o.record_commit_attempt(s, p, boundary, publication, attempt))
    }
    /// # Errors
    /// Boundary binding, capacity or persistence failure.
    pub fn record_commit_fence(
        &mut self,
        boundary: u64,
        publication: [u8; 16],
    ) -> Result<u64, OverlayError> {
        self.run(|o, s, p| o.record_commit_fence(s, p, boundary, publication))
    }
    /// Remove a rejected boundary using freshly loaded, attempt-bound evidence.
    /// # Errors
    /// Proof binding, snapshots, custody or replacement persistence failure.
    pub(crate) fn replace_rejected_with_proof(
        &mut self,
        boundary: u64,
        publication: [u8; 16],
        proof: crate::RejectionProof,
    ) -> Result<(), OverlayError> {
        self.invalidate_clean_content()?;
        self.run(|o, s, p| o.replace_rejected_with_proof(s, p, boundary, publication, Some(proof)))
    }
    /// Remove the boundary and its fence in one attempt-bound replacement.
    /// # Errors
    /// Proof binding, snapshots, custody or replacement persistence failure.
    pub(crate) fn replace_rejected_fenced(
        &mut self,
        boundary: u64,
        publication: [u8; 16],
        proof: crate::RejectionProof,
    ) -> Result<(), OverlayError> {
        self.invalidate_clean_content()?;
        self.run(|o, s, p| o.replace_rejected_fenced(s, p, boundary, publication, proof))
    }
    /// # Errors
    /// Invalid boundary or persistence failure.
    pub fn record_landed(&mut self, proof: &crate::LandedProof) -> Result<u64, OverlayError> {
        self.run(|o, s, p| o.record_landed(s, p, proof))
    }
    /// # Errors
    /// Unbound receipt, generation or persistence failure.
    pub fn record_landed_refresh(
        &mut self,
        generation: u64,
        root: GrainId,
    ) -> Result<u64, OverlayError> {
        self.run(|o, s, p| {
            o.record_intent_registered(
                s,
                p,
                generation,
                root,
                granary_core::overlay_journal::IntentCause::LandedRefresh,
            )
        })
    }
    /// Returns the identities the landing did not carry from the current view.
    /// # Errors
    /// Missing durable landing/refresh or invalid replacement.
    pub fn replace_landed(
        &mut self,
        proof: crate::LandedProof,
    ) -> Result<crate::ViewChange, OverlayError> {
        self.invalidate_clean_content()?;
        self.run(|o, s, p| o.replace_landed(s, p, proof))
    }
    /// Replace a clean journal with a header-only one on the published head
    /// `root` at `seq`, whose base entries are `entries`.
    /// # Errors
    /// An unclean journal or an invalid replacement.
    pub(crate) fn replace_adopted(
        &mut self,
        root: GrainId,
        seq: u64,
        entries: Vec<OverlayEntry>,
    ) -> Result<crate::ViewChange, OverlayError> {
        self.invalidate_clean_content()?;
        self.run(|o, s, p| o.replace_adopted(s, p, root, seq, entries))
    }

    pub(crate) fn replace_recovered(
        &mut self,
        witness: crate::recovery::DirtyWitness,
    ) -> Result<(), OverlayError> {
        self.invalidate_clean_content()?;
        self.run(|o, s, p| {
            o.replace_recovered(
                s,
                p,
                witness.tree.view.base_id,
                witness.tree.view.base_seq,
                witness.tree.entries,
            )
        })
    }

    pub(crate) fn recovery_prefix(
        &mut self,
    ) -> Result<crate::overlay_store::RecoveryPrefix, OverlayError> {
        if !self.mutations_closed {
            return Err(OverlayError::MutationsClosed);
        }
        self.run(|o, _, _| o.recovery_prefix())
    }

    pub(crate) fn replace_recovered_suffix(
        &mut self,
        witness: crate::recovery::DirtyWitness,
        suffix: crate::overlay_store::RecoveredSuffix,
    ) -> Result<crate::ViewChange, OverlayError> {
        self.invalidate_clean_content()?;
        self.run(|o, s, p| o.replace_recovered_suffix(s, p, witness, suffix))
    }
    fn run<R>(
        &mut self,
        action: impl FnOnce(
            &mut OverlayStore<P>,
            &mut Store,
            &OwnershipStatus,
        ) -> Result<R, OverlayError>,
    ) -> Result<R, OverlayError> {
        self.check_poison()?;
        let result = action(self.overlay, self.store, &self.permission)
            .inspect_err(|error| error.invalidate_bundle(self.bundle_overlay));
        *self.poisoned |= self.overlay.readiness() == OverlayReadiness::Poisoned;
        result
    }
    fn run_cached<R>(
        &mut self,
        action: impl FnOnce(
            &mut OverlayStore<P>,
            &mut Store,
            &OwnershipStatus,
            &mut crate::overlay_store::verified_range::VerifiedRangeCache,
        ) -> Result<R, OverlayError>,
    ) -> Result<R, OverlayError> {
        self.check_poison()?;
        let result = action(self.overlay, self.store, &self.permission, self.range_cache)
            .inspect_err(|error| error.invalidate_bundle(self.bundle_overlay));
        *self.poisoned |= self.overlay.readiness() == OverlayReadiness::Poisoned;
        result
    }
    /// Refuse a user mutation once a shutdown has closed the store.
    fn check_mutations_open(&self) -> Result<(), OverlayError> {
        if self.mutations_closed {
            return Err(OverlayError::MutationsClosed);
        }
        Ok(())
    }
    fn check_poison(&self) -> Result<(), OverlayError> {
        if *self.poisoned {
            crate::observe::op_failed(
                crate::observe::OperationKind::OverlayWrite,
                crate::observe::FailureClass::Io,
            );
            return Err(OverlayError::Poisoned);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn preparation_context(
        &mut self,
        expected: &OverlayEntry,
    ) -> Result<(OverlayQuery<Option<OverlayEntry>>, u64), OverlayError> {
        self.run_cached(|o, s, p, memo| {
            let query = o.query_inode_change(s, p, expected)?;
            Ok((query, memo.generation()))
        })
    }
    pub(crate) fn preparation_view(
        &mut self,
        expected: &OverlayEntry,
    ) -> Result<(OverlayQuery<Option<OverlayEntry>>, crate::MountViewContext), OverlayError> {
        self.run_cached(|o, s, p, memo| {
            let (base_id, base_seq) = o.sync_base()?;
            let query = o.query_inode_change(s, p, expected)?;
            Ok((
                query,
                crate::MountViewContext {
                    base_id,
                    base_seq,
                    generation: memo.generation(),
                },
            ))
        })
    }
    pub(crate) fn invalidate_clean_content(&mut self) -> Result<(), OverlayError> {
        let result = self.range_cache.invalidate();
        *self.poisoned |= result.is_err();
        result
    }
    /// # Errors
    /// Refuses unavailable service, custody, capacity or persistence.
    pub fn create_file(&mut self, at: Location, exec: bool) -> Result<u64, OverlayError> {
        self.check_mutations_open()?;
        self.run(|o, s, p| o.create_file(s, p, at, exec))
    }
    /// # Errors
    /// Refuses unavailable service, custody, capacity or persistence.
    pub fn namespace_record(&mut self, record: Record) -> Result<u64, OverlayError> {
        self.check_mutations_open()?;
        self.run(|o, s, p| o.namespace_record(s, p, record))
    }
    /// # Errors
    /// Refuses unavailable service, custody or persistence.
    pub fn entries(&mut self) -> Result<Vec<OverlayEntry>, OverlayError> {
        self.run(OverlayStore::entries)
    }
    /// Copy one live entry, including an explicit synthetic-root result.
    /// # Errors
    /// Readiness, custody or index-consistency failure.
    pub fn query_path(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<OverlayQuery<OverlayQueryEntry>, OverlayError> {
        self.run(|o, s, p| o.query_path(s, p, path))
    }
    pub(crate) fn query_path_inode(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<OverlayQuery<Option<u64>>, OverlayError> {
        self.run(|o, s, p| o.query_path_inode(s, p, path))
    }
    /// Refresh one attached identity without resolving its former name.
    /// # Errors
    /// Readiness, custody or index-consistency failure.
    pub fn query_inode(
        &mut self,
        inode: u64,
    ) -> Result<OverlayQuery<OverlayQueryEntry>, OverlayError> {
        self.run(|o, s, p| o.query_inode(s, p, inode))
    }
    pub(crate) fn query_inode_change(
        &mut self,
        expected: &OverlayEntry,
    ) -> Result<OverlayQuery<Option<OverlayEntry>>, OverlayError> {
        self.run(|o, s, p| o.query_inode_change(s, p, expected))
    }
    /// Validate a parent and query one child.
    /// # Errors
    /// Readiness, custody or index-consistency failure.
    pub fn query_lookup(
        &mut self,
        parent: &[granary_core::manifest::Name],
        name: &granary_core::manifest::Name,
    ) -> Result<OverlayQuery<OverlayQueryEntry>, OverlayError> {
        self.run(|o, s, p| o.query_lookup(s, p, parent, name))
    }
    pub(crate) fn query_has_children(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<OverlayQuery<bool>, OverlayError> {
        self.run(|o, s, p| o.query_has_children(s, p, path))
    }
    /// Start a revision-bound directory observation.
    /// # Errors
    /// Readiness, custody or index-consistency failure.
    pub fn query_directory(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<OverlayQuery<OverlayDirectoryQuery>, OverlayError> {
        self.run(|o, s, p| o.query_directory(s, p, path))
    }
    /// Copy one bounded page under its original observation.
    /// # Errors
    /// Readiness, custody or index-consistency failure.
    pub fn query_children(
        &mut self,
        cursor: &OverlayCursor,
    ) -> Result<OverlayQuery<OverlayPage>, OverlayError> {
        self.run(|o, s, p| o.query_children(s, p, cursor))
    }
    /// Open another handle to the shared stage identity.
    /// # Errors
    /// Unavailable service, invalid path or a missing stage.
    pub fn open_stage(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<u64, OverlayError> {
        self.run(|o, s, p| o.open_stage(s, p, path))
    }
    pub(crate) fn open_stage_holds(
        &mut self,
        path: &[granary_core::manifest::Name],
        holds: u64,
    ) -> Result<u64, OverlayError> {
        self.run(|o, s, p| o.open_stage_holds(s, p, path, holds))
    }
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub(crate) fn journal_cursor(&self) -> Result<u64, OverlayError> {
        self.overlay.journal_cursor()
    }
    pub(crate) fn stage_floor_ready(
        &mut self,
        stage: u64,
        size: u64,
    ) -> Result<bool, OverlayError> {
        self.check_mutations_open()?;
        self.run(|o, s, p| o.stage_floor_ready(s, p, stage, size))
    }
    pub(crate) fn hold_stage(&mut self, stage: u64) -> Result<(), OverlayError> {
        self.run(|o, s, p| o.hold_stage(s, p, stage, 1).map(|_| ()))
    }
    /// # Errors
    /// Refuses unavailable service, custody, capacity or persistence.
    pub fn write(&mut self, stage: u64, offset: u64, bytes: &[u8]) -> Result<usize, OverlayError> {
        self.check_mutations_open()?;
        self.run(|o, s, p| o.write(s, p, stage, offset, bytes))
    }
    /// # Errors
    /// Invalid size, unavailable service, pending capture floor or persistence.
    pub fn truncate(&mut self, stage: u64, size: u64) -> Result<(), OverlayError> {
        self.check_mutations_open()?;
        self.run(|o, s, p| o.truncate(s, p, stage, size))
    }
    /// # Errors
    /// Refuses unavailable service, custody, capacity or stale capture state.
    pub fn capture(&mut self, stage: u64) -> Result<CaptureToken, OverlayError> {
        self.run(|o, s, p| o.capture(s, p, stage))
    }
    /// Seal one shared namespace/file cursor without copying mutable contents.
    /// # Errors
    /// Refuses unavailable service, invalid targets or reservation exhaustion.
    pub fn seal_sync(&mut self, target: SyncTarget) -> Result<SyncBoundary, OverlayError> {
        if !self.sync_admission_open {
            return Err(OverlayError::PendingBoundary);
        }
        self.run(|o, s, p| o.seal_sync(s, p, target))
    }
    /// Copy one bounded range; resolve immutable parts after the facade ends.
    /// # Errors
    /// Refuses stale context, range bounds, custody or corrupt staging.
    pub fn captured_parts(
        &mut self,
        boundary: &SyncBoundary,
        file: &CapturedFile,
        offset: u64,
    ) -> Result<Vec<CapturedPart>, OverlayError> {
        self.run(|o, s, p| o.captured_parts(s, p, boundary, file, offset))
    }
    /// Return an opaque range for payload authentication outside this facade.
    /// # Errors
    /// Invalid index/range, stale seal, custody or corrupt staging.
    pub fn captured_range(
        &mut self,
        boundary: &SyncBoundary,
        index: usize,
        offset: u64,
    ) -> Result<CapturedRange, OverlayError> {
        self.run(|o, s, p| o.captured_range(s, p, boundary, index, offset))
    }
    /// # Errors
    /// Refuses stale captures, unavailable service or persistence uncertainty.
    pub fn flush_sync_boundary(&mut self, boundary: &SyncBoundary) -> Result<(), OverlayError> {
        self.run(|o, s, p| o.flush_sync_boundary(s, p, boundary))
    }
    /// Explicitly dispose of local references without inventing file marks.
    /// # Errors
    /// Refuses a stale or already completed boundary.
    pub fn release_sync_boundary(&mut self, boundary: &SyncBoundary) -> Result<(), OverlayError> {
        self.overlay
            .release_sync_boundary(boundary)
            .inspect_err(|error| error.invalidate_bundle(self.bundle_overlay))
    }
    /// # Errors
    /// Refuses unavailable service, custody, stale capture or persistence.
    pub fn flush_boundary(&mut self, capture: &CaptureToken) -> Result<(), OverlayError> {
        self.run(|o, s, p| o.flush_boundary(s, p, capture))
    }
    /// # Errors
    /// Refuses unavailable service, stale capture, invalid proof or persistence.
    pub fn record_file_synced(&mut self, proof: &RegisteredCapture) -> Result<(), OverlayError> {
        self.run(|o, s, p| o.record_file_synced(s, p, proof))
    }
    /// # Errors
    /// Refuses a stale or already completed capture.
    pub fn complete_failed_capture(&mut self, capture: &CaptureToken) -> Result<(), OverlayError> {
        self.run(|o, _, _| o.complete_failed_capture(capture))
    }
    /// # Errors
    /// Refuses invalid ownership, replay or persistence.
    pub fn recovery_commits(&mut self) -> Result<Vec<RecoveryCommit>, OverlayError> {
        self.run(OverlayStore::recovery_commits)
    }
    /// What a shutdown still owes: each stage a tree sync selects, in stage
    /// order, with its dirty bytes, and the records since the base.
    /// # Errors
    /// An inaccessible stage or an overflowing dirty interval.
    pub(crate) fn shutdown_work(&self) -> Result<crate::overlay_store::ShutdownWork, OverlayError> {
        self.overlay.shutdown_work()
    }
    #[must_use]
    pub fn summary(&self) -> OverlaySummary {
        self.overlay.summary()
    }
    #[cfg(test)]
    pub(crate) fn set_coalescing_journal_length_for_test(
        &mut self,
        length: u64,
    ) -> Result<(), OverlayError> {
        self.overlay.set_coalescing_journal_length(length)
    }
    #[cfg(test)]
    pub(crate) fn projected_tree_seal_charge_for_test(&self) -> Result<u64, OverlayError> {
        self.overlay.projected_tree_seal_charge_for_test()
    }
    /// Presence only; it makes no integrity claim about object bytes.
    #[must_use]
    pub fn content_exists(&self, id: &GrainId) -> bool {
        granary_core::grainsource::GrainSource::has(self.store, id)
    }
}

impl<P: OverlayIo> WritableStore<P> {
    pub(super) fn install_overlay(&mut self, mut overlay: OverlayStore<P>) {
        overlay.install_coalescer(self.coalesce_clock.clone(), self.coalesce_wake.clone());
        self.bundle_overlay = overlay.bundle_projection();
        self.overlay = Some(overlay);
    }

    pub(crate) fn overlay_bundle(&self) -> Result<BundleOverlay, BundleRefusal> {
        let mut retained = self.bundle_overlay;
        if self.poisoned || self.store.publication_poisoned {
            OverlayError::Poisoned.invalidate_bundle(&mut retained);
        }
        self.overlay
            .as_ref()
            .and_then(OverlayStore::bundle_failure)
            .map_or(retained, Err)
    }

    pub(super) fn retain_overlay_bundle(&mut self, error: Option<&OverlayError>) {
        if let Some(error) = error {
            error.invalidate_bundle(&mut self.bundle_overlay);
        } else if self
            .bundle_overlay
            .is_ok_and(|summary| summary.readiness != 4)
        {
            self.bundle_overlay = self
                .overlay
                .as_ref()
                .ok_or(BundleRefusal::Unavailable)
                .and_then(OverlayStore::bundle_projection);
        }
    }

    pub(crate) fn invalidate_clean_content(&mut self) -> Result<(), CoordinationError> {
        let result = self.range_cache.invalidate();
        self.poisoned |= result.is_err();
        Ok(result?)
    }
    /// Release an owned job's counted hold without filesystem access. The
    /// lease has already authenticated the stage identity; cleanup retains all
    /// journal and staging evidence even when custody cannot be read.
    pub(crate) fn release_stage_lease(&mut self, stage: u64) -> Result<(), CoordinationError> {
        let result = self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .release_stage_hold(stage);
        self.retain_overlay_bundle(result.as_ref().err());
        Ok(result?)
    }

    /// Dispose one process-local stage hold even after fencing or poison.
    /// No write permission or durability acknowledgement is granted by cleanup.
    /// # Errors
    /// Missing stage or failed custody validation.
    pub(crate) fn release_stage(&mut self, stage: u64) -> Result<(), CoordinationError> {
        let overlay = self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?;
        let result = overlay.close_stage(&mut self.store, stage);
        self.retain_overlay_bundle(result.as_ref().err());
        Ok(result?)
    }

    /// Land verified immutable objects fetched outside local transactions.
    /// This idempotent CAS put appends no journal record and incurs no overlay
    /// cap charge. It retains the sole Store lock and grants no write readiness.
    /// # Errors
    /// Hash mismatch, object size bound, corrupt existing object or local I/O.
    pub fn put_immutable(&mut self, id: GrainId, bytes: &[u8]) -> Result<bool, CoordinationError> {
        Ok(put_verified(&self.store, id, bytes)?)
    }
    /// Replay with authenticated objects already in this exact Store. Missing
    /// data leaves recovery pending; no network wait occurs under mediation.
    /// With `carry_forward`, a clean journal on an older base is first
    /// rewritten, header-only, on `header`'s base.
    /// # Errors
    /// Missing ownership, malformed replay, corrupt content, custody or I/O.
    pub fn open_overlay_local(
        &mut self,
        header: granary_core::overlay_journal::JournalHeader,
        base: Vec<OverlayEntry>,
        io: P,
        carry_forward: bool,
    ) -> Result<(), CoordinationError> {
        let permission = self.permission()?;
        self.open_overlay_local_with(header, base, io, carry_forward, &permission)
    }
    pub(crate) fn open_released_overlay_local(
        &mut self,
        header: granary_core::overlay_journal::JournalHeader,
        base: Vec<OverlayEntry>,
        io: P,
    ) -> Result<(), CoordinationError> {
        let permission = self.released_recovery_permission()?;
        self.open_overlay_local_with(header, base, io, false, &permission)
    }
    fn open_overlay_local_with(
        &mut self,
        header: granary_core::overlay_journal::JournalHeader,
        base: Vec<OverlayEntry>,
        io: P,
        carry_forward: bool,
        permission: &OwnershipStatus,
    ) -> Result<(), CoordinationError> {
        self.invalidate_clean_content()?;
        let result = OverlayStore::open_shared(
            &self.store,
            self.config.clone(),
            header,
            base,
            permission,
            &mut crate::overlay_store::local_content::LocalContent::new(&self.store),
            io,
            self.faults.clone(),
            carry_forward,
        );
        self.retain_overlay_bundle(result.as_ref().err());
        self.install_overlay(result?);
        Ok(())
    }
    /// Dispose of exact process-local references after failure, including when
    /// service is fenced or poisoned. This memory-only operation neither grants
    /// readiness nor retires network evidence. Persist the caller disposition
    /// separately before releasing a floor whose request may have been sent.
    /// # Errors
    /// Missing overlay, foreign context or an already disposed boundary.
    pub fn release_sync_boundary(
        &mut self,
        boundary: &SyncBoundary,
    ) -> Result<(), CoordinationError> {
        let result = self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .release_sync_boundary(boundary);
        self.retain_overlay_bundle(result.as_ref().err());
        result?;
        self.floor_changed.notify_waiters();
        Ok(())
    }
}

pub(super) fn put_verified(store: &Store, id: GrainId, bytes: &[u8]) -> Result<bool, OverlayError> {
    if bytes.len() as u64 > granary_store::bounds::META_MAX_BYTES {
        return Err(OverlayError::refused("immutable object size bound"));
    }
    if GrainId::of(bytes) != id {
        return Err(content_corrupt());
    }
    let novel = store.put(&id, bytes).map_err(content_error)?;
    if !novel {
        store.get(&id).map_err(content_error)?;
    }
    Ok(novel)
}

fn content_corrupt() -> OverlayError {
    OverlayError::ContentCorrupt
}

pub(super) fn content_error(error: crate::store::StoreError) -> OverlayError {
    match error {
        crate::store::StoreError::Io { source, .. } => source.into(),
        crate::store::StoreError::Corrupt { .. }
        | crate::store::StoreError::Incompatible { .. }
        | crate::store::StoreError::Locked => content_corrupt(),
    }
}
