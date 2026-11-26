// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Reconstruct a retained commit's merge from its immutable inputs.

use super::reporting::Conflict;
use super::{
    Arc, BTreeMap, Clock, CoordinationError, GrainId, LocalContent, MonotonicClock, OverlayIo,
    RetainedCommit, RootStore, Submission, SyncContent, SyncEngine, SyncRemote, SyncRuntime,
    VerifiedBase, bounded, driver, follows, refused, verify_commit_entries,
};
use granary_core::{retained_submission::FrozenIntent, root};

pub(super) enum MergePurpose {
    Verification(Conflict),
    /// A rebase about to dispatch, with the anchors of a projected lane's
    /// residual: the merged base must equal the projection at each.
    Attempt(Conflict, Option<crate::overlay_store::ResidualAnchors>),
}

impl<P, R, S, C, M, E> SyncEngine<P, R, S, C, M, E>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + RootStore + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    pub(super) fn commit_error(
        &self,
        error: CoordinationError,
        lane: &RetainedCommit,
    ) -> CoordinationError {
        self.lane_error(error, lane.publication, &lane.observation)
    }

    /// [`Self::commit_error`] from the two parts of the lane it reads.
    pub(super) fn lane_error(
        &self,
        error: CoordinationError,
        publication: [u8; 16],
        observation: &std::sync::Mutex<super::reporting::State>,
    ) -> CoordinationError {
        if matches!(
            &error,
            CoordinationError::Recovery(crate::RecoveryError::Journal(
                crate::PublicationStoreError {
                    kind: crate::PublicationStoreErrorKind::Fenced,
                    ..
                }
            ))
        ) {
            // The journal only fences the lane's own publication.
            CoordinationError::CommitFenced { publication }
        } else if matches!(
            &error,
            CoordinationError::Overlay(crate::OverlayError::Conflict)
                | CoordinationError::Recovery(crate::RecoveryError::Journal(
                    crate::PublicationStoreError {
                        kind: crate::PublicationStoreErrorKind::Conflict,
                        ..
                    }
                ))
        ) {
            if let Ok(mut state) = observation.lock() {
                state.terminal = Some(crate::CommitResult::Conflict);
            }
            self.local(|local| Ok(local.fence_commit_conflict()))
                .unwrap_or_else(|error| error)
        } else {
            error
        }
    }

    pub(super) async fn verify_commit_record(
        self: &Arc<Self>,
        record: &Submission,
        entries: &[crate::OverlayEntry],
        deadline: tokio::time::Instant,
        conflict: &Conflict,
    ) -> Result<(), CoordinationError> {
        granary_core::retained_submission::validate(record)
            .map_err(|_| refused("SyncCommitRecord"))?;
        let initial = root::decode_root(&record.frozen.initial_root)
            .map_err(|_| refused("SyncCommitSignature"))?;
        let writer = self.local(|local| Ok(local.writer_uuid()))?;
        granary_store::crypto::check_head(
            &record.frozen.initial_root,
            record.volume.as_str(),
            initial.seq,
            &self.trusted,
        )
        .map_err(|_| refused("SyncCommitSignature"))?;
        let base = self
            .base
            .lock()
            .map_err(|_| refused("SyncBasePoisoned"))?
            .clone();
        if initial.writer_uuid != writer
            || initial.parent != Some(base.id())
            || !follows(base.seq(), initial.seq)
        {
            return Err(refused("SyncCommitCandidateBinding"));
        }
        for candidate in &record.candidates {
            let doc = granary_store::crypto::check_head(
                &candidate.root,
                record.volume.as_str(),
                candidate.seq,
                &self.trusted,
            )
            .map_err(|_| refused("SyncCommitSignature"))?;
            if doc.writer_uuid != writer {
                return Err(refused("SyncCommitCandidateBinding"));
            }
            if candidate.number > 1 && doc.seq > initial.seq {
                let manifest = self
                    .merge_commit_manifest(
                        &record.frozen,
                        entries,
                        doc.parent,
                        doc.seq,
                        deadline,
                        MergePurpose::Verification(conflict.clone()),
                    )
                    .await?;
                if doc.manifest_root != manifest {
                    return Err(refused("SyncCommitRebaseManifest"));
                }
            } else {
                if doc.seq != initial.seq || doc.parent != initial.parent {
                    return Err(refused("SyncCommitCandidateBinding"));
                }
                // A later candidate's merge authenticates the frozen namespace
                // after restoring its immutable content from the retained root.
                if record
                    .candidates
                    .iter()
                    .any(|c| c.number > 1 && c.seq > initial.seq)
                {
                    continue;
                }
                let engine = self.clone();
                let entries = entries.to_vec();
                self.runtime
                    .blocking(move || {
                        let content = engine
                            .content
                            .with_deadline(engine.runtime.clone(), deadline);
                        verify_commit_entries(doc.manifest_root, &entries, &content, None)
                    })
                    .await
                    .map_err(|_| refused("SyncMaterializationLost"))??;
            }
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one operation authenticates ancestry, restores both immutable closures and reconstructs the merge"
    )]
    pub(super) async fn merge_commit_manifest(
        self: &Arc<Self>,
        frozen: &FrozenIntent,
        entries: &[crate::OverlayEntry],
        parent: Option<GrainId>,
        seq: u64,
        deadline: tokio::time::Instant,
        purpose: MergePurpose,
    ) -> Result<GrainId, CoordinationError> {
        let initial =
            root::decode_root(&frozen.initial_root).map_err(|_| refused("SyncCommitSignature"))?;
        if seq <= initial.seq {
            return Ok(initial.manifest_root);
        }
        let base = self
            .base
            .lock()
            .map_err(|_| refused("SyncBasePoisoned"))?
            .clone();
        if initial.parent != Some(base.id()) || !follows(base.seq(), initial.seq) {
            return Err(refused("SyncCommitRebaseManifest"));
        }
        let head_seq = seq
            .checked_sub(1)
            .filter(|n| *n >= base.seq())
            .ok_or_else(|| refused("SyncCommitRebaseManifest"))?;
        let mut expected = parent;
        let mut head = None;
        for n in (base.seq()..=head_seq).rev() {
            let bytes = bounded(
                self.runtime.as_ref(),
                deadline,
                self.remote.get_root(initial.volume.as_str(), n),
            )
            .await?
            .map_err(|_| refused("SyncCommitRebaseUnavailable"))?
            .ok_or_else(|| refused("SyncCommitRebaseUnavailable"))?;
            let doc = granary_store::crypto::check_head(
                &bytes,
                initial.volume.as_str(),
                n,
                &self.trusted,
            )
            .map_err(|_| refused("SyncCommitRebaseUnavailable"))?;
            if Some(GrainId::of(&bytes)) != expected
                || (n == base.seq() && expected != Some(base.id()))
            {
                return Err(refused("SyncCommitRebaseUnavailable"));
            }
            expected = doc.parent;
            if head.is_none() {
                head = Some(bytes);
            }
        }
        let bytes = head.ok_or_else(|| refused("SyncCommitRebaseManifest"))?;
        let state = bounded(
            self.runtime.as_ref(),
            deadline,
            VerifiedBase::attach_map(
                &bytes,
                initial.volume.as_str(),
                &self.trusted,
                self.remote.as_ref(),
            ),
        )
        .await?
        .map_err(|_| refused("SyncCommitRebaseUnavailable"))?;
        let mut recovered = BTreeMap::new();
        for root_bytes in [&frozen.initial_root, &bytes] {
            let doc = root::decode_root(root_bytes).map_err(|_| refused("SyncCommitSignature"))?;
            let input = FrozenIntent {
                initial_root: root_bytes.clone(),
                ..frozen.clone()
            };
            let objects = bounded(
                self.runtime.as_ref(),
                deadline,
                crate::recovery::read_closure(
                    self.remote.as_ref(),
                    &LocalContent(self.content.as_ref()),
                    &self.trusted,
                    &initial.volume,
                    doc.manifest_root,
                    Some(&input),
                ),
            )
            .await?
            .map_err(|_| refused("SyncCommitRebaseUnavailable"))?;
            recovered.extend(objects.retained);
        }
        let engine = self.clone();
        let entries = entries.to_vec();
        self.runtime
            .blocking(move || {
                let content = engine
                    .content
                    .with_deadline(engine.runtime.clone(), deadline);
                for (id, bytes) in recovered {
                    content.put_object(id, &bytes)?;
                }
                verify_commit_entries(initial.manifest_root, &entries, &content, None).map_err(
                    |error| match error {
                        CoordinationError::Refused("SyncCommitManifest")
                        | CoordinationError::Overlay(
                            crate::OverlayError::CaptureCoverageLost
                            | crate::OverlayError::ContentUnavailable,
                        ) => refused("SyncCommitRebaseUnavailable"),
                        _ => error,
                    },
                )?;
                let local = driver::build_landed_entries(initial.manifest_root, &entries, &content)
                    .map_err(|_| refused("SyncCommitRebaseUnavailable"))?;
                let head = VerifiedBase::attach_validated(
                    bytes,
                    initial.volume.as_str(),
                    &engine.trusted,
                    &content,
                    state,
                )
                .map_err(|_| refused("SyncCommitRebaseUnavailable"))?;
                // Resolve remote file payloads for canonical reconstruction, including
                // files absent from the lane and files whose kind the head changed.
                driver::build_landed_entries(head.manifest_root(), &[], &content)
                    .map_err(|_| refused("SyncCommitRebaseUnavailable"))?;
                let conflict = |path: &[granary_core::manifest::Name]| {
                    let reporter = match &purpose {
                        MergePurpose::Attempt(reporter, _) => {
                            engine.metrics.record_rebase_conflict();
                            reporter
                        }
                        MergePurpose::Verification(reporter) => reporter,
                    };
                    reporter.record(crate::local_report::namespace_path(path));
                    CoordinationError::Overlay(crate::OverlayError::Conflict)
                };
                let merged = crate::merge_manifests(base.manifest_root(), &local, &head, &content)
                    .map_err(|error| match error {
                        crate::RebaseError::Conflict(overlap) => conflict(&overlap.path),
                        crate::RebaseError::InvalidManifest => {
                            refused("SyncCommitRebaseUnavailable")
                        }
                    })?;
                // The residual replays over this base only where it equals the
                // projection; refuse before the rebased candidate can land.
                if let MergePurpose::Attempt(_, Some(anchors)) = &purpose
                    && let Some(path) = anchors.mismatch(&local, &merged)
                {
                    return Err(conflict(&path));
                }
                let (manifest, nodes) =
                    crate::sync::objects::entries_tree(&merged, &content, |id| {
                        content
                            .payload(id)
                            .map_err(|_| crate::PublishError::BadPlan)
                    })
                    .map_err(|_| refused("SyncCommitRebaseUnavailable"))?;
                for (id, bytes) in nodes {
                    content.put_object(id, &bytes)?;
                }
                Ok(manifest)
            })
            .await
            .map_err(|_| refused("SyncMaterializationLost"))?
    }
}
