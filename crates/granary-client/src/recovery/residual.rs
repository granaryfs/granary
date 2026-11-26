// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Read-only authentication of a journal held by a residual disposition.

use super::{
    AuthorityTransport, RecoveryCommandError, RecoveryError, RecoveryJournal, preparation, probe,
};
use crate::overlay_store::LandedJournal;
use crate::sync::{Budget, build_landed_entries, refused};
use crate::{
    CoordinationError, LandedProof, OverlayError, OverlayIo, SyncContent, SyncRuntime,
    TokioSyncRuntime, WritableStore,
};
use granary_core::{
    grainsource::{GrainSource, GrainSourceError},
    hash::GrainId,
    manifest::{FileGrains, node::file_payload},
    overlay_journal::{JournalHeader, ResidualDisposition},
    retained_submission::{FrozenIntent, Submission},
    root::VolumeName,
};
use granary_store::crypto::TrustedKeys;
use std::{collections::BTreeMap, sync::Mutex};

/// Authenticated namespaces and their exact local disposition source.
pub(crate) struct ResidualEvidence {
    pub(crate) source: ResidualSource,
    pub(crate) disposition: ResidualDisposition,
}

impl std::ops::Deref for ResidualEvidence {
    type Target = ResidualSource;

    fn deref(&self) -> &Self::Target {
        &self.source
    }
}

impl std::ops::DerefMut for ResidualEvidence {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.source
    }
}

/// Authenticated capture, landing and exact journal prefix used by inventory.
pub(crate) struct ResidualSource {
    pub(crate) header: JournalHeader,
    pub(crate) journal: Vec<u8>,
    pub(crate) boundary_seq: u64,
    pub(crate) publication_id: [u8; 16],
    pub(crate) source_end: u64,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "exact authenticated base bytes are retained for inspection"
        )
    )]
    pub(crate) base: Vec<u8>,
    pub(crate) proof: LandedProof,
    pub(crate) base_entries: Vec<crate::OverlayEntry>,
    pub(crate) captured: CapturedContent,
    pub(crate) budget: Budget<'static, ()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapturedPayload {
    pub(crate) size: u64,
    pub(crate) grains: FileGrains,
}

#[derive(Debug, Default)]
pub(crate) struct CapturedContent {
    pub(crate) payloads: BTreeMap<GrainId, CapturedPayload>,
    pub(crate) nodes: BTreeMap<GrainId, Vec<u8>>,
}

struct AuthenticatedNamespace {
    entries: Vec<crate::OverlayEntry>,
    content: CapturedContent,
}

struct ReadOnlyContent<'a> {
    local: &'a crate::Store,
    objects: &'a preparation::VerifiedObjects,
    budget: &'a Budget<'a, ()>,
    payloads: Mutex<BTreeMap<GrainId, CapturedPayload>>,
}
impl GrainSource for ReadOnlyContent<'_> {
    fn has(&self, id: &GrainId) -> bool {
        self.objects.overlay(self.local).has(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.objects.overlay(self.local).get(id)
    }
}
impl SyncContent for ReadOnlyContent<'_> {
    fn payload(&self, _: GrainId) -> Result<FileGrains, CoordinationError> {
        Err(refused("RecoveryResidualReadOnly"))
    }
    fn read_content(&self, _: GrainId, _: u64, _: usize) -> Result<Vec<u8>, OverlayError> {
        Err(OverlayError::refused("residual preflight is read-only"))
    }
    fn put_object(&self, _: GrainId, _: &[u8]) -> Result<(), CoordinationError> {
        Err(refused("RecoveryResidualReadOnly"))
    }
    fn remember_payload(
        &self,
        content: GrainId,
        size: u64,
        grains: &FileGrains,
    ) -> Result<(), CoordinationError> {
        let bytes = file_payload(size, grains).map_err(|_| refused("SyncCommitManifest"))?;
        let mut payloads = self
            .payloads
            .lock()
            .map_err(|_| refused("SyncGraphPoisoned"))?;
        if let std::collections::btree_map::Entry::Vacant(entry) = payloads.entry(content) {
            self.budget
                .charge(bytes.len())
                .map_err(|_| refused("RecoveryResidualWorkspace"))?;
            entry.insert(CapturedPayload {
                size,
                grains: grains.clone(),
            });
        }
        Ok(())
    }
}

fn source_error(
    error: impl Into<RecoveryCommandError>,
    invalid: &'static str,
) -> CoordinationError {
    match error.into() {
        RecoveryCommandError::Publication(RecoveryError::Invalid("residual workspace")) => {
            refused("RecoveryResidualWorkspace")
        }
        RecoveryCommandError::Coordination(CoordinationError::Refused(
            "ViewRootUnavailable" | "ViewRootUnpublished",
        ))
        | RecoveryCommandError::Publication(RecoveryError::RemoteIntegrity(
            "probe chain root missing" | "recovery root missing",
        )) => refused("RecoveryResidualUnavailable"),
        RecoveryCommandError::Publication(
            RecoveryError::Remote(error)
            | RecoveryError::Preparation(crate::PublishError::Remote(error)),
        ) if crate::resolve::is_transport_down(&error)
            || matches!(
                error,
                granary_core::rootstore::RootStoreError::Unavailable { .. }
            ) =>
        {
            refused("RecoveryResidualUnavailable")
        }
        _ => refused(invalid),
    }
}

async fn namespace<T: AuthorityTransport + Sync>(
    remote: &T,
    local: &crate::Store,
    keys: &TrustedKeys,
    volume: &VolumeName,
    frozen: &FrozenIntent,
    previous: &[crate::OverlayEntry],
    budget: &Budget<'_, ()>,
) -> Result<AuthenticatedNamespace, CoordinationError> {
    let manifest = granary_core::root::decode_root(&frozen.initial_root)
        .map_err(|_| refused("RecoveryResidualClosure"))?
        .manifest_root;
    let objects = preparation::read_closure_charged(
        remote,
        local,
        keys,
        volume,
        manifest,
        Some(frozen),
        |n| {
            budget
                .charge(n)
                .map_err(|_| RecoveryError::Invalid("residual workspace"))
        },
    )
    .await
    .map_err(|error| source_error(error, "RecoveryResidualClosure"))?;
    let content = ReadOnlyContent {
        local,
        objects: &objects,
        budget,
        payloads: Mutex::default(),
    };
    let entries = build_landed_entries(manifest, previous, &content)?;
    let payloads = content
        .payloads
        .into_inner()
        .map_err(|_| refused("SyncGraphPoisoned"))?;
    Ok(AuthenticatedNamespace {
        entries,
        content: CapturedContent {
            payloads,
            nodes: objects.retained,
        },
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "one read-only source transaction binds sealed bytes, authenticated trees and their shared budget"
)]
pub(crate) async fn authenticate_residual_sources<
    P: OverlayIo + Send + Sync,
    T: AuthorityTransport + Sync,
>(
    store: &mut WritableStore<P>,
    remote: &T,
    keys: &TrustedKeys,
    workspace_bytes: u64,
    (journal, record): (LandedJournal, Submission),
) -> Result<ResidualEvidence, CoordinationError> {
    let (header, source, disposition) = journal
        .sealed
        .ok_or_else(|| refused("RecoveryResidualSourceMissing"))?;
    let (publication, candidate) = journal
        .boundaries
        .get(&disposition.boundary_seq)
        .ok_or_else(|| refused("RecoveryResidualSourceMissing"))?;
    if (*publication, *candidate)
        != (
            record.publication_id,
            GrainId::of(&record.frozen.initial_root),
        )
    {
        return Err(refused("RecoveryResidualCaptureChanged"));
    }
    let volume = record.volume.clone();
    let initial = granary_core::root::decode_root(&record.frozen.initial_root)
        .map_err(|_| refused("RecoveryResidualCaptureSignature"))?;
    granary_store::crypto::check_head(
        &record.frozen.initial_root,
        volume.as_str(),
        initial.seq,
        keys,
    )
    .map_err(|_| refused("RecoveryResidualCaptureSignature"))?;
    let stored = (disposition.landed_seq, disposition.landed_root);
    let bytes = if record.is_complete() {
        super::refetch_landing(remote, &record, Some(stored), keys)
            .await
            .map_err(|error| source_error(error, "RecoveryResidualLandingChanged"))?
            .ok_or_else(|| refused("RecoveryResidualUnavailable"))?
            .0
    } else {
        let (root, _) = probe::read_landing_candidate(remote, &record, stored.0, stored.1, keys)
            .await
            .map_err(|error| source_error(error, "RecoveryResidualLandingChanged"))?;
        root.bytes().to_vec()
    };
    let (base, _) = RecoveryJournal::new(store, remote, keys)
        .root_at(&volume, header.base_seq, header.base_root)
        .await
        .map_err(|error| source_error(error, "RecoveryResidualClosure"))?;
    let budget = Budget::new(&(), workspace_bytes, None);
    // Captured traversal carries no inode identity.
    let captured = namespace(
        remote,
        store.recovery_store(),
        keys,
        &volume,
        &record.frozen,
        &[],
        &budget,
    )
    .await?;
    let landed = FrozenIntent {
        initial_root: bytes,
        ..record.frozen
    };
    let entries = namespace(
        remote,
        store.recovery_store(),
        keys,
        &volume,
        &landed,
        &captured.entries,
        &budget,
    )
    .await?;
    let base_frozen = FrozenIntent {
        initial_root: base.clone(),
        ..landed
    };
    let base_entries = namespace(
        remote,
        store.recovery_store(),
        keys,
        &volume,
        &base_frozen,
        &[],
        &budget,
    )
    .await?;
    for graph in [&base_entries.entries, &captured.entries, &entries.entries] {
        let bytes = crate::overlay_store::commit_graph_charge_of(graph)
            .ok_or_else(|| refused("RecoveryResidualWorkspace"))?;
        budget
            .charge_reserved(bytes)
            .map_err(|_| refused("RecoveryResidualWorkspace"))?;
    }
    budget
        .charge_reserved(
            u64::try_from(source.len()).map_err(|_| refused("RecoveryResidualWorkspace"))?,
        )
        .map_err(|_| refused("RecoveryResidualWorkspace"))?;
    let scan = granary_core::overlay_journal::scan_journal(&source)
        .map_err(|_| refused("RecoveryResidualSourceChanged"))?;
    let prefix_len = scan
        .valid_len
        .checked_sub(4 + granary_core::overlay_journal::LEN_MIN as usize + 110)
        .ok_or_else(|| refused("RecoveryResidualSourceChanged"))?;
    let journal = source
        .get(..prefix_len)
        .ok_or_else(|| refused("RecoveryResidualSourceChanged"))?
        .to_vec();
    Ok(ResidualEvidence {
        disposition,
        source: ResidualSource {
            header,
            journal,
            boundary_seq: disposition.boundary_seq,
            publication_id: disposition.publication_id,
            source_end: disposition.source_end,
            base,
            base_entries: base_entries.entries,
            captured: captured.content,
            budget,
            proof: LandedProof {
                boundary_seq: disposition.boundary_seq,
                landed_root: stored.1,
                landed_seq: stored.0,
                captured_entries: captured.entries,
                entries: entries.entries,
            },
        },
    })
}

/// Authenticate held sources and refuse admission without changing the store.
/// An unsealed journal returns before consulting the deadline or entering the runtime.
/// Authentication is timed; local validation cooperatively checks the same deadline
/// before replay and payload I/O. A single stalled syscall remains unbounded.
pub(crate) fn preflight_residual<P: OverlayIo + Send + Sync, T: AuthorityTransport + Sync>(
    store: &mut WritableStore<P>,
    remote: &T,
    keys: &TrustedKeys,
    runtime: &tokio::runtime::Runtime,
    deadline: impl FnOnce() -> Result<tokio::time::Instant, CoordinationError>,
) -> Result<(), CoordinationError> {
    let Some(sources) = store.residual_sources()? else {
        return Ok(());
    };
    let deadline = deadline()?;
    runtime.block_on(async {
        let evidence = tokio::time::timeout_at(
            deadline,
            authenticate_residual_sources(
                store,
                remote,
                keys,
                crate::overlay_store::RESIDUAL_PREFLIGHT_WORKSPACE_BYTES,
                sources,
            ),
        )
        .await
        .map_err(|_| refused("SyncDeadline"))??;
        store.validate_residual_sources(&evidence, || {
            #[cfg(test)]
            if let Some(result) =
                super::RESIDUAL_CHECK.with_borrow_mut(|check| check.as_mut().map(|check| check()))
            {
                result?;
            }
            if TokioSyncRuntime.now() >= deadline {
                return Err(refused("SyncDeadline"));
            }
            Ok(())
        })?;
        Err(refused("RecoveryResidualValidatedAwaitingExecution"))
    })
}

#[cfg(test)]
mod tests;
