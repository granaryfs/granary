// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The publication journal and authenticated merges of explicit store recovery.

use super::{AuthorityTransport, PublicationJournal, RecoveredObjects, RecoveryError, preparation};
use crate::{
    CoordinationError, OverlayIo, OwnedCandidate, PublicationStoreError, PublicationStoreErrorKind,
    WritableStore, publish, sync,
};
use granary_core::{
    grainsource::{GrainSource, GrainSourceError},
    hash::GrainId,
    retained_submission::{FrozenIntent, Scope, Submission},
    root::{self, VolumeName},
    secure_random::SecureRandom,
};
use granary_store::crypto::TrustedKeys;
use std::{collections::BTreeMap, sync::Arc};

/// A subsuming published root authenticated through the replayed journal base.
pub(crate) struct DirtyWitness {
    /// The carrier selection that must still match at installation.
    pub(crate) selected: GrainId,
    /// The prepared ID credited by the publication, used to prove the cut.
    pub(crate) prepared: GrainId,
    /// A distinct selection must be proved at its own registration.
    pub(crate) selection: Option<(u64, WitnessTree)>,
    pub(crate) tree: WitnessTree,
    pub(crate) event: crate::observe::RecoverEvent,
}

pub(crate) struct WitnessTree {
    pub(crate) view: Arc<crate::writable_store::ViewContext>,
    pub(crate) manifest: GrainId,
    pub(crate) entries: Vec<crate::OverlayEntry>,
}

/// A recovering store's retained publication and verified content. Every
/// write to the retained record first requires this process's own persisted
/// grant. A rebase merges the prepared root against its own parent, loading
/// root structures and the prepared root's novel grains through their signed
/// binmaps. Newer verified ancestors can witness superseding deletions.
pub struct RecoveryJournal<'a, P: OverlayIo, T> {
    store: &'a mut WritableStore<P>,
    transport: &'a T,
    keys: &'a TrustedKeys,
    objects: RecoveredObjects,
    conflict_secure: Option<std::sync::Mutex<&'a mut (dyn SecureRandom + Send)>>,
    conflict_operation: Option<crate::CorrelationId>,
}

impl<P: OverlayIo, T> std::fmt::Debug for RecoveryJournal<'_, P, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryJournal").finish_non_exhaustive()
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "map_err consumes the failed rebase's owned error"
)]
fn journal_error(error: RecoveryError) -> PublicationStoreError {
    let kind = match &error {
        RecoveryError::Journal(error) => error.kind,
        RecoveryError::Remote(_) | RecoveryError::Preparation(_) => {
            PublicationStoreErrorKind::Unavailable
        }
        RecoveryError::RemoteIntegrity(_) => PublicationStoreErrorKind::RemoteIntegrity,
        _ => PublicationStoreErrorKind::Refused,
    };
    PublicationStoreError {
        path: "journal".into(),
        kind,
        reason: error.to_string(),
    }
}
/// The retained store's own refusal unchanged; an ownership refusal by name.
fn owner_error(error: CoordinationError) -> PublicationStoreError {
    match error {
        CoordinationError::Publication(error) => error,
        error => PublicationStoreError {
            path: "journal".into(),
            kind: PublicationStoreErrorKind::Refused,
            reason: error.to_string(),
        },
    }
}

impl<'a, P: OverlayIo + Send + Sync, T: AuthorityTransport + Sync> RecoveryJournal<'a, P, T> {
    /// A journal over `store`'s retained publication and object store,
    /// fetching through `transport` with publisher trust `keys`.
    #[must_use]
    pub fn new(store: &'a mut WritableStore<P>, transport: &'a T, keys: &'a TrustedKeys) -> Self {
        let objects = RecoveredObjects {
            writer: Some(store.writer_uuid()),
            ..RecoveredObjects::default()
        };
        Self {
            store,
            transport,
            keys,
            objects,
            conflict_secure: None,
            conflict_operation: None,
        }
    }

    /// Draw one process-local join only if a conflict needs an actionable report.
    pub(crate) fn report_conflicts_with(
        mut self,
        secure: &'a mut (dyn SecureRandom + Send),
    ) -> Self {
        self.conflict_secure = Some(std::sync::Mutex::new(secure));
        self
    }

    /// Open the authenticated journal base under this instance's grant or
    /// its durably released receipt.
    pub(super) async fn open_boundary(
        &mut self,
        header: granary_core::overlay_journal::JournalHeader,
        io: P,
    ) -> Result<(), super::RecoveryCommandError> {
        let released = self.store.recovery_released();
        if !released {
            self.store.check_recovery_owner()?;
        }
        let volume = self.store.snapshot().volume.clone();
        let (bytes, state) = self
            .root_at(&volume, header.base_seq, header.base_root)
            .await?;
        let doc = root::decode_root(&bytes)
            .map_err(|_| RecoveryError::RemoteIntegrity("recovery root"))?;
        preparation::load_structure(self.transport, self, &state, doc.manifest_root).await?;
        let entries = crate::writable_store::capture::overlay_base_entries(
            self,
            doc.manifest_root,
            &|_, _| 0,
            &mut |_, _| Ok(()),
            &|| CoordinationError::Refused("SyncBase"),
        )?;
        let view = std::sync::Arc::new(crate::writable_store::ViewContext {
            base_id: header.base_root,
            base_seq: header.base_seq,
            base_bytes: bytes,
            bins: state.bins.into(),
            entries: state.known,
            pin_files: std::collections::BTreeMap::new(),
            pin_nodes: std::collections::BTreeMap::new(),
        });
        if released {
            self.store
                .open_released_overlay_local(header, entries, io)?;
        } else {
            self.store.open_overlay_local(header, entries, io, false)?;
        }
        self.store.bind_mount(view);
        Ok(())
    }

    /// The root at `seq`, which must be `id`, with its signed binmap.
    pub(super) async fn root_at(
        &self,
        volume: &VolumeName,
        seq: u64,
        id: GrainId,
    ) -> Result<(Vec<u8>, publish::RemoteState), RecoveryError> {
        let bytes = self
            .transport
            .probe_root_once(volume.as_str(), seq)
            .await?
            .ok_or(RecoveryError::RemoteIntegrity("recovery root missing"))?;
        if GrainId::of(&bytes) != id {
            return Err(RecoveryError::RemoteIntegrity("recovery root mismatch"));
        }
        let state =
            publish::state_from_head(self.transport, volume, seq, &bytes, self.keys).await?;
        Ok((bytes, state))
    }

    /// Classify the settled carrier selection before finishing a dirty journal.
    pub(crate) async fn dirty_witness(
        &mut self,
    ) -> Result<Option<DirtyWitness>, CoordinationError> {
        let volume = self.store.snapshot().volume.clone();
        let selected = self.store.snapshot().root.clone();
        let writer = self.store.writer_uuid();
        let (prepared, head, relation) = super::coordinator::selected_relation(
            self.transport,
            self,
            self.keys,
            &volume,
            writer,
            &selected,
        )
        .await
        .map_err(|error| match error {
            RecoveryError::Invalid(_) => CoordinationError::Refused("WritableRecoveryRequired"),
            error => CoordinationError::Recovery(error),
        })?;
        let base = self
            .store
            .shutdown_base()
            .ok_or(CoordinationError::Refused("SyncBase"))?;
        let (seq, id, witness_prepared, selection) = match relation {
            crate::HeadRelation::Subsumed { by_seq, by_root } => {
                (by_seq, by_root, prepared.id(), None)
            }
            crate::HeadRelation::NeedsRebase { chain } => {
                let Some((seq, id, through)) = self
                    .registered_witness(&volume, chain, &prepared, base)
                    .await?
                else {
                    return Ok(None);
                };
                let state = publish::state_from_head(
                    self.transport,
                    &volume,
                    prepared.seq(),
                    &selected,
                    self.keys,
                )
                .await
                .map_err(RecoveryError::from)
                .map_err(CoordinationError::Recovery)?;
                let tree = self.witness_tree(selected, state).await?;
                (seq, id, id, Some((through, tree)))
            }
            crate::HeadRelation::Stale => {
                crate::observe::recover(crate::observe::RecoverEvent::Stale);
                return Err(CoordinationError::Refused("RecoveryStale"));
            }
            crate::HeadRelation::Corrupt => {
                return Err(CoordinationError::Recovery(RecoveryError::RemoteIntegrity(
                    "prepared root ancestry",
                )));
            }
        };
        if seq < base.1 || (seq == base.1 && id != base.0) {
            return Err(CoordinationError::Refused("WritableRecoveryRequired"));
        }
        let (bytes, state) = self
            .root_at(&volume, seq, id)
            .await
            .map_err(CoordinationError::Recovery)?;
        let doc = root::decode_root(&bytes).map_err(|_| {
            CoordinationError::Recovery(RecoveryError::RemoteIntegrity("recovery witness"))
        })?;
        if selection.is_none() {
            self.walk_witness_parents(&volume, doc.parent, seq, base, |_, _| {})
                .await?;
        } else if doc.writer_uuid != writer {
            return Err(CoordinationError::Recovery(RecoveryError::RemoteIntegrity(
                "recovery witness writer",
            )));
        }
        Ok(Some(DirtyWitness {
            selected: prepared.id(),
            prepared: witness_prepared,
            selection,
            tree: self.witness_tree(bytes, state).await?,
            event: super::coordinator::subsumed_event(witness_prepared, head, seq, id),
        }))
    }

    async fn witness_tree(
        &mut self,
        bytes: Vec<u8>,
        state: publish::RemoteState,
    ) -> Result<WitnessTree, CoordinationError> {
        let doc = root::decode_root(&bytes).map_err(|_| witness_ancestry())?;
        let manifest = doc.manifest_root;
        preparation::load_structure(self.transport, self, &state, manifest)
            .await
            .map_err(CoordinationError::Recovery)?;
        let mut pin_files = BTreeMap::new();
        let entries = crate::writable_store::capture::overlay_base_entries(
            self,
            manifest,
            &|_, _| 0,
            &mut |size, grains| {
                let bytes = granary_core::manifest::node::file_payload(size, grains)
                    .map_err(|_| crate::OverlayError::ContentCorrupt)?;
                pin_files
                    .entry(GrainId::of(&bytes))
                    .or_insert_with(|| (size, grains.clone()));
                Ok(())
            },
            &|| CoordinationError::Refused("SyncBase"),
        )?;
        Ok(WitnessTree {
            view: Arc::new(crate::writable_store::ViewContext {
                base_id: GrainId::of(&bytes),
                base_seq: doc.seq,
                base_bytes: bytes,
                bins: state.bins.into(),
                entries: state.known,
                pin_files,
                pin_nodes: BTreeMap::new(),
            }),
            manifest,
            entries,
        })
    }

    async fn registered_witness(
        &mut self,
        volume: &VolumeName,
        mut chain: Vec<(u64, GrainId)>,
        prepared: &OwnedCandidate,
        base: (GrainId, u64),
    ) -> Result<Option<(u64, GrainId, u64)>, CoordinationError> {
        let (through, registrations) = self
            .store
            .registered_roots_through_selection()?
            .ok_or(CoordinationError::Refused("WritableRecoveryRequired"))?;
        let selected = root::decode_root(prepared.bytes()).map_err(|_| witness_ancestry())?;
        // NeedsRebase verified through the selected parent but excluded it
        // from the chain. Extend that same chain through the replay base.
        if base.1 < selected.seq {
            self.walk_witness_parents(volume, selected.parent, selected.seq, base, |seq, id| {
                chain.push((seq, id));
            })
            .await?;
        } else if !chain.contains(&(base.1, base.0)) {
            return Err(CoordinationError::Refused("WritableRecoveryRequired"));
        }
        // A registration stores an ID. Equality of manifests would require
        // authenticated prepared bytes as well. The installed base is credited.
        let witness = chain
            .iter()
            .find(|(seq, id)| *seq > base.1 && registrations.contains(id));
        // The selected parent may itself be the witness while the selected
        // root can still land. Require an occupied slot on the verified chain.
        if witness.is_some()
            && !chain
                .iter()
                .any(|(seq, id)| *seq == selected.seq && *id != prepared.id())
        {
            return Err(CoordinationError::Refused("WritableRecoveryRequired"));
        }
        Ok(witness.map(|&(seq, id)| (seq, id, through)))
    }

    async fn walk_witness_parents(
        &self,
        volume: &VolumeName,
        mut parent: Option<GrainId>,
        before_seq: u64,
        (base, base_seq): (GrainId, u64),
        mut visit: impl FnMut(u64, GrainId),
    ) -> Result<(), CoordinationError> {
        for seq in (base_seq..before_seq).rev() {
            let id = parent.ok_or_else(witness_ancestry)?;
            let bytes = self
                .transport
                .probe_root_once(volume.as_str(), seq)
                .await
                .map_err(|error| CoordinationError::Recovery(error.into()))?
                .ok_or_else(witness_ancestry)?;
            let doc = root::check_link(parent, &bytes, volume.as_str(), seq)
                .map_err(|_| witness_ancestry())?;
            if seq > base_seq {
                visit(seq, id);
            } else if id != base {
                return Err(CoordinationError::Refused("WritableRecoveryRequired"));
            }
            parent = doc.parent;
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "authenticated recovery loading and its one merge stay in protocol order"
    )]
    async fn merge(
        &mut self,
        frozen: &FrozenIntent,
        parent: Option<GrainId>,
        seq: u64,
    ) -> Result<GrainId, RecoveryError> {
        let volume = self.store.snapshot().volume.clone();
        let transport = self.transport;
        let prepared = root::decode_root(&frozen.initial_root)
            .map_err(|_| RecoveryError::Invalid("frozen root"))?;
        if (prepared.parent, prepared.seq) == (parent, seq) {
            return Ok(prepared.manifest_root);
        }
        let (Some(own_parent), Some(parent_seq)) = (prepared.parent, prepared.seq.checked_sub(1))
        else {
            return Err(RecoveryError::Invalid("parentless prepared root"));
        };
        let (Some(head_id), Some(head_seq)) = (parent, seq.checked_sub(1)) else {
            return Err(RecoveryError::Invalid("rebase onto an empty volume"));
        };
        let prepared_state = publish::state_from_head(
            transport,
            &volume,
            prepared.seq,
            &frozen.initial_root,
            self.keys,
        )
        .await?;
        let grains =
            preparation::load_structure(transport, self, &prepared_state, prepared.manifest_root)
                .await?;
        let (base_bytes, base_state) = self.root_at(&volume, parent_seq, own_parent).await?;
        let base = root::decode_root(&base_bytes)
            .map_err(|_| RecoveryError::RemoteIntegrity("recovery root"))?;
        preparation::load_structure(transport, self, &base_state, base.manifest_root).await?;
        let workspace = self.store.construction_workspace_bytes;
        preparation::stage_novel(
            transport,
            self,
            &prepared_state,
            &base_state.known,
            &grains,
            workspace,
        )
        .await?;
        let (head_bytes, head_state) = self.root_at(&volume, head_seq, head_id).await?;
        let head_doc = root::decode_root(&head_bytes)
            .map_err(|_| RecoveryError::RemoteIntegrity("recovery root"))?;
        let head_manifest = head_doc.manifest_root;
        preparation::load_structure(transport, self, &head_state, head_manifest).await?;
        // A newer ancestor carrying P's exact path content witnesses a later
        // deletion when head omits it. Verify every intervening link, including
        // the final link to P's own parent, before using those manifests.
        let mut ancestors = Vec::new();
        let mut previous = head_doc.parent;
        for ancestor_seq in (prepared.seq..head_seq).rev() {
            let id = previous.ok_or(RecoveryError::RemoteIntegrity("recovery ancestry"))?;
            let (bytes, state) = self.root_at(&volume, ancestor_seq, id).await?;
            let doc = root::decode_root(&bytes)
                .map_err(|_| RecoveryError::RemoteIntegrity("recovery ancestor"))?;
            preparation::load_structure(transport, self, &state, doc.manifest_root).await?;
            ancestors.push(doc.manifest_root);
            previous = doc.parent;
        }
        if previous != Some(own_parent) {
            return Err(RecoveryError::RemoteIntegrity("recovery ancestry"));
        }
        let head = sync::VerifiedBase::attach_validated(
            head_bytes,
            volume.as_str(),
            self.keys,
            self.store.recovery_store(),
            head_state,
        )
        .map_err(|_| RecoveryError::RemoteIntegrity("recovery head"))?;
        let store = self.store.recovery_store();
        let entries = crate::writable_store::capture::overlay_base_entries(
            store,
            prepared.manifest_root,
            &|_, _| 0,
            &mut |_, _| Ok(()),
            &|| CoordinationError::Refused("RecoveryManifest"),
        )
        .map_err(|_| RecoveryError::Invalid("prepared manifest entries"))?;
        let entries =
            sync::rebase::preserve_recovered_deletions(&entries, head_manifest, &ancestors, store)
                .map_err(|_| RecoveryError::Invalid("recovered deletion manifests"))?;
        // The prepared root is diffed only against its own parent: the head
        // as a base would read every change it made as P's to revert.
        let operation = &mut self.conflict_operation;
        let conflict_secure = &mut self.conflict_secure;
        let merged = sync::rebase::merge_reporting_conflicts(
            base.manifest_root,
            &entries,
            &head,
            store,
            |path| {
                crate::observe::recover(crate::observe::RecoverEvent::Conflict);
                if operation.is_none()
                    && let Some(secure) = conflict_secure
                    && let Ok(secure) = secure.get_mut()
                {
                    *operation = crate::CorrelationId::draw(&mut **secure).ok();
                }
                if let Some(operation) = *operation {
                    let path = crate::local_report::namespace_path(path);
                    if let Ok(status) = crate::LocalConflictStatus::new(&path, operation) {
                        crate::LocalReport::conflict(status).emit();
                    }
                }
                Ok(())
            },
        )
        .map_err(|error| match error {
            sync::rebase::RebaseError::Conflict(conflict) => {
                RecoveryError::Journal(PublicationStoreError {
                    path: "journal".into(),
                    kind: PublicationStoreErrorKind::Conflict,
                    reason: conflict.to_string(),
                })
            }
            sync::rebase::RebaseError::InvalidManifest => RecoveryError::Invalid("rebase manifest"),
        })?;
        let payloads = &self.objects.payloads;
        let (root, nodes) = sync::entries_tree(&merged, store, |payload| {
            payloads
                .get(&payload)
                .cloned()
                .ok_or(crate::PublishError::BadPlan)
        })?;
        for (id, bytes) in nodes {
            if GrainId::of(&bytes) != id {
                return Err(RecoveryError::Invalid("merged node hash"));
            }
            self.put_recovered(&id, &bytes)?;
            self.objects.verified.insert(id, bytes.len());
        }
        Ok(root)
    }
}

fn witness_ancestry() -> CoordinationError {
    CoordinationError::Recovery(RecoveryError::RemoteIntegrity("recovery witness ancestry"))
}

impl<P: OverlayIo + Send + Sync, T: Sync> GrainSource for RecoveryJournal<'_, P, T> {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        GrainSource::get(self.store.recovery_store(), id)
    }
    fn has(&self, id: &GrainId) -> bool {
        GrainSource::has(self.store.recovery_store(), id)
    }
}

impl<P: OverlayIo + Send + Sync, T: AuthorityTransport + Sync> PublicationJournal
    for RecoveryJournal<'_, P, T>
{
    fn load(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        self.store.check_recovery_owner().map_err(owner_error)?;
        self.store
            .publication_transaction(|store| store.load(scope, volume))
            .map_err(owner_error)
    }
    fn begin(&mut self, record: &Submission) -> Result<(), PublicationStoreError> {
        self.store.check_recovery_owner().map_err(owner_error)?;
        self.store
            .publication_transaction(|store| store.begin(record))
            .map_err(owner_error)
    }
    async fn rebase_manifest(
        &mut self,
        frozen: &FrozenIntent,
        parent: Option<GrainId>,
        seq: u64,
    ) -> Result<GrainId, PublicationStoreError> {
        self.merge(frozen, parent, seq).await.map_err(journal_error)
    }
    async fn replace(
        &mut self,
        generation: u64,
        record: &Submission,
    ) -> Result<(), PublicationStoreError> {
        self.store.check_recovery_owner().map_err(owner_error)?;
        self.store
            .publication_transaction(|store| store.replace(generation, record))
            .map_err(owner_error)
    }
    fn recovered(&mut self) -> Option<&mut RecoveredObjects> {
        Some(&mut self.objects)
    }
    fn put_recovered(&mut self, id: &GrainId, bytes: &[u8]) -> Result<(), PublicationStoreError> {
        if matches!(
            self.store.recovery_store().get(id),
            Err(crate::StoreError::Corrupt { .. })
        ) {
            return Err(PublicationStoreError {
                path: "objects".into(),
                kind: PublicationStoreErrorKind::Corrupt,
                reason: format!(
                    "RecoveryLocalObjectCorrupt: {id}; preserve the store and quarantine the corrupt object before retrying"
                ),
            });
        }
        self.store
            .recovery_store()
            .put(id, bytes)
            .map(|_| ())
            .map_err(|error| PublicationStoreError {
                path: "objects".into(),
                kind: PublicationStoreErrorKind::Io,
                reason: error.to_string(),
            })
    }
}
