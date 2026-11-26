// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Volatile immutable range references. Sealing reads no file contents; a writer
//! preserves unread dirty buffers before mutation. Immutable base reads and all
//! materialization callbacks belong outside the local transaction.

use super::{
    BUFFER, CaptureToken, NamespaceEffect, OverlayEntry, OverlayError, OverlayIo, OverlayKind,
    OverlayStore, OwnershipStatus, Store, codec, usize_bound,
};
use granary_core::hash::GrainId;
use granary_core::overlay_journal::{JournalHeader, Record};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// File handles select a stage identity, so detached open files remain usable.
/// Clean files and directories select their stable namespace identity. The root
/// directory uses `Directory(None)`.
#[derive(Debug, Clone, Copy)]
pub enum SyncTarget {
    Stage(u64),
    File(u64),
    Directory(Option<u64>),
    Tree,
}

/// A bounded piece of a captured file. Resolve immutable content outside the
/// overlay transaction; never read newer staging for an immutable piece.
#[derive(Debug, Clone)]
pub enum CapturedPart {
    Immutable {
        content: GrainId,
        offset: u64,
        length: usize,
    },
    Dirty {
        bytes: Arc<Vec<u8>>,
        start: usize,
        length: usize,
    },
    Zero(usize),
}

/// Opaque authenticated read plan returned by a short overlay transaction.
/// Resolve its immutable parts outside the mediator; callers cannot substitute
/// fabricated dirty bytes when authenticating a payload.
#[derive(Debug)]
pub struct CapturedRange {
    pub(crate) boundary: u64,
    pub(crate) index: usize,
    pub(crate) offset: u64,
    pub(crate) parts: Vec<CapturedPart>,
}

/// Captured metadata and byte-version references for one file. Clone retains
/// the same capability; completion is explicit and succeeds only once.
#[derive(Debug, Clone)]
pub struct CapturedFile {
    boundary: u64,
    token: Option<CaptureToken>,
    entry: Option<OverlayEntry>,
    size: u64,
    base: Option<GrainId>,
    base_size: u64,
    extents: BTreeMap<u64, Record>,
    zeros: Vec<(u64, u64)>,
    blocks: BTreeMap<u64, VersionKey>,
    dirty: Vec<(u64, u64)>,
    checkpoint: Option<(GrainId, u64)>,
    // A checkpoint neither its entry nor a journal `file-synced` holds: bytes
    // to reuse, not an acknowledgement.
    unacknowledged: bool,
    rechunk_fallback_counted: Arc<std::sync::atomic::AtomicBool>,
}
impl CapturedFile {
    pub(crate) fn record_rechunk_fallback(&self, metrics: &crate::ClientMetrics) {
        if !self
            .rechunk_fallback_counted
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            metrics.record_rechunk_fallback();
        }
    }
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }
    #[must_use]
    pub fn entry(&self) -> Option<&OverlayEntry> {
        self.entry.as_ref()
    }
    #[must_use]
    /// Identity/floor capability, without a whole-file byte copy. A consumer
    /// obtains the immutable byte version through `captured_parts`.
    pub fn capture_token(&self) -> Option<&CaptureToken> {
        self.token.as_ref()
    }
    /// Last acknowledged payload and size, or the immutable base before the
    /// first sync. Re-chunking authenticates its grain list separately.
    #[must_use]
    pub fn checkpoint(&self) -> Option<(GrainId, u64)> {
        self.checkpoint
    }
    #[must_use]
    pub fn needs_mark(&self) -> bool {
        self.token.is_some()
            && (self.checkpoint.is_none() || self.unacknowledged || !self.dirty.is_empty())
    }
    /// Dirty intervals include explicit zeros and length changes since the
    /// last acknowledged capture, retaining writes admitted after its seal.
    /// They describe this sealed version, never the live namespace.
    #[must_use]
    pub fn dirty_intervals(&self) -> Vec<(u64, u64)> {
        self.dirty.clone()
    }
}

impl CapturedFile {
    fn register_versions(
        &mut self,
        stage_id: u64,
        token_id: u64,
        versions: &mut Versions,
    ) -> Result<(), OverlayError> {
        for record in self.extents.values() {
            let Record::WriteExtent { offset, length, .. } = record else {
                continue;
            };
            let end = offset
                .checked_add(*length)
                .ok_or_else(|| OverlayError::refused("capture extent overflow"))?
                .min(self.size);
            let mut start = offset / BUFFER as u64 * BUFFER as u64;
            while start < end {
                let key = VersionKey {
                    stage: stage_id,
                    offset: start,
                    epoch: versions
                        .current
                        .get(&(stage_id, start))
                        .copied()
                        .unwrap_or(0),
                    length: (self.size - start).min(BUFFER as u64),
                };
                versions
                    .buffers
                    .entry(key)
                    .or_insert_with(|| Version {
                        users: BTreeSet::new(),
                        bytes: None,
                    })
                    .users
                    .insert(token_id);
                self.blocks.insert(start, key);
                start += BUFFER as u64;
            }
        }
        Ok(())
    }
}

enum Selection {
    Stage(u64),
    Clean(OverlayEntry),
}
struct SnapshotPlan {
    id: u64,
    incarnation: u64,
    through_seq: u64,
    next_capture: u64,
    versions: Versions,
}

/// One transaction-scoped namespace/file seal. Its cursor is the covering
/// boundary for roots constructed from this version. A directory seal selects
/// no file bytes; a tree seal selects all named staged files.
#[derive(Debug, Clone)]
pub struct SyncBoundary {
    id: u64,
    pub(super) header: JournalHeader,
    pub(super) instance: [u8; 16],
    pub(super) incarnation: u64,
    pub(super) through_seq: u64,
    entries: Vec<OverlayEntry>,
    files: Vec<CapturedFile>,
    pub(super) scope: String,
    pub(super) volume: granary_core::root::VolumeName,
    base_entries: Vec<OverlayEntry>,
    effects: Vec<Arc<NamespaceEffect>>,
    checkpoints: Vec<super::DurableFile>,
    complete_tree: bool,
}
impl SyncBoundary {
    /// Whether projection includes every frozen name without dependent exclusion.
    /// Only the drained `CommitBoundary` lane grants this capability; scoped Tree
    /// targets and replayed projected boundaries keep ordinary projection.
    pub(crate) fn complete_tree(&self) -> bool {
        self.complete_tree
    }
    /// Grant complete projection to the seal owned by a `CommitBoundary` lane.
    pub(crate) fn for_complete_commit(mut self) -> Self {
        self.complete_tree = true;
        self
    }
    #[must_use]
    pub fn volume(&self) -> &granary_core::root::VolumeName {
        &self.volume
    }
    pub(crate) fn context_id(&self) -> GrainId {
        GrainId::of(
            &[
                self.scope.as_bytes(),
                &[0],
                self.volume.as_str().as_bytes(),
                &[0],
                &self.instance,
                &self.header.writer,
                &self.header.base_root.to_bytes(),
                &self.header.base_seq.to_be_bytes(),
                &self.incarnation.to_be_bytes(),
            ]
            .concat(),
        )
    }
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
    #[must_use]
    pub fn through_seq(&self) -> u64 {
        self.through_seq
    }
    /// The commit context this seal fixed, its header, instance, incarnation
    /// and cursor, with `entries` as its candidate's namespace: a projected
    /// boundary binds the seal itself, not a second snapshot.
    pub(crate) fn commit_capture(&self, entries: Vec<OverlayEntry>) -> super::BoundaryCapture {
        super::BoundaryCapture {
            header: self.header,
            instance: self.instance,
            incarnation: self.incarnation,
            through_seq: self.through_seq,
            entries,
        }
    }
    #[must_use]
    pub fn base(&self) -> (GrainId, u64) {
        (self.header.base_root, self.header.base_seq)
    }
    #[must_use]
    pub fn entries(&self) -> &[OverlayEntry] {
        &self.entries
    }
    #[must_use]
    pub fn files(&self) -> &[CapturedFile] {
        &self.files
    }
    #[must_use]
    pub fn base_entries(&self) -> &[OverlayEntry] {
        &self.base_entries
    }
    #[must_use]
    pub fn effects(&self) -> &[Arc<NamespaceEffect>] {
        &self.effects
    }
    #[must_use]
    pub fn incarnation(&self) -> u64 {
        self.incarnation
    }
    pub(super) fn checkpoints(&self) -> &[super::DurableFile] {
        &self.checkpoints
    }
}

/// An overlay's identity for a replayed seal, copied so the replay itself
/// needs no lock.
#[derive(Debug, Clone)]
pub(super) struct ReplayContext {
    header: JournalHeader,
    instance: [u8; 16],
    incarnation: u64,
    scope: String,
    volume: granary_core::root::VolumeName,
}
impl ReplayContext {
    pub(super) fn retained(
        header: JournalHeader,
        config: &super::OverlayConfig,
    ) -> Result<Self, OverlayError> {
        Ok(Self {
            header,
            instance: config.instance,
            incarnation: 0,
            scope: config
                .scope
                .digest()
                .map_err(|_| OverlayError::refused("scope"))?,
            volume: config.volume.clone(),
        })
    }

    /// The sealed view of the journal prefix through `through_seq`, rebuilt by
    /// replay so a recovered candidate projects exactly as its seal did. It
    /// captures no file and pins no bytes; its id 0 is never a live capture's,
    /// so it owns no charge and is never released.
    pub(super) fn boundary(
        &self,
        through_seq: u64,
        namespace: &super::Namespace,
        history: super::provenance::History,
    ) -> SyncBoundary {
        SyncBoundary {
            id: 0,
            complete_tree: false,
            header: self.header,
            instance: self.instance,
            incarnation: self.incarnation,
            through_seq,
            entries: namespace.entries.values().cloned().collect(),
            files: Vec::new(),
            scope: self.scope.clone(),
            volume: self.volume.clone(),
            base_entries: history.base,
            effects: history.records,
            checkpoints: history.checkpoints.into_values().collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct VersionKey {
    stage: u64,
    offset: u64,
    epoch: u64,
    length: u64,
}
#[derive(Debug, Clone)]
struct Version {
    users: BTreeSet<u64>,
    bytes: Option<Arc<Vec<u8>>>,
}
#[derive(Debug, Clone, Default)]
pub(super) struct Versions {
    current: BTreeMap<(u64, u64), u64>,
    buffers: BTreeMap<VersionKey, Version>,
    lazy: BTreeSet<u64>,
    pub(super) lost: BTreeSet<u64>,
    boundaries: BTreeMap<u64, u64>,
    graphs: BTreeMap<u64, u64>,
    engine_graph: u64,
    flushed: BTreeSet<u64>,
}
impl Versions {
    pub(super) fn journal_reserve(&self) -> u64 {
        self.boundaries
            .values()
            .fold(0u64, |total, bytes| total.saturating_add(bytes / 2))
    }
    pub(super) fn release_file(&mut self, id: u64) {
        self.lazy.remove(&id);
        self.lost.remove(&id);
        self.buffers.retain(|_, version| {
            version.users.remove(&id);
            !version.users.is_empty()
        });
    }
    pub(super) fn discard_stage_versions(
        &mut self,
        stages: &BTreeMap<u64, super::state::Stage>,
        discarded: &BTreeSet<u64>,
    ) {
        if discarded.is_empty() {
            return;
        }
        self.lost.extend(
            discarded
                .iter()
                .filter_map(|id| stages.get(id))
                .flat_map(|stage| stage.captures.keys().copied()),
        );
        self.current
            .retain(|(stage, _), _| !discarded.contains(stage));
        self.buffers
            .retain(|key, _| !discarded.contains(&key.stage));
    }
    fn charge(&self) -> Result<u64, OverlayError> {
        self.buffers
            .keys()
            .map(|key| key.length)
            .chain(self.boundaries.values().copied())
            .chain(self.graphs.values().copied())
            .chain(std::iter::once(self.engine_graph))
            .try_fold(0u64, |total, length| {
                total.checked_add(length).ok_or_else(OverlayError::no_space)
            })
    }
}

/// What a shutdown still owes the authority.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ShutdownWork {
    /// Each stage a tree sync selects, in stage order, with its dirty bytes.
    pub(crate) stages: Vec<(u64, u64)>,
    /// The namespace records since the base.
    pub(crate) namespace_records: u64,
    /// The records since the base that are not bookkeeping.
    pub(crate) operations: u64,
}

impl<P: OverlayIo> OverlayStore<P> {
    pub(crate) fn sync_base(&self) -> Result<(GrainId, u64), OverlayError> {
        let journal = self.journal.lock().map_err(Self::lock_error)?;
        Ok((journal.header.base_root, journal.header.base_seq))
    }
    pub(crate) fn reserve_engine_graph(&mut self, bytes: u64) -> Result<(), OverlayError> {
        let previous = self.versions.engine_graph;
        let next = previous
            .checked_add(bytes)
            .ok_or_else(OverlayError::no_space)?;
        let length = self.journal.lock().map_err(Self::lock_error)?.length;
        if let Err(error) = self.capacity(bytes, length, self.namespace.stages.len()) {
            return Err(self.name_capacity_error(error));
        }
        self.versions.engine_graph = next;
        self.summary.captured_bytes = self.capture_charge()?;
        Ok(())
    }

    pub(crate) fn release_engine_graph(&mut self, bytes: u64) -> Result<(), OverlayError> {
        self.versions.engine_graph = self
            .versions
            .engine_graph
            .checked_sub(bytes)
            .ok_or_else(|| OverlayError::refused("engine graph underflow"))?;
        self.summary.captured_bytes = self.capture_charge()?;
        Ok(())
    }

    fn sync_graph_charge(&self) -> Result<u64, OverlayError> {
        let journal = self.journal.lock().map_err(Self::lock_error)?;
        let mut charge = 512u64;
        let mut add = |bytes: u64| -> Result<(), OverlayError> {
            charge = charge
                .checked_add(bytes)
                .ok_or_else(OverlayError::no_space)?;
            Ok(())
        };
        for entry in self.namespace.entries.values().chain(&self.history.base) {
            add(256)?;
            for name in &entry.path {
                add(64 + name.as_bytes().len() as u64)?;
            }
            if let OverlayKind::Symlink { target } = &entry.kind {
                add(target.as_bytes().len() as u64)?;
            }
        }
        for stage in self.namespace.stages.values() {
            add(512 + (stage.zeros.len() as u64).saturating_mul(32))?;
            for record in stage.extents.values() {
                add(256
                    + codec::encode_record(&journal.header, 1, record)
                        .map_err(|_| OverlayError::refused("graph extent encoding"))?
                        .len() as u64)?;
                if let Record::WriteExtent { length, .. } = record {
                    add((length / BUFFER as u64 + 2).saturating_mul(256))?;
                }
            }
        }
        add((self.history.checkpoints.len() as u64).saturating_mul(128))?;
        for effect in &self.history.records {
            add(256
                + codec::encode_record(&journal.header, effect.seq, &effect.record)
                    .map_err(|_| OverlayError::refused("graph effect encoding"))?
                    .len() as u64)?;
            add(
                (effect.parents.len() as u64 + effect.dependencies.len() as u64).saturating_mul(64),
            )?;
        }
        Ok(charge)
    }

    fn plan_sync_snapshot(
        &self,
        target: SyncTarget,
        incarnation: u64,
        through_seq: u64,
    ) -> Result<(Vec<OverlayEntry>, SnapshotPlan, Vec<CapturedFile>), OverlayError> {
        let entries: Vec<_> = self.namespace.entries.values().cloned().collect();
        let selected = self.select_sync_target(target, &entries)?;
        let id = self.next_capture;
        let mut plan = SnapshotPlan {
            id,
            incarnation,
            through_seq,
            next_capture: id
                .checked_add(1)
                .ok_or_else(|| OverlayError::refused("capture exhaustion"))?,
            versions: self.versions.clone(),
        };
        let completion = 348u64
            .checked_add(
                (selected.len() as u64)
                    .checked_mul(244)
                    .ok_or_else(OverlayError::no_space)?,
            )
            .ok_or_else(OverlayError::no_space)?;
        plan.versions.boundaries.insert(id, completion);
        // Account retained namespace, journal annotations, interval/index nodes
        // and token metadata, in addition to pinned byte versions. Deliberately
        // conservative per-boundary charging also covers shared graph nodes.
        let graph = self.sync_graph_charge()?;
        plan.versions.graphs.insert(id, graph);
        let files = selected
            .iter()
            .map(|selection| self.plan_captured_file(selection, &mut plan))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((entries, plan, files))
    }

    pub(super) fn projected_tree_seal_charge(&self) -> Result<u64, OverlayError> {
        let (incarnation, through_seq) = {
            let journal = self.journal.lock().map_err(Self::lock_error)?;
            (journal.incarnation, journal.state.next_seq() - 1)
        };
        let (_, plan, _) = self.plan_sync_snapshot(SyncTarget::Tree, incarnation, through_seq)?;
        let captured = plan
            .versions
            .charge()?
            .saturating_sub(self.versions.charge()?);
        let reserved = plan
            .versions
            .journal_reserve()
            .saturating_sub(self.versions.journal_reserve());
        captured
            .checked_add(reserved)
            .and_then(|bytes| bytes.checked_add(self.commit_graph_charge().ok()?))
            .ok_or_else(OverlayError::no_space)
    }

    pub(super) fn checkpoint_dirty(
        &self,
        stage_id: u64,
        stage: &super::state::Stage,
    ) -> Result<Vec<(u64, u64)>, OverlayError> {
        let checkpoint = stage.checkpoint();
        let (_, checkpoint_size) = checkpoint;
        let limit = stage.size.max(checkpoint_size);
        let clip = |ranges: Vec<(u64, u64)>| {
            merge(
                ranges
                    .into_iter()
                    .map(|(start, end)| (start.min(limit), end.min(limit)))
                    .filter(|(start, end)| start < end)
                    .collect(),
            )
        };
        let Some(boundary) = stage.checkpoint_boundary else {
            return replayed_dirty(stage);
        };
        let mut size = stage
            .mark
            .ok_or_else(|| OverlayError::refused("checkpoint mark missing"))?
            .synced_size;
        let mut ranges = Vec::new();
        // Journal fragments authenticate unchanged bytes after an overlapping
        // write. They remain in strict coverage provenance, but do not expand
        // the logical edit range used by the cutter. Reopen is conservative.
        for effect in self
            .history
            .records
            .iter()
            .filter(|effect| effect.seq > boundary && effect.content_change)
        {
            match effect.record {
                Record::WriteExtent {
                    stage_id: id,
                    offset,
                    length,
                    ..
                } if id == stage_id => {
                    let end = offset
                        .checked_add(length)
                        .ok_or_else(|| OverlayError::refused("dirty interval overflow"))?;
                    ranges.push((offset.min(size), end));
                    size = size.max(end);
                }
                Record::Truncate {
                    stage_id: id,
                    new_size,
                } if id == stage_id => {
                    ranges.push((size.min(new_size), size.max(new_size)));
                    size = new_size;
                }
                Record::StageRollback {
                    stage_id: id,
                    anchor,
                    ..
                } if id == stage_id => {
                    let restored = anchor.map_or((None, 0), |a| (Some(a.content), a.size));
                    if restored == checkpoint {
                        ranges.clear();
                    } else {
                        ranges.push((0, size.max(restored.1)));
                    }
                    size = restored.1;
                }
                _ => {}
            }
        }
        Ok(clip(ranges))
    }

    /// Reserve owned payload/proof graphs before validating or retaining them.
    /// A capacity refusal changes neither the boundary nor overlay readiness.
    /// # Errors
    /// Stale context, overflow or declared-cap exhaustion.
    pub(crate) fn reserve_sync_graph(
        &mut self,
        boundary: &SyncBoundary,
        extra: u64,
    ) -> Result<(), OverlayError> {
        self.validate_sync_boundary(boundary)?;
        let previous = *self
            .versions
            .graphs
            .get(&boundary.id)
            .ok_or_else(|| OverlayError::refused("sync graph missing"))?;
        let length = self.journal.lock().map_err(Self::lock_error)?.length;
        let next = previous
            .checked_add(extra)
            .ok_or_else(OverlayError::no_space)?;
        if let Err(error) = self.capacity(extra, length, self.namespace.stages.len()) {
            return Err(self.name_capacity_error(error));
        }
        self.versions.graphs.insert(boundary.id, next);
        self.summary.captured_bytes = self.capture_charge()?;
        Ok(())
    }

    pub(crate) fn release_sync_graph(
        &mut self,
        boundary: &SyncBoundary,
        bytes: u64,
    ) -> Result<(), OverlayError> {
        self.validate_sync_boundary(boundary)?;
        let charge = self
            .versions
            .graphs
            .get_mut(&boundary.id)
            .ok_or_else(|| OverlayError::refused("sync graph missing"))?;
        *charge = charge
            .checked_sub(bytes)
            .ok_or_else(|| OverlayError::refused("sync graph underflow"))?;
        self.summary.captured_bytes = self.capture_charge()?;
        Ok(())
    }

    pub(super) fn capture_charge(&self) -> Result<u64, OverlayError> {
        self.snapshots
            .iter()
            .filter(|(id, _)| !self.versions.lazy.contains(id))
            .try_fold(self.versions.charge()?, |total, (_, size)| {
                total.checked_add(*size).ok_or_else(OverlayError::no_space)
            })
    }

    /// Seal namespace, cursor, lengths and dirty byte versions together. This
    /// performs no staging content read and never invokes a content provider.
    /// # Errors
    /// Refuses invalid targets/context or cap exhaustion before admitting any
    /// token. A capacity refusal is non-poisoning and leaves all writers' bytes
    /// unchanged.
    pub fn seal_sync(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        target: SyncTarget,
    ) -> Result<SyncBoundary, OverlayError> {
        self.capacity_exhaustion = None;
        self.ready(store, ownership)?;
        let (header, incarnation, through_seq, length, completion_reserve) = {
            let journal = self.journal.lock().map_err(Self::lock_error)?;
            (
                journal.header,
                journal.incarnation,
                journal.state.next_seq() - 1,
                journal.length,
                journal.completion.clone(),
            )
        };
        let (entries, plan, files) = self.plan_sync_snapshot(target, incarnation, through_seq)?;
        let id = plan.id;
        let baseline = self.measure(length, self.namespace.stages.len(), &completion_reserve)?;
        let previous = std::mem::replace(&mut self.versions, plan.versions);
        if let Err(error) = self.capacity(0, length, self.namespace.stages.len()) {
            self.rebase_capacity_exhaustion(baseline);
            self.versions = previous;
            return Err(self.name_capacity_error(error));
        }
        for file in &files {
            if let Some(token) = &file.token {
                self.namespace
                    .stages
                    .get_mut(&token.stage_id)
                    .ok_or_else(|| OverlayError::refused("capture stage"))?
                    .captures
                    .insert(token.id, token.size);
                self.snapshots.insert(token.id, token.size);
            }
        }
        self.next_capture = plan.next_capture;
        self.summary.captured_bytes = self.capture_charge()?;
        Ok(SyncBoundary {
            id,
            complete_tree: false,
            header,
            instance: self.config.instance,
            incarnation,
            through_seq,
            entries,
            files,
            scope: self.scope.clone(),
            volume: self.config.volume.clone(),
            base_entries: self.history.base.clone(),
            effects: self.history.records.clone(),
            checkpoints: self.history.checkpoints.values().cloned().collect(),
        })
    }

    /// What a replayed seal takes from this overlay: its journal header and
    /// incarnation, instance, scope and volume.
    pub(super) fn replay_context(&self) -> Result<ReplayContext, OverlayError> {
        let journal = self.journal.lock().map_err(Self::lock_error)?;
        Ok(ReplayContext {
            header: journal.header,
            instance: self.config.instance,
            incarnation: journal.incarnation,
            scope: self.scope.clone(),
            volume: self.config.volume.clone(),
        })
    }

    fn select_sync_target(
        &self,
        target: SyncTarget,
        entries: &[OverlayEntry],
    ) -> Result<Vec<Selection>, OverlayError> {
        Ok(match target {
            SyncTarget::Stage(id) => {
                self.accessible_stage(id)?;
                vec![Selection::Stage(id)]
            }
            SyncTarget::File(inode) => {
                let entry = entries
                    .iter()
                    .find(|entry| {
                        entry.inode == inode && matches!(entry.kind, OverlayKind::File { .. })
                    })
                    .ok_or_else(|| OverlayError::refused("sync file identity"))?;
                vec![
                    entry
                        .stage_id
                        .map_or_else(|| Selection::Clean(entry.clone()), Selection::Stage),
                ]
            }
            SyncTarget::Directory(inode) => {
                if inode.is_some_and(|inode| {
                    !entries.iter().any(|entry| {
                        entry.inode == inode && matches!(entry.kind, OverlayKind::Directory)
                    })
                }) {
                    return Err(OverlayError::refused("sync directory identity"));
                }
                Vec::new()
            }
            SyncTarget::Tree => {
                let mut selected = Vec::new();
                for entry in entries {
                    if let Some(id) = entry.stage_id {
                        let stage = self.accessible_stage(id)?;
                        if stage.mark.is_none()
                            || stage.checkpoint_boundary.is_none()
                            || !self.checkpoint_dirty(id, stage)?.is_empty()
                        {
                            selected.push(Selection::Stage(id));
                        }
                    }
                }
                selected
            }
        })
    }

    /// What a shutdown still owes, in one read of memory: each stage a tree
    /// sync selects, in stage order, with the sum of its dirty spans; the
    /// namespace records since the base; and every record since the base
    /// that is not bookkeeping.
    /// # Errors
    /// An inaccessible stage or an overflowing dirty interval.
    pub(crate) fn shutdown_work(&self) -> Result<ShutdownWork, OverlayError> {
        let mut stages = Vec::new();
        for id in self
            .namespace
            .entries
            .values()
            .filter_map(|entry| entry.stage_id)
        {
            // The tree predicate, with the dirty spans computed once.
            let stage = self.accessible_stage(id)?;
            let dirty = self.checkpoint_dirty(id, stage)?;
            if stage.mark.is_none() || stage.checkpoint_boundary.is_none() || !dirty.is_empty() {
                let bytes = dirty.iter().fold(0u64, |total, (start, end)| {
                    total.saturating_add(end.saturating_sub(*start))
                });
                stages.push((id, bytes));
            }
        }
        stages.sort_unstable_by_key(|(id, _)| *id);
        let (mut namespace_records, mut operations) = (0u64, 0u64);
        for effect in &self.history.records {
            if matches!(
                effect.record,
                Record::Create { .. }
                    | Record::Move { .. }
                    | Record::Replace { .. }
                    | Record::Delete { .. }
                    | Record::SetattrExec { .. }
                    | Record::RecreateFile { .. }
            ) {
                namespace_records = namespace_records.saturating_add(1);
            }
            if !super::replacement::clean_record(&effect.record) {
                operations = operations.saturating_add(1);
            }
        }
        Ok(ShutdownWork {
            stages,
            namespace_records,
            operations,
        })
    }

    fn plan_captured_file(
        &self,
        selection: &Selection,
        plan: &mut SnapshotPlan,
    ) -> Result<CapturedFile, OverlayError> {
        let (entry, stage) = if let Selection::Stage(stage_id) = selection {
            let stage = self.accessible_stage(*stage_id)?.clone();
            let entry = stage
                .path
                .as_ref()
                .and_then(|path| self.namespace.entries.get(path))
                .cloned();
            (entry, Some(stage))
        } else {
            let Selection::Clean(entry) = selection else {
                return Err(OverlayError::refused("clean selection"));
            };
            (Some(entry.clone()), None)
        };
        let mut file = CapturedFile {
            boundary: plan.id,
            token: None,
            entry,
            size: 0,
            base: None,
            base_size: 0,
            extents: BTreeMap::new(),
            zeros: Vec::new(),
            blocks: BTreeMap::new(),
            dirty: Vec::new(),
            checkpoint: None,
            unacknowledged: false,
            rechunk_fallback_counted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        if let Some(stage) = stage {
            let Selection::Stage(stage_id) = selection else {
                return Err(OverlayError::refused("stage selection"));
            };
            let stage_id = *stage_id;
            let token_id = plan.next_capture;
            plan.next_capture = plan
                .next_capture
                .checked_add(1)
                .ok_or_else(|| OverlayError::refused("capture exhaustion"))?;
            file.size = stage.size;
            let (content, size) = stage.checkpoint();
            (file.base, file.base_size) = (content, size);
            file.checkpoint = content.map(|content| (content, size));
            file.dirty = self.checkpoint_dirty(stage_id, &stage)?;
            file.unacknowledged = unacknowledged(&file, self.history.checkpoints.get(&stage.inode));
            file.extents = stage.extents;
            file.zeros = stage.zeros;
            if let Some(mark) = stage.mark
                && stage.checkpoint_boundary.is_some()
            {
                file.base = Some(mark.content);
                file.base_size = mark.synced_size;
                // Preserved staging fragments still authenticate the live
                // overlay. Unchanged captured bytes come from the immutable
                // acknowledged payload, so only later edits pin byte versions.
                file.extents.retain(|_, record| match record {
                    Record::WriteExtent { offset, length, .. } => file
                        .dirty
                        .iter()
                        .any(|(a, b)| *a < *offset + *length && *offset < *b),
                    _ => false,
                });
            }
            file.token = Some(CaptureToken {
                id: token_id,
                instance: self.config.instance,
                incarnation: plan.incarnation,
                scope: self.scope.clone(),
                volume: self.config.volume.clone(),
                writer: self.writer.writer,
                at_capture: stage.path,
                stage_id,
                size: file.size,
                through_seq: plan.through_seq,
                chunks: Arc::default(),
            });
            plan.versions.lazy.insert(token_id);
            file.register_versions(stage_id, token_id, &mut plan.versions)?;
        } else {
            let entry = file
                .entry
                .as_ref()
                .ok_or_else(|| OverlayError::refused("clean file identity"))?;
            let OverlayKind::File {
                content: Some(content),
            } = entry.kind
            else {
                return Err(OverlayError::refused("clean file content"));
            };
            file.size = entry.size;
            file.base_size = entry.size;
            file.base = Some(content);
            file.checkpoint = Some((content, entry.size));
        }
        Ok(file)
    }

    pub(crate) fn validate_sync_boundary(
        &self,
        boundary: &SyncBoundary,
    ) -> Result<(), OverlayError> {
        self.validate_sync_owner(boundary)?;
        let journal = self.journal.lock().map_err(Self::lock_error)?;
        if boundary.header != journal.header || boundary.through_seq >= journal.state.next_seq() {
            return Err(OverlayError::refused("sync boundary context"));
        }
        Ok(())
    }

    pub(crate) fn validate_flushed_sync_boundary(
        &self,
        boundary: &SyncBoundary,
    ) -> Result<(), OverlayError> {
        self.validate_sync_captures(boundary)?;
        if !self.versions.flushed.contains(&boundary.id) {
            return Err(OverlayError::refused("sync boundary was not flushed"));
        }
        Ok(())
    }

    fn validate_sync_captures(&self, boundary: &SyncBoundary) -> Result<(), OverlayError> {
        for token in boundary.files.iter().filter_map(|file| file.token.as_ref()) {
            self.validate_capture(token)?;
        }
        self.validate_sync_boundary(boundary)
    }

    fn validate_sync_owner(&self, boundary: &SyncBoundary) -> Result<(), OverlayError> {
        let journal = self.journal.lock().map_err(Self::lock_error)?;
        if boundary.incarnation != journal.incarnation
            || boundary.scope != self.scope
            || boundary.volume != self.config.volume
            || boundary.instance != self.config.instance
            || boundary.header.writer != self.writer.writer
            || !self.versions.boundaries.contains_key(&boundary.id)
        {
            return Err(OverlayError::refused("sync boundary context"));
        }
        Ok(())
    }

    /// Copy at most one 65,536-byte logical buffer. Returned immutable reads
    /// must be resolved after dropping this transaction; no provider is called.
    /// # Errors
    /// Refuses stale context, misalignment, unreadable or corrupt staging.
    pub fn captured_parts(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        boundary: &SyncBoundary,
        file: &CapturedFile,
        offset: u64,
    ) -> Result<Vec<CapturedPart>, OverlayError> {
        self.ready(store, ownership)?;
        if file.boundary != boundary.id
            || !offset.is_multiple_of(BUFFER as u64)
            || offset >= file.size
        {
            return Err(OverlayError::refused("capture range context"));
        }
        if let Some(token) = &file.token {
            self.validate_capture(token)?;
        }
        self.validate_sync_boundary(boundary)?;
        let end = file.size.min(offset.saturating_add(BUFFER as u64));
        let buffer = file
            .blocks
            .get(&offset)
            .map(|key| self.load_version(*key))
            .transpose()?;
        let mut ranges = Vec::new();
        let dirty: Vec<_> = file
            .extents
            .values()
            .filter_map(|record| match record {
                Record::WriteExtent { offset, length, .. } => Some((*offset, offset + length)),
                _ => None,
            })
            .collect();
        let mut cuts = BTreeSet::from([offset, end]);
        for &(a, b) in dirty
            .iter()
            .chain(&file.zeros)
            .chain(std::iter::once(&(file.base_size, file.size)))
        {
            if a > offset && a < end {
                cuts.insert(a);
            }
            if b > offset && b < end {
                cuts.insert(b);
            }
        }
        let cuts: Vec<_> = cuts.into_iter().collect();
        for pair in cuts.windows(2) {
            let [a, b] = pair else {
                return Err(OverlayError::refused("capture partition"));
            };
            let length = usize_bound(b - a)?;
            if dirty.iter().any(|(start, end)| start <= a && b <= end) {
                let bytes = buffer
                    .as_ref()
                    .ok_or_else(|| OverlayError::refused("capture dirty version"))?;
                ranges.push(CapturedPart::Dirty {
                    bytes: Arc::clone(bytes),
                    start: usize_bound(a - offset)?,
                    length,
                });
            } else if file.zeros.iter().any(|(start, end)| start <= a && b <= end)
                || *a >= file.base_size
            {
                ranges.push(CapturedPart::Zero(length));
            } else if let Some(content) = file.base {
                ranges.push(CapturedPart::Immutable {
                    content,
                    offset: *a,
                    length,
                });
            } else {
                ranges.push(CapturedPart::Zero(length));
            }
        }
        Ok(ranges)
    }

    /// # Errors
    /// Invalid file/range, stale seal, custody or corrupt staging.
    pub fn captured_range(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        boundary: &SyncBoundary,
        index: usize,
        offset: u64,
    ) -> Result<CapturedRange, OverlayError> {
        let file = boundary
            .files
            .get(index)
            .ok_or_else(|| OverlayError::refused("capture file index"))?;
        let parts = self.captured_parts(store, ownership, boundary, file, offset)?;
        Ok(CapturedRange {
            boundary: boundary.id,
            index,
            offset,
            parts,
        })
    }

    fn load_version(&mut self, key: VersionKey) -> Result<Arc<Vec<u8>>, OverlayError> {
        let version = self
            .versions
            .buffers
            .get(&key)
            .ok_or_else(|| OverlayError::refused("capture version missing"))?;
        if let Some(bytes) = &version.bytes {
            return Ok(Arc::clone(bytes));
        }
        if self
            .versions
            .current
            .get(&(key.stage, key.offset))
            .copied()
            .unwrap_or(0)
            != key.epoch
        {
            self.poison();
            return Err(OverlayError::refused("capture version changed"));
        }
        self.header(key.stage)?;
        let extents: Vec<_> = self
            .accessible_stage(key.stage)?
            .extents
            .values()
            .filter(|record| match record {
                Record::WriteExtent { offset, length, .. } => {
                    *offset < key.offset + key.length && offset + length > key.offset
                }
                _ => false,
            })
            .cloned()
            .collect();
        // Authenticate the exact bytes copied, rather than verifying a read and
        // then re-reading attacker-writable staging. Each extent has a bounded
        // journal length; only its intersection enters the retained buffer.
        let mut bytes = vec![0; usize_bound(key.length)?];
        for extent in extents {
            let Record::WriteExtent {
                offset,
                length,
                check,
                ..
            } = extent
            else {
                continue;
            };
            let mut hasher = codec::ExtentHasher::new(key.stage, offset, length);
            let mut start = offset;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| OverlayError::refused("capture extent overflow"))?;
            while start < end {
                let n = usize_bound((end - start).min(BUFFER as u64))?;
                let fragment = self
                    .io
                    .read_at(&self.stage_path(key.stage), 160 + start, n)?;
                if fragment.len() != n {
                    self.poison();
                    return Err(OverlayError::refused("short capture extent"));
                }
                hasher.update(&fragment);
                let a = start.max(key.offset);
                let b = (start + n as u64).min(key.offset + key.length);
                if a < b {
                    let src = fragment
                        .get(usize_bound(a - start)?..usize_bound(b - start)?)
                        .ok_or_else(|| OverlayError::refused("capture verified range"))?;
                    bytes
                        .get_mut(usize_bound(a - key.offset)?..usize_bound(b - key.offset)?)
                        .ok_or_else(|| OverlayError::refused("capture buffer range"))?
                        .copy_from_slice(src);
                }
                start += n as u64;
            }
            if hasher.finalize() != check {
                self.poison();
                return Err(OverlayError::refused("capture extent mismatch"));
            }
        }
        let bytes = Arc::new(bytes);
        self.versions
            .buffers
            .get_mut(&key)
            .ok_or_else(|| OverlayError::refused("capture version missing"))?
            .bytes = Some(Arc::clone(&bytes));
        Ok(bytes)
    }

    pub(super) fn preserve_versions(
        &mut self,
        stage: u64,
        offset: u64,
        end: u64,
    ) -> Result<(), OverlayError> {
        let keys: Vec<_> = self
            .versions
            .buffers
            .keys()
            .filter(|key| {
                key.stage == stage && key.offset < end && key.offset + BUFFER as u64 > offset
            })
            .copied()
            .collect();
        for key in keys {
            self.load_version(key)?;
        }
        Ok(())
    }
    pub(super) fn invalidate_versions(
        &mut self,
        stage: u64,
        offset: u64,
        end: u64,
    ) -> Result<(), OverlayError> {
        let epoch = self
            .journal
            .lock()
            .map_err(Self::lock_error)?
            .state
            .next_seq();
        let mut start = offset / BUFFER as u64 * BUFFER as u64;
        while start < end {
            self.versions.current.insert((stage, start), epoch);
            start += BUFFER as u64;
        }
        Ok(())
    }

    /// Flush selected staging, namespace directory and journal barriers for a
    /// shared prefix. Directory-only seals do not invent a file token or mark.
    /// # Errors
    /// Refuses stale context; persistence uncertainty poisons the component.
    pub fn flush_sync_boundary(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        boundary: &SyncBoundary,
    ) -> Result<(), OverlayError> {
        self.ready(store, ownership)?;
        self.validate_sync_captures(boundary)?;
        let result = (|| {
            for file in &boundary.files {
                if let Some(token) = &file.token {
                    self.header(token.stage_id)?;
                    let path = self.stage_path(token.stage_id);
                    super::sync_step(
                        &mut self.io,
                        &self.faults,
                        "overlay.stage.sync",
                        &path,
                        boundary.through_seq,
                    )?;
                }
            }
            self.point("overlay.stage.dir_sync", "before", boundary.through_seq)?;
            self.io.sync_directory(&self.area.join("staging"))?;
            self.point("overlay.stage.dir_sync", "after", boundary.through_seq)?;
            let path = self.journal_path();
            super::sync_step(
                &mut self.io,
                &self.faults,
                "overlay.journal.pre_sync",
                &path,
                boundary.through_seq,
            )?;
            Ok(())
        })();
        if result.is_err() {
            self.poison();
        } else {
            self.versions.flushed.insert(boundary.id);
            for file in &boundary.files {
                if let Some(token) = &file.token {
                    self.flushed.insert(token.id);
                }
            }
        }
        result
    }

    /// Release all remaining tokens, including detached files and clean-file or
    /// directory headroom. This grants no receipt or acknowledgement and writes
    /// no file-synced mark. The coordinator persists the caller's disposition.
    /// # Errors
    /// Refuses stale or already completed boundaries; release occurs once.
    pub fn release_sync_boundary(&mut self, boundary: &SyncBoundary) -> Result<(), OverlayError> {
        self.validate_sync_owner(boundary)?;
        for file in &boundary.files {
            if let Some(token) = &file.token
                && self.snapshots.contains_key(&token.id)
            {
                self.complete_failed_capture(token)?;
            }
        }
        self.versions.boundaries.remove(&boundary.id);
        self.versions.graphs.remove(&boundary.id);
        self.versions.flushed.remove(&boundary.id);
        self.summary.captured_bytes = self.capture_charge()?;
        self.room_released();
        Ok(())
    }
}

pub(super) fn replayed_dirty(stage: &super::state::Stage) -> Result<Vec<(u64, u64)>, OverlayError> {
    let checkpoint = stage.checkpoint();
    let (_, checkpoint_size) = checkpoint;
    let limit = stage.size.max(checkpoint_size);
    let mut ranges = stage.zeros.clone();
    // Without a receipt boundary, a rollback to a different payload is
    // conservatively dirty across the whole file.
    if stage.rollback.is_some_and(|anchor| anchor != checkpoint) {
        ranges.push((0, limit));
    }
    for record in stage.extents.values() {
        if let Record::WriteExtent { offset, length, .. } = record {
            let end = offset
                .checked_add(*length)
                .ok_or_else(|| OverlayError::refused("dirty interval overflow"))?;
            ranges.push((*offset, end));
        }
    }
    ranges.push((stage.size.min(checkpoint_size), limit));
    Ok(merge(
        ranges
            .into_iter()
            .map(|(a, b)| (a.min(limit), b.min(limit)))
            .collect(),
    ))
}

pub(super) fn merge(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.retain(|(a, b)| a < b);
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (a, b) in ranges {
        if let Some(previous) = merged.last_mut()
            && a <= previous.1
        {
            previous.1 = previous.1.max(b);
        } else {
            merged.push((a, b));
        }
    }
    merged
}

/// Whether a file's checkpoint is held by nothing that acknowledges it. An
/// entry holding it as content (a copy-up, a re-bind or a landed file) or a
/// journal `file-synced` (`durable`) acknowledges it. A recreate's anchor and a
/// staging-header mark whose `file-synced` was lost are held by neither, so
/// the next capture still owes a mark.
fn unacknowledged(file: &CapturedFile, durable: Option<&super::DurableFile>) -> bool {
    file.checkpoint.is_some_and(|(content, size)| {
        let held = file.entry.as_ref().is_some_and(|entry| {
            entry.kind
                == OverlayKind::File {
                    content: Some(content),
                }
        });
        !held && durable.is_none_or(|d| (d.content, d.size) != (content, size))
    })
}
