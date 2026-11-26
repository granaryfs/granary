// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A cut proved by a published witness, and its retained journal image.

use super::super::{
    DurableFile,
    provenance::{History, record_paths},
    residual_inventory::ReconciliationPlan,
    snapshot::ReplayContext,
    state::Stage,
};
use super::{
    BTreeMap, BTreeSet, GrainId, Image, ImageSource, LandedProof, Namespace, OverlayEntry,
    OverlayError, OverlayIo, OverlayKind, OverlayStore, ProjectedPrefix, Record, ReplacementPlan,
    codec,
};
use crate::{
    CoordinationError, PublishError, SyncContent, SyncRuntime, ViewChange,
    recovery::{DirtyWitness, WitnessTree},
    sync,
};
use std::cell::Cell;

/// A snapshot taken with mutations closed, before reading immutable content
/// outside the mediator. Installation compares these exact bytes again.
#[derive(Debug)]
pub(crate) struct RecoveryPrefix {
    old: Vec<u8>,
    base: Vec<OverlayEntry>,
    context: ReplayContext,
}

#[derive(Debug)]
pub(crate) struct RecoveredSuffix {
    old: Vec<u8>,
    through: u64,
    witness: (GrainId, u64),
    selected: GrainId,
    registration: Option<(u64, u64)>,
    marks: BTreeSet<u64>,
    unchanged: BTreeSet<u64>,
    projected: Option<Box<ProjectedPrefix>>,
}

impl RecoveredSuffix {
    pub(crate) fn retires_registration(&self) -> bool {
        self.projected.is_none()
            && self
                .registration
                .is_some_and(|(seq, _)| seq <= self.through)
    }

    /// Account for the sole control record appended by the durable handoff.
    /// Installation still compares the resulting source byte for byte.
    pub(crate) fn record_handoff(&mut self, generation: u64) -> Result<(), CoordinationError> {
        let scan = codec::scan_journal(&self.old).map_err(|_| blocked())?;
        let record = Record::IntentRegistered {
            prepared_root: self.witness.0,
            generation,
            cause: codec::IntentCause::DirectorySync,
        };
        self.old.extend(
            codec::encode_record(&scan.header, scan.state.next_seq(), &record)
                .map_err(|_| blocked())?,
        );
        Ok(())
    }
}

fn blocked() -> CoordinationError {
    CoordinationError::Refused("WritableRecoveryRequired")
}

impl<P: OverlayIo> OverlayStore<P> {
    pub(crate) fn recovery_prefix(&mut self) -> Result<RecoveryPrefix, OverlayError> {
        self.check_finish_obligations()?;
        Ok(RecoveryPrefix {
            old: self.journal_bytes()?,
            base: self.base.clone(),
            context: self.replay_context()?,
        })
    }

    pub(crate) fn replace_recovered_suffix(
        &mut self,
        store: &mut super::Store,
        ownership: &super::OwnershipStatus,
        witness: DirtyWitness,
        suffix: RecoveredSuffix,
    ) -> Result<ViewChange, OverlayError> {
        self.check(store, ownership)?;
        self.check_finish_obligations()?;
        let proof = LandedProof {
            boundary_seq: 0,
            landed_root: witness.tree.view.base_id,
            landed_seq: witness.tree.view.base_seq,
            captured_entries: Vec::new(),
            entries: witness.tree.entries,
        };
        let old = self.journal_bytes()?;
        let result = self
            .recovered_image(&old, &proof, &suffix)
            .map_err(|error| match error {
                OverlayError::Conflict | OverlayError::Refused(_) => {
                    OverlayError::refused("WritableRecoveryRequired")
                }
                error => error,
            });
        let image = self.rebuilt_image(result)?;
        let original = self.journal.lock().map_err(Self::lock_error)?.header;
        self.install_recovered_plan(
            store,
            ownership,
            ReplacementPlan {
                proof,
                original,
                source: ImageSource::RecoveredSuffix(suffix),
                reconciliation: ReconciliationPlan::default(),
            },
            image.bytes.len(),
        )
    }

    pub(super) fn recovered_image(
        &self,
        old: &[u8],
        proof: &LandedProof,
        suffix: &RecoveredSuffix,
    ) -> Result<Image, OverlayError> {
        if old != suffix.old || suffix.witness != (proof.landed_root, proof.landed_seq) {
            return Err(OverlayError::refused("WritableRecoveryRequired"));
        }
        let scan =
            codec::scan_journal(old).map_err(|_| OverlayError::refused("replacement source"))?;
        scan.check_writer(&self.writer)
            .map_err(|_| OverlayError::refused("replacement writer"))?;
        let pending: BTreeSet<_> = scan.state.open_boundaries().collect();
        if pending.first().is_some_and(|seq| *seq <= suffix.through) {
            return Err(OverlayError::refused("WritableRecoveryRequired"));
        }
        if let Some(prefix) = &suffix.projected {
            return self.recovered_projection(old, proof, suffix, prefix);
        }
        let mut covered = BTreeSet::new();
        let mut absorbed_receipt = None;
        codec::scan_journal_with(old, |seq, record| match record {
            Record::LandedCommit {
                boundary_seq,
                landed_root,
                ..
            } if *landed_root == proof.landed_root => {
                covered.insert(*boundary_seq);
            }
            Record::FileSynced {
                generation,
                prepared_root,
                ..
            } if suffix.marks.contains(&seq) => {
                // Journal admission puts these marks in generation order.
                absorbed_receipt = Some((*generation, *prepared_root));
            }
            _ => {}
        })
        .map_err(|_| OverlayError::refused("replacement source"))?;
        // Both folds start with the proved tree. The image changes only
        // anchors, control cursors and covered controls. Each retained
        // namespace operation and extent check is replayed unchanged.
        super::build_suffix(
            old,
            &self.base,
            proof,
            &self.writer,
            &scan,
            suffix.through,
            &pending,
            |seq, record| {
                seq > suffix.through
                    && !covered.contains(&seq)
                    && !suffix.marks.contains(&seq)
                    && !matches!(record, Record::WriteExtent { stage_id, .. }
                        | Record::Truncate { stage_id, .. }
                        | Record::StageRollback { stage_id, .. }
                        if suffix.unchanged.contains(stage_id))
                    && !matches!(
                        record, Record::CommitAttempt { boundary_seq, .. }
                            | Record::CommitFence { boundary_seq, .. }
                            | Record::LandedCommit { boundary_seq, .. }
                            if covered.contains(boundary_seq)
                    )
            },
            Some(&self.dirty_spans),
            absorbed_receipt,
        )
    }

    /// Recovery owns the proved seal and its receipts. The ordinary landing
    /// builder separately requires a durable landing and its matched refresh.
    fn recovered_projection(
        &self,
        old: &[u8],
        proof: &LandedProof,
        suffix: &RecoveredSuffix,
        prefix: &ProjectedPrefix,
    ) -> Result<Image, OverlayError> {
        let (held, clean) = self.residual_inputs()?;
        let mut residual = super::super::residual::residual(
            old,
            &self.base,
            prefix,
            &held,
            &clean,
            &ReconciliationPlan::default(),
        )?;
        let registration = suffix.registration.map(|(_, generation)| {
            residual.records.push(Record::IntentRegistered {
                generation,
                prepared_root: suffix.selected,
                cause: codec::IntentCause::DirectorySync,
            });
            generation
        });
        super::projected_image(
            old,
            proof,
            &self.writer,
            prefix,
            residual,
            registration,
            |seq, record| match record {
                Record::FileSynced { prepared_root, .. } => {
                    seq <= prefix.through
                        || suffix.marks.contains(&seq)
                        || (*prepared_root == suffix.selected
                            && suffix
                                .registration
                                .is_some_and(|(through, _)| seq < through))
                }
                Record::IntentRegistered { prepared_root, .. } => {
                    seq <= prefix.through
                        || *prepared_root == proof.landed_root
                        || *prepared_root == suffix.selected
                }
                Record::ProjectedBoundary {
                    candidate,
                    through_seq,
                    ..
                } => {
                    (*candidate == proof.landed_root || *candidate == suffix.selected)
                        && *through_seq == prefix.through
                }
                _ => false,
            },
        )
    }
}

impl RecoveryPrefix {
    #[expect(
        clippy::too_many_lines,
        reason = "prove both roots against one journal and budget before deriving the install cut and retirement"
    )]
    pub(crate) fn prove(
        self,
        witness: &DirtyWitness,
        source: &impl SyncContent,
        read: impl Fn(&WitnessTree, GrainId, u64, usize) -> Result<Vec<u8>, OverlayError>,
        workspace: u64,
        deadline: tokio::time::Instant,
        runtime: &impl SyncRuntime,
    ) -> Result<RecoveredSuffix, CoordinationError> {
        let budget = ProofBudget {
            remaining: Cell::new(workspace),
            deadline,
            now: &|| runtime.now(),
        };
        budget.charge((self.old.len() as u64).saturating_mul(4))?;
        let remaining = budget.remaining.get();
        let reset = || {
            budget.remaining.set(remaining);
            budget.charge(0)
        };
        let verify_tree = |tree: &WitnessTree, stage: &Stage, id, content| {
            matches_stage(
                stage,
                id,
                content,
                tree,
                source,
                &|id, offset, len| read(tree, id, offset, len),
                &budget,
            )
        };
        let registration = if let Some((through, tree)) = &witness.selection {
            let verify = |stage: &Stage, id, content| verify_tree(tree, stage, id, content);
            let search = CutSearch::scan(
                &self.old,
                witness.selected,
                witness.selected,
                Some(*through),
            )?;
            let (prefix, _) = History::prefix(&self.base, &self.old, *through)?;
            if !matches_manifest(&prefix, tree, source, &verify, &budget)?
                && self
                    .find_projection(&search, tree, source, &verify, &budget, &reset)?
                    .is_none()
            {
                return Err(blocked());
            }
            search.generation.map(|generation| (*through, generation))
        } else {
            None
        };
        let tree = &witness.tree;
        let verify = |stage: &Stage, id, content| verify_tree(tree, stage, id, content);
        let search = CutSearch::scan(&self.old, tree.view.base_id, witness.prepared, None)?;
        let prefix = search.find_cut(|cursor| {
            reset()?;
            let (prefix, _) = History::prefix(&self.base, &self.old, cursor)?;
            matches_manifest(&prefix, tree, source, &verify, &budget)
        })?;
        let mut projected = if prefix.is_none() {
            Some(Box::new(
                self.find_projection(&search, tree, source, &verify, &budget, &reset)?
                    .ok_or_else(blocked)?,
            ))
        } else {
            None
        };
        let through = prefix
            .or_else(|| projected.as_ref().map(|seal| seal.through))
            .ok_or_else(blocked)?;
        let prefix_entries;
        let entries = if let Some(seal) = &projected {
            seal.projection.entries()
        } else {
            let (namespace, _) = History::prefix(&self.base, &self.old, through)?;
            prefix_entries = namespace
                .entries
                .values()
                .cloned()
                .zip(&tree.entries)
                .map(|(entry, expected)| OverlayEntry {
                    kind: expected.kind.clone(),
                    ..entry
                })
                .collect::<Vec<_>>();
            &prefix_entries
        };
        let marks = match &projected {
            // On the projected path `marks` names the receipts the image
            // keeps beside the residual: the store's own receipts of covered
            // stages. On the whole-prefix path it names the receipts dropped.
            Some(seal) => search
                .receipts
                .iter()
                .filter(|receipt| {
                    receipt.seq > through
                        && entries.iter().any(|entry| receipt.matches(entry))
                        && receipt.own
                        && seal.coverage.contains_key(&receipt.stage)
                })
                .map(|receipt| receipt.seq)
                .collect(),
            None => search.absorbed(through, entries),
        };
        reset()?;
        let mut unchanged = if search.open {
            BTreeSet::new()
        } else {
            self.unchanged_stages(through, entries, &marks, &verify)?
        };
        if let Some(seal) = &mut projected {
            seal.unchanged = Some(std::mem::take(&mut unchanged));
        }
        budget.charge(0)?;
        Ok(RecoveredSuffix {
            old: self.old,
            through,
            witness: (tree.view.base_id, tree.view.base_seq),
            selected: witness.selected,
            registration,
            marks,
            unchanged,
            projected,
        })
    }

    fn find_projection(
        &self,
        search: &CutSearch,
        witness: &WitnessTree,
        source: &impl SyncContent,
        verify: &impl Fn(&Stage, u64, GrainId) -> Result<bool, CoordinationError>,
        budget: &ProofBudget<'_>,
        reset: &impl Fn() -> Result<(), CoordinationError>,
    ) -> Result<Option<ProjectedPrefix>, CoordinationError> {
        let own = || search.receipts.iter().filter(|receipt| receipt.own);
        let Some(last) = own().next_back() else {
            return Ok(None);
        };
        let end = last.seq.min(search.limit);
        let (start, end) = search
            .projected
            .map_or((0, end), |seal| (seal, end.min(seal.saturating_add(1))));
        for through in (start..end).rev() {
            reset()?;
            let (namespace, history) = History::prefix(&self.base, &self.old, through)?;
            // A receipt is appended after its capture. It can establish bytes
            // at this seal only if the historical stage verifies them here.
            let candidates: BTreeMap<_, _> = own()
                .filter_map(|receipt| {
                    let stage = namespace.stages.get(&receipt.stage)?;
                    (through < receipt.seq
                        && stage.size == receipt.size
                        && witness.view.pin_files.contains_key(&receipt.content))
                    .then_some((receipt.stage, (stage, receipt)))
                })
                .collect();
            let selected: Vec<_> = candidates
                .values()
                .map(|(stage, receipt)| DurableFile {
                    inode: stage.inode,
                    size: receipt.size,
                    content: receipt.content,
                    content_boundary: through,
                })
                .collect();
            let sealed = self.context.boundary(through, &namespace, history);
            let projection = sealed.project(&selected)?;
            if !tree_matches(projection.entries(), witness, source, budget)? {
                continue;
            }
            let mut coverage = BTreeMap::new();
            for (&id, &(stage, receipt)) in &candidates {
                if !projection
                    .entries()
                    .iter()
                    .any(|entry| receipt.matches(entry))
                {
                    continue;
                }
                if !verify(stage, id, receipt.content)? {
                    break;
                }
                coverage.insert(id, through);
            }
            if coverage.len() == candidates.len()
                && !coverage.is_empty()
                && self.checkpoint_coverage(
                    &projection,
                    search,
                    through,
                    &mut coverage,
                    verify,
                    reset,
                )?
            {
                return Ok(Some(ProjectedPrefix {
                    through,
                    namespace,
                    sealed,
                    projection,
                    coverage,
                    unchanged: Some(BTreeSet::new()),
                }));
            }
        }
        Ok(None)
    }

    /// A checkpoint can contribute its payload to the projection even after
    /// the stage has changed. Prove where that payload was captured so later
    /// mutations of the stage can replay over it.
    fn checkpoint_coverage(
        &self,
        projection: &super::super::PreparedProjection,
        search: &CutSearch,
        through: u64,
        coverage: &mut BTreeMap<u64, u64>,
        verify: &impl Fn(&Stage, u64, GrainId) -> Result<bool, CoordinationError>,
        reset: &impl Fn() -> Result<(), CoordinationError>,
    ) -> Result<bool, CoordinationError> {
        'entries: for entry in projection.entries() {
            let Some(id) = entry.stage_id else { continue };
            if coverage.contains_key(&id) {
                continue;
            }
            let Some(mark) = search
                .receipts
                .iter()
                .rev()
                .find(|r| r.seq <= through && r.matches(entry))
            else {
                continue;
            };
            for cursor in std::iter::once(through).chain((0..mark.seq).rev()) {
                reset()?;
                let (namespace, _) = History::prefix(&self.base, &self.old, cursor)?;
                if let Some(stage) = namespace.stages.get(&id)
                    && stage.inode == entry.inode
                    && stage.size == mark.size
                    && verify(stage, id, mark.content)?
                {
                    coverage.insert(id, cursor);
                    continue 'entries;
                }
            }
            return Ok(false);
        }
        Ok(true)
    }

    fn unchanged_stages(
        &self,
        through: u64,
        entries: &[OverlayEntry],
        marks: &BTreeSet<u64>,
        verify: &impl Fn(&Stage, u64, GrainId) -> Result<bool, CoordinationError>,
    ) -> Result<BTreeSet<u64>, CoordinationError> {
        let (live, history) = History::prefix(&self.base, &self.old, u64::MAX)?;
        let mut unchanged = BTreeSet::new();
        for entry in entries {
            let (
                Some(id),
                OverlayKind::File {
                    content: Some(content),
                },
            ) = (entry.stage_id, &entry.kind)
            else {
                continue;
            };
            let Some(stage) = live.stages.get(&id) else {
                continue;
            };
            let mut mutated = false;
            let mut needed = false;
            for effect in history.records.iter().filter(|effect| effect.seq > through) {
                match &effect.record {
                    Record::WriteExtent { stage_id, .. }
                    | Record::Truncate { stage_id, .. }
                    | Record::StageRollback { stage_id, .. }
                        if *stage_id == id =>
                    {
                        mutated = true;
                    }
                    Record::FileSynced { stage_id, .. } if *stage_id == id => {
                        needed |= !marks.contains(&effect.seq);
                    }
                    record => {
                        let (from, to) = record_paths(record);
                        needed |= from
                            .into_iter()
                            .chain(to)
                            .any(|path| entry.path.starts_with(&path))
                            || super::reference(record) == Some(id);
                    }
                }
            }
            if mutated
                && !needed
                && stage.inode == entry.inode
                && stage.path.as_ref() == Some(&entry.path)
                && live
                    .entries
                    .get(&entry.path)
                    .is_some_and(|now| now.size == entry.size && now.exec == entry.exec)
                && verify(stage, id, *content)?
            {
                unchanged.insert(id);
            }
        }
        Ok(unchanged)
    }
}

struct Receipt {
    seq: u64,
    own: bool,
    stage: u64,
    content: GrainId,
    size: u64,
}

impl Receipt {
    fn matches(&self, entry: &OverlayEntry) -> bool {
        entry.stage_id == Some(self.stage)
            && entry.size == self.size
            && entry.kind
                == OverlayKind::File {
                    content: Some(self.content),
                }
    }
}

struct CutSearch {
    anchored: Option<u64>,
    projected: Option<u64>,
    limit: u64,
    open: bool,
    receipts: Vec<Receipt>,
    /// Each `stage-rollback` as `(seq, stage)`, in journal order.
    rollbacks: Vec<(u64, u64)>,
    generation: Option<u64>,
}

impl CutSearch {
    fn scan(
        old: &[u8],
        witness: GrainId,
        prepared: GrainId,
        registration: Option<u64>,
    ) -> Result<Self, CoordinationError> {
        let mut boundaries = BTreeMap::new();
        let mut anchored = None;
        let mut projected = None;
        let mut receipts = Vec::new();
        let mut rollbacks = Vec::new();
        let mut generation = None;
        let scan = codec::scan_journal_with(old, |seq, record| match record {
            Record::IntentRegistered {
                prepared_root,
                generation: registered,
                ..
            } if registration == Some(seq) && *prepared_root == prepared => {
                generation = Some(*registered);
            }
            Record::CommitBoundary {
                candidate,
                through_seq,
                ..
            }
            | Record::ProjectedBoundary {
                candidate,
                through_seq,
                ..
            } if registration.is_none_or(|through| seq <= through) => {
                boundaries.insert(seq, *through_seq);
                if *candidate == witness {
                    anchored = anchored.max(Some(*through_seq));
                }
                if matches!(record, Record::ProjectedBoundary { .. })
                    && (*candidate == witness || *candidate == prepared)
                {
                    projected = projected.max(Some(*through_seq));
                }
            }
            Record::LandedCommit {
                boundary_seq,
                landed_root,
                ..
            } if *landed_root == witness && registration.is_none() => {
                anchored = anchored.max(boundaries.get(boundary_seq).copied());
            }
            Record::FileSynced {
                stage_id,
                synced_size,
                content,
                prepared_root,
                ..
            } if registration.is_none_or(|through| seq <= through) => {
                receipts.push(Receipt {
                    seq,
                    own: *prepared_root == witness || *prepared_root == prepared,
                    stage: *stage_id,
                    content: *content,
                    size: *synced_size,
                });
            }
            Record::StageRollback { stage_id, .. }
                if registration.is_none_or(|through| seq <= through) =>
            {
                rollbacks.push((seq, *stage_id));
            }
            _ => {}
        })
        .map_err(|_| blocked())?;
        if scan.end != codec::JournalEnd::Clean || (registration.is_some() && generation.is_none())
        {
            return Err(blocked());
        }
        let pending = scan.state.open_boundaries().next();
        let limit = pending
            .unwrap_or_else(|| scan.state.next_seq())
            .min(registration.map_or(u64::MAX, |seq| seq.saturating_add(1)));
        Ok(Self {
            anchored: anchored.filter(|cursor| *cursor < limit),
            projected,
            limit,
            open: pending.is_some(),
            receipts,
            rollbacks,
            generation,
        })
    }

    /// The receipts after a whole-prefix cut that the image drops. Each names
    /// the content and size of its stage's entry at the cut, which the match
    /// proved and the prelude binds, so dropping it leaves the receipt's
    /// content as the image's checkpoint whatever root it names. A fold ranks
    /// a stage's last mark above its rollback baseline and that above its
    /// bind. Once a receipt of a stage is kept it is the image's mark, and
    /// once a `stage-rollback` of it follows the cut its baseline outranks the
    /// bind: either way a later receipt is kept, or the image's checkpoint
    /// would differ from the source's last mark. A receipt before a rollback
    /// can still be dropped, because replay anchors the rollback on the
    /// stage's checkpoint, then that receipt's mark (a staging header holding
    /// a different mark refuses the rollback).
    fn absorbed(&self, through: u64, entries: &[OverlayEntry]) -> BTreeSet<u64> {
        let mut rolled_back = BTreeMap::new();
        for &(seq, stage) in self.rollbacks.iter().filter(|(seq, _)| *seq > through) {
            rolled_back.entry(stage).or_insert(seq);
        }
        let mut kept = BTreeSet::new();
        let mut absorbed = BTreeSet::new();
        for receipt in self.receipts.iter().filter(|receipt| receipt.seq > through) {
            if !kept.contains(&receipt.stage)
                && rolled_back
                    .get(&receipt.stage)
                    .is_none_or(|seq| receipt.seq < *seq)
                && entries.iter().any(|entry| receipt.matches(entry))
            {
                absorbed.insert(receipt.seq);
            } else {
                kept.insert(receipt.stage);
            }
        }
        absorbed
    }

    fn find_cut(
        &self,
        mut matches: impl FnMut(u64) -> Result<bool, CoordinationError>,
    ) -> Result<Option<u64>, CoordinationError> {
        let mut best = None;
        if let Some(cursor) = self.anchored
            && matches(cursor)?
        {
            best = Some(cursor);
        }
        for cursor in (best.map_or(0, |cursor| cursor.saturating_add(1))..self.limit).rev() {
            if Some(cursor) != self.anchored && matches(cursor)? {
                return Ok(Some(cursor));
            }
        }
        Ok(best)
    }
}

struct ProofBudget<'a> {
    remaining: Cell<u64>,
    deadline: tokio::time::Instant,
    now: &'a dyn Fn() -> tokio::time::Instant,
}

impl ProofBudget<'_> {
    fn charge(&self, bytes: u64) -> Result<(), CoordinationError> {
        if (self.now)() >= self.deadline {
            return Err(CoordinationError::Refused("SyncDeadline"));
        }
        let remaining = self
            .remaining
            .get()
            .checked_sub(bytes)
            .ok_or(CoordinationError::Refused("SyncWorkspaceExhausted"))?;
        self.remaining.set(remaining);
        Ok(())
    }
}

fn matches_manifest(
    prefix: &Namespace,
    witness: &WitnessTree,
    source: &impl SyncContent,
    verify: &impl Fn(&Stage, u64, GrainId) -> Result<bool, CoordinationError>,
    budget: &ProofBudget<'_>,
) -> Result<bool, CoordinationError> {
    if prefix.entries.len() != witness.entries.len() {
        return Ok(false);
    }
    // Shape is a cheap rejection test before historical bytes are needed.
    let mut material = Vec::new();
    for (entry, expected) in prefix.entries.values().zip(&witness.entries) {
        if entry.path != expected.path
            || entry.size != expected.size
            || entry.exec != expected.exec
            || (entry.stage_id.is_none() && entry.kind != expected.kind)
        {
            return Ok(false);
        }
        budget.charge(
            256 + entry
                .path
                .iter()
                .map(|name| name.as_bytes().len() as u64)
                .sum::<u64>(),
        )?;
        material.push(entry.clone());
    }
    for (entry, expected) in material.iter_mut().zip(&witness.entries) {
        let Some(id) = entry.stage_id else { continue };
        let OverlayKind::File {
            content: Some(content),
        } = expected.kind
        else {
            return Ok(false);
        };
        let stage = prefix.stages.get(&id).ok_or_else(blocked)?;
        if !verify(stage, id, content)? {
            return Ok(false);
        }
        entry.kind = expected.kind.clone();
    }
    tree_matches(&material, witness, source, budget)
}

fn matches_stage(
    stage: &Stage,
    id: u64,
    content: GrainId,
    witness: &WitnessTree,
    source: &impl SyncContent,
    read: &impl Fn(GrainId, u64, usize) -> Result<Vec<u8>, OverlayError>,
    budget: &ProofBudget<'_>,
) -> Result<bool, CoordinationError> {
    let scratch = stage
        .size
        .min(granary_core::thresh::MAX_GRAIN as u64)
        .saturating_mul(2);
    budget.charge(scratch)?;
    let read = |offset, length| range(read(content, offset, length), length, budget);
    if !stage_matches(
        stage,
        id,
        &|base, offset, length| range(source.read_content(base, offset, length), length, budget),
        &read,
    )? {
        return Ok(false);
    }
    // Cut the authenticated byte stream with the same cutter and replay
    // checkpoint rules as whole-tree materialization.
    let (checkpoint, size) = stage.checkpoint();
    let (old, dirty) = if let Some(id) = checkpoint {
        let grains = if id == content {
            witness
                .view
                .pin_files
                .get(&id)
                .ok_or_else(blocked)?
                .1
                .clone()
        } else {
            source.payload(id).map_err(content_error)?
        };
        budget.charge(u64::from(grains.grain_count()).saturating_mul(128))?;
        (
            crate::writable_store::capture::captured_refs(source, size, &grains)
                .map_err(content_error)?,
            super::super::snapshot::replayed_dirty(stage)?,
        )
    } else {
        (Vec::new(), sync::fresh_dirty(stage.size))
    };
    let file = sync::rechunk_file(
        stage.size,
        old,
        &dirty,
        &mut |offset, length| read(offset, length),
        &mut |_, bytes| budget.charge(bytes.len() as u64),
        &mut sync::RechunkStats::default(),
    )?;
    if file.content != content {
        return Ok(false);
    }
    budget
        .remaining
        .set(budget.remaining.get().saturating_add(scratch));
    Ok(true)
}

fn tree_matches(
    material: &[OverlayEntry],
    witness: &WitnessTree,
    source: &impl SyncContent,
    budget: &ProofBudget<'_>,
) -> Result<bool, CoordinationError> {
    if material.len() != witness.entries.len()
        || material.iter().zip(&witness.entries).any(|(a, b)| {
            a.path != b.path || a.size != b.size || a.exec != b.exec || a.kind != b.kind
        })
    {
        return Ok(false);
    }
    if material.iter().any(|entry| {
        matches!(entry.kind, OverlayKind::File { content: Some(id) }
            if !witness.view.pin_files.contains_key(&id))
    }) {
        return Err(blocked());
    }
    let (root, nodes) = match sync::entries_tree(material, source, |content| {
        witness
            .view
            .pin_files
            .get(&content)
            .map(|(_, grains)| grains.clone())
            .ok_or(crate::PublishError::BadPlan)
    }) {
        Ok(tree) => tree,
        Err(PublishError::BadPlan) => return Ok(false),
        Err(error) => {
            return Err(CoordinationError::Recovery(
                crate::RecoveryError::Preparation(error),
            ));
        }
    };
    for bytes in nodes.values() {
        budget.charge(bytes.len() as u64)?;
    }
    Ok(root == witness.manifest)
}

fn content_error(error: CoordinationError) -> CoordinationError {
    match error {
        CoordinationError::Overlay(OverlayError::Refused("SyncDeadline")) => {
            CoordinationError::Refused("SyncDeadline")
        }
        CoordinationError::Overlay(
            OverlayError::ContentUnavailable | OverlayError::CaptureCoverageLost,
        ) => blocked(),
        error => error,
    }
}

fn range(
    bytes: Result<Vec<u8>, OverlayError>,
    length: usize,
    budget: &ProofBudget<'_>,
) -> Result<Vec<u8>, CoordinationError> {
    budget.charge(0)?;
    let bytes = bytes.map_err(|error| content_error(error.into()))?;
    if bytes.len() == length {
        Ok(bytes)
    } else {
        Err(blocked())
    }
}

/// Check live extents against the witness. In the gaps, compare it with the
/// checkpoint used by the rechunker, with zero spans and bytes past its end zero.
fn stage_matches(
    stage: &Stage,
    id: u64,
    read_checkpoint: &impl Fn(GrainId, u64, usize) -> Result<Vec<u8>, CoordinationError>,
    read: &impl Fn(u64, usize) -> Result<Vec<u8>, CoordinationError>,
) -> Result<bool, CoordinationError> {
    let (checkpoint, checkpoint_size) = stage.checkpoint();
    let zeros = super::super::snapshot::merge(stage.zeros.clone());
    let mut cursor = 0;
    let gap = |mut at, end| {
        while at < end {
            let zero = zeros.get(zeros.partition_point(|&(_, b)| b <= at));
            let content =
                checkpoint.filter(|_| at < checkpoint_size && zero.is_none_or(|&(a, _)| at < a));
            let boundary = if content.is_some() {
                zero.map_or(checkpoint_size, |&(a, _)| a.min(checkpoint_size))
            } else {
                zero.filter(|&&(a, _)| a <= at).map_or(end, |&(_, b)| b)
            };
            let n = chunk(at, end.min(boundary))?;
            let bytes = read(at, n)?;
            let same = if let Some(content) = content {
                read_checkpoint(content, at, n)? == bytes
            } else {
                bytes.iter().all(|&byte| byte == 0)
            };
            if !same {
                return Ok(false);
            }
            at = at.saturating_add(n as u64);
        }
        Ok::<_, CoordinationError>(true)
    };
    for record in stage.extents.values() {
        let Record::WriteExtent {
            offset,
            length,
            check,
            ..
        } = record
        else {
            return Err(blocked());
        };
        // History::prefix uses Namespace::fold, which retires checks crossing a truncate.
        let end = offset
            .checked_add(*length)
            .filter(|end| *end <= stage.size)
            .ok_or_else(blocked)?;
        if *offset < cursor || !gap(cursor, *offset)? {
            return Ok(false);
        }
        let mut hash = codec::ExtentHasher::new(id, *offset, *length);
        cursor = *offset;
        while cursor < end {
            let n = chunk(cursor, end)?;
            hash.update(&read(cursor, n)?);
            cursor = cursor.saturating_add(n as u64);
        }
        if hash.finalize() != *check {
            return Ok(false);
        }
    }
    gap(cursor, stage.size)
}

fn chunk(start: u64, end: u64) -> Result<usize, CoordinationError> {
    let length = end.saturating_sub(start).min(super::super::BUFFER as u64);
    usize::try_from(length)
        .ok()
        .filter(|n| *n != 0)
        .ok_or_else(blocked)
}

#[cfg(test)]
mod tests;
