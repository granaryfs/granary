// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The residual a projected landing keeps over its projection: the work the
//! projection left out through its boundary and all later local work, carried
//! by stage identity and replayed in original order.

use super::replacement::{
    ProjectedPrefix, payload_reference, projected_prefix, receipt_identity, reference,
};
use super::{BTreeMap, Namespace, OverlayEntry, OverlayError, OverlayKind, Record, codec};
use granary_core::hash::GrainId;
use granary_core::manifest::Name;
use std::collections::BTreeSet;

/// Where a prospective base must equal the projection before the residual can
/// replay over it: whole subtrees a residual effect reads or rewrites, and
/// single entries such as an effect's parent or a carried file's name.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ResidualAnchors {
    subtrees: BTreeSet<Vec<Name>>,
    exact: BTreeSet<Vec<Name>>,
}
impl ResidualAnchors {
    pub(super) fn record(&mut self, record: &Record) {
        let (source, destination) = super::provenance::record_paths(record);
        for path in source.into_iter().chain(destination) {
            if let Some((_, parent)) = path.split_last()
                && !parent.is_empty()
            {
                self.exact.insert(parent.to_vec());
            }
            self.subtrees.insert(path);
        }
    }
    /// The first anchored path at which `after` differs from `projection` in
    /// presence, kind, content or symlink target, size or exec. Both sides
    /// are immutable entries: a staged file's content is never assumed.
    pub(crate) fn mismatch(
        &self,
        projection: &[OverlayEntry],
        after: &[OverlayEntry],
    ) -> Option<Vec<Name>> {
        let index = |entries: &'_ [OverlayEntry]| -> BTreeMap<Vec<Name>, OverlayEntry> {
            entries
                .iter()
                .map(|e| (e.path.clone(), e.clone()))
                .collect()
        };
        let (before, after) = (index(projection), index(after));
        let anchored = |path: &&Vec<Name>| {
            self.exact.contains(*path) || self.subtrees.iter().any(|root| path.starts_with(root))
        };
        before
            .keys()
            .chain(after.keys())
            .chain(&self.exact)
            .filter(anchored)
            .find(|path| match (before.get(*path), after.get(*path)) {
                (None, None) => false,
                (Some(a), Some(b)) => a.kind != b.kind || a.size != b.size || a.exec != b.exec,
                _ => true,
            })
            .cloned()
    }
}

/// A copy of everything a projected boundary's residual is built from,
/// taken in one short acquisition so that building needs no lock.
pub(crate) struct ResidualSnapshot {
    pub(super) journal: Vec<u8>,
    pub(super) base: Vec<OverlayEntry>,
    pub(super) held: BTreeSet<u64>,
    pub(super) clean: Checkpoints,
    pub(super) context: super::snapshot::ReplayContext,
    pub(super) boundary: u64,
    pub(super) publication: [u8; 16],
}
impl ResidualSnapshot {
    pub(super) fn residual(&self) -> Result<Residual, OverlayError> {
        let prefix = projected_prefix(
            &self.context,
            &self.base,
            &self.journal,
            self.boundary,
            self.publication,
        )?;
        residual(
            &self.journal,
            &self.base,
            &prefix,
            &self.held,
            &self.clean,
            &super::residual_inventory::ReconciliationPlan::default(),
        )
    }
    /// Where a rebased base must equal the projection for the residual to
    /// replay over it.
    /// # Errors
    /// Refuses an unbound boundary or a residual that cannot be represented.
    pub(crate) fn anchors(&self) -> Result<ResidualAnchors, OverlayError> {
        Ok(self.residual()?.anchors)
    }
}

/// Live checkpoints by stage: content and size.
pub(super) type Checkpoints = BTreeMap<u64, (GrainId, u64)>;

/// The residual over the projection, before any remote contribution.
pub(super) struct Residual {
    /// Re-binds, lifted omitted effects, carried mutations and later work.
    pub records: Vec<Record>,
    /// The header floor used to admit the retained file receipts.
    pub receipt_generation: u64,
    /// The seqs of the source records whose retained work an ordinary
    /// commit still owes, wherever they fall relative to the boundary.
    pub dirty: Vec<u64>,
    pub anchors: ResidualAnchors,
    /// Stages not carried, each with its projected path if it has one.
    pub retired: Vec<(u64, Option<Vec<Name>>)>,
}

fn unsupported() -> OverlayError {
    OverlayError::refused("projected residual unsupported")
}

/// Records that publish, register or acknowledge rather than change the
/// local namespace or bytes.
pub(super) fn control(record: &Record) -> bool {
    matches!(
        record,
        Record::FileSynced { .. }
            | Record::IntentRegistered { .. }
            | Record::CommitBoundary { .. }
            | Record::ProjectedBoundary { .. }
            | Record::LandedCommit { .. }
            | Record::CommitAttempt { .. }
            | Record::CommitFence { .. }
    )
}

/// The residual namespace as it is lifted, and what has been emitted into it.
struct Lift {
    namespace: Namespace,
    records: Vec<Record>,
    dirty: Vec<u64>,
    anchors: ResidualAnchors,
}
impl Lift {
    /// Emit `record`, lifted from the source record at `source` if any.
    fn push(&mut self, source: Option<u64>, record: Record) -> Result<(), OverlayError> {
        if let Some(seq) = source
            && super::recovery::dirty_record(&self.namespace, &record)
        {
            self.dirty.push(seq);
        }
        self.namespace.fold(&record).map_err(|_| unsupported())?;
        self.records.push(record);
        Ok(())
    }
    fn path_of(&self, inode: u64) -> Result<Option<Vec<Name>>, OverlayError> {
        if inode == 0 {
            return Ok(Some(Vec::new()));
        }
        Ok(self
            .namespace
            .query_inode(inode)
            .map_err(|_| unsupported())?
            .map(|entry| entry.path.clone()))
    }
    /// An omitted effect resolved by its sealed identities in the residual:
    /// `None` when the identity it acts on is dead, detached at the boundary
    /// and not carried under a name.
    fn lift(
        &self,
        effect: &super::NamespaceEffect,
        prefix: &Namespace,
    ) -> Result<Option<Record>, OverlayError> {
        let location = |path: &[Name]| -> Result<codec::Location, OverlayError> {
            let (name, parent) = path.split_last().ok_or_else(unsupported)?;
            Ok(codec::Location {
                parent: codec::Parent::new(parent.to_vec()).map_err(|_| unsupported())?,
                name: name.clone(),
            })
        };
        let destination = |at: &codec::Location| -> Result<codec::Location, OverlayError> {
            let parent = effect.parents.last().ok_or_else(unsupported)?;
            let mut path = self.path_of(*parent)?.ok_or_else(unsupported)?;
            path.push(at.name.clone());
            location(&path)
        };
        let source = match effect.source {
            Some(inode) => match self.path_of(inode)? {
                Some(path) => Some(path),
                None => return Ok(None),
            },
            None => None,
        };
        let from = || location(source.as_deref().ok_or_else(unsupported)?);
        let detached = |id: &u64| prefix.stages.get(id).is_none_or(|s| s.path.is_none());
        Ok(Some(match &effect.record {
            Record::Create {
                at,
                kind: codec::CreateKind::File { stage_id, exec },
            } => {
                if detached(stage_id) {
                    return Ok(None);
                }
                Record::RecreateFile {
                    at: Some(destination(at)?),
                    exec: *exec,
                    stage_id: *stage_id,
                    anchor: None,
                }
            }
            Record::RecreateFile {
                at: Some(at),
                exec,
                stage_id,
                anchor,
            } => {
                if detached(stage_id) {
                    return Ok(None);
                }
                Record::RecreateFile {
                    at: Some(destination(at)?),
                    exec: *exec,
                    stage_id: *stage_id,
                    anchor: *anchor,
                }
            }
            Record::Create { at, kind } => Record::Create {
                at: destination(at)?,
                kind: kind.clone(),
            },
            Record::Move { to, .. } => Record::Move {
                from: from()?,
                to: destination(to)?,
            },
            // Its destination's only occupant may have been a dead identity
            // left out of the residual; the projector lifts that as a move.
            Record::Replace { to, .. } => {
                let (from, to) = (from()?, destination(to)?);
                if self
                    .namespace
                    .entries
                    .contains_key(&super::state::path(&to))
                {
                    Record::Replace { from, to }
                } else {
                    Record::Move { from, to }
                }
            }
            Record::Delete { kind, .. } => Record::Delete {
                at: from()?,
                kind: match kind {
                    codec::DeleteKind::File { .. } => codec::DeleteKind::File {
                        stage_id: source
                            .as_ref()
                            .and_then(|path| self.namespace.entries.get(path))
                            .and_then(|entry| entry.stage_id),
                    },
                    kind => kind.clone(),
                },
            },
            Record::SetattrExec { exec, .. } => Record::SetattrExec {
                at: from()?,
                exec: *exec,
            },
            // The prelude binds every carried stage; nothing else is a
            // namespace effect.
            _ => return Ok(None),
        }))
    }
}

/// Build the residual of `prefix`'s projected boundary over its projection
/// and check it reproduces the complete original replay of `old` over `base`.
///
/// A named stage is carried when a handle or capture in `held` holds it,
/// later local work names it, or it is not clean: clean is the selected
/// file, whose payload covers every mutation through the boundary, or a
/// stage `clean` maps (one a whole-tree sync would not select) to its live
/// checkpoint, when that checkpoint is its projected payload. A stage
/// detached at the boundary is carried detached when held or named later,
/// and retired otherwise.
/// # Errors
/// `projected residual unsupported` when an omitted effect cannot be lifted
/// by identity, a name is occupied, the residual breaks a journal value rule
/// or does not reproduce the original namespace, stages and mutations;
/// replay refusals otherwise.
#[expect(
    clippy::too_many_lines,
    reason = "classification and the four emission passes share the lifted namespace"
)]
pub(super) fn residual(
    old: &[u8],
    base: &[OverlayEntry],
    prefix: &ProjectedPrefix,
    held: &BTreeSet<u64>,
    clean: &Checkpoints,
    reconciled: &super::residual_inventory::ReconciliationPlan,
) -> Result<Residual, OverlayError> {
    let through = prefix.through;
    let unchanged = |id| {
        prefix
            .unchanged
            .as_ref()
            .is_some_and(|ids| ids.contains(&id))
    };
    let mut referenced = BTreeSet::new();
    codec::scan_journal_with(old, |seq, record| {
        if seq > through
            && !control(record)
            && let Some(id) = reference(record)
            && !((reconciled.contains(id) || unchanged(id))
                && payload_reference(record) == Some(id))
        {
            referenced.insert(id);
        }
    })
    .map_err(|_| OverlayError::refused("residual scan"))?;
    let projection: Vec<_> = prefix
        .projection
        .entries()
        .iter()
        .cloned()
        .map(|mut entry| {
            entry.stage_id = None;
            entry
        })
        .collect();
    let payloads: BTreeMap<u64, (&[Name], GrainId, u64)> = projection
        .iter()
        .filter_map(|entry| match entry.kind {
            OverlayKind::File {
                content: Some(content),
            } => Some((entry.inode, (entry.path.as_slice(), content, entry.size))),
            _ => None,
        })
        .collect();
    let coverage = &prefix.coverage;
    let absorbed = |id| coverage.get(&id) == Some(&through);
    let mut lift = Lift {
        namespace: Namespace::base_with_inodes(&projection).map_err(|_| unsupported())?,
        records: Vec::new(),
        dirty: Vec::new(),
        anchors: ResidualAnchors::default(),
    };
    let mut retired = Vec::new();
    let mut retired_payloads = BTreeMap::new();
    let mut carried = BTreeSet::new();
    let mut detached = Vec::new();
    for (&id, stage) in &prefix.namespace.stages {
        let needed = held.contains(&id) || referenced.contains(&id);
        let payload = payloads.get(&stage.inode);
        if stage.path.is_none() {
            if needed {
                let (content, size) = stage.checkpoint();
                let anchor = content.map(|content| codec::RecreateAnchor { content, size });
                detached.push(Record::RecreateFile {
                    at: None,
                    exec: false,
                    stage_id: id,
                    anchor,
                });
                carried.insert(id);
            } else {
                retired.push((id, None));
                retired_payloads.insert(id, None);
            }
            continue;
        }
        let is_clean = absorbed(id)
            || unchanged(id)
            || reconciled.contains(id)
            || payload.is_some_and(|p| clean.get(&id) == Some(&(p.1, p.2)));
        match payload {
            Some(&(path, content, _)) if is_clean && !needed => {
                retired.push((id, Some(path.to_vec())));
                retired_payloads.insert(id, Some(content));
            }
            Some(&(path, content, size)) => {
                let (name, parent) = path.split_last().ok_or_else(unsupported)?;
                lift.push(
                    None,
                    Record::StageBind {
                        at: codec::Location {
                            parent: codec::Parent::new(parent.to_vec())
                                .map_err(|_| unsupported())?,
                            name: name.clone(),
                        },
                        cause: codec::BindCause::Rebind,
                        stage_id: id,
                        staged_size: size,
                        base_content: content,
                    },
                )?;
                lift.anchors.exact.insert(path.to_vec());
                if !absorbed(id) {
                    carried.insert(id);
                }
            }
            // Recreated where its omitted creation replays.
            None => {
                carried.insert(id);
            }
        }
    }
    for record in detached {
        lift.push(None, record)?;
    }
    let excluded = prefix.projection.excluded();
    for effect in prefix.sealed.effects() {
        if !excluded.contains(&effect.seq) {
            continue;
        }
        let Some(record) = lift.lift(effect, &prefix.namespace)? else {
            continue;
        };
        // A recreated name takes its sealed identity, so later effects resolve.
        let created = matches!(record, Record::Create { .. } | Record::RecreateFile { .. })
            .then(|| super::provenance::record_paths(&record).1)
            .flatten();
        lift.anchors.record(&record);
        lift.push(Some(effect.seq), record)?;
        if let (Some(inode), Some(path)) = (effect.result, created) {
            lift.namespace
                .assign_inode(&path, inode)
                .map_err(|_| unsupported())?;
        }
    }
    let recovery = prefix.unchanged.is_some();
    let mut error = None;
    codec::scan_journal_with(old, |seq, record| {
        let reconciled_payload = payload_reference(record).is_some_and(|id| {
            (reconciled.contains(id) || unchanged(id))
                && retired_payloads.contains_key(&id)
        });
        // Recovery drops the staging mirror when it drops a journal mark.
        // Keep the receipt for a carried stage without a proved projection.
        let checkpoint = recovery
            && matches!(record, Record::FileSynced { stage_id, .. }
                if !coverage.contains_key(stage_id) && !retired_payloads.contains_key(stage_id));
        let keep = checkpoint || if seq <= through {
            matches!(record, Record::WriteExtent { stage_id, .. }
                        | Record::Truncate { stage_id, .. }
                        | Record::StageRollback { stage_id, .. }
                if carried.contains(stage_id) && coverage.get(stage_id).is_none_or(|cut| seq > *cut))
        } else {
            !control(record) && !reconciled_payload
        };
        if keep && error.is_none() {
            if seq > through {
                lift.anchors.record(record);
            }
            if let Err(e) = lift.push(Some(seq), record.clone()) {
                error = Some(e);
            }
        }
    })
    .map_err(|_| OverlayError::refused("residual scan"))?;
    if let Some(error) = error {
        return Err(error);
    }
    let mut original = Namespace::base(base)?;
    let mut error = None;
    codec::scan_journal_with(old, |_, record| {
        if error.is_none()
            && let Err(e) = original.fold(record)
        {
            error = Some(e);
        }
    })
    .map_err(|_| OverlayError::refused("residual scan"))?;
    if let Some(error) = error {
        return Err(error);
    }
    if !equivalent(
        &lift.namespace,
        &original,
        &retired_payloads,
        coverage,
        recovery,
    ) {
        return Err(unsupported());
    }
    let receipt_generation = admissible(old, through, &lift.records)?;
    Ok(Residual {
        records: lift.records,
        receipt_generation,
        dirty: lift.dirty,
        anchors: lift.anchors,
        retired,
    })
}

/// Check the residual's records under a header carrying the prefix's stage
/// ceiling. Return its receipt generation for use in the replacement image.
fn admissible(old: &[u8], through: u64, records: &[Record]) -> Result<u64, OverlayError> {
    let scan = codec::scan_journal(old).map_err(|_| OverlayError::refused("residual scan"))?;
    let mut prefix = codec::JournalState::new(&scan.header);
    let mut error = false;
    codec::scan_journal_with(old, |seq, record| {
        error |= seq <= through && prefix.admit(record).is_err();
    })
    .map_err(|_| OverlayError::refused("residual scan"))?;
    if error {
        return Err(OverlayError::refused("residual scan"));
    }
    let receipt_generation = records
        .iter()
        .find_map(receipt_identity)
        .map_or(scan.state.highest_generation(), |(generation, _)| {
            generation.saturating_sub(1)
        });
    let header = codec::JournalHeader {
        next_stage_id: prefix.next_stage_id(),
        receipt_generation,
        ..scan.header
    };
    let mut state = codec::JournalState::new(&header);
    for record in records {
        state.admit(record).map_err(|_| unsupported())?;
    }
    Ok(receipt_generation)
}

/// Whether the residual replay reproduces the original: the same names with
/// the same kinds, exec bits and sizes; a staged file under the same stage, a
/// clean retired stage's name at its payload and any other file at the same
/// immutable content; and every stage not retired under the same name and
/// size, with the same extents unless its absorbed prefix was dropped.
fn equivalent(
    residual: &Namespace,
    original: &Namespace,
    retired: &BTreeMap<u64, Option<GrainId>>,
    coverage: &BTreeMap<u64, u64>,
    recovery: bool,
) -> bool {
    let entries = residual.entries.len() == original.entries.len()
        && original.entries.iter().all(|(path, want)| {
            residual.entries.get(path).is_some_and(|got| {
                std::mem::discriminant(&got.kind) == std::mem::discriminant(&want.kind)
                    && got.exec == want.exec
                    && got.size == want.size
                    && match (want.stage_id, got.stage_id) {
                        (Some(a), Some(b)) => a == b,
                        (Some(a), None) => retired
                            .get(&a)
                            .copied()
                            .flatten()
                            .is_some_and(|c| got.kind == OverlayKind::File { content: Some(c) }),
                        (None, None) => got.kind == want.kind,
                        (None, Some(_)) => false,
                    }
            })
        });
    let live: Vec<_> = original
        .stages
        .iter()
        .filter(|(id, _)| !retired.contains_key(id))
        .collect();
    entries
        && live.len() == residual.stages.len()
        && live.iter().all(|(id, want)| {
            residual.stages.get(id).is_some_and(|got| {
                got.path == want.path
                    && got.size == want.size
                    && (coverage.contains_key(id)
                        || (got.extents == want.extents
                            && got.rollback == want.rollback
                            && (!recovery
                                || (got.checkpoint() == want.checkpoint()
                                    && got.zeros == want.zeros))))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_residual_requires_equivalent_checkpoint() {
        let at = codec::Location {
            parent: codec::Parent::new(vec![]).unwrap(),
            name: Name::new(b"file".to_vec()).unwrap(),
        };
        let mut original = Namespace::base(&[]).unwrap();
        for record in [
            Record::Create {
                at,
                kind: codec::CreateKind::File {
                    stage_id: 1,
                    exec: false,
                },
            },
            Record::WriteExtent {
                stage_id: 1,
                offset: 0,
                length: 4,
                check: codec::extent_check(1, 0, b"mark"),
            },
            Record::FileSynced {
                stage_id: 1,
                synced_size: 4,
                generation: 1,
                content: GrainId::of(b"mark"),
                prepared_root: GrainId::of(b"root"),
            },
            Record::Truncate {
                stage_id: 1,
                new_size: 3,
            },
        ] {
            original.fold(&record).unwrap();
        }
        let mut residual = original.clone();
        residual.stages.get_mut(&1).unwrap().mark = None;
        let compare = |candidate| {
            equivalent(
                candidate,
                &original,
                &BTreeMap::new(),
                &BTreeMap::new(),
                true,
            )
        };
        assert_eq!((compare(&original), compare(&residual)), (true, false));
    }
}
