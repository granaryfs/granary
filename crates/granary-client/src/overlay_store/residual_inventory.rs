// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Choice-independent residual collision inventory and reconciliation plan.

use super::{
    BTreeMap, OverlayConfig, OverlayEntry, OverlayError, OverlayIo, OverlayKind, Path, Record,
    StagingHeader, codec, provenance::History, replacement, residual::ResidualAnchors,
    snapshot::ReplayContext,
};
use crate::{CoordinationError, recovery::ResidualSource, sync::refused};
use granary_core::{
    encoding::{ObjectType, open_envelope},
    hash::{GrainId, GrainIdHasher},
    manifest::{self, FileGrains, GrainRef},
    overlay_journal::ResidualFile,
};
use std::collections::BTreeSet;

/// The fixed workspace used by every residual preflight consumer.
pub(crate) const RESIDUAL_PREFLIGHT_WORKSPACE_BYTES: u64 = 16_777_216;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ReconciliationPlan {
    equal_stages: BTreeMap<u64, ReconciledStage>,
}

impl ReconciliationPlan {
    pub(super) fn contains(&self, stage_id: u64) -> bool {
        self.equal_stages.contains_key(&stage_id)
    }

    pub(super) fn insert(&mut self, stage_id: u64, stage: ReconciledStage) {
        self.equal_stages.insert(stage_id, stage);
    }

    pub(super) fn stages(&self) -> &BTreeMap<u64, ReconciledStage> {
        &self.equal_stages
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReconciledStage {
    pub(super) size: u64,
    pub(super) payload_check: [u8; 32],
    pub(super) header: StagingHeader,
}

#[derive(Debug)]
pub(crate) struct ResidualInventory {
    pub(crate) collisions: Vec<ResidualFile>,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read-only residual validation does not grant installation authority"
        )
    )]
    pub(crate) reconciliation: ReconciliationPlan,
}

fn same_entry(a: Option<&OverlayEntry>, b: Option<&OverlayEntry>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.kind == b.kind && a.size == b.size && a.exec == b.exec,
        _ => false,
    }
}

fn unknown() -> CoordinationError {
    refused("RecoveryResidualCaptureUnknown")
}

fn walk_captured_refs<C, V>(
    id: GrainId,
    depth: u32,
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    check: &mut C,
    visit: &mut V,
) -> Result<(u64, u64), CoordinationError>
where
    C: FnMut() -> Result<(), CoordinationError>,
    V: FnMut(GrainRef, &mut C) -> Result<(), CoordinationError>,
{
    check()?;
    if depth > manifest::DEPTH_MAX {
        return Err(unknown());
    }
    // Closure authentication charged each retained node with Budget::charge's
    // eight-times multiplier. Decoder vectors are bounded by one recursion
    // path and spend that allowance without charging the retained bytes again.
    let bytes = nodes.get(&id).ok_or_else(unknown)?;
    if GrainId::of(bytes) != id {
        return Err(unknown());
    }
    let (kind, cursor) = open_envelope(bytes).map_err(|_| unknown())?;
    match kind {
        ObjectType::GrainListLeaf => {
            let refs = manifest::decode_grain_list_leaf(cursor).map_err(|_| unknown())?;
            let mut length = 0u64;
            let mut count = 0u64;
            for grain in refs {
                length = length
                    .checked_add(u64::from(grain.unpacked_len))
                    .ok_or_else(unknown)?;
                count = count.checked_add(1).ok_or_else(unknown)?;
                visit(grain, check)?;
            }
            Ok((length, count))
        }
        ObjectType::GrainListIndex => {
            let children = manifest::decode_grain_list_index(cursor).map_err(|_| unknown())?;
            let mut length = 0u64;
            let mut count = 0u64;
            for child in children {
                let (child_length, child_count) =
                    walk_captured_refs(child.child, depth + 1, nodes, check, visit)?;
                length = length.checked_add(child_length).ok_or_else(unknown)?;
                count = count.checked_add(child_count).ok_or_else(unknown)?;
                if length != child.cum_unpacked_len || count != child.cum_ref_count {
                    return Err(unknown());
                }
            }
            Ok((length, count))
        }
        _ => Err(unknown()),
    }
}

fn visit_captured_refs<C, V>(
    payload: &crate::recovery::CapturedPayload,
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    check: &mut C,
    mut visit: V,
) -> Result<(), CoordinationError>
where
    C: FnMut() -> Result<(), CoordinationError>,
    V: FnMut(GrainRef, &mut C) -> Result<(), CoordinationError>,
{
    let mut length = 0u64;
    let mut count = 0u64;
    match &payload.grains {
        FileGrains::Inline(refs) => {
            for &grain in refs {
                length = length
                    .checked_add(u64::from(grain.unpacked_len))
                    .ok_or_else(unknown)?;
                count = count.checked_add(1).ok_or_else(unknown)?;
                visit(grain, check)?;
            }
        }
        FileGrains::Spill { grain_count, root } => {
            let (walked_length, walked_count) =
                walk_captured_refs(*root, 1, nodes, check, &mut visit)?;
            length = walked_length;
            count = walked_count;
            if count != u64::from(*grain_count) {
                return Err(unknown());
            }
        }
    }
    if length != payload.size || count != u64::from(payload.grains.grain_count()) {
        return Err(unknown());
    }
    Ok(())
}

fn read_payload_chunk(
    io: &mut impl OverlayIo,
    path: &Path,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, CoordinationError> {
    let bytes = io
        .read_at(path, 160_u64.saturating_add(offset), length)
        .map_err(|_| refused("RecoveryResidualUnavailable"))?;
    if bytes.len() != length {
        return Err(refused("RecoveryResidualPayloadLength"));
    }
    Ok(bytes)
}

#[expect(
    clippy::too_many_lines,
    reason = "the sealed capture, residual support and complete inventory are checked before any admission"
)]
pub(crate) fn inventory(
    io: &mut impl OverlayIo,
    area: &Path,
    config: &OverlayConfig,
    source: &ResidualSource,
    mut check: impl FnMut() -> Result<(), CoordinationError>,
) -> Result<ResidualInventory, CoordinationError> {
    check()?;
    let old = source.journal.as_slice();
    let base = &source.base_entries;
    let (namespace, history) = History::prefix(base, old, source.source_end)?;
    let context = ReplayContext::retained(source.header, config)?;
    if history.records.iter().any(|effect| {
        effect.seq != source.boundary_seq
            && matches!(
                effect.record,
                Record::CommitBoundary { .. } | Record::ProjectedBoundary { .. }
            )
    }) {
        return Err(refused("RecoveryResidualUnrepresentable"));
    }
    let mut through = None;
    let mut projected = false;
    for effect in &history.records {
        if effect.seq == source.boundary_seq {
            match effect.record {
                Record::CommitBoundary { through_seq, .. } => through = Some(through_seq),
                Record::ProjectedBoundary { through_seq, .. } => {
                    through = Some(through_seq);
                    projected = true;
                }
                _ => {}
            }
        }
    }
    let through = through.ok_or_else(|| refused("RecoveryResidualSourceChanged"))?;
    let bound_after_capture = |stage_id| {
        history.records.iter().any(|effect| {
            effect.seq > through
                && matches!(effect.record, Record::StageBind { stage_id: id, .. } if id == stage_id)
        })
    };
    let (captured, records) = if projected {
        let prefix = replacement::projected_prefix(
            &context,
            base,
            old,
            source.boundary_seq,
            source.publication_id,
        )?;
        let residual = super::residual::residual(
            old,
            base,
            &prefix,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &ReconciliationPlan::default(),
        )
        .map_err(|_| refused("RecoveryResidualUnrepresentable"))?;
        (prefix.projection.entries().to_vec(), residual.records)
    } else {
        let captured =
            replacement::commit_entries(base, old, source.boundary_seq, source.publication_id)?;
        let records = history
            .records
            .iter()
            .filter(|effect| effect.seq > through && !super::residual::control(&effect.record))
            .map(|effect| effect.record.clone())
            .collect();
        (captured, records)
    };
    if captured.len() != source.proof.captured_entries.len()
        || captured
            .iter()
            .zip(&source.proof.captured_entries)
            .any(|(a, b)| {
                a.path != b.path
                    || a.size != b.size
                    || a.exec != b.exec
                    || !(a.kind == b.kind
                        || matches!(
                            (&a.kind, &b.kind),
                            (
                                OverlayKind::File { content: None },
                                OverlayKind::File { content: Some(_) }
                            )
                        ))
            })
    {
        return Err(refused("RecoveryResidualCaptureChanged"));
    }
    let captured: BTreeMap<_, _> = source
        .proof
        .captured_entries
        .iter()
        .map(|e| (e.path.clone(), e))
        .collect();
    let landed: BTreeMap<_, _> = source
        .proof
        .entries
        .iter()
        .map(|e| (e.path.clone(), e))
        .collect();
    let residual = namespace;
    let mut collisions = BTreeMap::new();
    let mut paths = BTreeSet::new();
    let mut anchors = ResidualAnchors::default();
    for record in &records {
        let id = match record {
            Record::RecreateFile { stage_id, .. } => Some(*stage_id),
            _ => replacement::reference(record),
        };
        if let Some(id) = id
            && let Some(stage) = residual.stages.get(&id)
            && let Some(path) = &stage.path
            && !same_entry(captured.get(path).copied(), landed.get(path).copied())
        {
            let entry = residual
                .entries
                .get(path)
                .ok_or_else(|| refused("RecoveryResidualUnrepresentable"))?;
            if !matches!(entry.kind, OverlayKind::File { .. })
                || !landed.get(path).is_some_and(|entry| {
                    matches!(entry.kind, OverlayKind::File { content: Some(_) })
                })
            {
                return Err(refused("RecoveryResidualUnrepresentable"));
            }
            collisions.insert(id, entry);
            paths.insert(path.clone());
        }
        let payload_only = matches!(
            record,
            Record::Create {
                kind: codec::CreateKind::File { .. },
                ..
            } | Record::StageBind { .. }
                | Record::RecreateFile { at: Some(_), .. }
        );
        if !payload_only {
            anchors.record(record);
        }
        let (source, destination) = super::provenance::record_paths(record);
        for path in source.into_iter().chain(destination) {
            paths.insert(path);
        }
    }
    if !collisions.is_empty() {
        source
            .budget
            .charge(super::BUFFER.saturating_add(std::mem::size_of::<GrainIdHasher>()))
            .map_err(|_| refused("RecoveryResidualWorkspace"))?;
    }
    let mut files = Vec::new();
    let mut reconciliation = ReconciliationPlan::default();
    let mut writer = None;
    for (id, entry) in collisions {
        check()?;
        let path = area.join("staging").join(format!("{id:016x}"));
        let length = entry
            .size
            .checked_add(160)
            .ok_or_else(|| refused("RecoveryResidualPayloadLength"))?;
        if io
            .length(&path)
            .map_err(|_| refused("RecoveryResidualUnavailable"))?
            != Some(length)
        {
            return Err(refused("RecoveryResidualPayloadLength"));
        }
        check()?;
        let header = StagingHeader::decode(
            &io.read_at(&path, 0, 160)
                .map_err(|_| refused("RecoveryResidualUnavailable"))?,
        )
        .map_err(|_| refused("RecoveryResidualPayloadHeader"))?;
        header
            .check_binding(&source.header.writer, id)
            .map_err(|_| refused("RecoveryResidualPayloadHeader"))?;
        let stage = residual.stages.get(&id);
        match (header.mark, stage.and_then(|stage| stage.mark)) {
            (codec::MarkState::Absent, None) => {}
            (codec::MarkState::Present(mark), Some(journal)) if mark == journal => {}
            (codec::MarkState::Present(mark), _) if stage.is_some_and(|s| s.agrees_with(mark)) => {
                check()?;
                let writer = writer
                    .get_or_insert_with(|| super::recovery::read_writer(io, &area.join("writer")))
                    .as_ref()
                    .map_err(|error| match error {
                        OverlayError::Io(_) => refused("RecoveryResidualUnavailable"),
                        _ => refused("RecoveryResidualPayloadHeader"),
                    })?;
                if writer.writer != source.header.writer || mark.generation > writer.ceiling {
                    return Err(refused("RecoveryResidualPayloadHeader"));
                }
            }
            _ => return Err(refused("RecoveryResidualPayloadHeader")),
        }
        let mut hash = codec::ResidualPayloadHasher::new(id, entry.size);
        let captured_entry = captured.get(&entry.path).copied();
        let mut equal = false;
        if let Some(captured_entry) = captured_entry
            && captured_entry.size == entry.size
        {
            let OverlayKind::File {
                content: Some(captured_content),
            } = captured_entry.kind
            else {
                return Err(refused("RecoveryResidualUnrepresentable"));
            };
            let payload = source
                .captured
                .payloads
                .get(&captured_content)
                .ok_or_else(unknown)?;
            if payload.size != captured_entry.size {
                return Err(unknown());
            }
            equal = true;
            let mut offset = 0u64;
            visit_captured_refs(
                payload,
                &source.captured.nodes,
                &mut check,
                |grain, check| {
                    let mut grain_hash = GrainIdHasher::new(grain.id.algorithm());
                    let mut remaining = u64::from(grain.unpacked_len);
                    while remaining > 0 {
                        check()?;
                        let n = usize::try_from(remaining.min(super::BUFFER as u64))
                            .map_err(|_| refused("RecoveryResidualWorkspace"))?;
                        let bytes = read_payload_chunk(io, &path, offset, n)?;
                        hash.update(&bytes);
                        grain_hash.update(&bytes);
                        let read =
                            u64::try_from(n).map_err(|_| refused("RecoveryResidualWorkspace"))?;
                        offset = offset
                            .checked_add(read)
                            .ok_or_else(|| refused("RecoveryResidualPayloadLength"))?;
                        remaining = remaining.saturating_sub(read);
                    }
                    if grain_hash.finalize() != grain.id {
                        equal = false;
                    }
                    Ok(())
                },
            )?;
            if offset != entry.size {
                return Err(unknown());
            }
        } else {
            let mut offset = 0u64;
            while offset < entry.size {
                check()?;
                let n = usize::try_from((entry.size - offset).min(super::BUFFER as u64))
                    .map_err(|_| refused("RecoveryResidualWorkspace"))?;
                let bytes = read_payload_chunk(io, &path, offset, n)?;
                hash.update(&bytes);
                offset = offset.saturating_add(
                    u64::try_from(n).map_err(|_| refused("RecoveryResidualWorkspace"))?,
                );
            }
        }
        let payload_check = hash.finalize();
        if equal {
            let captured_entry =
                captured_entry.ok_or_else(|| refused("RecoveryResidualUnrepresentable"))?;
            if entry.exec != captured_entry.exec {
                return Err(refused("RecoveryResidualExecChanged"));
            }
            // Installation can retire only a stage represented at the
            // boundary. A later binding remains an ordinary collision.
            if !bound_after_capture(id) {
                reconciliation.insert(
                    id,
                    ReconciledStage {
                        size: entry.size,
                        payload_check,
                        header,
                    },
                );
                continue;
            }
        }
        let (name, parent) = entry
            .path
            .split_last()
            .ok_or_else(|| refused("RecoveryResidualUnrepresentable"))?;
        files.push(codec::ResidualFile {
            stage_id: id,
            at: codec::Location {
                parent: codec::Parent::new(parent.to_vec())
                    .map_err(|_| refused("RecoveryResidualUnrepresentable"))?,
                name: name.clone(),
            },
            exec: entry.exec,
            local_size: entry.size,
            payload_check,
        });
    }
    if anchors
        .mismatch(&source.proof.captured_entries, &source.proof.entries)
        .is_some()
    {
        return Err(refused("RecoveryResidualUnrepresentable"));
    }
    for path in paths {
        let mut parent = path.as_slice();
        while let Some((_, prefix)) = parent.split_last() {
            if !same_entry(captured.get(prefix).copied(), landed.get(prefix).copied()) {
                return Err(refused("RecoveryResidualUnrepresentable"));
            }
            parent = prefix;
        }
    }
    Ok(ResidualInventory {
        collisions: files,
        reconciliation,
    })
}
