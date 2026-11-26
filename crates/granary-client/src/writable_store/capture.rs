// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Receipt-bound capture coverage and generation-ordered local completion.

use super::{CoordinationError, PendingIntent, WritableStore, refused};
use crate::overlay_store::{
    CaptureToken, OverlayEntry, OverlayError, OverlayIo, RegisteredCapture, SyncBoundary,
};
use granary_core::encoding::{ObjectType, open_envelope};
use granary_core::grainsource::GrainSource;
use granary_core::hash::GrainId;
use granary_core::intent::{self, ReceiptState};
use granary_core::manifest::{self, EntryKind, FileGrains, GrainRef, Name};
use granary_core::overlay_journal::IntentCause;
use granary_core::overlay_ownership::Operation;
use std::collections::BTreeMap;

/// Namespace annotation in the sealed covering projection. Incarnations prevent
/// a reused stage number from inheriting an older file's identity.
#[derive(Debug, Clone)]
pub struct StageProjection {
    pub stage_id: u64,
    pub incarnation: u64,
    pub path: Vec<Name>,
    pub content_boundary: u64,
}

/// An identity-annotated journal mutation. A truncate touches its new EOF onward;
/// a write touches [offset, offset + length), including same-value writes.
/// A rollback invalidates every capture of its stage.
#[derive(Debug, Clone)]
pub enum StageMutation {
    Write {
        seq: u64,
        stage_id: u64,
        incarnation: u64,
        offset: u64,
        length: u64,
    },
    Truncate {
        seq: u64,
        stage_id: u64,
        incarnation: u64,
        size: u64,
    },
    Rollback {
        seq: u64,
        stage_id: u64,
        incarnation: u64,
    },
}

/// Complete provenance supplied by the overlay for an exact sealed root.
/// The producer must include every write, truncate and rollback through `boundary`, with
/// identities resolved at mutation time, and every projected stage annotation.
/// Fields are crate-private so application callers cannot fabricate journal
/// provenance. This is an input to validation, never an acknowledgement proof.
#[derive(Debug, Clone)]
pub struct CaptureCoverageInput {
    pub(crate) prepared_root: GrainId,
    pub(crate) boundary: u64,
    pub(crate) projections: Vec<StageProjection>,
    pub(crate) mutations: Vec<StageMutation>,
    pub(crate) identities: Vec<OverlayEntry>,
}

/// Outcome for one original caller, identified by its admitted generation.
#[derive(Debug)]
pub struct CaptureCompletion {
    pub generation: u64,
    pub result: Result<(), OverlayError>,
    registered: Option<RegisteredCapture>,
    files: Vec<RegisteredCapture>,
}

/// Persisted capture context handed to the sync engine after reopen. This
/// grants no acknowledgement: reconstruction remains the engine's job.
#[derive(Debug, Clone)]
pub struct ReopenedCapture {
    request: PendingIntent,
    context: Vec<u8>,
    generation: u64,
}
impl ReopenedCapture {
    #[must_use]
    pub fn request(&self) -> &PendingIntent {
        &self.request
    }
    #[must_use]
    pub fn context(&self) -> &[u8] {
        &self.context
    }
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}
impl CaptureCompletion {
    /// Sealed coverage evidence, available only after durable local completion.
    #[must_use]
    pub fn registered_capture(&self) -> Option<&RegisteredCapture> {
        self.registered.as_ref()
    }
    /// Receipt-bound proofs for the named dirty staged files marked by this call.
    #[must_use]
    pub fn registered_captures(&self) -> &[RegisteredCapture] {
        &self.files
    }
}

#[derive(Debug, Clone)]
pub(super) struct QueuedCapture {
    pub request: PendingIntent,
    pub files: Vec<QueuedFile>,
    pub boundary: Option<SyncBoundary>,
}

#[derive(Debug, Clone)]
pub(super) struct QueuedFile {
    pub capture: Option<CaptureToken>,
    pub entry: Option<OverlayEntry>,
    pub size: u64,
    pub through_seq: u64,
    pub grains: FileGrains,
    pub verified: bool,
    pub needs_mark: bool,
}

pub(super) fn lost() -> CoordinationError {
    OverlayError::CaptureCoverageLost.into()
}

pub(super) fn object(source: &dyn GrainSource, id: GrainId) -> Result<Vec<u8>, CoordinationError> {
    let bytes = source.get(&id).map_err(|_| lost())?;
    if GrainId::of(&bytes) != id {
        return Err(lost());
    }
    Ok(bytes)
}

pub(crate) fn entries(
    source: &dyn GrainSource,
    id: GrainId,
    depth: u32,
) -> Result<Vec<manifest::DirEntry>, CoordinationError> {
    entries_visiting(source, id, depth, &mut |_| Ok(()))
}

/// [`entries`], also reporting the id of every directory node it opens.
pub(crate) fn entries_visiting(
    source: &dyn GrainSource,
    id: GrainId,
    depth: u32,
    visit: &mut dyn FnMut(&GrainId) -> Result<(), CoordinationError>,
) -> Result<Vec<manifest::DirEntry>, CoordinationError> {
    if depth > manifest::DEPTH_MAX {
        return Err(lost());
    }
    visit(&id)?;
    let bytes = object(source, id)?;
    let (kind, cursor) = open_envelope(&bytes).map_err(|_| lost())?;
    match kind {
        ObjectType::DirLeaf => manifest::decode_dir_leaf(cursor).map_err(|_| lost()),
        ObjectType::DirInterior => {
            let mut out = Vec::new();
            for child in manifest::decode_dir_interior(cursor).map_err(|_| lost())? {
                out.extend(entries_visiting(source, child.child, depth + 1, visit)?);
            }
            Ok(out)
        }
        _ => Err(lost()),
    }
}

/// The overlay base entries of the tree under `root`, read from `source`,
/// sorted by path. `file` sees each file's size and grains as it is met,
/// `inode` gives each entry its inode from its path and kind, and an entry
/// of a kind an overlay cannot hold refuses with what `unknown` gives.
pub(crate) fn overlay_base_entries(
    source: &dyn GrainSource,
    root: GrainId,
    inode: &dyn Fn(&[Name], &crate::OverlayKind) -> u64,
    file: &mut dyn FnMut(u64, &FileGrains) -> Result<(), CoordinationError>,
    unknown: &dyn Fn() -> CoordinationError,
) -> Result<Vec<OverlayEntry>, CoordinationError> {
    let mut result = Vec::new();
    let mut work = vec![(root, Vec::new())];
    while let Some((id, prefix)) = work.pop() {
        for leaf in entries(source, id, 1)? {
            let mut path = prefix.clone();
            path.push(leaf.name);
            if let EntryKind::Dir { child } = &leaf.kind {
                work.push((*child, path.clone()));
            }
            if let EntryKind::File { size, grains, .. } = &leaf.kind {
                file(*size, grains)?;
            }
            let (kind, size, exec) =
                crate::OverlayKind::from_manifest(leaf.kind).ok_or_else(unknown)?;
            let inode = inode(&path, &kind);
            result.push(OverlayEntry {
                path,
                inode,
                kind,
                stage_id: None,
                size,
                exec,
            });
        }
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

/// Report the id of every object a file's payload names: each inline grain, or
/// the spill root, every grain-list node beneath it and every grain they list.
pub(crate) fn file_object_ids(
    source: &dyn GrainSource,
    grains: &FileGrains,
    visit: &mut dyn FnMut(&GrainId) -> Result<(), CoordinationError>,
) -> Result<(), CoordinationError> {
    fn walk(
        source: &dyn GrainSource,
        id: GrainId,
        depth: u32,
        visit: &mut dyn FnMut(&GrainId) -> Result<(), CoordinationError>,
    ) -> Result<(), CoordinationError> {
        if depth > manifest::DEPTH_MAX {
            return Err(lost());
        }
        visit(&id)?;
        let bytes = object(source, id)?;
        let (kind, cursor) = open_envelope(&bytes).map_err(|_| lost())?;
        match kind {
            ObjectType::GrainListLeaf => {
                for r in manifest::decode_grain_list_leaf(cursor).map_err(|_| lost())? {
                    visit(&r.id)?;
                }
                Ok(())
            }
            ObjectType::GrainListIndex => {
                for child in manifest::decode_grain_list_index(cursor).map_err(|_| lost())? {
                    walk(source, child.child, depth + 1, visit)?;
                }
                Ok(())
            }
            _ => Err(lost()),
        }
    }
    match grains {
        FileGrains::Inline(refs) => refs.iter().try_for_each(|r| visit(&r.id)),
        FileGrains::Spill { root, .. } => walk(source, *root, 1, visit),
    }
}

/// The entry at `path` under `root`, read from the validated decode of each
/// directory along the path and from nothing else: a directory is validated
/// once, by [`manifest::validate_dir_btree`], and the lookup navigates the very
/// entries that call returned, so no node is fetched or decoded a second time
/// between validation and use. Directories off the path are not read.
fn leaf(
    source: &dyn GrainSource,
    root: GrainId,
    path: &[Name],
) -> Result<EntryKind, CoordinationError> {
    let mut dir = root;
    let mut rest = path;
    loop {
        let (name, tail) = rest.split_first().ok_or_else(lost)?;
        let (entries, _children) =
            manifest::validate_dir_btree(&dir, &|id| source.get(id).ok()).map_err(|_| lost())?;
        let entry = entries
            .into_iter()
            .find(|entry| &entry.name == name)
            .ok_or_else(lost)?;
        if tail.is_empty() {
            return Ok(entry.kind);
        }
        let EntryKind::Dir { child } = entry.kind else {
            return Err(lost());
        };
        dir = child;
        rest = tail;
    }
}

fn refs(source: &dyn GrainSource, grains: &FileGrains) -> Result<Vec<GrainRef>, CoordinationError> {
    fn walk(
        source: &dyn GrainSource,
        id: GrainId,
        depth: u32,
    ) -> Result<Vec<GrainRef>, CoordinationError> {
        if depth > manifest::DEPTH_MAX {
            return Err(lost());
        }
        let bytes = object(source, id)?;
        let (kind, cursor) = open_envelope(&bytes).map_err(|_| lost())?;
        match kind {
            ObjectType::GrainListLeaf => {
                manifest::decode_grain_list_leaf(cursor).map_err(|_| lost())
            }
            ObjectType::GrainListIndex => {
                let mut out = Vec::new();
                for child in manifest::decode_grain_list_index(cursor).map_err(|_| lost())? {
                    out.extend(walk(source, child.child, depth + 1)?);
                }
                Ok(out)
            }
            _ => Err(lost()),
        }
    }
    match grains {
        FileGrains::Inline(r) => Ok(r.clone()),
        FileGrains::Spill { grain_count, root } => {
            let r = walk(source, *root, 1)?;
            if r.len() as u64 != u64::from(*grain_count) {
                return Err(lost());
            }
            Ok(r)
        }
    }
}

/// Authenticate a captured file payload using the same tree validator as a
/// covering leaf, including spilled-list aggregates and canonical storage.
pub(crate) fn captured_refs(
    source: &dyn GrainSource,
    size: u64,
    grains: &FileGrains,
) -> Result<Vec<GrainRef>, CoordinationError> {
    let tree = manifest::build_dir(&[manifest::DirEntry {
        name: Name::new(b"capture".to_vec()).map_err(|_| lost())?,
        kind: EntryKind::File {
            exec: false,
            size,
            grains: grains.clone(),
        },
    }])
    .map_err(|_| lost())?;
    manifest::validate_dir_tree(&tree.root, &|id| {
        tree.nodes
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, bytes)| bytes.clone())
            .or_else(|| source.get(id).ok())
    })
    .map_err(|_| lost())?;
    refs(source, grains)
}

fn verify_prefix(
    source: &dyn GrainSource,
    expected: &[GrainRef],
    covering: &[GrainRef],
    chunks: Option<&[Vec<u8>]>,
) -> Result<(), CoordinationError> {
    let mut captured = chunks
        .unwrap_or_default()
        .iter()
        .flat_map(|chunk| chunk.iter().copied());
    let mut covering_refs = covering.iter();
    let mut current = Vec::new().into_iter();
    for r in expected {
        let mut prefix = Vec::new();
        for _ in 0..r.unpacked_len {
            let byte = loop {
                if let Some(byte) = current.next() {
                    break byte;
                }
                let next = covering_refs.next().ok_or_else(lost)?;
                let bytes = object(source, next.id)?;
                if bytes.len() as u64 != u64::from(next.unpacked_len) {
                    return Err(lost());
                }
                current = bytes.into_iter();
            };
            prefix.push(byte);
        }
        if GrainId::of(&prefix) != r.id {
            return Err(lost());
        }
        if chunks.is_some() {
            let original: Vec<_> = captured.by_ref().take(r.unpacked_len as usize).collect();
            if original.len() as u64 != u64::from(r.unpacked_len) || GrainId::of(&original) != r.id
            {
                return Err(lost());
            }
        }
    }
    if captured.next().is_some() {
        return Err(lost());
    }
    Ok(())
}

fn seal(
    capture: &CaptureToken,
    grains: &FileGrains,
    root: &[u8],
    generation: u64,
    input: &CaptureCoverageInput,
    source: &dyn GrainSource,
    verified: bool,
) -> Result<RegisteredCapture, CoordinationError> {
    if GrainId::of(root) != input.prepared_root {
        return Err(lost());
    }
    let projection = input
        .projections
        .iter()
        .find(|p| p.stage_id == capture.stage_id() && p.incarnation == capture.incarnation())
        .ok_or_else(lost)?;
    if projection.content_boundary < capture.through_seq()
        || projection.content_boundary > input.boundary
    {
        return Err(lost());
    }
    for change in &input.mutations {
        let (seq, stage, incarnation, touches) = match *change {
            StageMutation::Write {
                seq,
                stage_id,
                incarnation,
                offset,
                length,
            } => {
                offset.checked_add(length).ok_or_else(lost)?;
                (
                    seq,
                    stage_id,
                    incarnation,
                    length != 0 && offset < capture.size(),
                )
            }
            StageMutation::Truncate {
                seq,
                stage_id,
                incarnation,
                size,
            } => (seq, stage_id, incarnation, size < capture.size()),
            StageMutation::Rollback {
                seq,
                stage_id,
                incarnation,
            } => (seq, stage_id, incarnation, true),
        };
        if seq > capture.through_seq()
            && seq <= input.boundary
            && stage == capture.stage_id()
            && incarnation == capture.incarnation()
            && touches
        {
            return Err(lost());
        }
    }
    let doc = granary_core::root::decode_root(root).map_err(|_| lost())?;
    let EntryKind::File {
        size,
        grains: covering_grains,
        ..
    } = leaf(source, doc.manifest_root, &projection.path)?
    else {
        return Err(lost());
    };
    if size < capture.size() {
        return Err(lost());
    }
    let expected = captured_refs(source, capture.size(), grains)?;
    verify_prefix(
        source,
        &expected,
        &refs(source, &covering_grains)?,
        (!verified).then(|| capture.chunks()),
    )?;
    let content =
        GrainId::of(&manifest::node::file_payload(capture.size(), grains).map_err(|_| lost())?);
    Ok(RegisteredCapture {
        capture: capture.clone(),
        writer: doc.writer_uuid,
        generation,
        prepared_root: input.prepared_root,
        content,
    })
}

fn seal_file(
    file: &QueuedFile,
    root: &[u8],
    generation: u64,
    input: &CaptureCoverageInput,
    source: &dyn GrainSource,
) -> Result<Option<RegisteredCapture>, CoordinationError> {
    if GrainId::of(root) != input.prepared_root || input.boundary < file.through_seq {
        return Err(lost());
    }
    if let Some(capture) = &file.capture {
        if capture.captured_path().is_none() && file.verified {
            return Ok(None);
        }
        let proof = seal(
            capture,
            &file.grains,
            root,
            generation,
            input,
            source,
            file.verified,
        )?;
        return Ok(file.needs_mark.then_some(proof));
    }
    if !file.verified {
        return Err(lost());
    }
    let entry = file.entry.as_ref().ok_or_else(lost)?;
    let covering = input
        .identities
        .iter()
        .find(|p| p.inode == entry.inode)
        .ok_or_else(lost)?;
    if let Some(stage) = covering.stage_id
        && input.mutations.iter().any(|mutation| match mutation {
            StageMutation::Write {
                seq,
                stage_id,
                offset,
                length,
                ..
            } => {
                *stage_id == stage
                    && *seq > file.through_seq
                    && *seq <= input.boundary
                    && *length != 0
                    && *offset < file.size
            }
            StageMutation::Truncate {
                seq,
                stage_id,
                size,
                ..
            } => {
                *stage_id == stage
                    && *seq > file.through_seq
                    && *seq <= input.boundary
                    && *size < file.size
            }
            StageMutation::Rollback { seq, stage_id, .. } => {
                *stage_id == stage && *seq > file.through_seq && *seq <= input.boundary
            }
        })
    {
        return Err(lost());
    }
    let doc = granary_core::root::decode_root(root).map_err(|_| lost())?;
    let EntryKind::File { size, grains, .. } = leaf(source, doc.manifest_root, &covering.path)?
    else {
        return Err(lost());
    };
    if size < file.size {
        return Err(lost());
    }
    verify_prefix(
        source,
        &captured_refs(source, file.size, &file.grains)?,
        &refs(source, &grains)?,
        None,
    )?;
    Ok(None)
}

/// Owned receipt/root/capture work; no local guard survives its extraction.
#[derive(Debug)]
pub struct CaptureCompletionWork {
    ready: Vec<(u64, QueuedCapture, Vec<u8>)>,
    roots: BTreeMap<(u64, GrainId), Vec<u8>>,
}

/// Sealed authenticated completion plan. Applying it revalidates local context.
#[derive(Debug)]
pub struct ValidatedCaptureCompletions {
    work: CaptureCompletionWork,
    marks: BTreeMap<u64, RegisteredCapture>,
    results: Vec<CaptureCompletion>,
    highest: Option<(u64, GrainId)>,
}

impl CaptureCompletionWork {
    fn prove_queued(
        &self,
        generation: u64,
        queued: &QueuedCapture,
        answer: &[u8],
        inputs: &BTreeMap<GrainId, CaptureCoverageInput>,
        source: &dyn GrainSource,
    ) -> Result<(CaptureCompletion, Option<(u64, GrainId)>), CoordinationError> {
        let mut completion = CaptureCompletion {
            generation,
            result: Ok(()),
            registered: None,
            files: Vec::new(),
        };
        if answer.is_empty() {
            completion.result = Err(OverlayError::Refused("IntentCaptureRegistrationRefused"));
            return Ok((completion, None));
        }
        let receipt = intent::decode_receipt(answer).map_err(|_| lost())?;
        let ReceiptState::Live { prepared_root_id } = receipt.state else {
            return Err(lost());
        };
        let sent =
            intent::decode_register(queued.request.bytes(), queued.request.volume(), |_, _| true)
                .map_err(|_| lost())?;
        if receipt.writer != sent.writer
            || receipt.epoch != sent.epoch
            || receipt.instance != sent.instance
            || receipt.generation < generation
        {
            return Err(lost());
        }
        let Some(root) = self.roots.get(&(receipt.generation, prepared_root_id)) else {
            completion.result = Err(OverlayError::CaptureCoverageLost);
            return Ok((completion, None));
        };
        let input = inputs
            .get(&prepared_root_id)
            .ok_or_else(|| refused("IntentCaptureProvenanceUnavailable"))?;
        if let Some(boundary) = &queued.boundary
            && (input.boundary < boundary.through_seq() || input.prepared_root != prepared_root_id)
        {
            completion.result = Err(OverlayError::CaptureCoverageLost);
            return Ok((completion, Some((receipt.generation, prepared_root_id))));
        }
        for file in &queued.files {
            match seal_file(file, root, receipt.generation, input, source) {
                Ok(Some(proof)) => completion.files.push(proof),
                Ok(None) => {}
                Err(CoordinationError::Overlay(OverlayError::CaptureCoverageLost)) => {
                    completion.result = Err(OverlayError::CaptureCoverageLost);
                    completion.files.clear();
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        completion.registered = completion.files.first().cloned();
        Ok((completion, Some((receipt.generation, prepared_root_id))))
    }
    /// Authenticate coverage and the winning mirrors outside the mediator.
    /// # Errors
    /// Missing/corrupt provenance or objects; per-caller coverage loss is retained.
    pub fn validate(
        self,
        inputs: &BTreeMap<GrainId, CaptureCoverageInput>,
        source: &dyn GrainSource,
    ) -> Result<ValidatedCaptureCompletions, CoordinationError> {
        let mut marks: BTreeMap<u64, RegisteredCapture> = BTreeMap::new();
        let mut results = Vec::new();
        let mut highest = None;
        for (generation, queued, answer) in &self.ready {
            let (completion, receipt) =
                self.prove_queued(*generation, queued, answer, inputs, source)?;
            if let Some(receipt) = receipt
                && highest.is_none_or(|(generation, _)| generation < receipt.0)
            {
                highest = Some(receipt);
            }
            for proof in &completion.files {
                let stage = proof.capture.stage_id();
                if marks.get(&stage).is_none_or(|previous| {
                    (previous.generation, previous.capture.size())
                        <= (proof.generation, proof.capture.size())
                }) {
                    marks.insert(stage, proof.clone());
                }
            }
            results.push(completion);
        }
        // Every successful caller must fit the actual durable stage anchor.
        // Size alone cannot distinguish equal-length overwrites. Reprove
        // older prefixes against the winner's authenticated root and full
        // no-touch journal provenance, including same-value overwrites.
        for (completion, (_, queued, _)) in results.iter_mut().zip(&self.ready) {
            for file in &queued.files {
                let Some(capture) = &file.capture else {
                    continue;
                };
                let Some(mark) = marks.get(&capture.stage_id()) else {
                    continue;
                };
                if mark.capture.id() == capture.id() {
                    continue;
                }
                let input = inputs
                    .get(&mark.prepared_root)
                    .ok_or_else(|| refused("IntentCaptureProvenanceUnavailable"))?;
                let root = self
                    .roots
                    .get(&(mark.generation, mark.prepared_root))
                    .ok_or_else(lost)?;
                match seal_file(file, root, mark.generation, input, source) {
                    Ok(_) => {}
                    Err(CoordinationError::Overlay(OverlayError::CaptureCoverageLost)) => {
                        completion.result = Err(OverlayError::CaptureCoverageLost);
                        completion.registered = None;
                        completion.files.clear();
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(ValidatedCaptureCompletions {
            work: self,
            marks,
            results,
            highest,
        })
    }
}

impl<P: OverlayIo> WritableStore<P> {
    fn covering_root(&self, generation: u64, prepared_root_id: GrainId) -> Option<Vec<u8>> {
        self.carrier
            .pending
            .iter()
            .find_map(|pending| {
                if pending.operation != Operation::Register {
                    return None;
                }
                intent::decode_register(&pending.body, &self.config.volume, |_, _| true)
                    .ok()
                    .filter(|r| r.generation == generation && r.root_id() == prepared_root_id)
                    .map(|r| r.root.to_vec())
            })
            .or_else(|| {
                (GrainId::of(&self.carrier.root) == prepared_root_id)
                    .then(|| self.carrier.root.clone())
            })
    }

    /// Surface persisted contexts without inventing process-local capture tokens.
    /// # Errors
    /// Fencing, persistence poison or malformed retained registration.
    pub fn reopened_captures(&self) -> Result<Vec<ReopenedCapture>, CoordinationError> {
        self.check()?;
        self.carrier
            .pending
            .iter()
            .filter(|p| p.operation == Operation::Register && !p.context.is_empty())
            .filter_map(|p| match p.generation() {
                Ok(generation) if !self.capture_queue.contains_key(&generation) => {
                    Some(Ok(ReopenedCapture {
                        request: self.pending(p.operation, p.body.clone()),
                        context: p.context.clone(),
                        generation,
                    }))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error.into())),
            })
            .collect()
    }

    /// Durably fail a reopened caller when its capture cannot be reconstructed.
    /// The exact network evidence is preserved; an unresolved network request
    /// still requires reconciliation even after its local caller has failed.
    /// # Errors
    /// Stale handoff, a live process-local capture, fencing or persistence failure.
    pub fn fail_reopened_capture(
        &mut self,
        capture: &ReopenedCapture,
    ) -> Result<CaptureCompletion, CoordinationError> {
        self.check()?;
        let index = self.locate(&capture.request)?;
        let pending = self.carrier.pending.get(index).ok_or_else(lost)?;
        if self.capture_queue.contains_key(&capture.generation)
            || pending.context != capture.context
            || capture.context.is_empty()
        {
            return Err(refused("IntentCaptureRecoveryBinding"));
        }
        let mut next = self.carrier.clone();
        next.pending
            .get_mut(index)
            .ok_or_else(lost)?
            .context
            .clear();
        self.persist(next)?;
        Ok(CaptureCompletion {
            generation: capture.generation,
            result: Err(OverlayError::Refused("IntentCaptureRecoveryFailed")),
            registered: None,
            files: Vec::new(),
        })
    }
    /// Admit a captured registration in generation order. The grain payload is
    /// verified against immutable captured bytes at completion, never live staging.
    /// # Errors
    /// Invalid capture context, admission bounds, signature or persistence failure.
    pub fn prepare_captured_registration(
        &mut self,
        root: &[u8],
        capture: CaptureToken,
        grains: FileGrains,
        clock: &impl granary_core::clock::Clock,
        verify: impl FnMut(&granary_core::root::RootDoc, &[u8]) -> bool,
    ) -> Result<PendingIntent, CoordinationError> {
        self.overlay
            .as_ref()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .validate_capture(&capture)?;
        let context = [
            capture.stage_id().to_be_bytes(),
            capture.incarnation().to_be_bytes(),
            capture.through_seq().to_be_bytes(),
        ]
        .concat();
        let request = self.prepare_registration(root, context, clock, verify)?;
        let g = intent::decode_register(request.bytes(), request.volume(), |_, _| true)
            .map_err(|_| lost())?
            .generation;
        self.capture_queue.insert(
            g,
            QueuedCapture {
                request: request.clone(),
                files: vec![QueuedFile {
                    size: capture.size(),
                    through_seq: capture.through_seq(),
                    capture: Some(capture),
                    entry: None,
                    grains,
                    verified: false,
                    needs_mark: true,
                }],
                boundary: None,
            },
        );
        Ok(request)
    }

    /// Detach a ready admission prefix. The engine validates this owned work
    /// outside every mediator guard, then applies its sealed plan locally.
    /// # Errors
    /// Fenced/poisoned service, stale captures or malformed retained receipt.
    pub fn capture_completion_work(
        &self,
    ) -> Result<Option<CaptureCompletionWork>, CoordinationError> {
        self.check()?;
        let mut ready = Vec::new();
        let mut roots = BTreeMap::new();
        for (generation, queued) in &self.capture_queue {
            let pending = self
                .carrier
                .pending
                .get(self.locate(&queued.request)?)
                .ok_or_else(lost)?;
            if !pending.terminal {
                break;
            }
            if let Some(boundary) = &queued.boundary {
                self.overlay
                    .as_ref()
                    .ok_or_else(lost)?
                    .validate_flushed_sync_boundary(boundary)?;
            }
            if !pending.answer.is_empty() {
                let receipt = intent::decode_receipt(&pending.answer).map_err(|_| lost())?;
                if let ReceiptState::Live { prepared_root_id } = receipt.state
                    && let Some(root) = self.covering_root(receipt.generation, prepared_root_id)
                {
                    roots.insert((receipt.generation, prepared_root_id), root);
                }
            }
            ready.push((*generation, queued.clone(), pending.answer.clone()));
        }
        Ok((!ready.is_empty()).then_some(CaptureCompletionWork { ready, roots }))
    }

    /// Persist a validated plan in generation order, rechecking its exact
    /// request answers, admission prefix, live captures and base context first.
    /// This step performs only local bookkeeping/barriers; it invokes no provider.
    /// # Errors
    /// Stale/foreign plan, fencing, invalid context or persistence uncertainty.
    pub fn apply_capture_completions(
        &mut self,
        plan: ValidatedCaptureCompletions,
    ) -> Result<Vec<CaptureCompletion>, CoordinationError> {
        let result = self.apply_validated_captures(plan);
        self.retain_overlay_bundle(result.as_ref().err().and_then(|error| {
            if let CoordinationError::Overlay(error) = error {
                Some(error)
            } else {
                None
            }
        }));
        self.poisoned |= self
            .overlay
            .as_ref()
            .is_some_and(|overlay| overlay.readiness() == crate::OverlayReadiness::Poisoned);
        result
    }

    fn apply_validated_captures(
        &mut self,
        plan: ValidatedCaptureCompletions,
    ) -> Result<Vec<CaptureCompletion>, CoordinationError> {
        self.check()?;
        let ValidatedCaptureCompletions {
            work,
            marks,
            results,
            highest,
        } = plan;
        let ready = work.ready;
        if self
            .capture_queue
            .keys()
            .take(ready.len())
            .copied()
            .ne(ready.iter().map(|(g, _, _)| *g))
        {
            return Err(refused("IntentCaptureCompletionStale"));
        }
        for (_, queued, answer) in &ready {
            let pending = self
                .carrier
                .pending
                .get(self.locate(&queued.request)?)
                .ok_or_else(lost)?;
            if !pending.terminal || pending.answer != *answer {
                return Err(refused("IntentCaptureCompletionStale"));
            }
            let overlay = self.overlay.as_ref().ok_or_else(lost)?;
            if let Some(boundary) = &queued.boundary {
                overlay.validate_flushed_sync_boundary(boundary)?;
            }
            for file in &queued.files {
                if let Some(capture) = &file.capture {
                    overlay.validate_capture(capture)?;
                }
            }
        }
        let permission = self.permission()?;
        let overlay = self.overlay.as_mut().ok_or_else(lost)?;
        let mut ordered_marks: Vec<_> = marks.values().collect();
        ordered_marks.sort_by_key(|proof| proof.generation);
        for proof in ordered_marks {
            overlay.record_file_synced(&mut self.store, &permission, proof)?;
        }
        for (_, queued, _) in &ready {
            for file in &queued.files {
                if let Some(capture) = &file.capture
                    && !marks.values().any(|mark| mark.capture.id() == capture.id())
                {
                    overlay.complete_failed_capture(capture)?;
                }
            }
        }
        if let Some((generation, prepared_root_id)) = highest {
            overlay.record_intent_registered(
                &mut self.store,
                &permission,
                generation,
                prepared_root_id,
                IntentCause::DirectorySync,
            )?;
        }
        let mut next = self.carrier.clone();
        for (_, queued, _) in &ready {
            let index = self.locate(&queued.request)?;
            next.pending
                .get_mut(index)
                .ok_or_else(lost)?
                .context
                .clear();
        }
        self.persist(next)?;
        for (generation, queued, _) in ready {
            if let Some(boundary) = &queued.boundary {
                self.overlay
                    .as_mut()
                    .ok_or_else(lost)?
                    .release_sync_boundary(boundary)?;
            }
            self.capture_queue.remove(&generation);
        }
        self.floor_changed.notify_waiters();
        Ok(results)
    }

    /// Synchronous adapter for callers already outside a mediator guard. Engines
    /// use owned completion work so callbacks never enclose local transactions.
    /// # Errors
    /// Unavailable provenance, stale completion, fencing or persistence failure.
    pub fn complete_capture_queue(
        &mut self,
        inputs: &BTreeMap<GrainId, CaptureCoverageInput>,
        source: &dyn GrainSource,
    ) -> Result<Vec<CaptureCompletion>, CoordinationError> {
        let mut completions = Vec::new();
        while let Some(work) = self.capture_completion_work()? {
            let plan = work.validate(inputs, source)?;
            completions.extend(self.apply_capture_completions(plan)?);
        }
        Ok(completions)
    }
}
