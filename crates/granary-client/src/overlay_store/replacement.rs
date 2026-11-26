// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Landing, rejection and adoption replacements, with a split build/install
//! transaction interface.

use super::{
    BTreeMap, CompletionReserve, ContentSource, GrainId, JournalHeader, JournalState, LandedProof,
    MarkState, Namespace, OverlayEntry, OverlayError, OverlayIo, OverlayKind, OverlayReadiness,
    OverlayStore, OwnershipStatus, Record, StagingHeader, Store, ViewChange, WriterRecord, codec,
    local_content::LocalContent, point, sync_step, write_step,
};
use crate::RejectionProof;
use std::collections::BTreeSet;

mod recovered;
pub(crate) use recovered::{RecoveredSuffix, RecoveryPrefix};

#[derive(Debug)]
pub struct ReplacementPlan {
    proof: LandedProof,
    original: JournalHeader,
    source: ImageSource,
    reconciliation: super::residual_inventory::ReconciliationPlan,
}

/// What a replacement's image is rebuilt from at its install.
#[derive(Debug)]
enum ImageSource {
    /// The landing `proof` records.
    Landing,
    /// The removal of one rejected boundary, with its non-landing evidence.
    Rejected(u64, [u8; 16], Option<RejectionProof>, bool),
    /// A header-only journal on the verified base `proof` names.
    Adopted,
    RecoveredSuffix(RecoveredSuffix),
}

#[cfg(test)]
std::thread_local! {
    pub(super) static FOLD_FAULT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// A projected boundary's seal as its replay rebuilds it: the namespace at its
/// cursor, the sealed effects and the projection of its saved selection.
#[derive(Debug)]
pub(super) struct ProjectedPrefix {
    pub through: u64,
    /// Journal cursor whose payload each covered stage projects.
    pub coverage: BTreeMap<u64, u64>,
    /// Recovery's canonical equality proofs for trailing rewrites.
    pub unchanged: Option<BTreeSet<u64>>,
    pub namespace: Namespace,
    pub sealed: super::SyncBoundary,
    pub projection: super::PreparedProjection,
}

struct Image {
    bytes: Vec<u8>,
    scan: codec::JournalScan,
    namespace: Namespace,
    retired: Vec<u64>,
    through_seq: u64,
    /// For a projected landing, the source seqs of the residual's dirty work;
    /// a whole-tree landing keeps the work after `through_seq` instead.
    residual_dirty: Option<Vec<u64>>,
    recovered_dirty: Option<Vec<super::DirtySpan>>,
}

impl<P: OverlayIo> OverlayStore<P> {
    fn rebuilt_image(
        &mut self,
        result: Result<Image, OverlayError>,
    ) -> Result<Image, OverlayError> {
        if matches!(result, Err(OverlayError::Poisoned)) {
            self.poison();
        }
        result
    }

    fn verify_reconciliation(
        &mut self,
        plan: &super::residual_inventory::ReconciliationPlan,
    ) -> Result<(), OverlayError> {
        for (&id, expected) in plan.stages() {
            let path = self.stage_path(id);
            let length = expected
                .size
                .checked_add(160)
                .ok_or_else(|| OverlayError::refused("residual reconciliation changed"))?;
            if self.io.length(&path)? != Some(length) {
                return Err(OverlayError::refused("residual reconciliation changed"));
            }
            let header = StagingHeader::decode(&self.io.read_at(&path, 0, 160)?)
                .map_err(|_| OverlayError::refused("residual reconciliation changed"))?;
            if header != expected.header {
                return Err(OverlayError::refused("residual reconciliation changed"));
            }
            let mut hash = codec::ResidualPayloadHasher::new(id, expected.size);
            let mut offset = 0u64;
            while offset < expected.size {
                let length = usize::try_from((expected.size - offset).min(super::BUFFER as u64))
                    .map_err(|_| OverlayError::refused("residual reconciliation changed"))?;
                let bytes = self
                    .io
                    .read_at(&path, 160_u64.saturating_add(offset), length)?;
                if bytes.len() != length {
                    return Err(OverlayError::refused("residual reconciliation changed"));
                }
                hash.update(&bytes);
                offset = offset.saturating_add(
                    u64::try_from(length)
                        .map_err(|_| OverlayError::refused("residual reconciliation changed"))?,
                );
            }
            if hash.finalize() != expected.payload_check {
                return Err(OverlayError::refused("residual reconciliation changed"));
            }
        }
        Ok(())
    }

    pub(crate) fn commit_entries(
        &mut self,
        boundary: u64,
        publication: [u8; 16],
    ) -> Result<Vec<OverlayEntry>, OverlayError> {
        let old = self.journal_bytes()?;
        let mut entries = commit_entries(&self.base, &old, boundary, publication)?;
        self.view_inodes(&mut entries);
        Ok(entries)
    }
    /// The replay numbers inodes in fold order, which the view need not share:
    /// a landing looks a retired stage's captured entry up by the view's inode.
    /// A stage's inode follows its entry through moves, so a staged entry takes
    /// it from the view; no other entry is looked up.
    fn view_inodes(&self, entries: &mut [OverlayEntry]) {
        for entry in entries {
            entry.inode = entry
                .stage_id
                .and_then(|id| self.namespace.stages.get(&id))
                .map_or(0, |stage| stage.inode);
        }
    }
    /// The candidate entries of a projected boundary: the projection its seal
    /// made, rebuilt from the base and the journal through its through seq with
    /// the saved selection. Every file enters at an immutable payload, the
    /// selected file at its saved content and size and every other at its base
    /// or synced payload, so the retained candidate's manifest must match each
    /// one. Later staging is never read.
    pub(crate) fn projected_commit_entries(
        &mut self,
        boundary: u64,
        publication: [u8; 16],
    ) -> Result<Vec<OverlayEntry>, OverlayError> {
        let old = self.journal_bytes()?;
        let prefix = projected_prefix(
            &self.replay_context()?,
            &self.base,
            &old,
            boundary,
            publication,
        )?;
        let mut entries = prefix.projection.entries().to_vec();
        self.view_inodes(&mut entries);
        Ok(entries)
    }
    /// The stages a handle or capture holds, and the named stages a whole-tree
    /// sync would not select, synced at a recorded boundary with nothing
    /// since, each with that checkpoint's content and size.
    fn residual_inputs(
        &self,
    ) -> Result<(BTreeSet<u64>, super::residual::Checkpoints), OverlayError> {
        let mut held = BTreeSet::new();
        let mut clean = BTreeMap::new();
        for (&id, stage) in &self.namespace.stages {
            if stage.handles > 0 || !stage.captures.is_empty() {
                held.insert(id);
            }
            if let Some(mark) = stage.mark
                && stage.path.is_some()
                && stage.checkpoint_boundary.is_some()
                && self.checkpoint_dirty(id, stage)?.is_empty()
            {
                clean.insert(id, (mark.content, mark.synced_size));
            }
        }
        Ok((held, clean))
    }
    /// A copy of everything the residual of the projected boundary at
    /// `boundary` is built from: the journal, base, held and clean stages and
    /// the replay context. Taking it is short; building from it needs no lock.
    /// # Errors
    /// Refuses unreadable journal bytes or live stage state.
    pub(crate) fn residual_snapshot(
        &mut self,
        boundary: u64,
        publication: [u8; 16],
    ) -> Result<super::ResidualSnapshot, OverlayError> {
        let (held, clean) = self.residual_inputs()?;
        Ok(super::ResidualSnapshot {
            journal: self.journal_bytes()?,
            base: self.base.clone(),
            held,
            clean,
            context: self.replay_context()?,
            boundary,
            publication,
        })
    }
    /// The image a landing installs over `old`: a projected boundary's
    /// residual over the landed entries, else the whole-tree suffix.
    fn landing_image(
        &self,
        old: &[u8],
        proof: &LandedProof,
        reconciliation: &super::residual_inventory::ReconciliationPlan,
    ) -> Result<Image, OverlayError> {
        let mut projected = None;
        codec::scan_journal_with(old, |seq, record| {
            if seq == proof.boundary_seq
                && let Record::ProjectedBoundary { publication_id, .. } = record
            {
                projected = Some(*publication_id);
            }
        })
        .map_err(|_| OverlayError::refused("landing scan"))?;
        let (held, clean) = self.residual_inputs()?;
        let Some(publication) = projected else {
            return build(old, &self.base, proof, &self.writer, reconciliation, &held);
        };
        let prefix = projected_prefix(
            &self.replay_context()?,
            &self.base,
            old,
            proof.boundary_seq,
            publication,
        )?;
        let residual =
            super::residual::residual(old, &self.base, &prefix, &held, &clean, reconciliation)?;
        build_projected(old, proof, &self.writer, &prefix, residual)
    }
    /// Build without the journal mutex. The caller can end this local transaction,
    /// admit more writes, then install; the final copy rereads the retained suffix.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn prepare_replacement(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        proof: LandedProof,
    ) -> Result<ReplacementPlan, OverlayError> {
        self.prepare_replacement_with_reconciliation(
            store,
            ownership,
            proof,
            super::residual_inventory::ReconciliationPlan::default(),
        )
    }

    fn prepare_replacement_with_reconciliation(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        proof: LandedProof,
        reconciliation: super::residual_inventory::ReconciliationPlan,
    ) -> Result<ReplacementPlan, OverlayError> {
        self.check(store, ownership)?;
        if !self.replayed || self.readiness == OverlayReadiness::PendingReconciliation {
            return Err(OverlayError::PendingReconciliation);
        }
        let old = self.journal_bytes()?;
        let result = self.landing_image(&old, &proof, &reconciliation);
        let image = self.rebuilt_image(result)?;
        let original = codec::scan_journal(&old)
            .map_err(|_| OverlayError::refused("replacement source"))?
            .header;
        let path = self.area.join("journal.next");
        if self.io.length(&path)?.is_some() {
            return Err(OverlayError::refused(
                "replacement temporary already exists",
            ));
        }
        let charge = self.charge()?;
        if charge
            .checked_add(image.bytes.len() as u64)
            .and_then(|n| n.checked_add(self.config.ownership_completion_reserve))
            .is_none_or(|n| n > self.config.cap)
        {
            return Err(OverlayError::no_space());
        }
        self.point("overlay.replace.build", "before", 0)?;
        self.io.create(&path)?;
        if let Err(e) = write_step(
            &mut self.io,
            &self.faults,
            "overlay.replace.build",
            &path,
            0,
            &image.bytes,
            0,
        ) {
            self.poison();
            return Err(e);
        }
        Ok(ReplacementPlan {
            proof,
            original,
            source: ImageSource::Landing,
            reconciliation,
        })
    }

    /// Remove one uncharged, unfenced boundary without absorbing overlay effects.
    /// Charged boundaries require retained no-write evidence.
    pub(crate) fn replace_rejected(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        boundary: u64,
        publication: [u8; 16],
    ) -> Result<(), OverlayError> {
        self.replace_rejected_with_proof(store, ownership, boundary, publication, None)
    }

    /// Remove a sole unfenced boundary; charges require bound non-landing evidence.
    pub(crate) fn replace_rejected_with_proof(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        boundary: u64,
        publication: [u8; 16],
        no_write: Option<RejectionProof>,
    ) -> Result<(), OverlayError> {
        self.replace_rejected_inner(store, ownership, boundary, publication, no_write, false)
    }

    /// Strip a fenced boundary atomically with its attempt-bound settlement proof.
    pub(crate) fn replace_rejected_fenced(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        boundary: u64,
        publication: [u8; 16],
        proof: RejectionProof,
    ) -> Result<(), OverlayError> {
        self.replace_rejected_inner(store, ownership, boundary, publication, Some(proof), true)
    }

    fn replace_rejected_inner(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        boundary: u64,
        publication: [u8; 16],
        no_write: Option<RejectionProof>,
        fenced: bool,
    ) -> Result<(), OverlayError> {
        self.check(store, ownership)?;
        if !self.replayed || !self.snapshots.is_empty() {
            return Err(OverlayError::PendingReconciliation);
        }
        let old = self.journal_bytes()?;
        let result = build_rejected(
            &old,
            &self.base,
            boundary,
            publication,
            no_write.as_ref(),
            fenced,
            &self.writer,
        );
        let image = self.rebuilt_image(result)?;
        let path = self.area.join("journal.next");
        if self.io.length(&path)?.is_some() {
            return Err(OverlayError::refused(
                "replacement temporary already exists",
            ));
        }
        if self
            .charge()?
            .checked_add(image.bytes.len() as u64)
            .and_then(|n| n.checked_add(self.config.ownership_completion_reserve))
            .is_none_or(|n| n > self.config.cap)
        {
            return Err(OverlayError::no_space());
        }
        let original = image.scan.header;
        let proof = LandedProof {
            boundary_seq: boundary,
            landed_root: original.base_root,
            landed_seq: original.base_seq,
            captured_entries: self.base.clone(),
            entries: self.base.clone(),
        };
        self.io.create(&path)?;
        self.install_replacement(
            store,
            ownership,
            ReplacementPlan {
                proof,
                original,
                source: ImageSource::Rejected(boundary, publication, no_write, fenced),
                reconciliation: super::residual_inventory::ReconciliationPlan::default(),
            },
        )
        .map(|_| ())
    }
    /// Returns the identities the replacement did not carry from the current view.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn install_replacement(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        plan: ReplacementPlan,
    ) -> Result<ViewChange, OverlayError> {
        self.install_replacement_with_content(store, ownership, plan, &mut LocalContent::new(store))
    }

    fn install_replacement_with_content(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        plan: ReplacementPlan,
        content: &mut impl ContentSource,
    ) -> Result<ViewChange, OverlayError> {
        let result = match self.check(store, ownership) {
            Ok(()) => self.install_plan(plan, content),
            Err(OverlayError::PendingReconciliation) => Err(OverlayError::PendingReconciliation),
            Err(e) => return Err(e),
        };
        self.completion_credit = 0;
        if result.is_err() && self.readiness != OverlayReadiness::Poisoned {
            // The canonical journal is still authoritative before the switch.
            // A consumed build cannot prevent a later independent preparation.
            let next = self.area.join("journal.next");
            let cleanup = (|| {
                if self.io.length(&next)?.is_some() {
                    self.io.remove(&next)?;
                    self.io.sync_directory(&self.area)?;
                }
                Ok::<(), OverlayError>(())
            })();
            if let Err(e) = cleanup {
                self.poison();
                return Err(e);
            }
        }
        result
    }
    #[expect(
        clippy::too_many_lines,
        reason = "the quiesced switch keeps ordering and poison transitions together"
    )]
    fn install_plan(
        &mut self,
        plan: ReplacementPlan,
        content: &mut impl ContentSource,
    ) -> Result<ViewChange, OverlayError> {
        if self.journal.lock().map_err(Self::lock_error)?.header != plan.original {
            return Err(OverlayError::refused("stale replacement plan"));
        }
        self.verify_reconciliation(&plan.reconciliation)?;
        // Open handles/captures must retain their backing stage even with no dirty
        // suffix. An ordinary same-size truncate gives the suffix a stage reference
        // without changing bytes, names, the captured root or the v1 encoding.
        let held: Vec<_> = self
            .namespace
            .stages
            .iter()
            .filter(|(_, s)| s.handles > 0 || !s.captures.is_empty())
            .map(|(id, s)| (*id, s.size))
            .collect();
        self.completion_credit = (self.namespace.stages.len() as u64).saturating_mul(122);
        for (id, size) in held {
            if let Err(e) = self.append(&Record::Truncate {
                stage_id: id,
                new_size: size,
            }) {
                self.completion_credit = 0;
                return Err(e);
            }
        }
        let old = self.journal_bytes()?;
        let result = match &plan.source {
            ImageSource::Rejected(boundary, publication, no_write, fenced) => build_rejected(
                &old,
                &self.base,
                *boundary,
                *publication,
                no_write.as_ref(),
                *fenced,
                &self.writer,
            ),
            ImageSource::Landing => self.landing_image(&old, &plan.proof, &plan.reconciliation),
            ImageSource::Adopted => build_adopted(&old, &plan.proof, &self.writer),
            ImageSource::RecoveredSuffix(suffix) => self.recovered_image(&old, &plan.proof, suffix),
        };
        let mut image = self.rebuilt_image(result)?;
        let current = self.namespace.clone();
        if matches!(plan.source, ImageSource::Adopted) {
            image.retired.extend(current.stages.keys().copied());
        }
        // Only a landing has a capture; a rejected proof carries the base,
        // and an adopted one the head's entries.
        let captured: BTreeMap<_, _> = if matches!(plan.source, ImageSource::Landing) {
            plan.proof
                .captured_entries
                .iter()
                .filter(|entry| entry.inode != 0)
                .map(|entry| (entry.inode, entry))
                .collect()
        } else {
            BTreeMap::new()
        };
        let view_change = match image.namespace.preserve_inodes(&current, &captured) {
            Ok(view_change) => view_change,
            Err(error) => {
                if matches!(error, OverlayError::Poisoned) {
                    self.poison();
                }
                return Err(error);
            }
        };
        // Carried stages whose staging header holds a mark this image drops.
        let mut stale_marks = Vec::new();
        for (&id, stage) in &mut image.namespace.stages {
            if let Some(previous) = current.stages.get(&id) {
                stage.handles = previous.handles;
                stage.captures = previous.captures.clone();
                // Replay can leave a newer mirror out of the in-memory mark
                // while a rollback baseline is in effect. Check the actual header
                // so a later replay cannot fold a stale mirror back into the image.
                if let MarkState::Present(mark) = self.header(id)?.mark
                    && stage.mark != Some(mark)
                {
                    // A projected carry can retain an acknowledged base mirror
                    // beside a historical rollback to a different checkpoint.
                    if stage.agrees_with(mark)
                        || (stage.base == Some(mark.content) && stage.base_size == mark.synced_size)
                    {
                        // With a retained rollback, only a retained journal mark
                        // can supersede the baseline as a capture checkpoint.
                        if stage.rollback.is_none()
                            && stage
                                .mark
                                .is_none_or(|journal| mark.generation > journal.generation)
                        {
                            stage.mark = Some(mark);
                        }
                    } else {
                        stale_marks.push(id);
                    }
                }
            }
        }
        let old_scan = codec::scan_journal(&old)
            .map_err(|_| OverlayError::refused("replacement source scan"))?;
        if image.scan.state.next_stage_id() != old_scan.state.next_stage_id()
            || image.scan.state.highest_generation() != old_scan.state.highest_generation()
        {
            return Err(OverlayError::refused("replacement final counters"));
        }
        let next = self.area.join("journal.next");
        let existing = self
            .io
            .length(&next)?
            .ok_or_else(|| OverlayError::refused("replacement temporary missing"))?;
        let charge = self.charge()?;
        if charge
            .saturating_sub(existing)
            .checked_add(image.bytes.len() as u64)
            .and_then(|n| n.checked_add(self.config.ownership_completion_reserve))
            .is_none_or(|n| n > self.config.cap)
        {
            return Err(OverlayError::no_space());
        }
        // Stage access and retirement precede acquisition of the journal mutex.
        // &mut self/Store is the outer mediator transaction/namespace gate.
        self.poison();
        for &id in &image.retired {
            let previous = current
                .stages
                .get(&id)
                .ok_or_else(|| OverlayError::refused("retirement stage"))?;
            if previous.handles > 0 || !previous.captures.is_empty() {
                return Err(OverlayError::refused("retirement still held"));
            }
            self.clear_header_mark(id, "overlay.retire.mark_clear")?;
        }
        for &id in &stale_marks {
            self.clear_header_mark(id, "overlay.carry.mark_clear")?;
        }
        let path = self.journal_path();
        let mut journal = self.journal.lock().map_err(Self::lock_error)?;
        point(
            &self.faults,
            "overlay.replace.quiesced",
            "before",
            journal.state.next_seq(),
        )?;
        // Final source is stable while the mutex covers copy, sync, rename,
        // directory sync and state switch. No cached old inode escapes.
        let length = self
            .io
            .length(&path)?
            .ok_or_else(|| OverlayError::refused("final journal missing"))?;
        let final_old = self.io.read_at(&path, 0, codec::JOURNAL_MAX + 1)?;
        if final_old.len() as u64 != length || final_old != old {
            return Err(OverlayError::refused("final source changed"));
        }
        self.io.resize(&next, 0)?;
        write_step(
            &mut self.io,
            &self.faults,
            "overlay.replace.build",
            &next,
            0,
            &image.bytes,
            journal.state.next_seq(),
        )?;
        sync_step(
            &mut self.io,
            &self.faults,
            "overlay.replace.sync",
            &next,
            journal.state.next_seq(),
        )?;
        point(
            &self.faults,
            "overlay.replace.rename",
            "before",
            journal.state.next_seq(),
        )?;
        self.io.rename(&next, &path)?;
        point(
            &self.faults,
            "overlay.replace.rename",
            "after",
            journal.state.next_seq(),
        )?;
        point(
            &self.faults,
            "overlay.replace.dir_sync",
            "before",
            journal.state.next_seq(),
        )?;
        self.io.sync_directory(&self.area)?;
        point(
            &self.faults,
            "overlay.replace.dir_sync",
            "after",
            journal.state.next_seq(),
        )?;
        let mut completion = CompletionReserve::default();
        let mut completion_error = None;
        codec::scan_journal_with(&image.bytes, |index, record| {
            if let Err(e) = completion.fold(index, record) {
                completion_error = Some(e);
            }
        })
        .map_err(|_| OverlayError::refused("replacement completion scan"))?;
        if let Some(e) = completion_error {
            return Err(e);
        }
        journal.completion = completion;
        journal.header = image.scan.header;
        journal.state = image.scan.state.clone();
        journal.length = image.bytes.len() as u64;
        point(
            &self.faults,
            "overlay.replace.switched",
            "after",
            journal.state.next_seq(),
        )?;
        self.summary.records = journal.state.next_seq() - 1;
        let pending = !journal.completion.commits.is_empty();
        drop(journal);
        self.settle_installed_image(
            image,
            plan.proof.entries,
            pending,
            &plan.source,
            content,
            "overlay.retire.unlink",
        )?;
        Ok(view_change)
    }

    /// Install the in-memory image after its journal switch is durable.
    fn settle_installed_image(
        &mut self,
        image: Image,
        entries: Vec<OverlayEntry>,
        pending: bool,
        source: &ImageSource,
        content: &mut impl ContentSource,
        retire_fault: &'static str,
    ) -> Result<(), OverlayError> {
        self.namespace = image.namespace;
        self.base = entries;
        self.history =
            super::provenance::History::replay(&self.base, &image.bytes, &mut self.namespace)?;
        if !self.served {
            self.repair_installed_stages(content)?;
        }
        for id in image.retired {
            point(&self.faults, retire_fault, "before", 0)?;
            if let Err(e) = self.io.remove(&self.stage_path(id)) {
                self.poison();
                return Err(e.into());
            }
            self.io.sync_directory(&self.area.join("staging"))?;
            point(&self.faults, retire_fault, "after-sync", 0)?;
        }
        self.completion_credit = 0;
        // Completion consumes its reserved headroom; a conservative future
        // reservation can now refuse writes without undoing the landed install.
        if let Err(e) = self.settle_summary() {
            self.poison();
            return Err(e);
        }
        self.capacity_changed();
        self.query_incarnation = super::recovery::next_incarnation()?;
        match &image.residual_dirty {
            None if matches!(source, ImageSource::Landing) => self
                .dirty_spans
                .retain(|span| span.first_seq > image.through_seq),
            // An adopted journal holds no work, so it has no dirty span.
            None if matches!(source, ImageSource::Adopted) => self.dirty_spans.clear(),
            None => {}
            // A residual keeps the spans its retained work came from, on
            // either side of its boundary, with their ages.
            Some(dirty) => self.dirty_spans.retain(|span| {
                dirty
                    .iter()
                    .any(|seq| (span.first_seq..=span.last_seq).contains(seq))
            }),
        }
        if image.recovered_dirty.is_none() && self.dirty_spans.len() > 1 {
            let first_at = self.dirty_spans.first().and_then(|s| s.first_at);
            let last_at = self.dirty_spans.last().and_then(|s| s.last_at);
            self.dirty_spans.clear();
            if self.summary.records > 0 {
                self.dirty_spans.push(super::DirtySpan {
                    first_seq: 1,
                    last_seq: self.summary.records,
                    first_at,
                    last_at,
                });
            }
        }
        if let Some(dirty) = image.recovered_dirty {
            self.dirty_spans = dirty;
        } else if self.summary.records == 0 {
            self.dirty_spans.clear();
        } else {
            for span in &mut self.dirty_spans {
                span.first_seq = 1;
                span.last_seq = self.summary.records;
            }
        }
        self.last_boundary_seq = 0;
        self.dirty_split_seq = 0;
        self.projected_seal = None;
        self.readiness = if pending {
            OverlayReadiness::PendingRecovery
        } else {
            OverlayReadiness::Ready
        };
        Ok(())
    }
    /// Clear stage `id`'s header mark block, durably, around the `seam`
    /// fault points.
    fn clear_header_mark(&mut self, id: u64, seam: &'static str) -> Result<(), OverlayError> {
        let mut header = self.header(id)?;
        header.mark = MarkState::Absent;
        let bytes = header
            .encode()
            .map_err(|_| OverlayError::refused("retirement header"))?;
        point(&self.faults, seam, "before", 0)?;
        self.io.write_at(
            &self.stage_path(id),
            68,
            bytes
                .get(68..149)
                .ok_or_else(|| OverlayError::refused("retirement mark range"))?,
        )?;
        self.io.sync(&self.stage_path(id))?;
        point(&self.faults, seam, "after-sync", 0)
    }
    /// Returns the identities the landing did not carry from the current view.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn replace_landed(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        proof: LandedProof,
    ) -> Result<ViewChange, OverlayError> {
        let plan = self.prepare_replacement(store, ownership, proof)?;
        self.install_replacement(store, ownership, plan)
    }

    /// Prepare a landing using a validated residual reconciliation plan.
    ///
    /// # Errors
    /// The same refusals as [`OverlayStore::prepare_replacement`].
    pub(crate) fn prepare_residual_replacement(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        proof: LandedProof,
        inventory: &super::ResidualInventory,
    ) -> Result<ReplacementPlan, OverlayError> {
        self.prepare_replacement_with_reconciliation(
            store,
            ownership,
            proof,
            inventory.reconciliation.clone(),
        )
    }

    /// Install a landing using its validated residual inventory.
    ///
    /// # Errors
    /// The same refusals as [`OverlayStore::replace_landed`].
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "read-only residual validation does not grant installation authority"
        )
    )]
    pub(crate) fn replace_residual_landed(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        proof: LandedProof,
        inventory: &super::ResidualInventory,
        content: &mut impl ContentSource,
    ) -> Result<ViewChange, OverlayError> {
        let plan = self.prepare_residual_replacement(store, ownership, proof, inventory)?;
        self.install_replacement_with_content(store, ownership, plan, content)
    }

    /// Whether a successful finish must canonicalize semantic no-op history.
    pub(crate) fn normalization_required(&mut self) -> Result<bool, OverlayError> {
        let bytes = self.journal_bytes()?;
        Ok(!scan_clean(&bytes, &self.writer).is_some_and(|(_, clean)| clean))
    }

    pub(crate) fn check_finish_obligations(&self) -> Result<(), OverlayError> {
        let replay = !self.replayed;
        let readiness = self.readiness != OverlayReadiness::Ready;
        let snapshots = !self.snapshots.is_empty();
        let held = self
            .namespace
            .stages
            .values()
            .any(|stage| stage.handles > 0 || !stage.captures.is_empty());
        let completion = !self
            .journal
            .lock()
            .map_err(Self::lock_error)?
            .completion
            .commits
            .is_empty();
        let versions = self.versions.journal_reserve() != 0;
        #[cfg(test)]
        let (replay, readiness, snapshots, held, completion, versions) = {
            let debt = crate::writable_store::sync_engine::FINISH_DEBT.get();
            (
                replay || debt == "replay",
                readiness || debt == "readiness",
                snapshots || debt == "snapshot",
                held || debt == "stage",
                completion || debt == "completion",
                versions || debt == "version",
            )
        };
        if replay || readiness || snapshots || held || completion || versions {
            return Err(OverlayError::refused("WritableRecoveryRequired"));
        }
        Ok(())
    }

    /// Canonicalize a replayed, base-equivalent journal without moving its base.
    /// Marks retire before the journal switch; stage names retire afterwards.
    pub(crate) fn normalize_same_base(&mut self, store: &Store) -> Result<(), OverlayError> {
        if !self.initial_state_ready() {
            return Err(OverlayError::refused("WritableRecoveryRequired"));
        }
        self.check_finish_obligations()?;
        let old = self.journal_bytes()?;
        let scan =
            codec::scan_journal(&old).map_err(|_| OverlayError::refused("normalization scan"))?;
        scan.check_writer(&self.writer)
            .map_err(|_| OverlayError::refused("normalization writer"))?;
        let header = JournalHeader {
            next_stage_id: scan.state.next_stage_id(),
            receipt_generation: scan.state.highest_generation(),
            ..scan.header
        };
        let bytes = header
            .encode()
            .map_err(|_| OverlayError::refused("normalization header"))?;
        let canonical = codec::scan_journal(&bytes)
            .map_err(|_| OverlayError::refused("normalization image"))?;
        if self
            .charge()?
            .checked_add(bytes.len() as u64)
            .and_then(|n| n.checked_add(self.config.ownership_completion_reserve))
            .is_none_or(|n| n > self.config.cap)
        {
            return Err(OverlayError::no_space());
        }
        let retired: Vec<_> = self.namespace.stages.keys().copied().collect();
        for &id in &retired {
            self.clear_header_mark(id, "overlay.normalize.mark_clear")?;
        }
        self.install_journal(&bytes, "overlay.journal.normalize", |_| Ok(()))?;
        let mut journal = self.journal.lock().map_err(Self::lock_error)?;
        journal.header = canonical.header;
        journal.state = canonical.state.clone();
        journal.length = bytes.len() as u64;
        journal.completion = CompletionReserve::default();
        self.summary.records = journal.state.next_seq() - 1;
        drop(journal);
        let image = Image {
            bytes,
            scan: canonical,
            namespace: Namespace::base(&self.base)?,
            retired,
            through_seq: 0,
            residual_dirty: None,
            recovered_dirty: None,
        };
        self.settle_installed_image(
            image,
            self.base.clone(),
            false,
            &ImageSource::Adopted,
            &mut LocalContent::new(store),
            "overlay.normalize.retire",
        )
    }

    /// Whether this overlay holds nothing a published head lacks: it is
    /// replayed and ready with no snapshot and no stage, its journal holds no
    /// open boundary and no pending completion, and every record is
    /// bookkeeping ([`clean_record`]). Decided from the journal's records,
    /// not from the dirty spans, which a replacement rebases. A journal that
    /// cannot be read is not clean.
    pub(crate) fn adoption_clean(&mut self) -> bool {
        if !self.replayed
            || self.readiness != OverlayReadiness::Ready
            || !self.snapshots.is_empty()
            || !self.namespace.stages.is_empty()
        {
            return false;
        }
        let Ok(bytes) = self.journal_bytes() else {
            return false;
        };
        scan_clean(&bytes, &self.writer).is_some_and(|(_, clean)| clean)
    }

    /// Replace a clean journal with a header-only one on the published head
    /// `root` at `seq`, whose base entries are `entries`, keeping the old
    /// journal's next stage id and highest receipt generation. Returns the
    /// view change, which on a clean overlay is the change from the old base
    /// to `entries`.
    ///
    /// A journal that is not clean refuses before anything is written. A
    /// caller that checked the overlay clean under the gates that keep it
    /// so never meets that refusal: there it is an equivalent mutant, and
    /// the overlay's own rows kill it.
    ///
    /// # Errors
    /// An unclean journal, custody, capacity or persistence failure.
    /// Evidence is preserved.
    pub(crate) fn replace_adopted(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        root: GrainId,
        seq: u64,
        entries: Vec<OverlayEntry>,
    ) -> Result<ViewChange, OverlayError> {
        self.check(store, ownership)?;
        if !self.adoption_clean() {
            return Err(OverlayError::refused("adoption journal not clean"));
        }
        self.replace_base(store, ownership, root, seq, entries)
    }

    /// Explicit recovery has proved the replayed tree equals this published base.
    pub(crate) fn replace_recovered(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        root: GrainId,
        seq: u64,
        entries: Vec<OverlayEntry>,
    ) -> Result<(), OverlayError> {
        self.check(store, ownership)?;
        self.check_finish_obligations()?;
        self.replace_base(store, ownership, root, seq, entries)
            .map(|_| ())
    }

    fn replace_base(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        root: GrainId,
        seq: u64,
        entries: Vec<OverlayEntry>,
    ) -> Result<ViewChange, OverlayError> {
        let proof = LandedProof {
            boundary_seq: 0,
            landed_root: root,
            landed_seq: seq,
            captured_entries: Vec::new(),
            entries,
        };
        let old = self.journal_bytes()?;
        let result = build_adopted(&old, &proof, &self.writer);
        let image = self.rebuilt_image(result)?;
        let original = codec::scan_journal(&old)
            .map_err(|_| OverlayError::refused("replacement source"))?
            .header;
        self.install_recovered_plan(
            store,
            ownership,
            ReplacementPlan {
                proof,
                original,
                source: ImageSource::Adopted,
                reconciliation: super::residual_inventory::ReconciliationPlan::default(),
            },
            image.bytes.len(),
        )
    }

    fn install_recovered_plan(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        plan: ReplacementPlan,
        image_len: usize,
    ) -> Result<ViewChange, OverlayError> {
        let path = self.area.join("journal.next");
        if self.io.length(&path)?.is_some() {
            return Err(OverlayError::refused(
                "replacement temporary already exists",
            ));
        }
        if self
            .charge()?
            .checked_add(image_len as u64)
            .and_then(|n| n.checked_add(self.config.ownership_completion_reserve))
            .is_none_or(|n| n > self.config.cap)
        {
            return Err(OverlayError::no_space());
        }
        self.io.create(&path)?;
        self.install_replacement(store, ownership, plan)
    }
}

/// The whole-tree capture replayed from the same sealed journal bytes.
pub(super) fn commit_entries(
    base: &[OverlayEntry],
    old: &[u8],
    boundary: u64,
    publication: [u8; 16],
) -> Result<Vec<OverlayEntry>, OverlayError> {
    let mut through = None;
    codec::scan_journal_with(old, |seq, record| {
        if seq == boundary
            && let Record::CommitBoundary {
                through_seq,
                publication_id,
                ..
            } = record
            && *publication_id == publication
        {
            through = Some(*through_seq);
        }
    })
    .map_err(|_| OverlayError::refused("commit prefix scan"))?;
    let through = through.ok_or_else(|| OverlayError::refused("commit prefix binding"))?;
    let mut namespace = Namespace::base(base)?;
    let mut result = Ok(());
    codec::scan_journal_with(old, |seq, record| {
        if seq <= through && result.is_ok() {
            result = namespace.fold(record);
        }
    })
    .map_err(|_| OverlayError::refused("commit prefix replay"))?;
    result?;
    let mut entries: Vec<_> = namespace.entries.into_values().collect();
    for entry in &mut entries {
        // Only the retained signed candidate establishes a sealed payload.
        if entry.stage_id.is_some() {
            entry.kind = OverlayKind::File { content: None };
        }
    }
    Ok(entries)
}

/// The seal of the projected boundary at `boundary`, replayed from `old` over
/// `base` through its cursor, and the projection it made with its saved
/// selection. It reads no live state, so it runs on a snapshot.
pub(super) fn projected_prefix(
    context: &super::snapshot::ReplayContext,
    base: &[OverlayEntry],
    old: &[u8],
    boundary: u64,
    publication: [u8; 16],
) -> Result<ProjectedPrefix, OverlayError> {
    let mut found = None;
    codec::scan_journal_with(old, |seq, record| {
        if seq == boundary
            && let Record::ProjectedBoundary {
                through_seq,
                publication_id,
                selection,
                ..
            } = record
            && *publication_id == publication
        {
            found = Some((*through_seq, *selection));
        }
    })
    .map_err(|_| OverlayError::refused("projected prefix scan"))?;
    let (through, selection) =
        found.ok_or_else(|| OverlayError::refused("projected prefix binding"))?;
    let (namespace, history) = super::provenance::History::prefix(base, old, through)?;
    let mut selected = Vec::new();
    if let Some(selection) = selection {
        // The file the replay names at the boundary, wherever it is now.
        let entry = namespace
            .stages
            .get(&selection.stage_id)
            .and_then(|stage| stage.path.as_ref())
            .and_then(|path| namespace.entries.get(path))
            .ok_or_else(|| OverlayError::refused("projected selection unnamed"))?;
        selected.push(super::DurableFile {
            inode: entry.inode,
            size: selection.size,
            content: selection.content,
            content_boundary: through,
        });
    }
    let sealed = context.boundary(through, &namespace, history);
    let projection = sealed.project(&selected)?;
    Ok(ProjectedPrefix {
        through,
        coverage: selection
            .into_iter()
            .filter(|s| {
                projection
                    .stage_projections()
                    .iter()
                    .any(|p| p.stage_id == s.stage_id && p.content_boundary == through)
            })
            .map(|s| (s.stage_id, through))
            .collect(),
        unchanged: None,
        namespace,
        sealed,
        projection,
    })
}

pub(super) fn reference(record: &Record) -> Option<u64> {
    match record {
        Record::WriteExtent { stage_id, .. }
        | Record::Truncate { stage_id, .. }
        | Record::StageRollback { stage_id, .. }
        | Record::FileSynced { stage_id, .. }
        | Record::StageBind { stage_id, .. }
        | Record::Create {
            kind: codec::CreateKind::File { stage_id, .. },
            ..
        } => Some(*stage_id),
        Record::Delete {
            kind: codec::DeleteKind::File { stage_id: Some(id) },
            ..
        } => Some(*id),
        Record::ProjectedBoundary {
            selection: Some(selection),
            ..
        } => Some(selection.stage_id),
        _ => None,
    }
}

/// A stage reference whose effect changes only staged payload state.
pub(super) fn payload_reference(record: &Record) -> Option<u64> {
    if matches!(
        record,
        Record::WriteExtent { .. }
            | Record::Truncate { .. }
            | Record::StageRollback { .. }
            | Record::StageBind { .. }
    ) {
        reference(record)
    } else {
        None
    }
}

fn check_suffix_anchor(
    prefix: &Namespace,
    landed: &Namespace,
    record: &Record,
) -> Result<(), OverlayError> {
    let before = super::provenance::touched(prefix, record);
    let after = super::provenance::touched(landed, record);
    for path in before.keys().chain(after.keys()) {
        let same = match (prefix.entries.get(path), landed.entries.get(path)) {
            (None, None) => true,
            (Some(old), Some(new)) => {
                old.size == new.size
                    && old.exec == new.exec
                    && (old.kind == new.kind
                        || (old.stage_id.is_some()
                            && matches!(
                                (&old.kind, &new.kind),
                                (OverlayKind::File { .. }, OverlayKind::File { .. })
                            )))
            }
            _ => false,
        };
        if !same {
            crate::observe::namespace_conflict(path);
            return Err(OverlayError::Conflict);
        }
    }
    Ok(())
}

/// The image an adoption installs over the clean journal `old`: a header on
/// `proof`'s head with `old`'s next stage id and highest receipt generation,
/// and no records, over `proof`'s entries.
fn build_adopted(
    old: &[u8],
    proof: &LandedProof,
    writer: &WriterRecord,
) -> Result<Image, OverlayError> {
    let old_scan =
        codec::scan_journal(old).map_err(|_| OverlayError::refused("replacement fenced source"))?;
    old_scan
        .check_writer(writer)
        .map_err(|_| OverlayError::refused("replacement writer"))?;
    if old_scan.end != codec::JournalEnd::Clean {
        return Err(OverlayError::refused("replacement torn source"));
    }
    let header = JournalHeader {
        writer: writer.writer,
        base_root: proof.landed_root,
        base_seq: proof.landed_seq,
        next_stage_id: old_scan.state.next_stage_id(),
        receipt_generation: old_scan.state.highest_generation(),
    };
    let bytes = header
        .encode()
        .map_err(|_| OverlayError::refused("replacement header"))?;
    let scan = codec::scan_journal(&bytes)
        .map_err(|_| OverlayError::refused("replacement final rescan"))?;
    Ok(Image {
        bytes,
        scan,
        namespace: Namespace::base(&proof.entries)?,
        retired: Vec::new(),
        through_seq: 0,
        residual_dirty: None,
        recovered_dirty: None,
    })
}

fn build_rejected(
    old: &[u8],
    base: &[OverlayEntry],
    boundary: u64,
    publication: [u8; 16],
    no_write: Option<&RejectionProof>,
    fenced: bool,
    writer: &WriterRecord,
) -> Result<Image, OverlayError> {
    let scan = codec::scan_journal(old).map_err(|_| OverlayError::refused("rejection source"))?;
    scan.check_writer(writer)
        .map_err(|_| OverlayError::refused("rejection writer"))?;
    if scan.end != codec::JournalEnd::Clean {
        return Err(OverlayError::refused("rejection torn source"));
    }
    let mut bytes = scan
        .header
        .encode()
        .map_err(|_| OverlayError::refused("rejection header"))?;
    let mut state = JournalState::new(&scan.header);
    let mut namespace = Namespace::base(base)?;
    let mut found = false;
    let mut error = None;
    codec::scan_journal_with(old, |seq, record| {
        if error.is_some() {
            return;
        }
        match record {
            Record::CommitBoundary {
                candidate,
                publication_id,
                ..
            }
            | Record::ProjectedBoundary {
                candidate,
                publication_id,
                ..
            } if seq == boundary => {
                if *publication_id != publication
                    || no_write.is_some_and(|proof| {
                        !proof.matches(
                            publication,
                            *candidate,
                            scan.state
                                .commit_progress(&publication)
                                .map_or(0, |p| p.attempts),
                        )
                    })
                {
                    error = Some(OverlayError::refused("rejection boundary binding"));
                    return;
                }
                found = true;
            }
            Record::CommitAttempt { boundary_seq, .. } if *boundary_seq == boundary => {
                if no_write.is_none() {
                    error = Some(OverlayError::refused("rejection attempt evidence"));
                }
            }
            Record::CommitFence {
                boundary_seq,
                publication_id,
            } if fenced
                && no_write.is_some()
                && *boundary_seq == boundary
                && *publication_id == publication => {}
            Record::CommitFence { .. } => {
                error = Some(OverlayError::refused("rejection fenced"));
            }
            Record::CommitBoundary { .. }
            | Record::ProjectedBoundary { .. }
            | Record::LandedCommit { .. } => {
                error = Some(OverlayError::refused("rejection boundary binding"));
            }
            _ => {
                if let Err(e) =
                    append_image(&mut bytes, &scan.header, &mut state, &mut namespace, record)
                {
                    error = Some(e);
                }
            }
        }
    })
    .map_err(|_| OverlayError::refused("rejection scan"))?;
    if let Some(error) = error {
        return Err(error);
    }
    if !found {
        return Err(OverlayError::refused("rejection boundary missing"));
    }
    let scan =
        codec::scan_journal(&bytes).map_err(|_| OverlayError::refused("rejection final scan"))?;
    Ok(Image {
        bytes,
        scan,
        namespace,
        retired: Vec::new(),
        through_seq: 0,
        residual_dirty: None,
        recovered_dirty: None,
    })
}

fn build(
    old: &[u8],
    base: &[OverlayEntry],
    proof: &LandedProof,
    writer: &WriterRecord,
    reconciliation: &super::residual_inventory::ReconciliationPlan,
    held: &BTreeSet<u64>,
) -> Result<Image, OverlayError> {
    let old_scan =
        codec::scan_journal(old).map_err(|_| OverlayError::refused("replacement fenced source"))?;
    old_scan
        .check_writer(writer)
        .map_err(|_| OverlayError::refused("replacement writer"))?;
    if old_scan.end != codec::JournalEnd::Clean {
        return Err(OverlayError::refused("replacement torn source"));
    }
    let mut through = None;
    codec::scan_journal_with(old, |seq, record| {
        if let Record::CommitBoundary { through_seq, .. } = record
            && seq == proof.boundary_seq
        {
            through = Some(*through_seq);
        }
    })
    .map_err(|_| OverlayError::refused("landing scan"))?;
    let through = through.ok_or_else(|| OverlayError::refused("landing boundary missing"))?;
    landed_refresh(old, proof)?;
    let pending: BTreeSet<_> = old_scan.state.open_boundaries().collect();
    if pending.first().is_some_and(|seq| *seq <= through) {
        return Err(OverlayError::refused("replacement pending prefix boundary"));
    }
    let retained = |seq: u64, record: &Record| {
        let reconciled_payload = payload_reference(record)
            .is_some_and(|id| reconciliation.contains(id) && !held.contains(&id));
        let in_doubt = match record {
            Record::CommitBoundary { .. } | Record::ProjectedBoundary { .. } => {
                pending.contains(&seq)
            }
            Record::CommitAttempt { boundary_seq, .. }
            | Record::CommitFence { boundary_seq, .. } => pending.contains(boundary_seq),
            _ => false,
        };
        in_doubt
            || (seq > through
                && !reconciled_payload
                && seq != proof.boundary_seq
                && !matches!(record, Record::LandedCommit { boundary_seq, .. }
                | Record::CommitAttempt { boundary_seq, .. }
                | Record::CommitFence { boundary_seq, .. } if *boundary_seq == proof.boundary_seq))
    };
    build_suffix(
        old, base, proof, writer, &old_scan, through, &pending, retained, None, None,
    )
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "both replacement lanes share the cursor mapping and stage retirement"
)]
fn build_suffix(
    old: &[u8],
    base: &[OverlayEntry],
    proof: &LandedProof,
    writer: &WriterRecord,
    old_scan: &codec::JournalScan,
    through: u64,
    pending: &BTreeSet<u64>,
    retained: impl Fn(u64, &Record) -> bool,
    dirty_spans: Option<&[super::DirtySpan]>,
    absorbed_receipt: Option<(u64, GrainId)>,
) -> Result<Image, OverlayError> {
    let mut prefix = Namespace::base(base)?;
    let mut prefix_codec = JournalState::new(&old_scan.header);
    let mut required = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut first_generation = None;
    let mut error = None;
    codec::scan_journal_with(old, |seq, record| {
        if seq <= through && error.is_none() {
            if let Err(e) = prefix.fold(record).map_err(|_| OverlayError::poisoned()) {
                error = Some(e);
            }
            if prefix_codec.admit(record).is_err() {
                error = Some(OverlayError::refused("replacement prefix value"));
            }
        }
        if retained(seq, record) {
            if let Some(id) = reference(record) {
                required.insert(id);
            }
            first_generation = first_generation
                .or_else(|| receipt_identity(record).map(|(generation, _)| generation));
            match record {
                Record::CommitBoundary { through_seq, .. }
                | Record::ProjectedBoundary { through_seq, .. } => {
                    targets.insert(*through_seq);
                }
                Record::LandedCommit { boundary_seq, .. }
                | Record::CommitAttempt { boundary_seq, .. }
                | Record::CommitFence { boundary_seq, .. } => {
                    targets.insert(*boundary_seq);
                }
                _ => {}
            }
        }
    })
    .map_err(|_| OverlayError::refused("replacement prefix scan"))?;
    if let Some(error) = error {
        return Err(error);
    }
    let generation = if dirty_spans.is_some() {
        old_scan.state.highest_generation()
    } else {
        prefix_codec.highest_generation()
    };
    let receipt = first_generation.map_or(generation, |g| generation.min(g.saturating_sub(1)));
    let header = JournalHeader {
        writer: writer.writer,
        base_root: proof.landed_root,
        base_seq: proof.landed_seq,
        next_stage_id: prefix_codec.next_stage_id(),
        receipt_generation: receipt,
    };
    let mut ns = Namespace::base(&proof.entries)?;
    let mut bytes = header
        .encode()
        .map_err(|_| OverlayError::refused("replacement header"))?;
    let mut codec_state = JournalState::new(&header);
    let mut retired = Vec::new();
    let captured: BTreeMap<_, _> = proof
        .captured_entries
        .iter()
        .map(|e| (&e.path, e))
        .collect();
    for (&id, stage) in &prefix.stages {
        if !required.contains(&id) {
            if let Some(path) = &stage.path {
                let entry = ns.entries.get(path).ok_or_else(|| {
                    crate::observe::namespace_conflict(path);
                    OverlayError::Conflict
                })?;
                if !matches!(entry.kind, OverlayKind::File { content: Some(_) }) {
                    crate::observe::namespace_conflict(path);
                    return Err(OverlayError::Conflict);
                }
            }
            retired.push(id);
            continue;
        }
        let p = stage
            .path
            .as_ref()
            .ok_or_else(|| OverlayError::refused("retained orphan has no landed Location"))?;
        let (name, parent) = p
            .split_last()
            .ok_or_else(|| OverlayError::refused("rebind empty path"))?;
        let content = if let Some(OverlayKind::File {
            content: Some(content),
        }) = ns.entries.get(p).map(|e| &e.kind)
        {
            *content
        } else {
            crate::observe::namespace_conflict(p);
            return Err(OverlayError::Conflict);
        };
        if dirty_spans.is_none()
            && captured.get(p).map(|e| &e.kind)
                != Some(&OverlayKind::File {
                    content: Some(content),
                })
        {
            crate::observe::namespace_conflict(p);
            return Err(OverlayError::Conflict);
        }
        let record = Record::StageBind {
            at: codec::Location {
                parent: codec::Parent::new(parent.to_vec())
                    .map_err(|_| OverlayError::refused("rebind parent"))?,
                name: name.clone(),
            },
            cause: codec::BindCause::Rebind,
            stage_id: id,
            staged_size: stage.size,
            base_content: content,
        };
        check_suffix_anchor(&prefix, &ns, &record)?;
        append_image(&mut bytes, &header, &mut codec_state, &mut ns, &record)?;
    }
    let prelude = codec_state.next_seq() - 1;
    let mut carried = 0u64;
    let mut mapped = BTreeMap::new();
    codec::scan_journal_with(old, |seq, record| {
        if retained(seq, record) {
            carried += 1;
        }
        if targets.contains(&seq) {
            mapped.insert(seq, prelude + carried);
        }
    })
    .map_err(|_| OverlayError::refused("replacement cursor map"))?;
    let mut error = None;
    let mut recovered_dirty: Vec<super::DirtySpan> = Vec::new();
    let mut source_span = None;
    codec::scan_journal_with(old, |seq, record| {
        if !retained(seq, record) || error.is_some() {
            return;
        }
        if let Err(e) = check_suffix_anchor(&prefix, &ns, record) {
            error = Some(e);
            return;
        }
        if let Some(spans) = dirty_spans
            && super::recovery::dirty_record(&prefix, record)
            && let Some(span) = spans
                .iter()
                .find(|span| (span.first_seq..=span.last_seq).contains(&seq))
        {
            let next = codec_state.next_seq();
            if let Some(last) = recovered_dirty
                .last_mut()
                .filter(|_| source_span == Some(span.first_seq))
            {
                last.last_seq = next;
            } else {
                source_span = Some(span.first_seq);
                recovered_dirty.push(super::DirtySpan {
                    first_seq: next,
                    last_seq: next,
                    ..*span
                });
            }
        }
        if prefix.fold(record).is_err() {
            error = Some(OverlayError::poisoned());
            return;
        }
        let mut record = record.clone();
        match &mut record {
            Record::CommitBoundary { through_seq, .. }
            | Record::ProjectedBoundary { through_seq, .. } => {
                *through_seq = if *through_seq <= through {
                    prelude
                } else if let Some(seq) = mapped.get(through_seq) {
                    *seq
                } else {
                    error = Some(OverlayError::refused("through cursor mapping"));
                    return;
                }
            }
            Record::LandedCommit { boundary_seq, .. }
            | Record::CommitAttempt { boundary_seq, .. }
            | Record::CommitFence { boundary_seq, .. } => {
                if *boundary_seq == proof.boundary_seq
                    || (*boundary_seq <= through && !pending.contains(boundary_seq))
                {
                    error = Some(OverlayError::refused("landing refers to absorbed boundary"));
                    return;
                }
                if let Some(seq) = mapped.get(boundary_seq) {
                    *boundary_seq = *seq;
                } else {
                    error = Some(OverlayError::refused("boundary cursor mapping"));
                    return;
                }
            }
            _ => {}
        }
        if let Err(e) = append_image(&mut bytes, &header, &mut codec_state, &mut ns, &record) {
            error = Some(e);
        }
    })
    .map_err(|_| OverlayError::refused("replacement retained scan"))?;
    if let Some(error) = error {
        return Err(error);
    }
    retain_registration(
        &mut bytes,
        &header,
        &mut codec_state,
        &mut ns,
        absorbed_receipt,
    )?;
    let scan = codec::scan_journal(&bytes)
        .map_err(|_| OverlayError::refused("replacement final rescan"))?;
    scan.check_writer(writer)
        .map_err(|_| OverlayError::refused("replacement final writer"))?;
    Ok(Image {
        bytes,
        scan,
        namespace: ns,
        retired,
        through_seq: through,
        residual_dirty: None,
        recovered_dirty: dirty_spans.map(|_| recovered_dirty),
    })
}

/// The seq of the refresh that registered `proof`'s landing after the
/// landing itself was recorded for `proof`'s boundary.
fn landed_refresh(old: &[u8], proof: &LandedProof) -> Result<u64, OverlayError> {
    let mut landed = false;
    let mut refresh = None;
    codec::scan_journal_with(old, |seq, record| match record {
        Record::LandedCommit {
            boundary_seq,
            landed_root,
            landed_seq,
        } if *boundary_seq == proof.boundary_seq => {
            landed = *landed_root == proof.landed_root && *landed_seq == proof.landed_seq;
        }
        Record::IntentRegistered {
            prepared_root,
            cause: codec::IntentCause::LandedRefresh,
            ..
        } if landed && *prepared_root == proof.landed_root => refresh = Some(seq),
        _ => {}
    })
    .map_err(|_| OverlayError::refused("landing scan"))?;
    refresh.ok_or_else(|| OverlayError::refused("durable landing/refresh required"))
}

/// The landing image of a projected boundary: its residual over the landed
/// entries. The lane's own boundary, attempts, fence and landing are
/// consumed, as is every registration through the matched refresh, so the
/// header's receipt is the source's highest generation; any other
/// publication record, another lane's boundary included, refuses rather
/// than being dropped. The landed entries must still equal the projection
/// where the residual replays, and keep each retired name an immutable file.
fn build_projected(
    old: &[u8],
    proof: &LandedProof,
    writer: &WriterRecord,
    prefix: &ProjectedPrefix,
    residual: super::residual::Residual,
) -> Result<Image, OverlayError> {
    let refresh = landed_refresh(old, proof)?;
    projected_image(
        old,
        proof,
        writer,
        prefix,
        residual,
        None,
        |seq, record| match record {
            Record::ProjectedBoundary { .. } => seq == proof.boundary_seq,
            Record::LandedCommit { boundary_seq, .. }
            | Record::CommitAttempt { boundary_seq, .. }
            | Record::CommitFence { boundary_seq, .. } => *boundary_seq == proof.boundary_seq,
            Record::FileSynced { .. } | Record::IntentRegistered { .. } => seq <= refresh,
            _ => false,
        },
    )
}

fn projected_image(
    old: &[u8],
    proof: &LandedProof,
    writer: &WriterRecord,
    prefix: &ProjectedPrefix,
    residual: super::residual::Residual,
    retained_generation: Option<u64>,
    own: impl Fn(u64, &Record) -> bool,
) -> Result<Image, OverlayError> {
    let old_scan =
        codec::scan_journal(old).map_err(|_| OverlayError::refused("replacement fenced source"))?;
    old_scan
        .check_writer(writer)
        .map_err(|_| OverlayError::refused("replacement writer"))?;
    if old_scan.end != codec::JournalEnd::Clean {
        return Err(OverlayError::refused("replacement torn source"));
    }
    let mut prefix_codec = JournalState::new(&old_scan.header);
    let mut error = None;
    let mut latest_receipt = None;
    codec::scan_journal_with(old, |seq, record| {
        if error.is_some() {
            return;
        }
        if super::residual::control(record) && !own(seq, record) {
            error = Some(OverlayError::refused("replacement unexpected control"));
        }
        if seq <= prefix.through && prefix_codec.admit(record).is_err() {
            error = Some(OverlayError::refused("replacement prefix value"));
        }
        latest_receipt = receipt_identity(record).or(latest_receipt);
    })
    .map_err(|_| OverlayError::refused("replacement prefix scan"))?;
    if let Some(error) = error {
        return Err(error);
    }
    if let Some(path) = residual
        .anchors
        .mismatch(prefix.projection.entries(), &proof.entries)
    {
        crate::observe::namespace_conflict(&path);
        return Err(OverlayError::Conflict);
    }
    let landed: BTreeMap<_, _> = proof.entries.iter().map(|e| (&e.path, e)).collect();
    for path in residual
        .retired
        .iter()
        .filter_map(|(_, path)| path.as_ref())
    {
        if !landed
            .get(path)
            .is_some_and(|e| matches!(e.kind, OverlayKind::File { content: Some(_) }))
        {
            crate::observe::namespace_conflict(path);
            return Err(OverlayError::Conflict);
        }
    }
    let highest = old_scan.state.highest_generation();
    // The header permits retained receipts and the selected registration.
    let receipt_generation = match retained_generation {
        Some(generation) if generation == highest => residual
            .receipt_generation
            .min(generation.saturating_sub(1)),
        Some(_) => return Err(OverlayError::refused("replacement value rule")),
        None => residual.receipt_generation,
    };
    let header = JournalHeader {
        writer: writer.writer,
        base_root: proof.landed_root,
        base_seq: proof.landed_seq,
        next_stage_id: prefix_codec.next_stage_id(),
        receipt_generation,
    };
    let mut ns = Namespace::base(&proof.entries)?;
    let mut bytes = header
        .encode()
        .map_err(|_| OverlayError::refused("replacement header"))?;
    let mut codec_state = JournalState::new(&header);
    for record in &residual.records {
        append_image(&mut bytes, &header, &mut codec_state, &mut ns, record)?;
    }
    retain_registration(
        &mut bytes,
        &header,
        &mut codec_state,
        &mut ns,
        latest_receipt,
    )?;
    let scan = codec::scan_journal(&bytes)
        .map_err(|_| OverlayError::refused("replacement final rescan"))?;
    scan.check_writer(writer)
        .map_err(|_| OverlayError::refused("replacement final writer"))?;
    Ok(Image {
        bytes,
        scan,
        namespace: ns,
        retired: residual.retired.into_iter().map(|(id, _)| id).collect(),
        through_seq: prefix.through,
        residual_dirty: Some(residual.dirty),
        recovered_dirty: None,
    })
}

/// The generation and root bound by a file receipt or a registration.
pub(super) fn receipt_identity(record: &Record) -> Option<(u64, GrainId)> {
    match record {
        Record::FileSynced {
            generation,
            prepared_root,
            ..
        }
        | Record::IntentRegistered {
            generation,
            prepared_root,
            ..
        } => Some((*generation, *prepared_root)),
        _ => None,
    }
}

/// A completed receipt can outlive its stage even if its registration was interrupted.
fn retain_registration(
    bytes: &mut Vec<u8>,
    header: &JournalHeader,
    state: &mut JournalState,
    namespace: &mut Namespace,
    receipt: Option<(u64, GrainId)>,
) -> Result<(), OverlayError> {
    if let Some((generation, prepared_root)) =
        receipt.filter(|(generation, _)| *generation > state.highest_generation())
    {
        append_image(
            bytes,
            header,
            state,
            namespace,
            &Record::IntentRegistered {
                generation,
                prepared_root,
                cause: codec::IntentCause::DirectorySync,
            },
        )?;
    }
    Ok(())
}

fn append_image(
    bytes: &mut Vec<u8>,
    header: &JournalHeader,
    state: &mut JournalState,
    ns: &mut Namespace,
    record: &Record,
) -> Result<(), OverlayError> {
    let seq = state.next_seq();
    state
        .admit(record)
        .map_err(|_| OverlayError::refused("replacement value rule"))?;
    let frame = codec::encode_record(header, seq, record)
        .map_err(|_| OverlayError::refused("replacement encode"))?;
    if bytes
        .len()
        .checked_add(frame.len())
        .is_none_or(|n| n > codec::JOURNAL_MAX)
    {
        return Err(OverlayError::no_space());
    }
    #[cfg(test)]
    if let Some(remaining) = FOLD_FAULT.get() {
        FOLD_FAULT.set(remaining.checked_sub(1));
        if remaining == 0 {
            ns.inject_inverse_reference(1, Vec::new());
        }
    }
    ns.fold(record).map_err(|_| OverlayError::poisoned())?;
    bytes.extend_from_slice(&frame);
    Ok(())
}

/// Whether a journal record is disposable bookkeeping. Namespace and stage
/// records hold unpublished local work; a residual disposition holds a choice
/// that must survive until replacement executes it.
pub(super) fn clean_record(record: &Record) -> bool {
    match record {
        Record::Create { .. }
        | Record::StageBind { .. }
        | Record::WriteExtent { .. }
        | Record::Truncate { .. }
        | Record::StageRollback { .. }
        | Record::Move { .. }
        | Record::Replace { .. }
        | Record::Delete { .. }
        | Record::SetattrExec { .. }
        | Record::FileSynced { .. }
        | Record::RecreateFile { .. }
        | Record::ResidualDisposition(_) => false,
        Record::IntentRegistered { .. }
        | Record::CommitBoundary { .. }
        | Record::LandedCommit { .. }
        | Record::CommitAttempt { .. }
        | Record::CommitFence { .. }
        | Record::ProjectedBoundary { .. } => true,
    }
}

/// The journal `bytes` scanned, and whether it is clean: bound to `writer`,
/// scanned to a clean end, every record bookkeeping ([`clean_record`]), no
/// boundary open and no completion slot held. The one check a start's
/// reading of its journal, a carry and an adoption share. `None` for a
/// journal that does not scan.
pub(crate) fn scan_clean(
    bytes: &[u8],
    writer: &WriterRecord,
) -> Option<(codec::JournalScan, bool)> {
    let mut records_clean = true;
    let mut completion = CompletionReserve::default();
    let mut folded = Ok(());
    let scan = codec::scan_journal_with(bytes, |index, record| {
        records_clean &= clean_record(record);
        if folded.is_ok() {
            folded = completion.fold(index, record);
        }
    })
    .ok()?;
    let clean = scan.end == codec::JournalEnd::Clean
        && scan.check_writer(writer).is_ok()
        && scan.state.open_boundaries().next().is_none()
        && folded.is_ok()
        && adoption_clean(records_clean, &completion);
    Some((scan, clean))
}

/// Whether a scanned journal is clean: every record passed [`clean_record`],
/// and its completion fold holds no slot. Every boundary inserts a slot and a
/// landing only marks it, so a journal still holding any boundary is not clean.
pub(super) fn adoption_clean(records_clean: bool, completion: &CompletionReserve) -> bool {
    records_clean && completion.commits.is_empty()
}
