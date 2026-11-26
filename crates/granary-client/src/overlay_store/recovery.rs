// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Evidence-first replay. Input is bounded; decoded paths are folded and dropped.

use super::{
    BTreeMap, BUFFER, CompletionReserve, ContentSource, FaultControl, Journal, JournalHeader,
    JournalState, MarkState, Mutex, Namespace, OverlayConfig, OverlayEntry, OverlayError,
    OverlayIo, OverlayReadiness, OverlayStore, OverlaySummary, OwnershipStatus, Path, Record,
    StagingHeader, Store, SweepEntry, SyncedMark, UnmergedInventory, VolumeName, WriterRecord,
    codec, durable_file, observe, point, stage_id, state::Stage, sync_step, usize_bound, verified,
    write_step,
};
use granary_core::{hash::GrainId, secure_random::SecureRandom};
use std::collections::BTreeSet;

#[derive(Default)]
struct StageReplay {
    extent_seqs: BTreeMap<u64, u64>,
    synced_seq: u64,
    size_peak: u64,
    // The stage's first extent, truncate or rollback in this journal. A
    // `file-synced` does not move it: its mark is the file as the fsync
    // captured it, before the record, and a write between the two is not in it.
    first_payload: Option<u64>,
    rollback_report: Option<(u64, u64, u64)>,
    mirrored_mark: Option<SyncedMark>,
}

impl StageReplay {
    fn fold(&mut self, seq: u64, record: &Record, stage: &Stage, prior_size: u64) {
        match record {
            Record::WriteExtent { offset, .. } => {
                self.extent_seqs.insert(*offset, seq);
                self.rollback_report = None;
            }
            Record::Truncate { .. } => {
                self.rollback_report = None;
            }
            Record::StageRollback {
                old_size,
                discarded_bytes,
                ..
            } => {
                self.rollback_report = Some((seq, *old_size, *discarded_bytes));
            }
            Record::FileSynced { .. } => {
                self.synced_seq = seq;
                // Later writes can already have passed the capture size.
                // PendingShrink keeps this size at or above every outstanding capture's size.
                self.size_peak = stage.size;
                self.rollback_report = None;
                return;
            }
            _ => return,
        }
        self.size_peak = self.size_peak.max(prior_size).max(stage.size);
        self.first_payload.get_or_insert(seq);
        self.extent_seqs
            .retain(|offset, _| stage.extents.contains_key(offset));
    }

    fn extent_anchor(&self, stage: &super::state::Stage) -> Option<(GrainId, u64)> {
        let (content, size) = self.mirrored_mark.map_or_else(
            || stage.checkpoint(),
            |mark| (Some(mark.content), mark.synced_size),
        );
        content.map(|content| (content, size))
    }
}

fn extent_above_acknowledgements(seq: u64, synced: u64, through: u64) -> bool {
    seq > synced && seq > through
}

enum LiveExtentFailure {
    MissingAnchor,
    BeyondAnchor,
    RefetchedMismatch,
    Mismatch,
}

impl LiveExtentFailure {
    fn refusal(self) -> OverlayError {
        match self {
            Self::MissingAnchor => OverlayError::refused("short live extent without anchor"),
            Self::BeyondAnchor => OverlayError::refused("short live extent beyond anchor"),
            Self::RefetchedMismatch => OverlayError::refused("refetched extent mismatch"),
            Self::Mismatch => OverlayError::refused("live extent mismatch"),
        }
    }
}

impl<P: OverlayIo> OverlayStore<P> {
    /// Establish W only in a fresh area. This neither takes ownership nor allocates
    /// a generation. Existing evidence always requires the existing canonical W.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn establish_writer(
        store: &mut Store,
        config: &OverlayConfig,
        io: &mut P,
        random: &mut impl SecureRandom,
        faults: &FaultControl,
    ) -> Result<WriterRecord, OverlayError> {
        Self::establish_writer_inner(store, config, io, random, faults, None)
    }

    /// Install an explicitly selected recovery identity with establishment barriers.
    /// # Errors
    /// Refuses incompatible identity, missing consent, custody or persistence failure.
    /// An existing matching writer may be raised beside its retained journal.
    pub fn install_selected_writer(
        store: &mut Store,
        config: &OverlayConfig,
        io: &mut P,
        selected: &super::SelectedWriter,
        faults: &FaultControl,
    ) -> Result<WriterRecord, OverlayError> {
        struct NoEntropy;
        impl SecureRandom for NoEntropy {
            fn fill(
                &mut self,
                _: &mut [u8],
            ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
                Err(granary_core::secure_random::EntropyUnavailable)
            }
        }
        Self::establish_writer_inner(store, config, io, &mut NoEntropy, faults, Some(selected))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one writer establishment transaction validates identity and durably raises an adopted ceiling before exposing the record"
    )]
    fn establish_writer_inner(
        store: &mut Store,
        config: &OverlayConfig,
        io: &mut P,
        random: &mut impl SecureRandom,
        faults: &FaultControl,
        selected: Option<&super::SelectedWriter>,
    ) -> Result<WriterRecord, OverlayError> {
        io.check_root(store.publication_root(), config.euid)?;
        crate::overlay_discard::claims::gate(io, store.publication_root(), &config.volume)?;
        let scope = config
            .scope
            .digest()
            .map_err(|_| OverlayError::refused("scope"))?;
        let area = super::area_path(store.publication_root(), &config.scope, &config.volume)?;
        if selected.is_some_and(|s| s.volume != config.volume || s.scope != scope) {
            return Err(OverlayError::refused("selected writer binding"));
        }
        settle_area(io, faults, &area)?;
        if io.length(&area.join("writer"))?.is_some() {
            let mut writer = read_writer(io, &area.join("writer"))?;
            if writer.volume != config.volume || selected.is_some_and(|s| s.writer != writer.writer)
            {
                return Err(OverlayError::refused("writer volume"));
            }
            if let Some(selected) = selected
                && writer.ceiling < selected.ceiling
            {
                writer.ceiling = selected.ceiling;
                let bytes = writer
                    .encode()
                    .map_err(|_| OverlayError::refused("writer encode"))?;
                if (bytes.len() as u64)
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(211))
                    .and_then(|n| n.checked_add(config.ownership_completion_reserve))
                    .is_none_or(|n| n > config.cap)
                {
                    return Err(OverlayError::no_space());
                }
                if io.length(&area.join("writer.tmp"))?.is_some() {
                    io.remove(&area.join("writer.tmp"))?;
                    io.sync_directory(&area)?;
                }
                durable_file(
                    io,
                    faults,
                    &area,
                    "writer.tmp",
                    "writer",
                    &bytes,
                    "overlay.writer",
                    0,
                )?;
            }
            return Ok(writer);
        }
        match io.directory(&area) {
            Ok(()) => {
                if io
                    .entries(&area)?
                    .iter()
                    .any(|n| !matches!(n.as_str(), "staging" | "writer.tmp"))
                {
                    return Err(OverlayError::refused("writer missing beside evidence"));
                }
                match io.directory(&area.join("staging")) {
                    Ok(()) if !io.entries(&area.join("staging"))?.is_empty() => {
                        return Err(OverlayError::refused("writer missing beside evidence"));
                    }
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
                io.length(&area.join("writer.tmp"))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        establish_directories(io, store.publication_root(), &area)?;
        if io.length(&area.join("writer.tmp"))?.is_some() {
            io.remove(&area.join("writer.tmp"))?;
            io.sync_directory(&area)?;
        }
        let mut writer = selected.map_or([0; 16], |s| s.writer);
        if selected.is_none() {
            random
                .fill(&mut writer)
                .map_err(|_| OverlayError::refused("writer entropy unavailable"))?;
        }
        let record = WriterRecord {
            writer,
            ceiling: selected.map_or(0, |s| s.ceiling),
            volume: config.volume.clone(),
        };
        let bytes = record
            .encode()
            .map_err(|_| OverlayError::refused("writer encode"))?;
        if (bytes.len() as u64)
            .checked_mul(2)
            .and_then(|n| n.checked_add(211))
            .and_then(|n| n.checked_add(config.ownership_completion_reserve))
            .is_none_or(|n| n > config.cap)
        {
            return Err(OverlayError::no_space());
        }
        durable_file(
            io,
            faults,
            &area,
            "writer.tmp",
            "writer",
            &bytes,
            "overlay.writer",
            0,
        )?;
        Ok(record)
    }

    /// `base` is the authenticated tree named by `header`. Pending ownership
    /// returns an inert component after custody checks, without repair or sweep.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    #[expect(
        clippy::too_many_arguments,
        reason = "one recovery transaction receives independent authority and filesystem inputs"
    )]
    pub fn open(
        store: &mut Store,
        config: OverlayConfig,
        header: JournalHeader,
        base: Vec<OverlayEntry>,
        ownership: &OwnershipStatus,
        source: &mut impl ContentSource,
        io: P,
        faults: FaultControl,
    ) -> Result<Self, OverlayError> {
        Self::open_shared(
            store, config, header, base, ownership, source, io, faults, false,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one recovery transaction receives independent authority and filesystem inputs"
    )]
    pub(crate) fn open_shared(
        store: &Store,
        config: OverlayConfig,
        header: JournalHeader,
        base: Vec<OverlayEntry>,
        ownership: &OwnershipStatus,
        source: &mut impl ContentSource,
        mut io: P,
        faults: FaultControl,
        carry_forward: bool,
    ) -> Result<Self, OverlayError> {
        let root = store.publication_root().to_owned();
        io.check_root(&root, config.euid)?;
        crate::overlay_discard::claims::gate(&mut io, &root, &config.volume)?;
        let scope = config
            .scope
            .digest()
            .map_err(|_| OverlayError::refused("scope"))?;
        let overlay = root.join("overlay");
        io.directory(&overlay)?;
        for other in io.entries(&overlay)? {
            if !granary_core::retained_archive::is_scope_digest(other.as_bytes()) {
                return Err(OverlayError::refused("foreign scope"));
            }
            let path = overlay.join(&other);
            io.directory(&path)?;
            for volume in io.entries(&path)? {
                if granary_core::overlay_discard::DiscardName::parse(volume.as_bytes())
                    .is_ok_and(|name| name.is_some())
                {
                    continue; // The claim gate already validated this sibling.
                }
                if VolumeName::from_bytes(volume.as_bytes()).is_err() {
                    return Err(OverlayError::refused("foreign volume"));
                }
                io.directory(&path.join(&volume))?;
                if volume == config.volume.as_str() && other != scope {
                    return Err(OverlayError::refused("second scope for volume"));
                }
            }
        }
        let area = super::area_path(&root, &config.scope, &config.volume)?;
        io.directory(&area)?;
        io.directory(&area.join("staging"))?;
        settle_area(&mut io, &faults, &area)?;
        let writer = read_writer(&mut io, &area.join("writer"))?;
        if writer.volume != config.volume || writer.writer != header.writer {
            return Err(OverlayError::refused("writer volume/identity"));
        }
        let incarnation = next_incarnation()?;
        let unmerged_inventory = super::unmerged::inventory(&mut io, &area, config.cap)?;
        let unmerged = super::unmerged::lengths(&unmerged_inventory);
        let mut io = super::accounting::Accounted::new(io, area.join("staging"), unmerged);
        io.inventory()?;
        let mut result = Self {
            io,
            root,
            area,
            config,
            scope,
            writer,
            journal: Mutex::new(Journal {
                header,
                state: JournalState::new(&header),
                length: 117,
                incarnation,
                completion: CompletionReserve::default(),
            }),
            query_incarnation: incarnation,
            namespace: Namespace::base(&base)?,
            base,
            readiness: OverlayReadiness::PendingReconciliation,
            next_capture: 1,
            snapshots: BTreeMap::new(),
            versions: super::snapshot::Versions::default(),
            history: super::provenance::History::default(),
            flushed: std::collections::BTreeSet::new(),
            summary: OverlaySummary::default(),
            bundle_failure: None,
            faults,
            completion_credit: 0,
            replayed: false,
            served: false,
            sweep_manifest: Vec::new(),
            dirty_spans: Vec::new(),
            last_boundary_seq: 0,
            dirty_split_seq: 0,
            projected_seal: None,
            coalesce_clock: None,
            coalesce_wake: std::sync::Arc::new(tokio::sync::Notify::new()),
            capacity_refused: None,
            capacity_exhaustion: None,
        };
        // Even a supplied permission cannot excuse foreign custody. Ownership
        // bytes are never read here; both carrier names are preserved and charged.
        result.summary.charged_bytes = result.charge()?;
        match result.check(store, ownership) {
            Err(OverlayError::PendingReconciliation) => {
                result.measure_unreplayed();
                observe::overlay_recovery(
                    observe::RecoveryOutcome::Pending,
                    0,
                    result.config.cap,
                    result.summary,
                );
                return Ok(result);
            }
            other => other?,
        }
        result.classify_unmerged(unmerged_inventory)?;
        if result.io.length(&result.journal_path())?.is_none() {
            if !result.io.entries(&result.area.join("staging"))?.is_empty() {
                return Err(OverlayError::refused("journal missing beside staging"));
            }
            if !result.io.unmerged().is_empty() {
                return Err(OverlayError::refused("journal missing beside unmerged"));
            }
            let bytes = header
                .encode()
                .map_err(|_| OverlayError::refused("initial journal header"))?;
            codec::scan_journal(&bytes)
                .map_err(|_| OverlayError::refused("initial journal scan"))?
                .check_writer(&result.writer)
                .map_err(|_| OverlayError::refused("initial journal writer"))?;
            result.install_journal(&bytes, "overlay.journal.create", |overlay| {
                overlay.capacity(bytes.len() as u64, 117, 0)
            })?;
            result.readiness = OverlayReadiness::PendingReconciliation;
        }
        result.check(store, ownership)?;
        result.recover_settled(source, |overlay| overlay.carry_forward(carry_forward))?;
        Ok(result)
    }

    pub(super) fn journal_bytes(&mut self) -> Result<Vec<u8>, OverlayError> {
        let path = self.journal_path();
        let result = read_journal(&mut self.io, &path);
        if let Err(error) = &result {
            self.record_bundle_failure(error);
        }
        result
    }
    /// Complete replay under a durable carrier grant. The component's
    /// poison is terminal; reopening requires the mediator's recovery lifecycle.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn recover(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        source: &mut impl ContentSource,
    ) -> Result<(), OverlayError> {
        self.recover_shared(store, ownership, source)
    }

    /// What a recovery that has not replayed owes, measured from the area's
    /// files: the journal's length and one stage per staged file. Completion
    /// slots are unknown before replay, so `owed` is a lower bound; a failed
    /// measurement leaves the summary as it was.
    fn measure_unreplayed(&mut self) {
        let Ok(length) = self.io.length(&self.journal_path()) else {
            return;
        };
        let stages = self.io.stages().len();
        if let Ok(measured) =
            self.measure(length.unwrap_or(117), stages, &CompletionReserve::default())
        {
            self.summary.owed = measured.owed;
        }
    }

    /// Leave the store pending recovery without a replay: measure what it
    /// owes and report the pending outcome.
    fn enter_pending(&mut self) {
        self.readiness = OverlayReadiness::PendingRecovery;
        self.replayed = false;
        self.measure_unreplayed();
        self.summary.rolled_back_stages = 0;
        self.summary.rolled_back_bytes = 0;
        observe::overlay_recovery(
            observe::RecoveryOutcome::Pending,
            self.namespace.stages.len() as u64,
            self.config.cap,
            self.summary,
        );
    }

    /// Delayed replay uses the current durable inventory before cutting a tail.
    fn recover_shared(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        source: &mut impl ContentSource,
    ) -> Result<(), OverlayError> {
        self.check_context(store)?;
        settle_area(&mut self.io, &self.faults, &self.area)?;
        self.check_evidence(ownership)?;
        self.recover_settled(source, |overlay| {
            let inventory =
                super::unmerged::inventory(&mut overlay.io, &overlay.area, overlay.config.cap)?;
            overlay.classify_unmerged(inventory)?;
            Ok(false)
        })
    }

    /// Classify the export inventory against the canonical journal, if present.
    fn classify_unmerged(&mut self, inventory: UnmergedInventory) -> Result<(), OverlayError> {
        let path = self.journal_path();
        let bytes = if self.io.length(&path)?.is_some() {
            Some(self.journal_bytes()?)
        } else {
            None
        };
        super::unmerged::classify(inventory, bytes.as_deref()).map(|_| ())
    }

    fn recover_settled(
        &mut self,
        source: &mut impl ContentSource,
        prepare: impl FnOnce(&mut Self) -> Result<bool, OverlayError>,
    ) -> Result<(), OverlayError> {
        self.served = false;
        let result = prepare(self).and_then(|carried| self.replay(source, carried));
        if matches!(&result, Err(OverlayError::ContentUnavailable)) {
            self.enter_pending();
        } else if result.is_err() {
            observe::overlay_refused(
                observe::FailureClass::Corrupt,
                self.summary.records,
                self.namespace.stages.len() as u64,
                self.summary.charged_bytes,
            );
            self.poison();
        }
        result
    }
    /// Install `bytes` as the journal through its temporary, under the fault
    /// seam `name`. Before the rename the canonical journal is authoritative,
    /// so a temporary an interrupted install left is removed first; `admit`
    /// then runs, and the component stays poisoned until the caller settles it.
    pub(super) fn install_journal(
        &mut self,
        bytes: &[u8],
        name: &'static str,
        admit: impl FnOnce(&mut Self) -> Result<(), OverlayError>,
    ) -> Result<(), OverlayError> {
        let next = self.area.join("journal.next");
        if self.io.length(&next)?.is_some() {
            self.io.remove(&next)?;
            self.io.sync_directory(&self.area)?;
        }
        admit(self)?;
        self.poison();
        durable_file(
            &mut self.io,
            &self.faults,
            &self.area,
            "journal.next",
            "journal",
            bytes,
            name,
            0,
        )
    }

    /// When `enabled`, rewrite a clean journal written on an older base,
    /// header-only, on the opened header's base, so that replay starts on that
    /// base; returns whether it did. It carries only a journal whose header
    /// lies strictly below the opened base and that scans clean, is bound to
    /// this writer, holds only bookkeeping and has no staging file beside it.
    /// Otherwise nothing is written and replay's base comparison refuses as
    /// before. All evidence is validated before the leftover temporary is
    /// swept or the journal replaced; a failed rewrite leaves the component
    /// poisoned.
    fn carry_forward(&mut self, enabled: bool) -> Result<bool, OverlayError> {
        if !enabled {
            return Ok(false);
        }
        let expected = self.journal.lock().map_err(Self::lock_error)?.header;
        let Ok(raw) = self
            .io
            .read_at(&self.journal_path(), 0, codec::JOURNAL_HEADER_LEN)
        else {
            return Ok(false);
        };
        if !JournalHeader::decode(&raw).is_ok_and(|header| header.base_seq < expected.base_seq) {
            return Ok(false);
        }
        let Ok(bytes) = self.journal_bytes() else {
            return Ok(false);
        };
        let Some((scan, true)) = super::replacement::scan_clean(&bytes, &self.writer) else {
            return Ok(false);
        };
        if !self.io.entries(&self.area.join("staging"))?.is_empty() {
            return Ok(false);
        }
        let header = JournalHeader {
            writer: expected.writer,
            base_root: expected.base_root,
            base_seq: expected.base_seq,
            next_stage_id: scan.state.next_stage_id(),
            receipt_generation: scan.state.highest_generation(),
        };
        let bytes = header
            .encode()
            .map_err(|_| OverlayError::refused("carried journal header"))?;
        let carried = codec::scan_journal(&bytes)
            .map_err(|_| OverlayError::refused("carried journal scan"))?;
        self.install_journal(&bytes, "overlay.journal.carry", |_| Ok(()))?;
        let mut journal = self.journal.lock().map_err(Self::lock_error)?;
        journal.header = carried.header;
        journal.state = carried.state;
        journal.length = carried.valid_len as u64;
        drop(journal);
        self.readiness = OverlayReadiness::PendingReconciliation;
        Ok(true)
    }
    #[expect(
        clippy::too_many_lines,
        reason = "validation of all evidence precedes any repair or sweep"
    )]
    fn replay(
        &mut self,
        source: &mut impl ContentSource,
        carried: bool,
    ) -> Result<(), OverlayError> {
        self.io.inventory()?;
        self.charge()?;
        let mut bytes = self.journal_bytes()?;
        let expected = self.journal.lock().map_err(Self::lock_error)?.header;
        let now = self.coalesce_clock.as_ref().map(|clock| (clock.0)());
        let (
            scan,
            namespace,
            evidence,
            completion,
            dirty_spans,
            last_boundary_seq,
            commit_pending,
            present,
            sweep,
            torn_headers,
        ) = loop {
            let mut namespace = Namespace::base(&self.base)?;
            let mut folded = Ok(());
            let mut commit_pending = false;
            let mut completion = CompletionReserve::default();
            let mut dirty_spans: Vec<super::DirtySpan> = Vec::new();
            let mut last_boundary_seq = 0_u64;
            let mut through = 0;
            let mut evidence: BTreeMap<u64, StageReplay> = BTreeMap::new();
            let scan = codec::scan_journal_with(&bytes, |index, record| {
                let dirty = dirty_record(&namespace, record);
                if folded.is_ok() {
                    let prior = match record {
                        Record::WriteExtent { stage_id, .. }
                        | Record::Truncate { stage_id, .. }
                        | Record::StageRollback { stage_id, .. }
                        | Record::FileSynced { stage_id, .. } => namespace
                            .stages
                            .get(stage_id)
                            .map(|stage| (*stage_id, stage.size)),
                        _ => None,
                    };
                    folded = namespace
                        .fold(record)
                        .and_then(|()| completion.fold(index, record));
                    if let Some((id, prior_size)) = prior
                        && let Some(stage) = namespace.stages.get(&id)
                    {
                        evidence
                            .entry(id)
                            .or_default()
                            .fold(index, record, stage, prior_size);
                    }
                }
                if let Record::CommitBoundary { through_seq, .. }
                | Record::ProjectedBoundary { through_seq, .. } = record
                {
                    through = through.max(*through_seq);
                }
                // An in-doubt projected boundary holds service like any boundary
                // but does not split dirty spans: a landing keeps each span its
                // residual work came from whole, with that span's oldest age.
                if matches!(record, Record::ProjectedBoundary { .. }) {
                    commit_pending = true;
                }
                if let Record::CommitBoundary { through_seq, .. } = record {
                    commit_pending = true;
                    if let Some(span) = dirty_spans.last_mut().filter(|span| {
                        span.first_seq <= *through_seq && span.last_seq > *through_seq
                    }) {
                        let last_seq = span.last_seq;
                        span.last_seq = *through_seq;
                        dirty_spans.push(super::DirtySpan {
                            first_seq: *through_seq + 1,
                            last_seq,
                            first_at: now,
                            last_at: now,
                        });
                    }
                    last_boundary_seq = index;
                } else if dirty {
                    if let Some(span) = dirty_spans
                        .last_mut()
                        .filter(|span| span.last_seq > last_boundary_seq)
                    {
                        span.last_seq = index;
                        span.last_at = now;
                    } else {
                        dirty_spans.push(super::DirtySpan {
                            first_seq: index,
                            last_seq: index,
                            first_at: now,
                            last_at: now,
                        });
                    }
                }
            })
            .map_err(|_| OverlayError::refused("journal fenced"))?;
            folded?;
            if scan.header.base_root != expected.base_root
                || scan.header.base_seq != expected.base_seq
            {
                return Err(OverlayError::refused("base root/sequence mismatch"));
            }
            scan.check_writer(&self.writer)
                .map_err(|_| OverlayError::refused("writer ceiling or identity"))?;
            if scan.state.residual_disposition().is_some() {
                // A sealed source cannot be repaired before its inventory is verified.
                let mut journal = self.journal.lock().map_err(Self::lock_error)?;
                journal.state = scan.state;
                journal.length = scan.valid_len as u64;
                drop(journal);
                self.enter_pending();
                return Ok(());
            }
            let mut sweep = Vec::new();
            let mut present = std::collections::BTreeSet::new();
            let mut torn_headers = Vec::new();
            let mut unmatched_marks = std::collections::BTreeSet::new();
            // All headers, including late unnamed mirrors, precede any mutation.
            for name in self.io.entries(&self.area.join("staging"))? {
                let id =
                    stage_id(&name).ok_or_else(|| OverlayError::refused("foreign staging name"))?;
                let path = self.stage_path(id);
                let length = self
                    .io
                    .length(&path)?
                    .ok_or_else(|| OverlayError::refused("stage vanished"))?;
                let raw = self.io.read_at(&path, 0, 160)?;
                let header = if raw.len() < 160 {
                    let expected = StagingHeader {
                        writer: self.writer.writer,
                        stage_id: id,
                        mark: MarkState::Absent,
                    };
                    let canonical = expected
                        .encode()
                        .map_err(|_| OverlayError::refused("staging header encode"))?;
                    if !canonical.starts_with(&raw) {
                        return Err(OverlayError::refused("unprovable short staging header"));
                    }
                    if scan.state.stage(id).is_some() {
                        torn_headers.push((id, canonical));
                    }
                    expected
                } else {
                    StagingHeader::decode(&raw)
                        .map_err(|_| OverlayError::refused("staging header"))?
                };
                if matches!(header.mark,MarkState::Present(mark) if mark.generation>self.writer.ceiling)
                {
                    return Err(OverlayError::refused("mark above ceiling"));
                }
                match scan
                    .classify_staging(id, &header)
                    .map_err(|_| OverlayError::refused("stage identity binding"))?
                {
                    codec::StagingDisposition::RecoveryEvidence => {
                        return Err(OverlayError::refused("unnamed synced staging evidence"));
                    }
                    codec::StagingDisposition::Sweep => sweep.push(SweepEntry {
                        stage_id: id,
                        bytes: length,
                        modified: self.io.modified(&path)?,
                    }),
                    codec::StagingDisposition::Named => {
                        present.insert(id);
                        if let MarkState::Present(mark) = header.mark {
                            let stage = namespace
                                .stages
                                .get_mut(&id)
                                .ok_or_else(|| OverlayError::refused("named stage missing"))?;
                            let agrees = stage.agrees_with(mark);
                            if !agrees {
                                unmatched_marks.insert(id);
                            }
                            match stage.mark {
                                Some(old) if old.generation == mark.generation && old != mark => {
                                    return Err(OverlayError::refused("equal mark conflict"));
                                }
                                Some(old) if old.generation >= mark.generation => {}
                                _ => {
                                    let peak = evidence
                                        .get(&id)
                                        .map_or(stage.size, |proof| proof.size_peak);
                                    if !agrees && mark.synced_size > peak {
                                        return Err(OverlayError::refused(
                                            "synced mark beyond journal",
                                        ));
                                    }
                                    if stage.rollback.is_some() {
                                        // A short live extent can authenticate a newer mirror's
                                        // bytes. The mirror alone cannot supersede the baseline
                                        // as a capture checkpoint.
                                        evidence.entry(id).or_default().mirrored_mark = Some(mark);
                                    } else {
                                        stage.mark = Some(mark);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // A subsequent rescan may reuse the cut sequence numbers for rollbacks.
            let mut discarded: BTreeSet<_> = self
                .history
                .records
                .iter()
                .rev()
                .take_while(|effect| effect.seq >= scan.state.next_seq())
                .filter_map(|effect| super::replacement::reference(&effect.record))
                .collect();
            let mut rollbacks = Vec::new();
            for (&id, stage) in &namespace.stages {
                if !present.contains(&id)
                    && stage.mark.is_none()
                    && stage.inherited().0.is_none()
                    && stage.rollback.is_none()
                {
                    return Err(OverlayError::refused("missing unanchored staging"));
                }
                if stage.extents.is_empty() {
                    continue;
                }
                let proof = evidence
                    .get(&id)
                    .ok_or_else(|| OverlayError::refused("not extent"))?;
                let mut failed = false;
                let mut discarded_bytes = 0u64;
                for (&offset, extent) in &stage.extents {
                    let seq = *proof
                        .extent_seqs
                        .get(&offset)
                        .ok_or_else(|| OverlayError::refused("not extent"))?;
                    let Record::WriteExtent { length, .. } = extent else {
                        return Err(OverlayError::refused("not extent"));
                    };
                    if seq > proof.synced_seq {
                        // Live checks are disjoint and lie within the stage's size limit.
                        discarded_bytes += length;
                    }
                    if let Some(failure) =
                        self.replay_extent(id, proof.extent_anchor(stage), extent, source)?
                    {
                        if !extent_above_acknowledgements(seq, proof.synced_seq, through)
                            || proof.first_payload.is_some_and(|first| first <= through)
                            || unmatched_marks.contains(&id)
                        {
                            return Err(failure.refusal());
                        }
                        failed = true;
                    }
                }
                if failed {
                    discarded.insert(id);
                    let (content, size) = stage.checkpoint();
                    let anchor = content.map(|content| codec::RecreateAnchor { content, size });
                    rollbacks.push(Record::StageRollback {
                        stage_id: id,
                        old_size: stage.size,
                        anchor,
                        discarded_bytes,
                    });
                }
            }
            // A local reconciliation is not a process restart: preserve capabilities
            // and inode identities, and refuse to discard a still-held stage.
            namespace.preserve_inodes(&self.namespace, &BTreeMap::new())?;
            for (&id, previous) in &self.namespace.stages {
                if let Some(stage) = namespace.stages.get_mut(&id) {
                    stage.handles = previous.handles;
                    stage.captures = previous.captures.clone();
                } else if previous.handles > 0 || !previous.captures.is_empty() {
                    return Err(OverlayError::refused("replay would discard held stage"));
                }
            }
            if rollbacks.is_empty() {
                self.versions
                    .discard_stage_versions(&self.namespace.stages, &discarded);
                break (
                    scan,
                    namespace,
                    evidence,
                    completion,
                    dirty_spans,
                    last_boundary_seq,
                    commit_pending,
                    present,
                    sweep,
                    torn_headers,
                );
            }
            bytes.truncate(scan.valid_len);
            for (seq, record) in (scan.state.next_seq()..).zip(&rollbacks) {
                let frame = codec::encode_record(&scan.header, seq, record)
                    .map_err(|_| OverlayError::refused("record encode"))?;
                bytes.extend_from_slice(&frame);
            }
            codec::scan_journal(&bytes).map_err(|_| OverlayError::refused("journal fenced"))?;
            // A retry may see the installed rollback even if repair awaits content.
            self.versions
                .discard_stage_versions(&self.namespace.stages, &discarded);
            self.install_journal(&bytes, "overlay.journal.rollback", |_| Ok(()))?;
            if self.journal_bytes()? != bytes {
                return Err(OverlayError::refused("repaired journal changed"));
            }
            // The installed image is now the input to the fold and final rescan.
        };

        self.namespace = namespace;
        self.history = super::provenance::History::replay(&self.base, &bytes, &mut self.namespace)?;
        let generation = scan.state.highest_generation();
        if generation > self.writer.ceiling {
            return Err(OverlayError::refused("replay ceiling"));
        }
        // Recorded work above the cap refuses new admissions, not the replay:
        // the summary settles once the journal state is installed.
        match self.capacity_with(
            0,
            scan.valid_len as u64,
            self.namespace.stages.len(),
            &completion,
        ) {
            Ok(()) | Err(OverlayError::NoSpace) => {}
            Err(e) => return Err(e),
        }
        // No repair starts before global custody/evidence/extent validation.
        let mut repaired = scan.end != codec::JournalEnd::Clean
            || !sweep.is_empty()
            || !torn_headers.is_empty()
            || carried;
        for (id, header) in torn_headers {
            self.io.write_at(&self.stage_path(id), 0, &header)?;
            self.io.sync(&self.stage_path(id))?;
        }
        let ids: Vec<_> = self.namespace.stages.keys().copied().collect();
        for &id in &ids {
            let stage = self
                .namespace
                .stages
                .get(&id)
                .ok_or_else(|| OverlayError::refused("repair stage"))?
                .clone();
            let proof = evidence.get(&id);
            let path = self.stage_path(id);
            if !present.contains(&id) {
                self.io.create(&path)?;
                let header = StagingHeader {
                    writer: self.writer.writer,
                    stage_id: id,
                    mark: stage.mark.map_or(MarkState::Absent, MarkState::Present),
                }
                .encode()
                .map_err(|_| OverlayError::refused("repair header"))?;
                self.io.write_at(&path, 0, &header)?;
                repaired = true;
            }
            let extent_anchor = proof.and_then(|proof| proof.extent_anchor(&stage));
            repaired |= self.repair_stage(id, &stage, stage.checkpoint(), extent_anchor, source)?;
        }
        point(&self.faults, "overlay.stage.dir_sync", "before", 0)?;
        self.io.sync_directory(&self.area.join("staging"))?;
        point(&self.faults, "overlay.stage.dir_sync", "after", 0)?;
        if scan.end != codec::JournalEnd::Clean {
            point(
                &self.faults,
                "overlay.tail.cut",
                "before",
                scan.state.next_seq(),
            )?;
            self.io
                .resize(&self.journal_path(), scan.valid_len as u64)?;
            point(
                &self.faults,
                "overlay.tail.cut",
                "after-cut",
                scan.state.next_seq(),
            )?;
            self.io.sync(&self.journal_path())?;
            point(
                &self.faults,
                "overlay.tail.cut",
                "after-sync",
                scan.state.next_seq(),
            )?;
        }
        for entry in sweep {
            let id = entry.stage_id;
            let length = entry.bytes;
            point(
                &self.faults,
                "overlay.sweep.remove",
                "before",
                scan.state.next_seq(),
            )?;
            self.io.remove(&self.stage_path(id))?;
            self.summary.swept_files += 1;
            self.summary.swept_bytes += length;
            self.sweep_manifest.push(entry);
            point(
                &self.faults,
                "overlay.sweep.remove",
                "after",
                scan.state.next_seq(),
            )?;
        }
        self.io.sync_directory(&self.area.join("staging"))?;
        point(
            &self.faults,
            "overlay.sweep.remove",
            "after-dir-sync",
            scan.state.next_seq(),
        )?;
        for name in ["writer.tmp", "journal.next"] {
            let p = self.area.join(name);
            if self.io.length(&p)?.is_some() {
                self.io.remove(&p)?;
                self.io.sync_directory(&self.area)?;
                repaired = true;
            }
        }
        let final_bytes = self.journal_bytes()?;
        let final_scan = codec::scan_journal(&final_bytes)
            .map_err(|_| OverlayError::refused("repaired journal rescan"))?;
        if final_scan.end != codec::JournalEnd::Clean
            || final_scan.header != scan.header
            || final_scan.valid_len != scan.valid_len
        {
            return Err(OverlayError::refused("repaired journal changed"));
        }
        let checks: Vec<_> = self
            .namespace
            .stages
            .iter()
            .flat_map(|(&id, s)| s.extents.values().cloned().map(move |e| (id, e)))
            .collect();
        for (id, extent) in checks {
            self.verify_extent(id, &extent)?;
        }
        for id in &ids {
            self.header(*id)?;
        }
        let mut journal = self.journal.lock().map_err(Self::lock_error)?;
        journal.header = scan.header;
        journal.state = scan.state;
        journal.length = scan.valid_len as u64;
        journal.completion = completion;
        self.summary.records = journal.state.next_seq() - 1;
        drop(journal);
        self.dirty_spans = dirty_spans;
        self.last_boundary_seq = last_boundary_seq;
        self.dirty_split_seq = last_boundary_seq;
        // The in-doubt coordinator or landed replacement must run before service.
        self.query_incarnation = next_incarnation()?;
        self.replayed = true;
        self.readiness = if commit_pending {
            OverlayReadiness::PendingRecovery
        } else {
            OverlayReadiness::Ready
        };
        self.settle_summary()?;
        if self.summary.swept_files > 0 {
            observe::overlay_sweep(self.summary.swept_files, self.summary.swept_bytes);
        }
        self.summary.rolled_back_stages = 0;
        self.summary.rolled_back_bytes = 0;
        for (&id, stage) in &self.namespace.stages {
            if let Some((seq, old_size, discarded_bytes)) =
                evidence.get(&id).and_then(|proof| proof.rollback_report)
            {
                point(&self.faults, "overlay.stage.rollback_report", "before", seq)?;
                observe::stage_rolled_back(
                    seq,
                    id,
                    stage.path.as_deref(),
                    old_size,
                    stage.size,
                    discarded_bytes,
                );
                self.summary.rolled_back_stages += 1;
                self.summary.rolled_back_bytes = self
                    .summary
                    .rolled_back_bytes
                    .saturating_add(discarded_bytes);
            }
        }
        observe::overlay_recovery(
            if commit_pending {
                observe::RecoveryOutcome::Pending
            } else if repaired || self.summary.rolled_back_stages > 0 {
                observe::RecoveryOutcome::Repaired
            } else {
                observe::RecoveryOutcome::Clean
            },
            self.namespace.stages.len() as u64,
            self.config.cap,
            self.summary,
        );
        Ok(())
    }

    /// Reconcile carried stages using the checkpoint bound by the installed image.
    pub(super) fn repair_installed_stages(
        &mut self,
        source: &mut impl ContentSource,
    ) -> Result<(), OverlayError> {
        let ids: Vec<_> = self.namespace.stages.keys().copied().collect();
        for id in ids {
            let stage = self
                .namespace
                .stages
                .get(&id)
                .ok_or_else(|| OverlayError::refused("repair stage"))?
                .clone();
            // Replay already verified and restored the live extents.
            self.repair_stage(id, &stage, stage.checkpoint(), None, source)?;
        }
        Ok(())
    }

    fn repair_stage(
        &mut self,
        id: u64,
        stage: &Stage,
        (content, anchor_size): (Option<GrainId>, u64),
        extent_anchor: Option<(GrainId, u64)>,
        source: &mut impl ContentSource,
    ) -> Result<bool, OverlayError> {
        let path = self.stage_path(id);
        let mut repaired = false;
        let mut cursor = 0;
        while cursor < stage.size {
            let boundary = stage
                .extents
                .values()
                .filter_map(|e| match e {
                    Record::WriteExtent { offset, length, .. } => Some((*offset, offset + length)),
                    _ => None,
                })
                .find(|(a, b)| *a <= cursor && cursor < *b);
            if let Some((_, end)) = boundary {
                if self.io.length(&path)?.unwrap_or(0) < 160 + end {
                    let (content, anchor_size) =
                        extent_anchor.ok_or_else(|| OverlayError::refused("live repair anchor"))?;
                    if end > anchor_size {
                        return Err(OverlayError::refused("live repair bounds"));
                    }
                    let n = usize_bound((end - cursor).min(BUFFER as u64))?;
                    let data = replay_verified(source, content, cursor, n, &self.faults)?;
                    write_step(
                        &mut self.io,
                        &self.faults,
                        "overlay.stage.write",
                        &path,
                        160 + cursor,
                        &data,
                        0,
                    )?;
                    cursor += n as u64;
                    repaired = true;
                    continue;
                }
                cursor = end.min(stage.size);
                continue;
            }
            let next_live = stage
                .extents
                .keys()
                .copied()
                .filter(|offset| *offset > cursor)
                .min()
                .unwrap_or(stage.size);
            let next_zero = stage
                .zeros
                .iter()
                .flat_map(|(a, b)| [*a, *b])
                .filter(|n| *n > cursor)
                .min()
                .unwrap_or(stage.size);
            let n = usize_bound(
                (stage.size - cursor)
                    .min(next_live - cursor)
                    .min(next_zero - cursor)
                    .min(BUFFER as u64),
            )?;
            let existing = self.io.read_at(&path, 160 + cursor, n)?;
            let mut data = vec![0u8; n];
            // Each chunk outside live extents is wholly inside or outside a zero
            // span. Fill it from the repair anchor up to its size and zero the rest.
            if let Some(content) = content
                && cursor < anchor_size
                && !stage.zeros.iter().any(|(a, b)| *a <= cursor && cursor < *b)
            {
                let count = usize_bound((anchor_size - cursor).min(n as u64))?;
                let fetched = replay_verified(source, content, cursor, count, &self.faults)?;
                data.get_mut(..count)
                    .ok_or_else(|| OverlayError::refused("repair range"))?
                    .copy_from_slice(&fetched);
            }
            if existing != data {
                write_step(
                    &mut self.io,
                    &self.faults,
                    "overlay.stage.write",
                    &path,
                    160 + cursor,
                    &data,
                    0,
                )?;
                repaired = true;
            }
            cursor += n as u64;
        }
        if self.io.length(&path)? != Some(160 + stage.size) {
            self.io.resize(&path, 160 + stage.size)?;
            repaired = true;
        }
        sync_step(&mut self.io, &self.faults, "overlay.stage.sync", &path, 0)?;
        Ok(repaired)
    }

    fn replay_extent(
        &mut self,
        id: u64,
        anchor: Option<(GrainId, u64)>,
        extent: &Record,
        source: &mut impl ContentSource,
    ) -> Result<Option<LiveExtentFailure>, OverlayError> {
        let Record::WriteExtent {
            offset,
            length,
            check,
            ..
        } = extent
        else {
            return Err(OverlayError::refused("not extent"));
        };
        let end = offset
            .checked_add(*length)
            .ok_or_else(|| OverlayError::refused("live extent bounds"))?;
        let stage_end = end
            .checked_add(160)
            .ok_or_else(|| OverlayError::refused("live extent bounds"))?;
        if self.io.length(&self.stage_path(id))?.unwrap_or(0) < stage_end {
            let Some((content, anchor_size)) = anchor else {
                return Ok(Some(LiveExtentFailure::MissingAnchor));
            };
            if end > anchor_size {
                return Ok(Some(LiveExtentFailure::BeyondAnchor));
            }
            let mut fetched = Vec::with_capacity(usize_bound(*length)?);
            let mut cursor = *offset;
            while cursor < end {
                let n = usize_bound((end - cursor).min(BUFFER as u64))?;
                fetched.extend_from_slice(&replay_verified(
                    source,
                    content,
                    cursor,
                    n,
                    &self.faults,
                )?);
                cursor = cursor
                    .checked_add(n as u64)
                    .ok_or_else(|| OverlayError::refused("live extent bounds"))?;
            }
            if codec::extent_check(id, *offset, &fetched) != *check {
                return Ok(Some(LiveExtentFailure::RefetchedMismatch));
            }
        } else if self.check_extent(id, extent)?.is_none() {
            return Ok(Some(LiveExtentFailure::Mismatch));
        }
        Ok(None)
    }
}

fn replay_verified(
    source: &mut dyn super::ContentSource,
    content: granary_core::hash::GrainId,
    offset: u64,
    length: usize,
    faults: &FaultControl,
) -> Result<Vec<u8>, OverlayError> {
    point(faults, "overlay.replay.authenticated_read", "before", 0)?;
    verified(source, content, offset, length)
}

/// Settle the namespace and journal before using overlay evidence.
/// # Errors
/// Returns a custody or persistence error before reading replay evidence.
pub(crate) fn settle_area(
    io: &mut impl OverlayIo,
    faults: &FaultControl,
    area: &Path,
) -> Result<(), OverlayError> {
    const BARRIER: &str = "overlay.open.barrier";
    match io.directory(area) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    point(faults, BARRIER, "area", 0)?;
    io.sync_directory(area)?;
    let staging = area.join("staging");
    match io.directory(&staging) {
        Ok(()) => {
            point(faults, BARRIER, "staging", 0)?;
            io.sync_directory(&staging)?;
        }
        // An interrupted directory establishment can precede every carrier.
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && io.entries(area)?.iter().all(|name| name == "writer.tmp") =>
        {
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    // No production path renames or unlinks under unmerged/. An export writer needs a sync here.
    let journal = area.join("journal");
    if io.length(&journal)?.is_some() {
        point(faults, BARRIER, "journal", 0)?;
        io.sync(&journal)?;
    }
    Ok(())
}

fn establish_directories<P: OverlayIo>(
    io: &mut P,
    root: &Path,
    area: &Path,
) -> Result<(), OverlayError> {
    io.establish(root)?;
    let relative = area
        .strip_prefix(root)
        .map_err(|_| OverlayError::refused("overlay root"))?;
    let mut prefix = root.to_owned();
    for component in relative.components() {
        let parent = prefix.clone();
        prefix.push(component.as_os_str());
        io.create_directory(&prefix)?;
        if parent == root {
            io.establish(root)?;
        } else {
            io.sync_directory(&parent)?;
        }
        io.sync_directory(&prefix)?;
    }
    io.create_directory(&area.join("staging"))?;
    io.sync_directory(area)?;
    Ok(())
}

pub(super) fn read_writer(
    io: &mut impl OverlayIo,
    path: &Path,
) -> Result<WriterRecord, OverlayError> {
    let length = io
        .length(path)?
        .ok_or_else(|| OverlayError::refused("writer missing"))?;
    let bytes = io.read_at(path, 0, 132)?;
    if bytes.len() as u64 != length || io.length(path)? != Some(length) {
        return Err(OverlayError::refused(
            "writer length changed or exceeded bound",
        ));
    }
    WriterRecord::decode(&bytes).map_err(|_| OverlayError::refused("writer decode"))
}

/// The journal at `path`, read whole within its input budget.
fn read_journal(io: &mut impl OverlayIo, path: &Path) -> Result<Vec<u8>, OverlayError> {
    let length = io
        .length(path)?
        .ok_or_else(|| OverlayError::refused("journal missing"))?;
    if length > codec::JOURNAL_MAX as u64 {
        return Err(OverlayError::refused("journal input budget"));
    }
    let bytes = io.read_at(path, 0, codec::JOURNAL_MAX + 1)?;
    if bytes.len() as u64 != length
        || bytes.len() > codec::JOURNAL_MAX
        || io.length(path)? != Some(length)
    {
        return Err(OverlayError::refused(
            "journal input changed or exceeded budget",
        ));
    }
    Ok(bytes)
}

/// The journal in the overlay area `area`, read before any overlay opens on
/// it: `None` when there is none, else its header and whether it is clean
/// as a carry finds it, with no staging file beside it: anything else holds
/// work, or leftovers only a replay on its own base removes. A journal that
/// does not scan, or that another writer wrote, refuses as replay refuses it.
/// # Errors
/// `journal fenced`, `writer ceiling or identity`, the journal's input
/// budget, the writer file's own refusal, or the area's I/O.
pub(crate) fn journal_condition(
    io: &mut impl OverlayIo,
    area: &Path,
) -> Result<Option<(JournalHeader, bool)>, OverlayError> {
    crate::overlay_discard::claims::gate_area(io, area)?;
    let path = area.join("journal");
    if io.length(&path)?.is_none() {
        return Ok(None);
    }
    let writer = read_writer(io, &area.join("writer"))?;
    let bytes = read_journal(io, &path)?;
    let (scan, clean) = super::replacement::scan_clean(&bytes, &writer)
        .ok_or_else(|| OverlayError::refused("journal fenced"))?;
    scan.check_writer(&writer)
        .map_err(|_| OverlayError::refused("writer ceiling or identity"))?;
    let clean = clean && io.entries(&area.join("staging"))?.is_empty();
    Ok(Some((scan.header, clean)))
}

/// Landed commit records in the overlay journal before the overlay opens.
/// The same bounded, stable read and writer binding used by replay applies.
pub(crate) struct LandedJournal {
    pub(crate) sealed: Option<(JournalHeader, Vec<u8>, codec::ResidualDisposition)>,
    pub(crate) commits: Vec<(u64, granary_core::hash::GrainId, u64)>,
    pub(crate) refreshes: Vec<(u64, granary_core::hash::GrainId)>,
    pub(crate) registrations: Vec<(u64, granary_core::hash::GrainId)>,
    pub(crate) file_receipts: Vec<(u64, granary_core::hash::GrainId)>,
    pub(crate) boundaries: std::collections::BTreeMap<u64, ([u8; 16], granary_core::hash::GrainId)>,
    pub(crate) highest_generation: u64,
    /// The newest boundary, including one already answered by a landing.
    pub(crate) latest_boundary: Option<u64>,
    /// Each boundary no landed commit answered: its publication and whether
    /// a fence record was admitted for it.
    pub(crate) open: Vec<([u8; 16], bool)>,
}

impl LandedJournal {
    pub(crate) fn registration_of(&self, selected: granary_core::hash::GrainId) -> Option<u64> {
        self.registrations
            .iter()
            .rev()
            .find_map(|(seq, root)| (*root == selected).then_some(*seq))
    }
}

pub(crate) fn landed_commits(
    io: &mut impl OverlayIo,
    area: &Path,
) -> Result<LandedJournal, OverlayError> {
    crate::overlay_discard::claims::gate_area(io, area)?;
    let path = area.join("journal");
    if io.length(&path)?.is_none() {
        return Ok(LandedJournal {
            sealed: None,
            commits: Vec::new(),
            boundaries: std::collections::BTreeMap::new(),
            refreshes: Vec::new(),
            registrations: Vec::new(),
            file_receipts: Vec::new(),
            highest_generation: 0,
            latest_boundary: None,
            open: Vec::new(),
        });
    }
    let writer = read_writer(io, &area.join("writer"))?;
    let bytes = read_journal(io, &path)?;
    let mut commits = Vec::new();
    let mut refreshes = Vec::new();
    let mut registrations = Vec::new();
    let mut file_receipts = Vec::new();
    let mut boundaries = std::collections::BTreeMap::new();
    let scan = codec::scan_journal_with(&bytes, |seq, record| match record {
        Record::LandedCommit {
            boundary_seq,
            landed_root,
            landed_seq,
        } => commits.push((*boundary_seq, *landed_root, *landed_seq)),
        Record::IntentRegistered {
            generation,
            prepared_root,
            cause,
        } => {
            registrations.push((seq, *prepared_root));
            if *cause == codec::IntentCause::LandedRefresh {
                refreshes.push((*generation, *prepared_root));
            }
        }
        Record::FileSynced { prepared_root, .. } => file_receipts.push((seq, *prepared_root)),
        Record::CommitBoundary {
            publication_id,
            candidate,
            ..
        }
        | Record::ProjectedBoundary {
            publication_id,
            candidate,
            ..
        } => {
            boundaries.insert(seq, (*publication_id, *candidate));
        }
        _ => {}
    })
    .map_err(|_| OverlayError::refused("journal fenced"))?;
    scan.check_writer(&writer)
        .map_err(|_| OverlayError::refused("writer ceiling or identity"))?;
    let mut open = Vec::new();
    for boundary in scan.state.open_boundaries() {
        let (publication, _) = *boundaries
            .get(&boundary)
            .ok_or_else(|| OverlayError::refused("journal fenced"))?;
        let fenced = scan
            .state
            .commit_progress(&publication)
            .is_some_and(|progress| progress.fenced);
        open.push((publication, fenced));
    }
    let sealed = scan
        .state
        .residual_disposition()
        .copied()
        .map(|choice| (scan.header, bytes, choice));
    Ok(LandedJournal {
        sealed,
        commits,
        refreshes,
        registrations,
        file_receipts,
        highest_generation: scan.state.highest_generation(),
        latest_boundary: boundaries.last_key_value().map(|(seq, _)| *seq),
        boundaries,
        open,
    })
}

pub(super) fn next_incarnation() -> Result<u64, OverlayError> {
    // Process identity plus a never-reused counter binds capabilities and query observations
    // across facades and repeated opens within the same mediator process.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.try_update(
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
        |n| n.checked_add(1),
    )
    .map_err(|_| OverlayError::refused("incarnation exhaustion"))
}

/// Whether `record` leaves local work an ordinary commit still owes, folded
/// over `namespace` as it stands before the record: a same-size truncate,
/// a re-bind, a detached recreate, a rollback and the publication records
/// add no unpublished local work.
pub(super) fn dirty_record(namespace: &Namespace, record: &Record) -> bool {
    match record {
        Record::Truncate { stage_id, new_size } => namespace
            .stages
            .get(stage_id)
            .is_some_and(|stage| stage.size != *new_size),
        Record::Create { .. }
        | Record::RecreateFile { at: Some(_), .. }
        | Record::StageBind {
            cause: codec::BindCause::CopyUp,
            ..
        }
        | Record::WriteExtent { .. }
        | Record::Move { .. }
        | Record::Replace { .. }
        | Record::Delete { .. }
        | Record::SetattrExec { .. } => true,
        Record::StageBind {
            cause: codec::BindCause::Rebind,
            ..
        }
        | Record::RecreateFile { at: None, .. }
        | Record::StageRollback { .. }
        | Record::FileSynced { .. }
        | Record::IntentRegistered { .. }
        | Record::CommitBoundary { .. }
        | Record::LandedCommit { .. }
        | Record::CommitAttempt { .. }
        | Record::CommitFence { .. }
        | Record::ProjectedBoundary { .. }
        | Record::ResidualDisposition(_) => false,
    }
}

#[cfg(test)]
#[test]
fn rollback_extent_sequence_must_be_above_sync() {
    let cases = [9, 10, 11].map(|seq| extent_above_acknowledgements(seq, 10, 0));
    assert_eq!(cases, [false, false, true], "sync cutoff is exclusive");
}

#[cfg(test)]
#[test]
fn rollback_extent_sequence_must_be_above_boundary() {
    let cases = [9, 10, 11].map(|seq| extent_above_acknowledgements(seq, 0, 10));
    assert_eq!(cases, [false, false, true], "boundary cutoff is exclusive");
}
