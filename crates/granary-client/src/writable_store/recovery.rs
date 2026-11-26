// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Explicit disk-loss selection and acknowledgement, independent of mount UI.

use super::{
    BundleRefusal, Carrier, Clock, CoordinationError, FaultControl, HORIZON_MILLIS, IntentReply,
    Operation, OverlayConfig, OverlayIo, OverlayStore, Ownership, OwnershipMode,
    OwnershipPermission, OwnershipStatus, Pending, PendingIntent, Phase, Receipt, ReceiptState,
    RootDoc, SecureRandom, SelectedWriter, Store, Verdict, WritableStore, codec, intent,
    is_unstarted_takeover, now, refused, retire_displaced_release,
};
use crate::observe::{RecoverEvent, recover};
use granary_core::root::VolumeName;
use granary_core::{hash::GrainId, retained_submission::Scope};
use std::collections::BTreeSet;

/// A boundary commit requires recovery even if its refresh is already registered.
fn boundary_unrefreshed(landed: &crate::overlay_store::LandedJournal) -> Option<bool> {
    landed
        .commits
        .iter()
        .find(|(seq, _, _)| Some(*seq) == landed.latest_boundary)
        .map(|(_, root, _)| {
            !landed
                .refreshes
                .iter()
                .any(|(_, refreshed)| refreshed == root)
        })
}

/// Where explicit recovery places a store, in evaluation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryRule {
    /// Not owned (fenced, unowned or still in its handshake), beside a
    /// journalled landing with no refresh: report only.
    LandedUnowned,
    /// Not owned otherwise: report only.
    OwnershipLost,
    /// A journalled landing whose refresh is not registered.
    LandedUnrefreshed,
    /// A journalled landing with its refresh: the install is owed.
    LandedRefreshed,
    /// An open boundary whose own retained record completed.
    BoundaryComplete,
    /// An open boundary with its own incomplete retained record.
    BoundaryRecorded,
    /// An open unfenced boundary with no record for it: none, or a settled
    /// record of an earlier commit.
    BoundaryUnrecorded,
    /// An open boundary whose record was archived.
    BoundaryArchived,
    /// An open boundary no retained record accounts for: fenced with none,
    /// beside an unsettled foreign record, or one of several.
    BoundaryUnaccounted,
    /// No boundary; archive terminal evidence or resume an incomplete publication.
    ResumeRecovery,
    /// The registered root's own publication or installed landing completed
    /// over an absent or clean journal: release the row.
    Release,
    /// No boundary; the journal holds work.
    DirtyJournal,
    /// Classify the registered root against the remote chain.
    Classify,
    /// Nothing owed.
    Nothing,
}
impl RecoveryRule {
    /// Refuse reports and states needing a boundary settlement; never infer
    /// "nothing owed" from a refusal.
    /// # Errors
    /// `RecoveryLandedUnowned`, `IntentSelectedWriterMissing`,
    /// `SyncCommitRecoveryRequired` or `WritableRecoveryRequired`.
    pub fn admitted(self) -> Result<Self, CoordinationError> {
        match self {
            Self::LandedUnowned => {
                recover(RecoverEvent::LandedUnowned);
                Err(refused("RecoveryLandedUnowned"))
            }
            Self::OwnershipLost => {
                recover(RecoverEvent::SelectionChanged("none"));
                Err(refused("IntentSelectedWriterMissing"))
            }
            Self::BoundaryUnaccounted => Err(refused("SyncCommitRecoveryRequired")),
            Self::LandedUnrefreshed
            | Self::LandedRefreshed
            | Self::BoundaryComplete
            | Self::BoundaryRecorded
            | Self::BoundaryUnrecorded
            | Self::BoundaryArchived => Err(refused("WritableRecoveryRequired")),
            Self::DirtyJournal
            | Self::ResumeRecovery
            | Self::Release
            | Self::Classify
            | Self::Nothing => Ok(self),
        }
    }
}

/// Verified exact live readback selection. It grants no ownership.
#[derive(Debug, Clone)]
pub struct SelectedRecovery {
    scope: Scope,
    volume: VolumeName,
    receipt: Receipt,
    root: Vec<u8>,
    cursor: u64,
}
/// Operator acknowledgement of this exact selection; never inferred from credentials.
#[derive(Debug)]
pub struct AcknowledgedRecovery(SelectedRecovery);
impl SelectedRecovery {
    pub(crate) const fn selected_receipt(&self) -> Receipt {
        self.receipt
    }
    /// Exact signature-verified selected candidate, including its own parent.
    #[must_use]
    pub fn root_bytes(&self) -> &[u8] {
        &self.root
    }

    /// Select from a strictly judged authenticated readback using the configured scope.
    /// # Errors
    /// Invalid scope, reply, signature or missing selected writer.
    pub fn from_readback(
        scope: Scope,
        volume: VolumeName,
        writer: [u8; 16],
        reply: &IntentReply,
        verify: impl FnMut(&RootDoc, &[u8]) -> bool,
    ) -> Result<Self, CoordinationError> {
        Self::readback_selection(scope, volume, writer, reply, verify)?
            .1
            .ok_or_else(|| {
                recover(RecoverEvent::Nothing);
                refused("IntentSelectedWriterMissing")
            })
    }

    /// Judge a scope-bound readback and return its cursor and any Live selection.
    pub(crate) fn readback_selection(
        scope: Scope,
        volume: VolumeName,
        writer: [u8; 16],
        reply: &IntentReply,
        verify: impl FnMut(&RootDoc, &[u8]) -> bool,
    ) -> Result<(u64, Option<Self>), CoordinationError> {
        scope.digest().map_err(|_| refused("IntentScope"))?;
        if !reply.matches_scope(&scope, &volume) {
            return Err(refused("IntentReadbackScope"));
        }
        let Verdict::Accepted(readback) =
            intent::judge_readback(&reply.borrowed(), &volume, verify)
        else {
            return Err(refused("IntentReadbackRefused"));
        };
        let selection = readback
            .rows
            .iter()
            .find(|r| r.writer == writer)
            .map(|row| Self {
                scope,
                volume,
                receipt: Receipt {
                    writer,
                    epoch: row.epoch,
                    instance: [0; 16],
                    generation: row.generation,
                    state: ReceiptState::Live {
                        prepared_root_id: row.root_id(),
                    },
                },
                root: row.root.to_vec(),
                cursor: readback.cursor,
            });
        Ok((readback.cursor, selection))
    }
    fn takeover(&self, instance: [u8; 16]) -> Result<Vec<u8>, CoordinationError> {
        intent::encode_ownership(Ownership {
            writer: self.receipt.writer,
            instance,
            mode: OwnershipMode::Takeover {
                expected_epoch: self.receipt.epoch,
                generation: self.receipt.generation,
                state: self.receipt.state,
                recovery_ack: true,
            },
        })
        .map_err(|_| refused("IntentTakeover"))
    }
    /// Explicitly acknowledge displacement of the selected ownership record.
    #[must_use]
    pub fn acknowledge_displacement(self) -> AcknowledgedRecovery {
        AcknowledgedRecovery(self)
    }
    /// Acknowledge displacement only for the writer the operator named: an
    /// acknowledgement naming another writer acknowledges nothing.
    /// # Errors
    /// `IntentSelectionBinding` when `writer` is not the selected writer.
    pub fn acknowledge_takeover(
        self,
        writer: [u8; 16],
    ) -> Result<AcknowledgedRecovery, CoordinationError> {
        if writer != self.receipt.writer {
            return Err(refused("IntentSelectionBinding"));
        }
        Ok(self.acknowledge_displacement())
    }
}
fn unstarted_takeover(body: Vec<u8>) -> Pending {
    Pending {
        operation: Operation::Ownership,
        body,
        context: vec![],
        first: 0,
        expires: 0,
        eligible: 0,
        attempts: 0,
        terminal: false,
        answered: false,
        answer: vec![],
    }
}

impl<P: OverlayIo> WritableStore<P> {
    /// Establish selected W and consent before an acknowledged conditional takeover.
    /// # Errors
    /// Foreign selection, adjacent evidence, entropy, custody or persistence failure.
    pub fn adopt_selected(
        mut store: Store,
        mut config: OverlayConfig,
        mut io: P,
        random: &mut impl SecureRandom,
        faults: FaultControl,
        acknowledged: AcknowledgedRecovery,
    ) -> Result<Self, CoordinationError> {
        let s = acknowledged.0;
        if s.scope != config.scope
            || s.volume != config.volume
            || config.ownership_completion_reserve < codec::REPLACEMENT_RESERVE
        {
            return Err(refused("IntentSelectionBinding"));
        }
        random
            .fill(&mut config.instance)
            .map_err(|_| refused("IntentEntropyUnavailable"))?;
        let body = s.takeover(config.instance)?;
        let mut carrier = Carrier {
            scope: s.scope,
            volume: s.volume,
            writer: s.receipt.writer,
            instance: config.instance,
            revision: 0,
            phase: Phase::Handshake,
            cursor: s.cursor,
            allocated: s.receipt.generation,
            // The lost store sent the selected G and the takeover keeps it,
            // so a later release names it.
            sent: s.receipt.generation,
            handshake: vec![],
            grant: vec![],
            current: vec![],
            root: vec![],
            selected: intent::encode_receipt(s.receipt).map_err(|_| refused("IntentSelection"))?,
            selected_root: s.root,
            selected_cursor: s.cursor,
            consent: vec![],
            fence: 0,
            fence_evidence: vec![],
            pending: vec![],
        };
        carrier.consent = codec::recovery_consent(&carrier, &body)?;
        // No dispatch is possible until the caller assigns the original retry
        // horizon with begin_selected_attempt. Zero ticks retain the exact consent.
        carrier.pending.push(unstarted_takeover(body));

        let area = store
            .publication_root()
            .join("overlay")
            .join(config.scope.digest().map_err(|_| refused("IntentScope"))?)
            .join(config.volume.as_str());
        crate::overlay_discard::claims::gate(&mut io, store.publication_root(), &config.volume)?;
        crate::overlay_store::settle_area(&mut io, &faults, &area)?;
        if io.length(&area.join("ownership"))?.is_some()
            || io.length(&area.join("journal"))?.is_some()
        {
            return Err(refused("IntentAdoptionBesideEvidence"));
        }
        let selected = SelectedWriter::acknowledged(&carrier)?;
        let writer = OverlayStore::install_selected_writer(
            &mut store, &config, &mut io, &selected, &faults,
        )?;
        if writer.ceiling < carrier.allocated {
            return Err(refused("IntentCeilingBelowEvidence"));
        }
        let mut result = Self {
            store,
            config,
            io,
            area,
            carrier,
            overlay: None,
            bundle_overlay: Err(BundleRefusal::Unavailable),
            range_cache: crate::overlay_store::verified_range::VerifiedRangeCache::default(),
            poisoned: false,
            startup_attempts: 0,
            release_deadline: None,
            faults,
            metrics: None,
            contention: crate::contention::Window::default(),
            generation_floor: writer.ceiling,
            capture_queue: std::collections::BTreeMap::new(),
            failed_sync_registrations: std::collections::BTreeSet::new(),
            landing_refresh: None,
            measured_attempts: std::collections::BTreeMap::new(),
            engine_attached: false,
            mount_pin: None,
            commit_lane: None,
            commit_conflict: false,
            fenced_publication: None,
            commit_serial: 0,
            commit_landings: 0,
            floor_changed: std::sync::Arc::new(tokio::sync::Notify::new()),
            coalesce_wake: std::sync::Arc::new(tokio::sync::Notify::new()),
            coalesce_clock: None,
            object_leases: std::collections::BTreeMap::new(),
            admitted_syncs: 0,
            replaced_leases: std::collections::BTreeSet::new(),
            mutations_closed: false,
            construction_workspace_bytes: crate::SyncOptions::default().workspace_bytes,
        };
        result.persist(result.carrier.clone())?;
        Ok(result)
    }
    /// Renew explicit consent for this store's lost writer, preserving its
    /// journal, registration/release evidence and generation high-water.
    /// # Errors
    /// Wrong phase or selection, attached engine, poison or persistence failure.
    pub fn reselect(
        &mut self,
        acknowledged: AcknowledgedRecovery,
        clock: &impl Clock,
    ) -> Result<PendingIntent, CoordinationError> {
        match self.check() {
            Ok(()) | Err(CoordinationError::Fenced { .. }) => (),
            Err(error) => return Err(error),
        }
        let s = acknowledged.0;
        if !matches!(self.carrier.phase, Phase::Unowned | Phase::Fenced)
            || self.engine_attached
            || !matches!(
                self.recovery_rule()?,
                RecoveryRule::OwnershipLost | RecoveryRule::LandedUnowned
            )
        {
            return Err(refused("IntentOwnershipUnresolved"));
        }
        if (&s.scope, &s.volume, s.receipt.writer)
            != (&self.config.scope, &self.config.volume, self.carrier.writer)
        {
            return Err(refused("IntentSelectionBinding"));
        }
        let body = s.takeover(self.config.instance)?;
        let mut next = self.carrier.clone();
        next.phase = Phase::Handshake;
        if next.fence == 1 && next.current.is_empty() {
            next.current.clone_from(&next.selected);
            next.root.clone_from(&next.selected_root);
        }
        next.selected =
            intent::encode_receipt(s.receipt).map_err(|_| refused("IntentSelection"))?;
        next.selected_root = s.root;
        next.selected_cursor = s.cursor;
        next.cursor = s.cursor;
        next.allocated = next.allocated.max(s.receipt.generation);
        next.sent = next.sent.max(s.receipt.generation);
        next.pending.retain(|p| p.operation != Operation::Ownership);
        retire_displaced_release(&mut next, s.receipt.epoch);
        next.consent = codec::recovery_consent(&next, &body)?;
        // Persist consent before starting its horizon, just as adoption does.
        next.pending.push(unstarted_takeover(body));
        next.pending
            .sort_by_key(|p| (p.operation, p.generation().unwrap_or(u64::MAX)));
        let selected = SelectedWriter::acknowledged(&next)?;
        OverlayStore::install_selected_writer(
            &mut self.store,
            &self.config,
            &mut self.io,
            &selected,
            &self.faults,
        )?;
        self.persist_transition(next, true)?;
        self.begin_selected_attempt(clock)
    }
    /// Start the selected request's horizon exactly once, before dispatch.
    /// # Errors
    /// Already started, wrong phase, clock or persistence failure.
    pub fn begin_selected_attempt(
        &mut self,
        clock: &impl Clock,
    ) -> Result<PendingIntent, CoordinationError> {
        self.check()?;
        let mut next = self.carrier.clone();
        let p = next
            .pending
            .iter_mut()
            .find(|p| is_unstarted_takeover(p))
            .ok_or_else(|| refused("IntentSelectionAlreadyStarted"))?;
        p.first = now(clock)?;
        p.eligible = p.first;
        p.expires = p
            .first
            .checked_add(HORIZON_MILLIS)
            .ok_or_else(|| refused("IntentDeadlineOverflow"))?;
        let body = p.body.clone();
        self.persist(next)?;
        Ok(self.pending(Operation::Ownership, body))
    }
    /// Read a held journal and observe its retained record without replay,
    /// temporary cleanup, or publication execution authority.
    pub(crate) fn residual_sources(
        &mut self,
    ) -> Result<
        Option<(
            crate::overlay_store::LandedJournal,
            granary_core::retained_submission::Submission,
        )>,
        CoordinationError,
    > {
        let landed = crate::overlay_store::landed_commits(&mut self.io, &self.area)?;
        if landed.sealed.is_none() {
            return Ok(None);
        }
        let scope = self.config.scope.clone();
        let volume = self.config.volume.clone();
        let record = self
            .publication_read_transaction(|journal| journal.observe(&scope, &volume))?
            .ok_or_else(|| refused("RecoveryResidualCaptureMissing"))?;
        Ok(Some((landed, record)))
    }
    pub(crate) fn validate_residual_sources(
        &mut self,
        evidence: &crate::recovery::ResidualEvidence,
        check: impl FnMut() -> Result<(), CoordinationError>,
    ) -> Result<(), CoordinationError> {
        crate::overlay_store::validate_residual_sources(
            &mut self.io,
            &self.area,
            &self.config,
            evidence,
            check,
        )
    }
    /// Where explicit recovery places this store: the carrier, the journal's
    /// files and the retained record, read without the fence check so a
    /// fenced or unowned carrier is placed too, and without writing any of
    /// them. First match wins, and a
    /// carrier that is not owned is placed before any rule that acts.
    /// # Errors
    /// The journal's or the retained store's own refusal.
    pub fn recovery_rule(&mut self) -> Result<RecoveryRule, CoordinationError> {
        let landed = crate::overlay_store::landed_commits(&mut self.io, &self.area)?;
        let boundary = boundary_unrefreshed(&landed);
        // A handshake holds no grant yet: it is reported like a lost one,
        // and the grant it awaits never lets a classification act early.
        if matches!(
            self.carrier.phase,
            Phase::Fenced | Phase::Unowned | Phase::Handshake
        ) {
            return Ok(if boundary == Some(true) {
                RecoveryRule::LandedUnowned
            } else {
                RecoveryRule::OwnershipLost
            });
        }
        self.recovery_work(&landed, boundary)
    }

    /// Absence settlement, Acquire admission and unowned recovery all require
    /// a read-only proof that no local work is owed. A read failure counts as debt.
    pub(crate) fn owes_nothing(&mut self) -> bool {
        self.check_no_recovery_work().is_ok_and(|nothing| nothing)
    }

    fn check_no_recovery_work(&mut self) -> Result<bool, CoordinationError> {
        let landed = crate::overlay_store::landed_commits(&mut self.io, &self.area)?;
        if self.recovery_work(&landed, boundary_unrefreshed(&landed))? != RecoveryRule::Nothing
            || self.carrier.pending.iter().any(|p| !p.context.is_empty())
            || (self.io.length(&self.area.join("journal"))?.is_none()
                && !self.io.entries(&self.area.join("staging"))?.is_empty())
        {
            return Ok(false);
        }
        self.store
            .publications_read_only(self.config.euid)?
            .require_settled_abandonments(&self.config.scope, &self.config.volume)?;
        Ok(true)
    }

    fn recovery_work(
        &mut self,
        landed: &crate::overlay_store::LandedJournal,
        boundary: Option<bool>,
    ) -> Result<RecoveryRule, CoordinationError> {
        if let Some(unrefreshed) = boundary {
            return Ok(if unrefreshed {
                RecoveryRule::LandedUnrefreshed
            } else {
                RecoveryRule::LandedRefreshed
            });
        }
        // Observed, never loaded: a load crosses a generation barrier and
        // re-establishes archives, and placing a store writes nothing, so
        // the store is opened read-only (no temporaries are removed).
        let record = self
            .store
            .publications_read_only(self.config.euid)?
            .observe(&self.config.scope, &self.config.volume)?;
        if let Some(&(publication, fenced)) = landed.open.first() {
            if landed.open.len() > 1 {
                return Ok(RecoveryRule::BoundaryUnaccounted);
            }
            return Ok(match &record {
                Some(r) if r.publication_id == publication && r.is_complete() => {
                    RecoveryRule::BoundaryComplete
                }
                Some(r) if r.publication_id == publication => RecoveryRule::BoundaryRecorded,
                Some(r) if !r.is_complete() && !crate::sync::terminal_non_landing(r) => {
                    RecoveryRule::BoundaryUnaccounted
                }
                _ if self.boundary_archived(publication)? => RecoveryRule::BoundaryArchived,
                _ if fenced => RecoveryRule::BoundaryUnaccounted,
                _ => RecoveryRule::BoundaryUnrecorded,
            });
        }
        let journal = crate::overlay_store::journal_condition(&mut self.io, &self.area)?;
        let clean = journal.as_ref().is_none_or(|(_, clean)| *clean);
        let live = intent::decode_receipt(&self.carrier.current)
            .is_ok_and(|receipt| matches!(receipt.state, ReceiptState::Live { .. }));
        Ok(match record {
            Some(r) if !r.is_complete() => RecoveryRule::ResumeRecovery,
            Some(r)
                if live
                    && clean
                    && journal.as_ref().is_some_and(|(header, _)| {
                        let granary_core::retained_submission::Phase::Complete(done) = &r.phase
                        else {
                            return false;
                        };
                        let root = granary_core::hash::GrainId::of(&self.carrier.root);
                        intent::decode_receipt(&self.carrier.current).is_ok_and(|receipt| {
                            receipt.state
                                == ReceiptState::Live {
                                    prepared_root_id: root,
                                }
                        }) && (header.base_root, header.base_seq) == (root, done.seq)
                            && crate::recovery::same_landing(&done.root, &self.carrier.root)
                            && self.carrier.pending.iter().all(|p| p.context.is_empty())
                    }) =>
            {
                RecoveryRule::Release
            }
            // Byte equality: a root's id is the hash of its signed bytes, and
            // an equal tree under another root is a different publication.
            Some(r) if live && clean && r.frozen.initial_root == self.carrier.root => {
                RecoveryRule::Release
            }
            _ if !clean => RecoveryRule::DirtyJournal,
            _ if !live => RecoveryRule::Nothing,
            _ => RecoveryRule::Classify,
        })
    }
    /// The selected root's own registration in this store's admitted journal.
    /// Only a local grant can append a registration; reselection does not.
    /// # Errors
    /// The journal's read, scan or writer-binding refusal.
    pub(crate) fn selection_registration(&mut self) -> Result<Option<u64>, CoordinationError> {
        let selected = GrainId::of(&self.carrier.root);
        let journal = crate::overlay_store::landed_commits(&mut self.io, &self.area)?;
        Ok(journal.registration_of(selected))
    }

    /// Only evidence admitted through the current selection's own registration
    /// can credit an earlier publication to this dirty journal.
    pub(crate) fn registered_roots_through_selection(
        &mut self,
    ) -> Result<Option<(u64, BTreeSet<GrainId>)>, CoordinationError> {
        let selected = GrainId::of(&self.carrier.root);
        let journal = crate::overlay_store::landed_commits(&mut self.io, &self.area)?;
        Ok(journal.registration_of(selected).map(|through| {
            let roots = journal
                .registrations
                .into_iter()
                .chain(journal.file_receipts)
                .filter_map(|(seq, root)| (seq <= through).then_some(root))
                .collect();
            (through, roots)
        }))
    }
    fn boundary_archived(&mut self, publication: [u8; 16]) -> Result<bool, CoordinationError> {
        let digest = self
            .config
            .scope
            .digest()
            .map_err(|_| refused("IntentScope"))?;
        Ok(self
            .store
            .publications_read_only(self.config.euid)?
            .archived(&digest, &self.config.volume, publication)?)
    }
    /// The object store a recovery verifies content into.
    pub(crate) const fn recovery_store(&self) -> &Store {
        &self.store
    }
    /// Archive terminal non-landing evidence before generic recovery can resume it.
    /// The caller has classified a journal without an open boundary.
    pub(crate) fn reconcile_terminal_publication(&mut self) -> Result<bool, CoordinationError> {
        self.check_recovery_owner()?;
        let scope = self.config.scope.clone();
        let volume = self.config.volume.clone();
        let record = self.publication_transaction(|journal| journal.load(&scope, &volume))?;
        if let Some(record) = record.filter(crate::sync::terminal_non_landing) {
            self.archive_proven_non_landing(&record, 0)?;
            return Ok(true);
        }
        Ok(false)
    }
    /// Refuse recovery work before this process's own grant is persisted:
    /// owned start or serving, with the current receipt naming this instance.
    /// # Errors
    /// Fencing, poison, a pending handshake or another instance's receipt.
    pub(crate) fn check_recovery_owner(&self) -> Result<(), CoordinationError> {
        self.check()?;
        if self.carrier.phase == Phase::Handshake {
            return Err(refused("IntentOwnershipPending"));
        }
        let receipt = intent::decode_receipt(&self.carrier.current)
            .map_err(|_| refused("IntentOwnershipPending"))?;
        if receipt.instance != self.config.instance
            || !matches!(self.carrier.phase, Phase::OwnedStart | Phase::Serving)
        {
            return Err(refused("IntentFreshInstanceRequired"));
        }
        Ok(())
    }

    /// Re-derive completion from the journal, retained publication and local debt.
    pub(crate) fn check_recovery_finished(
        &mut self,
        publication_proved: bool,
    ) -> Result<u64, (&'static str, CoordinationError)> {
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        {
            if self
                .faults
                .point("recover.postcondition", "capacity", 0)
                .is_some()
            {
                return Err((
                    "obligations",
                    CoordinationError::Overlay(crate::OverlayError::NoSpace),
                ));
            }
            if self
                .faults
                .point("recover.postcondition", "sequence", 0)
                .is_some()
            {
                return Err(("publication", refused("IntentGenerationExhausted")));
            }
        }
        let settled = !self
            .publication_unsettled()
            .map_err(|error| ("publication", error))?;
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        let settled = settled
            && self
                .faults
                .point("recover.postcondition", "retained", 0)
                .is_none();
        if !settled {
            return Err(("publication", refused("WritableRecoveryRequired")));
        }
        let obligations = self.check_finish_obligations();
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        let obligations = if self
            .faults
            .point("recover.postcondition", "obligations", 0)
            .is_some()
        {
            Err(refused("WritableRecoveryRequired"))
        } else {
            obligations
        };
        obligations.map_err(|error| ("obligations", error))?;
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        let _ = self.faults.point("recover.postcondition", "read", 0);
        let journal = crate::overlay_store::journal_condition(&mut self.io, &self.area)
            .map_err(|error| ("replay", error.into()))?;
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        let journal = if self
            .faults
            .point("recover.postcondition", "journal", 0)
            .is_some()
        {
            journal.map(|(header, _)| (header, false))
        } else {
            journal
        };
        let Some((header, true)) = journal else {
            return Err(("replay", refused("WritableRecoveryRequired")));
        };
        let locally_published = self
            .finish_publication_proved()
            .map_err(|error| ("publication", error))?;
        let published = locally_published || publication_proved;
        let detached = !self.engine_attached;
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        let (published, detached) = (
            published
                && self
                    .faults
                    .point("recover.postcondition", "publication", 0)
                    .is_none(),
            detached
                && self
                    .faults
                    .point("recover.postcondition", "engine", 0)
                    .is_none(),
        );
        if !published {
            return Err(("publication", refused("WritableRecoveryRequired")));
        }
        if !detached {
            return Err(("obligations", refused("WritableRecoveryRequired")));
        }
        Ok(header.base_seq)
    }

    pub(crate) fn recovery_released(&self) -> bool {
        let released = self.carrier.phase == Phase::Released
            && intent::decode_receipt(&self.carrier.current)
                .is_ok_and(|receipt| receipt.state == ReceiptState::Released);
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        let released = released
            && self
                .faults
                .point("recover.postcondition", "release", 0)
                .is_none();
        released
    }
    pub(super) fn released_recovery_permission(
        &self,
    ) -> Result<OwnershipStatus, CoordinationError> {
        self.check()?;
        if !self.recovery_released() {
            return Err(refused("IntentOwnershipPending"));
        }
        Ok(OwnershipStatus::Durable(OwnershipPermission::new(
            self.carrier
                .scope
                .digest()
                .map_err(|_| refused("IntentScope"))?,
            self.carrier.volume.clone(),
            self.carrier.writer,
            self.carrier.allocated,
        )))
    }
    /// Release the recovered row. A grant leaves the carrier in owned start
    /// and recovery sends no registration, so the grant's own receipt moves
    /// it to serving before the ordinary release drains and names `sent`.
    /// # Errors
    /// Fencing, poison, a pending handshake or another instance's receipt,
    /// then as [`Self::prepare_release`].
    pub fn prepare_recovery_release(
        &mut self,
        clock: &impl Clock,
        bound: std::time::Duration,
    ) -> Result<PendingIntent, CoordinationError> {
        self.enter_recovery_serving()?;
        self.prepare_release(clock, bound, None)
    }

    /// Admit local finishing under the current instance's already durable grant.
    pub(crate) fn enter_recovery_serving(&mut self) -> Result<(), CoordinationError> {
        self.check_recovery_owner()?;
        if self.carrier.phase == Phase::OwnedStart {
            let mut next = self.carrier.clone();
            next.phase = Phase::Serving;
            self.persist(next)?;
        }
        Ok(())
    }
}
