// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Ordered explicit recovery, settlement and bounded journal completion.

use super::{
    PublicationHandle, PublicationOutcome, RecoveryBackoff, RecoveryError, RecoveryIntent,
    RecoveryJournal, RecoveryParts, SelectedPublication, begin_selected_publication,
    resume_store_publication,
};
use crate::{
    CoordinationError, FailureClass, FaultControl, IntentReply, IntentTransportError,
    OverlayConfig, OverlayIo, RecoveryRule, SelectedRecovery, Store, SyncRuntime,
    WritableAuthority, WritableStartError, WritableStore,
    observe::{RecoverEvent, recover},
    overlay_store::{area_path, journal_condition, settle_area},
    writable_store::is_unstarted_takeover,
};
use granary_core::{
    clock::Clock,
    hash::GrainId,
    overlay_ownership::{Operation, Phase},
    rng::Rng,
    secure_random::SecureRandom,
};
use granary_store::crypto::{SigningKey, TrustedKeys, check_signatures};

/// A recovery's checked local and remote inputs. The caller holds the store
/// lock and loads its signing key through its ordinary custody checks.
#[expect(
    missing_debug_implementations,
    reason = "the command borrows private signing authority"
)]
pub struct RecoveryCommand<'a, T, P: OverlayIo> {
    /// The locked store and its overlay io, rooted at the store's own root.
    /// `None` only reports: the run reads back, reports the selection
    /// whatever the acknowledgement names, and touches no disk.
    pub local: Option<(Store, P)>,
    pub config: OverlayConfig,
    pub transport: &'a T,
    pub runtime: &'a tokio::runtime::Runtime,
    pub signer: &'a SigningKey,
    pub publisher_keys: &'a TrustedKeys,
    pub writer: [u8; 16],
    pub acknowledge_takeover: Option<[u8; 16]>,
    pub acknowledge_resend: Option<[u8; 16]>,
    pub faults: FaultControl,
    pub construction_workspace_bytes: u64,
}

/// The durable ending observed by explicit recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// No local recovery action. For an unowned carrier, readback also found
    /// no Live selection and can still hide a Released row.
    NothingOwed,
    JournalFinished {
        base_seq: u64,
    },
    /// Journal completion with the authority's saved admission refusal.
    JournalFinishedAfterRefusal {
        base_seq: u64,
        refusals: Vec<String>,
    },
    /// Journal completion when the archived refusal report is unavailable.
    JournalFinishedWithUnavailableRefusalReport {
        base_seq: u64,
        /// Refusals settled by this recovery.
        refusals: Vec<String>,
        /// The archive listing error's display text.
        reason: String,
    },
}

/// A journal stage retained by a refused namespace recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryConflictStage {
    path: Option<Vec<granary_core::manifest::Name>>,
    id: u64,
    size: u64,
}

impl RecoveryConflictStage {
    /// Builds one row from a checked namespace-stage binding.
    #[must_use]
    pub fn new(path: Option<Vec<granary_core::manifest::Name>>, id: u64, size: u64) -> Self {
        Self { path, id, size }
    }

    /// The current namespace path, or `None` after the stage was detached.
    #[must_use]
    pub fn path(&self) -> Option<&[granary_core::manifest::Name]> {
        self.path.as_deref()
    }

    /// The staging file's stable journal identifier.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The payload size after the common staging header.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// Complete original stage-table inventory for a refused namespace recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryConflictInventory {
    scope: String,
    stages: Vec<RecoveryConflictStage>,
}

impl RecoveryConflictInventory {
    /// Builds an inventory from a checked scope and complete stage table.
    #[must_use]
    pub fn new(scope: String, stages: Vec<RecoveryConflictStage>) -> Self {
        Self { scope, stages }
    }

    /// The overlay scope directory digest.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Stages sorted by their stable journal identifier.
    #[must_use]
    pub fn stages(&self) -> &[RecoveryConflictStage] {
        &self.stages
    }

    /// Renders the complete stdout report using the selected path policy.
    ///
    /// # Errors
    /// Returns an error if formatting the bounded report fails.
    pub fn stdout_bytes(&self, paths: crate::LogPaths) -> std::io::Result<Vec<u8>> {
        use std::io::Write as _;

        let mut bytes = Vec::new();
        writeln!(bytes, "B5-scope\t{}", self.scope)?;
        let mut count = 0_u64;
        for stage in &self.stages {
            bytes.extend_from_slice(b"B5-stage\t");
            write_inventory_path(&mut bytes, stage.path(), paths)?;
            writeln!(bytes, "\t{:016x}\t{}", stage.id, stage.size)?;
            count = count
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("inventory row count overflow"))?;
        }
        writeln!(bytes, "B5-stages\t{count}")?;
        Ok(bytes)
    }
}

fn write_inventory_path(
    bytes: &mut Vec<u8>,
    path: Option<&[granary_core::manifest::Name]>,
    paths: crate::LogPaths,
) -> std::io::Result<()> {
    use std::io::Write as _;

    let Some(path) = path else {
        bytes.extend_from_slice(b"<detached>");
        return Ok(());
    };
    if paths == crate::LogPaths::Redacted {
        bytes.extend_from_slice(b"<file>");
        return Ok(());
    }
    let mut separator = false;
    for name in path {
        if separator {
            bytes.push(b'/');
        }
        separator = true;
        for byte in name.as_bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
                bytes.push(*byte);
            } else {
                write!(bytes, "%{byte:02X}")?;
            }
        }
    }
    Ok(())
}

/// The selected row is retained when acknowledgement is missing or names a
/// different writer. Its public identifiers let the operator inspect consent.
#[derive(Debug)]
pub enum RecoveryCommandError {
    Coordination(CoordinationError),
    Start(WritableStartError),
    Publication(RecoveryError),
    Acknowledgement {
        epoch: u64,
        generation: u64,
        root: GrainId,
        parent_seq: u64,
    },
    Conflict {
        inventory: Option<RecoveryConflictInventory>,
    },
}
impl std::fmt::Display for RecoveryCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Coordination(error) => error.fmt(f),
            Self::Start(error) => error.fmt(f),
            Self::Publication(RecoveryError::RemoteIntegrity(rule)) => {
                write!(f, "RecoveryRemoteIntegrity: {rule}")
            }
            Self::Publication(RecoveryError::Journal(error))
                if error.kind == crate::PublicationStoreErrorKind::Conflict =>
            {
                f.write_str("RecoveryConflict")
            }
            Self::Publication(error) => error.fmt(f),
            Self::Acknowledgement {
                epoch,
                generation,
                root,
                parent_seq,
            } => write!(
                f,
                "IntentSelectionBinding: --acknowledge-takeover must name --writer; selected E={epoch} G={generation} root={root} parent_seq={parent_seq}"
            ),
            Self::Conflict { .. } => f.write_str("intent refused: RecoveryConflict"),
        }
    }
}
impl std::error::Error for RecoveryCommandError {}
impl RecoveryCommandError {
    /// The complete stage inventory when an engine namespace conflict produced one.
    #[must_use]
    pub fn conflict_inventory(&self) -> Option<&RecoveryConflictInventory> {
        match self {
            Self::Conflict { inventory } => inventory.as_ref(),
            _ => None,
        }
    }
}
impl From<CoordinationError> for RecoveryCommandError {
    fn from(error: CoordinationError) -> Self {
        Self::Coordination(error)
    }
}
impl From<WritableStartError> for RecoveryCommandError {
    fn from(error: WritableStartError) -> Self {
        Self::Start(error)
    }
}
impl From<RecoveryError> for RecoveryCommandError {
    fn from(error: RecoveryError) -> Self {
        Self::Publication(error)
    }
}

pub(super) fn recovery_at_limit(error: &RecoveryCommandError) -> bool {
    match error {
        RecoveryCommandError::Coordination(error)
        | RecoveryCommandError::Start(WritableStartError::Coordination(error)) => {
            matches!(
                error,
                CoordinationError::Refused(
                    "SyncDeadline"
                        | "IntentGenerationExhausted"
                        | "IntentEpochExhausted"
                        | "SyncCommitExhausted"
                ) | CoordinationError::Overlay(
                    crate::OverlayError::NoSpace
                        | crate::OverlayError::Refused("OverlayCapacityExhausted")
                ) | CoordinationError::Recovery(RecoveryError::RemoteIntegrity(
                    "candidate sequence exhausted"
                ))
            )
        }
        RecoveryCommandError::Publication(RecoveryError::RemoteIntegrity(
            "candidate sequence exhausted",
        )) => true,
        _ => false,
    }
}

impl<
    T: WritableAuthority + super::AuthorityTransport + crate::SyncRemote + Sync + 'static,
    P: OverlayIo + Clone + Send + Sync + 'static,
> RecoveryCommand<'_, T, P>
{
    /// Scan the journal and settle retained requests before classification.
    /// An unowned, unfenced carrier with no pending request or local work owed
    /// checks the authenticated cursor and uses any Live row as the selection.
    /// With no Live row it returns `NothingOwed`. A changed selection stops
    /// the invocation before another readback or takeover.
    /// # Errors
    /// Missing or mismatched acknowledgement, ownership or journal refusal,
    /// remote-integrity failure, conflict, stale history or unresolved publication.
    #[expect(
        clippy::too_many_lines,
        reason = "one ordered flow keeps journal scan, consent, grant, classification, publication and release visible"
    )]
    pub fn run<C>(
        mut self,
        clock: &std::sync::Arc<C>,
        landing_key: SigningKey,
        secure: &mut (impl SecureRandom + Send),
        rng: impl Rng + Send,
    ) -> Result<RecoveryOutcome, RecoveryCommandError>
    where
        C: Clock + Send + Sync + 'static,
    {
        let scope = self.config.scope.clone();
        let scope_digest = scope
            .digest()
            .map_err(|_| CoordinationError::Refused("IntentScope"))?;
        let volume = self.config.volume.clone();
        let mut delay = RecoveryBackoff { rng };
        let Some((store, mut io)) = self.local.take() else {
            return Err(unacknowledged(&self.select(&scope, &volume)?));
        };
        let area = area_path(store.publication_root(), &scope, &volume)
            .map_err(CoordinationError::from)?;
        crate::overlay_discard::claims::gate_area(&mut io, &area)
            .map_err(CoordinationError::from)?;
        settle_area(&mut io, &self.faults, &area).map_err(CoordinationError::from)?;
        let journal = journal_condition(&mut io, &area).map_err(CoordinationError::from)?;
        let deadline = crate::TokioSyncRuntime
            .now()
            .checked_add(crate::sync::DEFAULT_SHUTDOWN_BOUND)
            .ok_or(CoordinationError::Refused("SyncDeadline"))?;
        let prologue = |store: &mut WritableStore<P>, rng: &mut _, enclosing| {
            let result = crate::writable_start::settle_recovery(
                store,
                clock.as_ref(),
                |store, request, landed| {
                    crate::writable_start::drive_inner(
                        store,
                        self.transport,
                        self.runtime,
                        &scope,
                        request,
                        self.signer.public_key(),
                        clock.as_ref(),
                        rng,
                        landed,
                        if request.operation() == Operation::Release {
                            Some(deadline)
                        } else {
                            enclosing
                        },
                    )
                },
            );
            match &result {
                Err(WritableStartError::Coordination(CoordinationError::Refused(
                    "IntentSelectionChanged",
                ))) => recover(RecoverEvent::SelectionChanged("intent-changed")),
                Err(WritableStartError::Coordination(CoordinationError::Fenced {
                    recorded_generation,
                })) => {
                    recover(RecoverEvent::SelectionChanged(
                        if recorded_generation.is_some() {
                            "intent-superseded"
                        } else {
                            "intent-absent"
                        },
                    ));
                    return Err(WritableStartError::from(CoordinationError::Refused(
                        "IntentSelectionChanged",
                    ))
                    .into());
                }
                _ => (),
            }
            result.map_err(RecoveryCommandError::from)
        };
        let fenced = crate::overlay_store::landed_commits(&mut io, &area)
            .map_err(CoordinationError::from)?
            .open
            .iter()
            .any(|(_, fenced)| *fenced);
        let overlay_io = io.clone();
        let existing = io
            .length(&area.join("ownership"))
            .map_err(CoordinationError::from)?
            .is_some();
        let verifies = |doc: &granary_core::root::RootDoc, prefix: &[u8]| {
            check_signatures(doc, prefix, self.publisher_keys).is_ok()
        };
        let mut store = if existing {
            WritableStore::new(
                store,
                self.config.clone(),
                io,
                secure,
                self.faults.clone(),
                verifies,
            )?
        } else {
            let selection = self.select(&scope, &volume)?;
            if self.acknowledge_takeover != Some(self.writer) {
                return Err(unacknowledged(&selection));
            }
            let acknowledged = selection.acknowledge_takeover(
                self.acknowledge_takeover
                    .ok_or(CoordinationError::Refused("IntentSelectionBinding"))?,
            )?;
            let mut store = WritableStore::adopt_selected(
                store,
                self.config.clone(),
                io,
                secure,
                self.faults.clone(),
                acknowledged,
            )?;
            store.begin_selected_attempt(clock.as_ref())?;
            store
        };
        store.construction_workspace_bytes = self.construction_workspace_bytes;
        if store.writer_uuid() != self.writer {
            return Err(CoordinationError::Refused("IntentSelectionBinding").into());
        }
        super::preflight_residual(
            &mut store,
            self.transport,
            self.publisher_keys,
            self.runtime,
            || Ok(deadline),
        )?;
        if existing
            && store.snapshot().phase == Phase::Handshake
            && store
                .snapshot()
                .pending
                .iter()
                .any(|pending| !pending.terminal && is_unstarted_takeover(pending))
        {
            store.begin_selected_attempt(clock.as_ref())?;
        }
        prologue(
            &mut store,
            &mut delay.rng,
            journal.is_some().then_some(deadline),
        )?;
        let selection = if store.snapshot().phase == Phase::Unowned
            && store.snapshot().fence == 0
            && store
                .snapshot()
                .pending
                .iter()
                .all(|pending| pending.terminal)
            && store.owes_nothing()
        {
            let reply = self.readback(&scope, &volume, Some(deadline))?;
            let (cursor, selection) = SelectedRecovery::readback_selection(
                scope.clone(),
                volume.clone(),
                self.writer,
                &reply,
                verifies,
            )?;
            store.check_acquisition_cursor(cursor)?;
            let Some(selection) = selection else {
                return Ok(RecoveryOutcome::NothingOwed);
            };
            if self.acknowledge_takeover != Some(self.writer) {
                return Err(unacknowledged(&selection));
            }
            Some(selection)
        } else if matches!(
            store.recovery_rule()?,
            RecoveryRule::OwnershipLost | RecoveryRule::LandedUnowned
        ) && matches!(store.snapshot().phase, Phase::Unowned | Phase::Fenced)
            && self.acknowledge_takeover == Some(self.writer)
        {
            Some(
                self.select_before(&scope, &volume, Some(deadline))
                    .inspect_err(|error| {
                        if matches!(
                            error,
                            RecoveryCommandError::Coordination(CoordinationError::Refused(
                                "IntentSelectedWriterMissing"
                            ))
                        ) {
                            recover(RecoverEvent::SelectionChanged("none"));
                        }
                    })?,
            )
        } else {
            None
        };
        let reselected = selection.is_some();
        if let Some(selection) = selection {
            crate::writable_start::check_deadline(Some(deadline))?;
            store.reselect(selection.acknowledge_takeover(self.writer)?, clock.as_ref())?;
            prologue(
                &mut store,
                &mut delay.rng,
                journal.is_some().then_some(deadline),
            )?;
        }
        let mut already_released = store.recovery_released();
        let mut rule = store.recovery_rule()?;
        let boundary = matches!(
            rule,
            RecoveryRule::BoundaryArchived | RecoveryRule::BoundaryUnrecorded
        ) || (rule == RecoveryRule::BoundaryRecorded && fenced);
        let landing = matches!(
            rule,
            RecoveryRule::BoundaryComplete
                | RecoveryRule::LandedUnrefreshed
                | RecoveryRule::LandedRefreshed
        );
        let retained = rule == RecoveryRule::BoundaryRecorded && !fenced;
        if !boundary && !landing && !retained {
            rule.admitted()?;
        }
        if rule == RecoveryRule::Nothing {
            return Ok(RecoveryOutcome::NothingOwed);
        }
        if existing
            && !reselected
            && matches!(
                store.snapshot().phase,
                Phase::OwnedStart | Phase::Serving | Phase::Releasing
            )
        {
            #[cfg(test)]
            self.runtime.block_on(async {
                crate::TokioSyncRuntime
                    .sleep(super::FINISH_DELAYS.get().0)
                    .await;
            });
            store.prepare_succession(clock.as_ref())?;
            prologue(
                &mut store,
                &mut delay.rng,
                journal.is_some().then_some(deadline),
            )?;
            already_released = store.recovery_released();
        }
        if rule == RecoveryRule::ResumeRecovery && store.reconcile_terminal_publication()? {
            rule = store.recovery_rule()?;
            rule.admitted()?;
            if rule == RecoveryRule::Nothing {
                return Ok(RecoveryOutcome::NothingOwed);
            }
        }
        let reason = std::cell::Cell::new("replay");
        let prove_selection = |store: &mut WritableStore<P>, covered: bool| {
            self.runtime.block_on(async {
                tokio::time::timeout_at(deadline, async {
                    let selected = store.snapshot().root.clone();
                    let writer = store.writer_uuid();
                    let (_, _, relation) = super::coordinator::selected_relation(
                        self.transport,
                        &mut RecoveryJournal::new(store, self.transport, self.publisher_keys),
                        self.publisher_keys,
                        &volume,
                        writer,
                        &selected,
                    )
                    .await
                    .map_err(|error| match error {
                        RecoveryError::Invalid(_) => {
                            CoordinationError::Refused("WritableRecoveryRequired").into()
                        }
                        error => RecoveryCommandError::from(error),
                    })?;
                    match relation {
                        crate::HeadRelation::Subsumed { .. } => (),
                        crate::HeadRelation::NeedsRebase { .. } if covered => (),
                        crate::HeadRelation::Corrupt => {
                            return Err(
                                RecoveryError::RemoteIntegrity("prepared root ancestry").into()
                            );
                        }
                        _ => {
                            reason.set("selected-root-not-proved-published");
                            return Err(
                                CoordinationError::Refused("WritableRecoveryRequired").into()
                            );
                        }
                    }
                    Ok::<(), RecoveryCommandError>(())
                })
                .await
                .map_err(|_| CoordinationError::Refused("SyncDeadline"))?
            })
        };
        let action = |store: &mut WritableStore<P>,
                      secure: &mut (dyn SecureRandom + Send),
                      delay: &mut (dyn super::RecoveryDelay + Send)| {
            let mut action_rule = rule;
            loop {
                if !boundary && !landing && !retained && action_rule != RecoveryRule::DirtyJournal {
                    let bytes = store.snapshot().root.clone();
                    match action_rule {
                        RecoveryRule::ResumeRecovery => {
                            let record = store
                                .publication_transaction(|journal| {
                                    journal.observe(&scope, &volume)
                                })?
                                .ok_or(CoordinationError::Refused("RecoveryPublicationMissing"))?;
                            let handle = PublicationHandle {
                                scope: scope.clone(),
                                volume: volume.clone(),
                                publication_id: record.publication_id,
                            };
                            let result = crate::writable_start::run_before(
                                self.runtime,
                                journal.is_some().then_some(deadline),
                                resume_store_publication(
                                    RecoveryParts {
                                        transport: self.transport,
                                        journal: &mut RecoveryJournal::new(
                                            store,
                                            self.transport,
                                            self.publisher_keys,
                                        ),
                                        publisher_keys: self.publisher_keys,
                                        signer: self.signer,
                                        secure,
                                        clock: clock.as_ref(),
                                        delay,
                                    },
                                    &handle,
                                    RecoveryIntent::ExplicitRecovery,
                                    self.writer,
                                ),
                            )??;
                            if let Some(error) = result.admission_error() {
                                return Err(error.into());
                            }
                            let PublicationOutcome::Landed(done) = result.outcome else {
                                return Err(CoordinationError::Refused(
                                    "RecoveryPublicationUnresolved",
                                )
                                .into());
                            };
                            recover(RecoverEvent::Landed(done.seq));
                        }
                        RecoveryRule::Classify => {
                            let result = crate::writable_start::run_before(
                                self.runtime,
                                journal.is_some().then_some(deadline),
                                begin_selected_publication(
                                    RecoveryParts {
                                        transport: self.transport,
                                        journal: &mut RecoveryJournal::new(
                                            store,
                                            self.transport,
                                            self.publisher_keys,
                                        ),
                                        publisher_keys: self.publisher_keys,
                                        signer: self.signer,
                                        secure,
                                        clock: clock.as_ref(),
                                        delay,
                                    },
                                    scope.clone(),
                                    volume.clone(),
                                    self.writer,
                                    bytes,
                                ),
                            )??;
                            match result {
                                SelectedPublication::Stale => {
                                    return Err(CoordinationError::Refused("RecoveryStale").into());
                                }
                                SelectedPublication::Driven(result)
                                    if !matches!(result.outcome, PublicationOutcome::Landed(_)) =>
                                {
                                    if let Some(error) = result.admission_error() {
                                        return Err(error.into());
                                    }
                                    return Err(CoordinationError::Refused(
                                        "RecoveryPublicationUnresolved",
                                    )
                                    .into());
                                }
                                SelectedPublication::Subsumed { .. }
                                | SelectedPublication::Driven(_) => (),
                            }
                        }
                        RecoveryRule::Release => (),
                        _ => {
                            return Err(
                                CoordinationError::Refused("WritableRecoveryRequired").into()
                            );
                        }
                    }
                }
                if action_rule != RecoveryRule::ResumeRecovery {
                    break;
                }
                action_rule = store.recovery_rule()?;
                action_rule.admitted()?;
                if !matches!(
                    action_rule,
                    RecoveryRule::Classify | RecoveryRule::DirtyJournal | RecoveryRule::Release
                ) {
                    return Err(CoordinationError::Refused("WritableRecoveryRequired").into());
                }
            }
            Ok::<(), RecoveryCommandError>(())
        };
        if journal.is_some() {
            store.close_mutations();
            let conflict = std::cell::Cell::new(false);
            let conflict_inventory = std::cell::RefCell::new(None);
            let conflict_reported = std::cell::Cell::new(false);
            let finished = (|| {
                if !already_released {
                    store.check_recovery_owner()?;
                }
                crate::writable_start::check_deadline(Some(deadline))?;
                let (header, _) =
                    journal.ok_or(CoordinationError::Refused("SyncCommitRecoveryRequired"))?;
                self.runtime.block_on(async {
                    tokio::time::timeout_at(
                        deadline,
                        RecoveryJournal::new(&mut store, self.transport, self.publisher_keys)
                            .open_boundary(header, overlay_io),
                    )
                    .await
                    .map_err(|_| CoordinationError::Refused("SyncDeadline"))?
                })?;
                crate::writable_start::check_deadline(Some(deadline))?;
                reason.set("publication");
                action(&mut store, secure, &mut delay)?;
                crate::writable_start::check_deadline(Some(deadline))?;
                let mut refusals = Vec::new();
                if boundary || retained {
                    reason.set("publication");
                    let (reported, refusal) = self.runtime.block_on(async {
                        tokio::time::timeout_at(
                            deadline,
                            super::settlement::settle_recovery_boundary_reporting(
                                &mut store,
                                self.transport,
                                self.publisher_keys,
                                self.acknowledge_resend,
                                Some(secure),
                            ),
                        )
                        .await
                        .map_err(|_| CoordinationError::Refused("SyncDeadline"))?
                    })?;
                    conflict_reported.set(reported);
                    refusals.extend(refusal);
                    crate::writable_start::check_deadline(Some(deadline))?;
                }
                let landing_rule = store.recovery_rule()?;
                let landing = if matches!(
                    landing_rule,
                    RecoveryRule::BoundaryComplete
                        | RecoveryRule::LandedUnrefreshed
                        | RecoveryRule::LandedRefreshed
                ) {
                    reason.set("publication");
                    crate::writable_start::check_deadline(Some(deadline))?;
                    let commits = store.recovery_commits()?;
                    let covered = match commits
                        .iter()
                        .find(|commit| matches!(commit, crate::RecoveryCommit::Boundary { .. }))
                    {
                        Some(crate::RecoveryCommit::Boundary {
                            through_seq,
                            selection: crate::BoundarySelection::Tree,
                            ..
                        }) => Some(*through_seq),
                        _ => None,
                    };
                    // A whole-tree capture after our own registration carries
                    // that selection, including subsequent overwrites/deletions.
                    let covered = store.selection_registration()?.is_some_and(|registered| {
                        covered.is_some_and(|through| registered < through)
                    });
                    prove_selection(&mut store, covered)?;
                    Some(self.runtime.block_on(async {
                        tokio::time::timeout_at(
                            deadline,
                            super::landing::prepare(
                                &mut store,
                                self.transport,
                                self.publisher_keys,
                            ),
                        )
                        .await
                        .map_err(|_| CoordinationError::Refused("SyncDeadline"))?
                    })?)
                } else {
                    None
                };
                crate::writable_start::check_deadline(Some(deadline))?;
                #[cfg(test)]
                self.runtime.block_on(async {
                    crate::TokioSyncRuntime
                        .sleep(super::FINISH_DELAYS.get().1)
                        .await;
                });
                crate::writable_start::check_deadline(Some(deadline))?;
                reason.set("obligations");
                let metrics = crate::ClientMetrics::new(secure);
                let pending_landing_base = landing.as_ref().and_then(|_| store.shutdown_base());
                let (finished_store, publication_proved) =
                    crate::writable_start::shared_finish::finish_bound_store(
                        crate::writable_start::shared_finish::FinishInputs {
                            remote: std::sync::Arc::new(self.transport.read_facade()),
                            runtime: self.runtime,
                            key: self.signer,
                            spare: landing_key,
                            clock: clock.clone(),
                            metrics,
                            view_mode: crate::ViewMode::default(),
                            deadline,
                            send_budget: None,
                            landing,
                            after_landing: || recover(RecoverEvent::FenceSettled("landed")),
                            may_publish: !already_released,
                            selection_transport: Some(self.transport),
                            keys: self.publisher_keys.clone(),
                            refuse: |error, _| WritableStartError::Coordination(error),
                        },
                        store,
                        secure,
                        &mut delay.rng,
                        |outcome, store, proved_conflict, blocked| {
                            reason.set(blocked);
                            conflict.set(proved_conflict);
                            let landed_collision = pending_landing_base
                                .is_some_and(|base| store.shutdown_base() == Some(base));
                            if proved_conflict && landed_collision {
                                *conflict_inventory.borrow_mut() =
                                    store.recovery_stages().map(|stages| {
                                        RecoveryConflictInventory::new(
                                            scope_digest.clone(),
                                            stages
                                                .into_iter()
                                                .map(|stage| {
                                                    RecoveryConflictStage::new(
                                                        stage.path, stage.id, stage.size,
                                                    )
                                                })
                                                .collect(),
                                        )
                                    });
                            }
                            if outcome
                                == crate::sync::Outcome::Incomplete(crate::sync::Cause::Deadline)
                            {
                                reason.set("limit");
                            }
                        },
                        || Ok(()),
                    )
                    .map_err(|error| match error {
                        WritableStartError::Coordination(CoordinationError::Recovery(
                            error @ RecoveryError::Journal(crate::PublicationStoreError {
                                kind: crate::PublicationStoreErrorKind::Conflict,
                                ..
                            }),
                        )) => {
                            conflict.set(true);
                            RecoveryCommandError::Publication(error)
                        }
                        WritableStartError::Coordination(error) => {
                            RecoveryCommandError::Coordination(error)
                        }
                        error => RecoveryCommandError::Start(error),
                    })?;
                store = finished_store;
                crate::writable_start::check_deadline(Some(deadline))?;
                store
                    .check_recovery_finished(publication_proved)
                    .map_err(|(why, error)| {
                        reason.set(why);
                        error
                    })?;
                reason.set("release");
                if !already_released {
                    #[cfg(test)]
                    self.runtime.block_on(async {
                        crate::TokioSyncRuntime
                            .sleep(super::FINISH_DELAYS.get().2)
                            .await;
                    });
                    crate::writable_start::check_deadline(Some(deadline))?;
                    crate::overlay_store::point(&self.faults, "recover.release", "before", 0)
                        .map_err(CoordinationError::from)?;
                    let remaining =
                        deadline.saturating_duration_since(crate::TokioSyncRuntime.now());
                    store.prepare_recovery_release(clock.as_ref(), remaining)?;
                    crate::overlay_store::point(&self.faults, "recover.release", "prepared", 0)
                        .map_err(CoordinationError::from)?;
                    prologue(&mut store, &mut delay.rng, Some(deadline))?;
                    crate::overlay_store::point(&self.faults, "recover.release", "confirmed", 0)
                        .map_err(CoordinationError::from)?;
                    crate::writable_start::check_deadline(Some(deadline))?;
                }
                if !store.recovery_released() {
                    return Err(CoordinationError::Refused("RecoveryJournalBlocked").into());
                }
                let base_seq =
                    store
                        .check_recovery_finished(publication_proved)
                        .map_err(|(why, error)| {
                            reason.set(why);
                            error
                        })?;
                recover(RecoverEvent::JournalFinished(base_seq));
                let mut archive_report_error = None;
                if rule == RecoveryRule::DirtyJournal {
                    match super::settlement::archived_admission_refusals(
                        &mut store, &scope, &header,
                    ) {
                        Ok(archived) => refusals.extend(archived),
                        Err(error) => archive_report_error = Some(error.to_string()),
                    }
                    refusals.sort_unstable();
                    refusals.dedup();
                }
                if let Some(reason) = archive_report_error {
                    Ok(
                        RecoveryOutcome::JournalFinishedWithUnavailableRefusalReport {
                            base_seq,
                            refusals,
                            reason,
                        },
                    )
                } else if refusals.is_empty() {
                    Ok(RecoveryOutcome::JournalFinished { base_seq })
                } else {
                    Ok(RecoveryOutcome::JournalFinishedAfterRefusal { base_seq, refusals })
                }
            })();
            return finished.map_err(|error: RecoveryCommandError| {
                let at_limit = recovery_at_limit(&error);
                if at_limit || reason.get() == "limit" {
                    reason.set("limit");
                }
                recover(RecoverEvent::JournalBlocked(reason.get()));
                if conflict.get() {
                    if !conflict_reported.get() {
                        recover(RecoverEvent::Conflict);
                    }
                    RecoveryCommandError::Conflict {
                        inventory: conflict_inventory.into_inner(),
                    }
                } else if matches!(
                    &error,
                    RecoveryCommandError::Coordination(CoordinationError::Refused(
                        "WritableRecoveryRequired"
                    )) | RecoveryCommandError::Start(
                        WritableStartError::Coordination(CoordinationError::Refused(
                            "WritableRecoveryRequired"
                        )) | WritableStartError::Refused("WritableRecoveryRequired", _)
                    )
                ) {
                    CoordinationError::Refused("RecoveryJournalBlocked").into()
                } else {
                    error
                }
            });
        }
        action(&mut store, secure, &mut delay)?;
        store.prepare_recovery_release(clock.as_ref(), crate::DEFAULT_RESOLUTION_BOUND)?;
        prologue(&mut store, &mut delay.rng, None).map(|()| RecoveryOutcome::NothingOwed)
    }

    /// One readback, and `--writer`'s row in it. A transport failure is
    /// classed as the start classes its readback's, apart from a body the
    /// selection refuses.
    fn select(
        &self,
        scope: &granary_core::retained_submission::Scope,
        volume: &granary_core::root::VolumeName,
    ) -> Result<SelectedRecovery, RecoveryCommandError> {
        self.select_before(scope, volume, None)
    }

    fn select_before(
        &self,
        scope: &granary_core::retained_submission::Scope,
        volume: &granary_core::root::VolumeName,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<SelectedRecovery, RecoveryCommandError> {
        let reply = self.readback(scope, volume, deadline)?;
        Ok(SelectedRecovery::from_readback(
            scope.clone(),
            volume.clone(),
            self.writer,
            &reply,
            |doc, prefix| check_signatures(doc, prefix, self.publisher_keys).is_ok(),
        )?)
    }

    fn readback(
        &self,
        scope: &granary_core::retained_submission::Scope,
        volume: &granary_core::root::VolumeName,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<IntentReply, RecoveryCommandError> {
        let readback = self
            .transport
            .writable_readback(scope, volume, self.signer.public_key());
        let reply = if let Some(deadline) = deadline {
            self.runtime
                .block_on(async { tokio::time::timeout_at(deadline, readback).await })
                .map_err(|_| CoordinationError::Refused("SyncDeadline"))?
        } else {
            self.runtime.block_on(readback)
        };
        reply
            .map_err(|error| match error {
                IntentTransportError::Backend | IntentTransportError::InvalidRequest => {
                    WritableStartError::Refused(
                        "WritableIntentDiscoveryInvalid",
                        FailureClass::Corrupt,
                    )
                }
                _ => WritableStartError::Refused(
                    "WritableIntentUnavailable",
                    FailureClass::Unavailable,
                ),
            })
            .map_err(RecoveryCommandError::from)
    }
}

/// The selection's public identifiers, reported for the operator's consent.
fn unacknowledged(selection: &SelectedRecovery) -> RecoveryCommandError {
    let receipt = selection.selected_receipt();
    match granary_core::root::decode_root(selection.root_bytes()) {
        Ok(doc) => RecoveryCommandError::Acknowledgement {
            epoch: receipt.epoch,
            generation: receipt.generation,
            root: GrainId::of(selection.root_bytes()),
            parent_seq: doc.seq.saturating_sub(1),
        },
        Err(_) => CoordinationError::Refused("IntentPreparedRoot").into(),
    }
}
