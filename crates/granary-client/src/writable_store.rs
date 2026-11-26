// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Sole-store ownership mediation. Transactions end before a transport attempt.

use crate::intent_transport::{IntentReply, IntentTransportError};
use crate::metrics::{ClientMetrics, RegistrationResult};
use crate::observe::{self, FailureClass, OperationKind, RetryReason};
use crate::overlay_store::{
    self, ContentSource, FaultControl, OverlayConfig, OverlayEntry, OverlayError, OverlayIo,
    OverlayReadiness, OverlayStore, OwnershipPermission, OwnershipStatus, SelectedWriter,
};
use crate::publication_store::{PublicationStore, PublicationStoreError};
use crate::store::Store;
use granary_core::clock::Clock;
use granary_core::intent::{
    self, Ownership, OwnershipMode, Receipt, ReceiptState, Resend, Verdict,
};
use granary_core::overlay_journal::JournalHeader;
use granary_core::overlay_ownership::{self as codec, Carrier, Operation, Pending, Phase};
use granary_core::rng::Rng;
use granary_core::root::RootDoc;
use granary_core::secure_random::SecureRandom;
use granary_core::support::{BundleOverlay, BundleRefusal};
use std::path::PathBuf;
use std::time::Duration;

pub(crate) mod capture;
mod sync_capture;
pub(crate) mod sync_engine;
pub use capture::{
    CaptureCompletion, CaptureCompletionWork, CaptureCoverageInput, ReopenedCapture, StageMutation,
    StageProjection, ValidatedCaptureCompletions,
};
pub use sync_capture::{SyncPayloadVerifier, VerifiedSyncPayload};
mod content;
pub(crate) use content::ViewContext;
pub use content::{ImmutableContent, MountViewContext};
mod overlay;
pub use overlay::WritableOverlay;
mod recovery;
pub use recovery::{AcknowledgedRecovery, RecoveryRule, SelectedRecovery};
mod shared;
pub(crate) use shared::AdmittedSync;
pub use shared::SharedWritableStore;
#[cfg(test)]
pub(crate) use shared::{acquisitions_for_test, track_acquisitions_for_test};

pub const STARTUP_ATTEMPTS: u32 = 8;
/// Default resolution/release bound. Callers may configure a shorter bound.
pub const DEFAULT_RESOLUTION_BOUND: Duration = Duration::from_secs(30);
/// Default quiescence delay before a dirty overlay with no open write handles commits.
pub const DEFAULT_QUIESCE_DELAY: Duration = Duration::from_millis(500);
/// Default maximum age from the first dirty record before a commit triggers.
pub const DEFAULT_MAX_COALESCE_DELAY: Duration = Duration::from_secs(5);
/// How long the coalescer waits before retrying a commit refused for room,
/// unless a handle close, a landing or a measurement frees room first.
pub(crate) const CAPACITY_RETRY_DELAY: Duration = Duration::from_mins(10);
const HORIZON_MILLIS: u64 = 86_400_000;
pub(crate) const MIN_RETRY_WAIT_MS: u64 = 10;

/// Cause retained from a checked sync or publication refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncRefusalKind {
    Authorization,
    Other,
    MissingReference {
        publication: [u8; 16],
        uncertain: bool,
    },
    InvalidReference {
        uncertain: bool,
    },
    PublishWorkLimit {
        uncertain: bool,
    },
}

#[derive(Debug)]
pub enum CoordinationError {
    Recovery(crate::RecoveryError),
    Refused(&'static str),
    SyncRefusal(SyncRefusalKind),
    Fenced { recorded_generation: Option<u64> },
    CommitFenced { publication: [u8; 16] },
    Overlay(OverlayError),
    Codec(codec::Error),
    Publication(PublicationStoreError),
}
impl CoordinationError {
    pub(crate) fn admission_refusal(
        answer: crate::PublishResponse,
        publication: [u8; 16],
        uncertain: bool,
    ) -> Option<Self> {
        use crate::{PublishRefusal as R, PublishResponse::Refused};
        let kind = match answer {
            Refused(R::MissingReference) => SyncRefusalKind::MissingReference {
                publication,
                uncertain,
            },
            Refused(R::InvalidReference) => SyncRefusalKind::InvalidReference { uncertain },
            Refused(R::PublishWorkLimit) => SyncRefusalKind::PublishWorkLimit { uncertain },
            _ => return None,
        };
        Some(Self::SyncRefusal(kind))
    }
}
impl std::fmt::Display for CoordinationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SyncRefusal(kind) => {
                let uncertain = match kind {
                    SyncRefusalKind::Authorization => {
                        return f.write_str("sync authorization refused");
                    }
                    SyncRefusalKind::Other => return f.write_str("sync refused"),
                    SyncRefusalKind::MissingReference {
                        publication,
                        uncertain,
                    } => {
                        f.write_str("missing-reference for publication ")?;
                        for byte in publication {
                            write!(f, "{byte:02x}")?;
                        }
                        *uncertain
                    }
                    SyncRefusalKind::InvalidReference { uncertain } => {
                        f.write_str("invalid-reference")?;
                        *uncertain
                    }
                    SyncRefusalKind::PublishWorkLimit { uncertain } => {
                        f.write_str("publish-work-limit against this head")?;
                        *uncertain
                    }
                };
                if uncertain {
                    f.write_str(" (earlier attempts unresolved)")?;
                }
                Ok(())
            }
            Self::Recovery(e) => e.fmt(f),
            Self::Refused(reason) => write!(f, "intent refused: {reason}"),
            Self::Fenced {
                recorded_generation,
            } => write!(
                f,
                "intent fenced (ESTALE), recorded generation {recorded_generation:?}"
            ),
            Self::CommitFenced { publication } => {
                f.write_str("commit publication ")?;
                for byte in publication {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str(" fenced (ESTALE)")
            }
            Self::Overlay(e) => e.fmt(f),
            Self::Codec(e) => e.fmt(f),
            Self::Publication(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for CoordinationError {}
impl From<OverlayError> for CoordinationError {
    fn from(e: OverlayError) -> Self {
        Self::Overlay(e)
    }
}
impl From<codec::Error> for CoordinationError {
    fn from(e: codec::Error) -> Self {
        observe::op_failed(OperationKind::Session, FailureClass::Corrupt);
        Self::Codec(e)
    }
}
impl From<std::io::Error> for CoordinationError {
    fn from(e: std::io::Error) -> Self {
        Self::Overlay(e.into())
    }
}
impl From<PublicationStoreError> for CoordinationError {
    fn from(e: PublicationStoreError) -> Self {
        Self::Publication(e)
    }
}

fn landed_publication_error(error: PublicationStoreError) -> CoordinationError {
    if matches!(
        error.kind,
        crate::PublicationStoreErrorKind::Unavailable | crate::PublicationStoreErrorKind::Io
    ) {
        CoordinationError::Publication(error)
    } else {
        refused("IntentLandedReplayInvalid")
    }
}

fn landed_journal_error(error: OverlayError) -> CoordinationError {
    match error {
        OverlayError::Refused(_) => refused("IntentLandedReplayInvalid"),
        error => CoordinationError::Overlay(error),
    }
}

pub(crate) fn landed_replay_wait(
    now: u64,
    eligible: u64,
    deadline: u64,
) -> Result<Option<u64>, CoordinationError> {
    if now >= deadline || eligible > deadline {
        return Err(refused("IntentStartupAttemptsExhausted"));
    }
    Ok((eligible > now).then(|| eligible - now))
}

fn retire_displaced_release(carrier: &mut Carrier, newer_epoch: u64) -> bool {
    if let Some(release) = carrier.pending.iter_mut().find(|pending| {
        pending.operation == Operation::Release
            && !pending.terminal
            && intent::decode_release(&pending.body)
                .is_ok_and(|release| release.epoch < newer_epoch)
    }) {
        release.terminal = true;
        return true;
    }
    false
}

/// The persisted consent marker has no horizon or dispatch yet.
pub(crate) fn is_unstarted_takeover(pending: &Pending) -> bool {
    pending.operation == Operation::Ownership && pending.expires == 0 && pending.attempts == 0
}

/// Restore the retained fence when a handshake ends without a grant.
fn failed_handshake_phase(fence: u8) -> Phase {
    if fence == 0 {
        Phase::Unowned
    } else {
        Phase::Fenced
    }
}

#[expect(
    clippy::match_same_arms,
    reason = "recorded refusal names keep their failure-class mappings explicit"
)]
fn refused(reason: &'static str) -> CoordinationError {
    let class = match reason {
        "IntentEntropyUnavailable"
        | "IntentRetryDeadline"
        | "IntentRetryNotEligible"
        | "IntentStartupAttemptsExhausted"
        | "IntentClockDomainChanged" => FailureClass::Unavailable,
        "IntentSelectionChanged" | "IntentCursorChanged" | "IntentTokenDisplaced" => {
            FailureClass::Conflict
        }
        "IntentPreparedRoot"
        | "IntentPreparedSignature"
        | "IntentPendingSignature"
        | "IntentCarrierChanged"
        | "IntentLandedReplayInvalid"
        | "WritableIntentDiscoveryInvalid" => FailureClass::Corrupt,
        "IntentCompletionBinding"
        | "IntentCompletionOwner"
        | "IntentRequestNotRetained"
        | "IntentAttemptNotStarted"
        | "IntentVerdictMismatch" => FailureClass::Internal,
        "IntentPersistencePoisoned" | "IntentCapExhausted" => FailureClass::Io,
        "IntentExpiredRegisterUnresolved" => FailureClass::Refused,
        _ => FailureClass::Refused,
    };
    observe::op_failed(OperationKind::Session, class);
    CoordinationError::Refused(reason)
}
fn now(clock: &impl Clock) -> Result<u64, CoordinationError> {
    let t = clock.now();
    if !t.is_valid() {
        return Err(refused("IntentClockInvalid"));
    }
    u64::try_from(t.secs)
        .ok()
        .and_then(|s| s.checked_mul(1000))
        .and_then(|s| s.checked_add(u64::from(t.nanos / 1_000_000)))
        .ok_or_else(|| refused("IntentClockInvalid"))
}

/// Persisted network outcome. Capture acknowledgement additionally requires a
/// successful generation-bound result from `complete_capture_queue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentCompletion {
    /// The exact request was accepted and its receipt persisted.
    Accepted(Receipt),
    /// Absence answered an unconsented Released takeover with no local work owed.
    /// The carrier is durably unowned and may attempt fresh acquisition.
    TakeoverAbsent,
    /// A higher same-owner generation retired this request; coverage is separate.
    Overtaken(Receipt),
    /// Mutation remains unresolved and the exact request is retained for retry.
    Unknown,
}

/// Owned immutable request; private binding prevents accidental retargeting.
#[derive(Clone)]
pub struct PendingIntent {
    scope: granary_core::retained_submission::Scope,
    volume: granary_core::root::VolumeName,
    operation: Operation,
    body: Vec<u8>,
    process: [u8; 16],
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct LandedReplay {
    request: PendingIntent,
    expires: u64,
}
impl LandedReplay {
    #[must_use]
    #[doc(hidden)]
    pub fn request(&self) -> &PendingIntent {
        &self.request
    }

    #[must_use]
    pub(crate) const fn expires(&self) -> u64 {
        self.expires
    }
}
impl std::fmt::Debug for PendingIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingIntent")
            .field("operation", &self.operation)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}
impl PendingIntent {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }
    #[must_use]
    pub fn operation(&self) -> Operation {
        self.operation
    }
    #[must_use]
    pub fn volume(&self) -> &granary_core::root::VolumeName {
        &self.volume
    }
    #[must_use]
    pub fn scope(&self) -> &granary_core::retained_submission::Scope {
        &self.scope
    }
}

/// One Store/flock and persistent component state. No borrowed facade is retained.
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent poison, engine attachment, commit conflict and shutdown latch states"
)]
pub struct WritableStore<P: OverlayIo> {
    store: Store,
    config: OverlayConfig,
    io: P,
    area: PathBuf,
    carrier: Carrier,
    overlay: Option<OverlayStore<P>>,
    bundle_overlay: Result<BundleOverlay, BundleRefusal>,
    range_cache: crate::overlay_store::verified_range::VerifiedRangeCache,
    poisoned: bool,
    startup_attempts: u32,
    release_deadline: Option<u64>,
    faults: FaultControl,
    metrics: Option<ClientMetrics>,
    contention: crate::contention::Window,
    // A new process skips the entire previously durable reservation.
    generation_floor: u64,
    capture_queue: std::collections::BTreeMap<u64, capture::QueuedCapture>,
    failed_sync_registrations: std::collections::BTreeSet<u64>,
    /// The Register currently driven by a landing finish, if any.
    landing_refresh: Option<u64>,
    measured_attempts: std::collections::BTreeMap<granary_core::hash::GrainId, u32>,
    engine_attached: bool,
    /// The only holder of the mount's pinned view; `None` until a mount binds one.
    mount_pin: Option<std::sync::Arc<ViewContext>>,
    commit_lane: Option<u64>,
    commit_conflict: bool,
    fenced_publication: Option<[u8; 16]>,
    commit_serial: u64,
    commit_landings: u64,
    pub(crate) floor_changed: std::sync::Arc<tokio::sync::Notify>,
    pub(crate) coalesce_wake: std::sync::Arc<tokio::sync::Notify>,
    pub(crate) coalesce_clock: Option<crate::overlay_store::CoalesceClock>,
    pub(crate) object_leases: std::collections::BTreeMap<u64, (u64, Option<u64>)>,
    /// Syncs admitted at the adapter and not yet answered, which a shutdown
    /// drains before its own syncs.
    pub(crate) admitted_syncs: u64,
    /// Leased objects a landing replaced: their pending syncs owe nothing.
    pub(crate) replaced_leases: std::collections::BTreeSet<u64>,
    /// Set once a shutdown begins: no user mutation or sync is admitted after.
    mutations_closed: bool,
    pub(crate) construction_workspace_bytes: u64,
}

impl<P: OverlayIo> std::fmt::Debug for WritableStore<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WritableStore")
            .field("phase", &self.carrier.phase)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}
impl<P: OverlayIo> WritableStore<P> {
    /// Open canonical evidence, or establish a verified never-sent fresh area.
    /// `clock` inputs to later calls must share a monotonic domain across reopen.
    /// # Errors
    /// Custody, entropy, bounds, invalid canonical evidence or persistence uncertainty.
    #[expect(
        clippy::too_many_lines,
        reason = "canonical carrier validation and writer establishment finish before exposing the owned components"
    )]
    pub fn new(
        mut store: Store,
        mut config: OverlayConfig,
        mut io: P,
        random: &mut impl SecureRandom,
        faults: FaultControl,
        mut verify: impl FnMut(&RootDoc, &[u8]) -> bool,
    ) -> Result<Self, CoordinationError> {
        random
            .fill(&mut config.instance)
            .map_err(|_| refused("IntentEntropyUnavailable"))?;
        if config.ownership_completion_reserve < codec::REPLACEMENT_RESERVE {
            return Err(refused("IntentReplacementReserve"));
        }
        let writer = OverlayStore::establish_writer(&mut store, &config, &mut io, random, &faults)?;
        let area = store
            .publication_root()
            .join("overlay")
            .join(config.scope.digest().map_err(|_| refused("IntentScope"))?)
            .join(config.volume.as_str());
        let canonical = area.join("ownership");
        let existing = io.length(&canonical)?;
        io.length(&area.join("ownership.tmp"))?;
        let carrier = if let Some(length) = existing {
            if length > codec::MAX_BYTES as u64 {
                return Err(refused("IntentCarrierCap"));
            }
            let bytes = io.read_at(&canonical, 0, codec::MAX_BYTES + 1)?;
            if bytes.len() as u64 != length || io.length(&canonical)? != Some(length) {
                return Err(refused("IntentCarrierChanged"));
            }
            let c = codec::decode(&bytes)?;
            if c.scope != config.scope || c.volume != config.volume || c.writer != writer.writer {
                return Err(refused("IntentCarrierBinding"));
            }
            if writer.ceiling < c.allocated || writer.ceiling < c.sent {
                return Err(refused("IntentCeilingBelowEvidence"));
            }
            for bytes in [&c.root, &c.selected_root] {
                if !bytes.is_empty() {
                    let doc = granary_core::root::decode_root(bytes)
                        .map_err(|_| refused("IntentPreparedRoot"))?;
                    let prefix = granary_core::root::signed_prefix(bytes)
                        .map_err(|_| refused("IntentPreparedRoot"))?;
                    if !verify(&doc, prefix) {
                        return Err(refused("IntentPreparedSignature"));
                    }
                }
            }
            for p in &c.pending {
                if p.operation == Operation::Register {
                    intent::decode_register(&p.body, &config.volume, &mut verify)
                        .map_err(|_| refused("IntentPendingSignature"))?;
                }
            }
            c
        } else {
            if writer.ceiling != 0
                || io
                    .entries(&area)?
                    .iter()
                    .any(|n| !matches!(n.as_str(), "writer" | "staging"))
                || !io.entries(&area.join("staging"))?.is_empty()
            {
                return Err(refused("IntentPendingReconciliation"));
            }
            Carrier {
                scope: config.scope.clone(),
                volume: config.volume.clone(),
                writer: writer.writer,
                instance: config.instance,
                revision: 0,
                phase: Phase::Unowned,
                cursor: 0,
                allocated: 0,
                sent: 0,
                handshake: vec![],
                grant: vec![],
                current: vec![],
                root: vec![],
                selected: vec![],
                selected_root: vec![],
                selected_cursor: 0,
                consent: vec![],
                fence: 0,
                fence_evidence: vec![],
                pending: vec![],
            }
        };
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
        if existing.is_none() {
            result.persist(result.carrier.clone())?;
        }
        Ok(result)
    }
    #[must_use]
    pub fn fault_control(&self) -> FaultControl {
        self.faults.clone()
    }
    #[cfg(test)]
    pub(crate) fn clean_generation_for_test(&mut self, generation: u64) {
        self.range_cache.generation_for_test(generation);
    }
    #[cfg(test)]
    pub(crate) fn generation_floor_for_test(&mut self, floor: u64) {
        self.generation_floor = floor;
    }
    #[cfg(test)]
    pub(crate) const fn landing_refresh_for_test(&self) -> Option<u64> {
        self.landing_refresh
    }
    #[cfg(test)]
    pub(crate) fn set_landing_refresh_for_test(&mut self, generation: Option<u64>) {
        self.landing_refresh = generation;
    }
    #[cfg(test)]
    pub(crate) fn fail_publication_file_sync_for_test(&mut self, fail: bool) {
        self.store.publication_fail_file_sync = fail;
    }
    #[cfg(test)]
    pub(crate) fn cap_for_test(&mut self, cap: u64) {
        self.config.cap = cap;
        if let Some(overlay) = &mut self.overlay {
            overlay.cap_for_test(cap);
        }
    }
    #[cfg(test)]
    pub(crate) fn phase_for_test(&mut self, phase: Phase) -> Result<(), CoordinationError> {
        let mut next = self.carrier.clone();
        next.phase = phase;
        if phase == Phase::Fenced && next.fence == 0 {
            next.fence = 2;
            next.fence_evidence.clear();
        }
        self.persist(next)
    }
    /// Inject a displaced token before dispatch can retire the pending request.
    #[cfg(test)]
    pub(crate) fn displace_token_for_test(&mut self) {
        let mut receipt = intent::decode_receipt(&self.carrier.current).unwrap();
        receipt.instance = [0xf0; 16];
        self.carrier.current = intent::encode_receipt(receipt).unwrap();
    }
    /// Replace the registered prepared root, and the current receipt's root id
    /// with it, persisted as every carrier change is. No bytes leave no root
    /// registered: the receipt is released.
    #[cfg(test)]
    pub(crate) fn set_carrier_root_for_test(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<(), CoordinationError> {
        let mut receipt =
            intent::decode_receipt(&self.carrier.current).map_err(|_| refused("IntentReceipt"))?;
        receipt.state = if bytes.is_empty() {
            ReceiptState::Released
        } else {
            ReceiptState::Live {
                prepared_root_id: granary_core::hash::GrainId::of(&bytes),
            }
        };
        let mut next = self.carrier.clone();
        next.current = intent::encode_receipt(receipt).map_err(|_| refused("IntentReceipt"))?;
        next.root = bytes;
        self.persist(next)
    }
    /// Configure the advisory rate independently of commit admission.
    pub(crate) fn set_contention_threshold(&mut self, threshold: crate::ContentionThreshold) {
        self.contention.set_threshold(threshold);
    }
    pub(crate) fn observe_commit(&mut self, result: crate::CommitResult) {
        self.contention.record(result, self.metrics.as_ref());
    }
    pub fn set_metrics(&mut self, metrics: ClientMetrics) {
        if self.metrics.is_none() {
            metrics.reset_contention();
        }
        self.contention.publish(&metrics);
        self.metrics = Some(metrics);
    }
    #[must_use]
    pub fn writer_uuid(&self) -> [u8; 16] {
        self.carrier.writer
    }
    #[must_use]
    pub fn snapshot(&self) -> &Carrier {
        &self.carrier
    }
    /// # Errors
    /// Persistence poison or publication custody/evidence refusal.
    pub fn publication_transaction<R>(
        &mut self,
        local: impl FnOnce(&mut PublicationStore<'_>) -> Result<R, PublicationStoreError>,
    ) -> Result<R, CoordinationError> {
        self.check()?;
        if self.engine_attached && self.commit_lane.is_none() {
            return Err(refused("SyncCommitLaneRequired"));
        }
        Ok(local(&mut self.store.publications(self.config.euid)?)?)
    }
    fn publication_read_transaction<R>(
        &mut self,
        local: impl FnOnce(&mut PublicationStore<'_>) -> Result<R, PublicationStoreError>,
    ) -> Result<R, CoordinationError> {
        self.check()?;
        if self.engine_attached && self.commit_lane.is_none() {
            return Err(refused("SyncCommitLaneRequired"));
        }
        Ok(local(
            &mut self.store.publications_read_only(self.config.euid)?,
        )?)
    }
    /// The base of the overlay journal when it holds work, or leftovers
    /// only a replay on that base removes, read from the area's files before
    /// any overlay opens on it; `None` for no journal or a clean one.
    /// # Errors
    /// The store's own refusal, `journal fenced` for a journal that does not
    /// scan, `writer ceiling or identity` for another writer's, its input
    /// budget, or the area's I/O.
    pub(crate) fn dirty_journal_base(
        &mut self,
    ) -> Result<Option<(granary_core::hash::GrainId, u64)>, CoordinationError> {
        self.check()?;
        Ok(overlay_store::journal_condition(&mut self.io, &self.area)?
            .filter(|(_, clean)| !clean)
            .map(|(header, _)| (header.base_root, header.base_seq)))
    }

    /// The exact old-owner registration proven to refresh a retained landing.
    /// A valid registration outside that lane is deliberately not classified.
    ///
    /// # Errors
    /// Persistence, publication or malformed landed-lane evidence refusal.
    #[doc(hidden)]
    pub fn landed_replay(&mut self) -> Result<Option<LandedReplay>, CoordinationError> {
        self.check()?;
        let Ok(current) = intent::decode_receipt(&self.carrier.current) else {
            return Ok(None);
        };
        let mut owner_registers = Vec::new();
        for pending in self.carrier.pending.iter().filter(|pending| {
            pending.operation == Operation::Register
                && !pending.terminal
                && pending.context.is_empty()
        }) {
            let register = intent::decode_register(&pending.body, &self.config.volume, |_, _| true)
                .map_err(|_| refused("IntentLandedReplayInvalid"))?;
            if register.writer == self.carrier.writer
                && (register.epoch, register.instance) == (current.epoch, current.instance)
            {
                owner_registers.push((
                    pending.body.clone(),
                    pending.expires,
                    register.root.to_vec(),
                ));
            }
        }
        if owner_registers.is_empty() {
            return Ok(None);
        }
        let mut relevant = Vec::new();
        for (body, expires, root) in owner_registers {
            if self.stored_landing(&root)?.is_some() {
                relevant.push((body, expires));
            }
        }
        if relevant.len() > 1 {
            return Err(refused("IntentLandedReplayInvalid"));
        }
        Ok(relevant.pop().map(|(body, expires)| LandedReplay {
            request: self.pending(Operation::Register, body),
            expires,
        }))
    }

    /// Bind locally authenticated root bytes to the answered journal boundary.
    /// Missing retained material does not hide an exact pending refresh; its
    /// reconstruction is checked separately before installation. Dispatch
    /// counters bound probes; the journal landing supplies that evidence here.
    fn stored_landing(
        &mut self,
        root: &[u8],
    ) -> Result<Option<overlay_store::LandedJournal>, CoordinationError> {
        let scope = self.config.scope.clone();
        let volume = self.config.volume.clone();
        let retained = self
            .publication_read_transaction(|store| store.inspect_selected(&scope, &volume))
            .map_err(|error| match error {
                CoordinationError::Publication(error) => landed_publication_error(error),
                error => error,
            })?;
        let landed = overlay_store::landed_commits(&mut self.io, &self.area)
            .map_err(landed_journal_error)?;
        let doc = granary_core::root::decode_root(root)
            .map_err(|_| refused("IntentLandedReplayInvalid"))?;
        let id = granary_core::hash::GrainId::of(root);
        if landed
            .commits
            .iter()
            .any(|(_, stored, seq)| *stored == id && *seq != doc.seq)
        {
            return Err(refused("IntentLandedReplayInvalid"));
        }
        if doc.volume != volume
            || !landed.commits.iter().any(|(boundary, stored, seq)| {
                if (*stored, *seq) != (id, doc.seq) {
                    return false;
                }
                retained.as_ref().is_none_or(|record| {
                    landed.boundaries.get(boundary)
                        == Some(&(
                            record.publication_id,
                            granary_core::hash::GrainId::of(&record.frozen.initial_root),
                        ))
                        && record.candidates.iter().any(|candidate| {
                            candidate.seq == doc.seq
                                && match &record.phase {
                                    granary_core::retained_submission::Phase::Complete(done) => {
                                        candidate.id == done.id
                                    }
                                    _ => true,
                                }
                                && crate::recovery::finish_landing_matches(&candidate.root, root)
                        })
                })
            })
        {
            return Ok(None);
        }
        Ok(Some(landed))
    }

    /// Whether the current stored-root receipt proves the journal's refresh.
    /// Recovery may consume a durable witness under its own fresh grant;
    /// the live lane retains its generation ordering.
    pub(crate) fn landed_refresh_registered(
        &mut self,
        root: &[u8],
        same_process_lane: bool,
    ) -> Result<bool, CoordinationError> {
        self.check()?;
        let receipt = intent::decode_receipt(&self.carrier.current)
            .map_err(|_| refused("IntentLandedReplayInvalid"))?;
        let id = granary_core::hash::GrainId::of(root);
        if receipt.writer != self.carrier.writer
            || receipt.state
                != (ReceiptState::Live {
                    prepared_root_id: id,
                })
            || self.carrier.root != root
        {
            return Ok(false);
        }
        let Some(landed) = self.stored_landing(root)? else {
            return Ok(false);
        };
        let witnessed = landed
            .refreshes
            .iter()
            .any(|(generation, root)| *generation == receipt.generation && *root == id);
        Ok(receipt.generation > landed.highest_generation
            || (witnessed && (same_process_lane || self.check_recovery_owner().is_ok())))
    }

    pub(crate) fn check_initial_state(&mut self) -> Result<(), CoordinationError> {
        self.check()?;
        if self
            .overlay
            .as_ref()
            .is_none_or(|overlay| !overlay.initial_state_ready())
            || self.publication_unsettled()?
        {
            return Err(refused("WritableRecoveryRequired"));
        }
        Ok(())
    }
    pub(crate) fn begin_landing_refresh(&mut self, generation: u64) {
        self.landing_refresh = Some(generation);
    }
    pub(crate) fn finish_landing_refresh(&mut self, generation: u64) {
        if self.landing_refresh == Some(generation) {
            self.landing_refresh = None;
        }
    }
    /// Admission requires owned Serving, a ready overlay and settled
    /// publication. A closed commit lane owns the retained publication, so
    /// with one open the view also stays admitted in an owned start and
    /// before the publication settles. A nonterminal Register is admitted
    /// only while it belongs to the capture queue or to a failed engine
    /// caller whose network evidence is still retained, or is the refresh
    /// driven by a landing finish; any other pending request refuses.
    /// # Errors
    /// Ownership, replay or retained publication still requires recovery.
    pub(crate) fn check_readiness(&mut self) -> Result<(), CoordinationError> {
        let sync_open = self.sync_admission_open()?;
        let permission = self.permission();
        if !(self.carrier.phase == Phase::Serving
            || (!sync_open && self.carrier.phase == Phase::OwnedStart))
            || !matches!(
                permission,
                Ok(OwnershipStatus::Durable(_) | OwnershipStatus::Owned(_))
            )
            || (sync_open && !matches!(permission, Ok(OwnershipStatus::Durable(_))))
            || self
                .overlay
                .as_ref()
                .is_none_or(|overlay| overlay.readiness() != OverlayReadiness::Ready)
            || self.carrier.pending.iter().any(|pending| {
                !pending.terminal
                    && match pending.operation {
                        Operation::Register => !pending.generation().is_ok_and(|generation| {
                            self.capture_queue.contains_key(&generation)
                                || self.failed_sync_registrations.contains(&generation)
                                || self.landing_refresh == Some(generation)
                        }),
                        Operation::Ownership | Operation::Release => true,
                    }
            })
            || (sync_open && self.publication_unsettled()?)
        {
            return Err(refused("WritableRecoveryRequired"));
        }
        Ok(())
    }
    /// Shutdown requires durable Serving, a ready overlay, no pending request
    /// of any kind and settled publication: work that still owes the
    /// authority an answer is reported, not released.
    /// # Errors
    /// Ownership, replay, a pending request or retained publication remains.
    pub(crate) fn check_quiescent(&mut self) -> Result<(), CoordinationError> {
        self.check()?;
        if self.carrier.phase != Phase::Serving
            || self
                .overlay
                .as_ref()
                .is_none_or(|overlay| overlay.readiness() != OverlayReadiness::Ready)
            || self.carrier.pending.iter().any(|pending| !pending.terminal)
            || self.publication_unsettled()?
        {
            return Err(refused("WritableRecoveryRequired"));
        }
        Ok(())
    }
    /// Close the store to user mutations for good: the write seams, the
    /// mutation pre-check, the adapter's two sync admissions (an fsync's and
    /// a shrink retry's) and a waiting shrink refuse from here on. The
    /// engine's own syncs and records, which the shutdown runs, are not
    /// affected.
    pub(crate) fn close_mutations(&mut self) {
        self.mutations_closed = true;
    }
    /// Whether a shutdown has closed the store to user mutations.
    pub(crate) const fn mutations_closed(&self) -> bool {
        self.mutations_closed
    }
    /// What a shutdown leaves owed, read from memory without readiness or
    /// permission, so a releasing, released or fenced store answers too.
    /// `None` when no overlay is open or its state cannot be read.
    pub(crate) fn shutdown_report(&self) -> Option<overlay_store::ShutdownWork> {
        self.overlay.as_ref()?.shutdown_work().ok()
    }
    /// The overlay's base, read as [`Self::shutdown_report`] is.
    pub(crate) fn shutdown_base(&self) -> Option<(granary_core::hash::GrainId, u64)> {
        self.overlay.as_ref()?.sync_base().ok()
    }
    pub(crate) fn recovery_stages(&self) -> Option<Vec<overlay_store::RecoveryStageRow>> {
        Some(self.overlay.as_ref()?.recovery_stages())
    }
    pub(crate) fn publication_unsettled(&mut self) -> Result<bool, CoordinationError> {
        Ok(self
            .store
            .publications(self.config.euid)?
            .load(&self.config.scope, &self.config.volume)?
            .is_some_and(|record| !record.is_complete()))
    }
    fn check(&self) -> Result<(), CoordinationError> {
        if self.poisoned
            || self.store.publication_poisoned
            || self
                .overlay
                .as_ref()
                .is_some_and(|o| o.readiness() == OverlayReadiness::Poisoned)
        {
            return Err(refused("IntentPersistencePoisoned"));
        }
        if self.commit_conflict || self.carrier.phase == Phase::Fenced {
            observe::op_failed(OperationKind::IntentRegister, FailureClass::Conflict);
            if let Some(publication) = self.fenced_publication {
                return Err(CoordinationError::CommitFenced { publication });
            }
            return Err(CoordinationError::Fenced {
                recorded_generation: intent::decode_receipt(&self.carrier.fence_evidence)
                    .ok()
                    .map(|r| r.generation),
            });
        }
        Ok(())
    }
    fn persist(&mut self, next: Carrier) -> Result<(), CoordinationError> {
        self.persist_transition(next, false)
    }
    fn persist_transition(
        &mut self,
        mut next: Carrier,
        acknowledged: bool,
    ) -> Result<(), CoordinationError> {
        if self.poisoned {
            return Err(refused("IntentPersistencePoisoned"));
        }
        self.carrier.phase.transition(next.phase, acknowledged)?;
        next.revision = self
            .carrier
            .revision
            .checked_add(1)
            .ok_or_else(|| refused("IntentRevisionExhausted"))?;
        let bytes = codec::encode(&next)?;
        self.io
            .check_root(self.store.publication_root(), self.config.euid)?;
        self.io.directory(&self.area)?;
        let mut charged = 0u64;
        for name in self.io.entries(&self.area)? {
            if name == "staging" {
                let dir = self.area.join(&name);
                self.io.directory(&dir)?;
                for file in self.io.entries(&dir)? {
                    charged = charged
                        .checked_add(
                            self.io
                                .length(&dir.join(file))?
                                .ok_or_else(|| refused("IntentStagingChanged"))?,
                        )
                        .ok_or_else(|| refused("IntentCapOverflow"))?;
                }
            } else if name == "unmerged" {
                let expected = self
                    .overlay
                    .as_ref()
                    .ok_or_else(|| refused("IntentUnmergedUnclassified"))?
                    .unmerged_lengths();
                let directory = self.area.join("unmerged");
                self.io.directory(&directory)?;
                let mut observed = std::collections::BTreeMap::new();
                for entry in self.io.entries(&directory)? {
                    let length = self
                        .io
                        .length(&directory.join(&entry))?
                        .ok_or_else(|| refused("IntentUnmergedChanged"))?;
                    charged = charged
                        .checked_add(length)
                        .ok_or_else(|| refused("IntentCapOverflow"))?;
                    if observed.insert(entry, length).is_some() {
                        return Err(refused("IntentUnmergedChanged"));
                    }
                }
                if &observed != expected {
                    return Err(refused("IntentUnmergedChanged"));
                }
            } else {
                if !matches!(
                    name.as_str(),
                    "writer"
                        | "writer.tmp"
                        | "journal"
                        | "journal.next"
                        | "ownership"
                        | "ownership.tmp"
                ) {
                    return Err(refused("IntentForeignControl"));
                }
                let length = self
                    .io
                    .length(&self.area.join(&name))?
                    .ok_or_else(|| refused("IntentControlChanged"))?;
                if !matches!(name.as_str(), "ownership" | "ownership.tmp") {
                    charged = charged
                        .checked_add(length)
                        .ok_or_else(|| refused("IntentCapOverflow"))?;
                }
            }
        }
        // The combined reserve covers both complete carrier names and completion
        // growth. Ordinary overlay admission retains this same credit.
        if charged
            .checked_add(codec::REPLACEMENT_RESERVE)
            .is_none_or(|n| n > self.config.cap)
        {
            return Err(refused("IntentCapExhausted"));
        }
        self.poisoned = true;
        let temporary = self.area.join("ownership.tmp");
        if self.io.length(&temporary)?.is_some() {
            self.io.remove(&temporary)?;
            self.io.sync_directory(&self.area)?;
        }
        overlay_store::durable_file(
            &mut self.io,
            &self.faults,
            &self.area,
            "ownership.tmp",
            "ownership",
            &bytes,
            "intent.pending",
            next.revision,
        )?;
        self.carrier = next;
        self.poisoned = false;
        Ok(())
    }
    fn permission(&self) -> Result<OwnershipStatus, CoordinationError> {
        self.check()?;
        if !matches!(self.carrier.phase, Phase::OwnedStart | Phase::Serving) {
            return Err(refused("IntentOwnershipPending"));
        }
        let r = intent::decode_receipt(&self.carrier.current)
            .map_err(|_| refused("IntentOwnershipPending"))?;
        let scope = self
            .carrier
            .scope
            .digest()
            .map_err(|_| refused("IntentScope"))?;
        let (volume, writer, high_water) = (
            self.carrier.volume.clone(),
            self.carrier.writer,
            self.carrier.allocated,
        );
        if self.carrier.phase == Phase::Serving && r.instance == self.config.instance {
            Ok(OwnershipStatus::Durable(OwnershipPermission::new(
                scope, volume, writer, high_water,
            )))
        } else {
            Ok(OwnershipStatus::Owned(OwnershipPermission::new(
                scope, volume, writer, high_water,
            )))
        }
    }
    /// Replay under owned readiness, retaining the component for all transactions.
    /// # Errors
    /// Missing ownership, invalid replay, custody or persistence failure.
    pub fn open_overlay(
        &mut self,
        header: JournalHeader,
        base: Vec<OverlayEntry>,
        source: &mut impl ContentSource,
        io: P,
    ) -> Result<(), CoordinationError> {
        let permission = self.permission()?;
        self.invalidate_clean_content()?;
        let result = OverlayStore::open(
            &mut self.store,
            self.config.clone(),
            header,
            base,
            &permission,
            source,
            io,
            self.faults.clone(),
        );
        self.retain_overlay_bundle(result.as_ref().err());
        self.install_overlay(result?);
        Ok(())
    }
    /// Short local transaction. Callbacks and network waits must run after return.
    /// # Errors
    /// Fencing, poison or service readiness refusal.
    pub fn overlay_transaction<R>(
        &mut self,
        local: impl FnOnce(&mut WritableOverlay<'_, P>) -> Result<R, OverlayError>,
    ) -> Result<R, CoordinationError> {
        #[cfg(test)]
        shared::record_transaction();
        let permission = self.permission()?;
        self.overlay_transaction_with(permission, local)
    }
    fn overlay_transaction_with<R>(
        &mut self,
        permission: OwnershipStatus,
        local: impl FnOnce(&mut WritableOverlay<'_, P>) -> Result<R, OverlayError>,
    ) -> Result<R, CoordinationError> {
        let sync_admission_open = self.sync_admission_open()?;
        let overlay = self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?;
        let mut transaction = WritableOverlay {
            overlay,
            bundle_overlay: &mut self.bundle_overlay,
            range_cache: &mut self.range_cache,
            store: &mut self.store,
            permission,
            poisoned: &mut self.poisoned,
            sync_admission_open,
            mutations_closed: self.mutations_closed,
        };
        let result = local(&mut transaction);
        self.retain_overlay_bundle(result.as_ref().err());
        Ok(result?)
    }
    fn pending(&self, operation: Operation, body: Vec<u8>) -> PendingIntent {
        PendingIntent {
            scope: self.carrier.scope.clone(),
            volume: self.carrier.volume.clone(),
            operation,
            body,
            process: self.config.instance,
        }
    }
    fn add(
        &mut self,
        mut next: Carrier,
        operation: Operation,
        body: Vec<u8>,
        context: Vec<u8>,
        clock: &impl Clock,
    ) -> Result<PendingIntent, CoordinationError> {
        let first = now(clock)?;
        let expires = first
            .checked_add(HORIZON_MILLIS)
            .ok_or_else(|| refused("IntentDeadlineOverflow"))?;
        let expires = if operation == Operation::Release {
            self.release_deadline
                .map_or(expires, |deadline| deadline.min(expires))
        } else {
            expires
        };
        next.pending.push(Pending {
            operation,
            body: body.clone(),
            context,
            first,
            expires,
            eligible: first,
            attempts: 0,
            terminal: false,
            answered: false,
            answer: vec![],
        });
        next.pending
            .sort_by_key(|p| (p.operation, p.generation().unwrap_or(u64::MAX)));
        self.persist(next)?;
        Ok(self.pending(operation, body))
    }
    fn acquisition_floor(&self) -> Option<u64> {
        let carrier = &self.carrier;
        let epochs = [&carrier.current, &carrier.selected]
            .into_iter()
            .filter_map(|bytes| {
                intent::decode_receipt(bytes)
                    .ok()
                    .map(|receipt| receipt.epoch)
            });
        let cursors = [carrier.cursor, carrier.selected_cursor]
            .into_iter()
            .filter(|&cursor| cursor != 0);
        // Zero is the initial field value. A retained Acquire also proves an
        // observation when the authority cursor really was zero.
        let observed_zero = carrier.pending.iter().any(|pending| {
            pending.operation == Operation::Ownership
                && intent::decode_ownership(&pending.body).is_ok_and(|request| {
                    request.mode == OwnershipMode::Acquire { observed_cursor: 0 }
                })
        });
        epochs
            .chain(cursors)
            .chain(observed_zero.then_some(0))
            .max()
    }

    /// Reject an authenticated cursor below the retained same-scope evidence.
    pub(crate) fn check_acquisition_cursor(&self, cursor: u64) -> Result<(), CoordinationError> {
        if self.acquisition_floor().is_some_and(|floor| cursor < floor) {
            return Err(refused("WritableIntentDiscoveryInvalid"));
        }
        Ok(())
    }

    /// A carrier with acquisition history must owe nothing before an Acquire.
    pub(crate) fn check_acquisition_debt(&mut self) -> Result<(), CoordinationError> {
        if self.acquisition_floor().is_some() && !self.owes_nothing() {
            return Err(refused("WritableRecoveryRequired"));
        }
        Ok(())
    }

    /// Prepare absent ownership using an authenticated observed cursor.
    /// A carrier with history must owe nothing locally, and the cursor must
    /// cover its current and selected epochs and cursors.
    /// # Errors
    /// Existing/uncertain ownership, fencing, local debt, continuity,
    /// bounds or persistence failure.
    pub fn prepare_acquire(
        &mut self,
        cursor: u64,
        clock: &impl Clock,
    ) -> Result<PendingIntent, CoordinationError> {
        self.check()?;
        if self.carrier.phase != Phase::Unowned || self.carrier.pending.iter().any(|p| !p.terminal)
        {
            return Err(refused("IntentOwnershipUnresolved"));
        }
        self.check_acquisition_debt()?;
        self.check_acquisition_cursor(cursor)?;
        let body = intent::encode_ownership(Ownership {
            writer: self.carrier.writer,
            instance: self.config.instance,
            mode: OwnershipMode::Acquire {
                observed_cursor: cursor,
            },
        })
        .map_err(|_| refused("IntentAcquire"))?;
        let mut next = self.carrier.clone();
        next.pending.retain(|p| p.operation != Operation::Ownership);
        next.cursor = cursor;
        next.phase.transition(Phase::Handshake, false)?;
        next.phase = Phase::Handshake;
        self.add(next, Operation::Ownership, body, vec![], clock)
    }
    /// Conditional succession preserves the complete retained snapshot.
    /// # Errors
    /// Unresolved handshake, incomplete snapshot, fencing or persistence failure.
    pub fn prepare_succession(
        &mut self,
        clock: &impl Clock,
    ) -> Result<PendingIntent, CoordinationError> {
        self.check()?;
        if self.landed_replay()?.is_some() {
            return Err(refused("IntentReplayPending"));
        }
        if self
            .carrier
            .pending
            .iter()
            .any(|p| !p.terminal && p.operation != Operation::Register)
        {
            return Err(refused("IntentOwnershipUnresolved"));
        }
        let receipt = intent::decode_receipt(&self.carrier.current)
            .map_err(|_| refused("IntentSnapshotMissing"))?;
        let body = intent::encode_ownership(Ownership {
            writer: self.carrier.writer,
            instance: self.config.instance,
            mode: OwnershipMode::Takeover {
                expected_epoch: receipt.epoch,
                generation: receipt.generation,
                state: receipt.state,
                recovery_ack: false,
            },
        })
        .map_err(|_| refused("IntentTakeover"))?;
        let mut next = self.carrier.clone();
        next.phase.transition(Phase::Handshake, false)?;
        next.phase = Phase::Handshake;
        next.selected.clone_from(&next.current);
        next.selected_root.clone_from(&next.root);
        next.selected_cursor = next.cursor;
        next.pending.retain(|p| p.operation != Operation::Ownership);
        self.add(next, Operation::Ownership, body, vec![], clock)
    }
    /// Sole generation allocation: ceiling, then exact carrier/request, then dispatch.
    /// # Errors
    /// Bad prepared root, unresolved ownership, capacity, exhaustion or persistence.
    pub fn prepare_registration(
        &mut self,
        root: &[u8],
        context: Vec<u8>,
        clock: &impl Clock,
        verify: impl FnMut(&RootDoc, &[u8]) -> bool,
    ) -> Result<PendingIntent, CoordinationError> {
        if !self.sync_admission_open()? {
            return Err(refused("SyncCommitInFlight"));
        }
        self.prepare_registration_inner(root, context, clock, verify)
    }

    pub(crate) fn prepare_registration_inner(
        &mut self,
        root: &[u8],
        context: Vec<u8>,
        clock: &impl Clock,
        verify: impl FnMut(&RootDoc, &[u8]) -> bool,
    ) -> Result<PendingIntent, CoordinationError> {
        self.check()?;
        let receipt = intent::decode_receipt(&self.carrier.current)
            .map_err(|_| refused("IntentOwnershipPending"))?;
        if receipt.instance != self.config.instance
            || !matches!(self.carrier.phase, Phase::OwnedStart | Phase::Serving)
        {
            return Err(refused("IntentFreshInstanceRequired"));
        }
        if self
            .carrier
            .pending
            .iter()
            .filter(|p| p.operation == Operation::Register)
            .count()
            >= codec::MAX_PENDING
            || context.len() > codec::CONTEXT_MAX
        {
            return Err(refused("IntentPipelineFull"));
        }
        let overlay = self
            .overlay
            .as_mut()
            .ok_or_else(|| refused("IntentReplayPending"))?;
        let g = [
            receipt.generation,
            self.generation_floor,
            self.carrier.allocated,
            self.carrier.sent,
        ]
        .into_iter()
        .max()
        .and_then(|n| n.checked_add(1))
        .filter(|g| *g < u64::MAX)
        .ok_or_else(|| refused("IntentGenerationExhausted"))?;
        let body = intent::encode_register(
            &self.carrier.writer,
            receipt.epoch,
            &self.config.instance,
            g,
            root,
        )
        .map_err(|_| refused("IntentPreparedRoot"))?;
        let request = intent::decode_register(&body, &self.config.volume, verify)
            .map_err(|_| refused("IntentPreparedSignature"))?;
        let doc = granary_core::root::decode_root(request.root)
            .map_err(|_| refused("IntentPreparedRoot"))?;
        if doc.writer_uuid != self.carrier.writer {
            return Err(refused("IntentPreparedWriter"));
        }
        overlay_store::point(&self.faults, "intent.ceiling", "before", g)?;
        if g > overlay.writer().ceiling {
            let ceiling = g.saturating_add(63).min(u64::MAX - 1);
            let result = overlay.raise_ceiling(&mut self.store, ceiling);
            self.retain_overlay_bundle(result.as_ref().err());
            result?;
        }
        overlay_store::point(&self.faults, "intent.ceiling", "after", g)?;
        let mut next = self.carrier.clone();
        next.allocated = g;
        next.sent = g;
        self.add(next, Operation::Register, body, context, clock)
    }
    /// Release after final commit/refresh, retaining uncertainty past the deadline.
    /// `bound` is the caller configuration; `enclosing_deadline` is an existing
    /// absolute millisecond deadline in the supplied clock domain. The retained
    /// request carries the minimum for shutdown. Mount or recovery may re-arm
    /// an expired Release that may have been sent.
    /// # Errors
    /// Generation zero, uncompleted pipeline, wrong ownership, poison or persistence.
    pub fn prepare_release(
        &mut self,
        clock: &impl Clock,
        bound: Duration,
        enclosing_deadline: Option<u64>,
    ) -> Result<PendingIntent, CoordinationError> {
        self.check()?;
        if self.carrier.phase != Phase::Serving
            || self.carrier.pending.iter().any(|p| {
                p.operation == Operation::Register && (!p.terminal || !p.context.is_empty())
            })
        {
            return Err(refused("IntentDrainPending"));
        }
        let r = intent::decode_receipt(&self.carrier.current)
            .map_err(|_| refused("IntentOwnershipPending"))?;
        if r.instance != self.config.instance {
            return Err(refused("IntentFreshInstanceRequired"));
        }
        let body = intent::encode_release(intent::Release {
            writer: self.carrier.writer,
            epoch: r.epoch,
            instance: self.config.instance,
            generation: self.carrier.sent,
        })
        .map_err(|_| refused("IntentReleaseGenerationZero"))?;
        let duration =
            u64::try_from(bound.as_millis()).map_err(|_| refused("IntentDeadlineOverflow"))?;
        let deadline = now(clock)?
            .checked_add(duration)
            .ok_or_else(|| refused("IntentDeadlineOverflow"))?;
        self.release_deadline = Some(
            [Some(deadline), enclosing_deadline, self.release_deadline]
                .into_iter()
                .flatten()
                .min()
                .ok_or_else(|| refused("IntentDeadlineOverflow"))?,
        );
        let mut next = self.carrier.clone();
        next.phase = Phase::Releasing;
        self.add(next, Operation::Release, body, vec![], clock)
    }
    /// Resolve send eligibility at mount or recovery entry, before enumerating
    /// retained requests. An expired Release that may have reached the authority
    /// must settle before the retained snapshot can be used for succession.
    pub(crate) fn settle_expired_release(
        &mut self,
        clock: &impl Clock,
    ) -> Result<(), CoordinationError> {
        self.check()?;
        let time = now(clock)?;
        let Some(index) = self
            .carrier
            .pending
            .iter()
            .position(|pending| pending.operation == Operation::Release && !pending.terminal)
        else {
            return Ok(());
        };
        let mut next = self.carrier.clone();
        // A resumed consented handshake already proves displacement before
        // its grant can reclaim the older request.
        if self.carrier.phase == Phase::Handshake
            && let Some(expected_epoch) = self.carrier.pending.iter().find_map(|p| {
                if p.operation == Operation::Ownership
                    && !p.terminal
                    && let Ok(request) = intent::decode_ownership(&p.body)
                    && let OwnershipMode::Takeover {
                        expected_epoch,
                        recovery_ack: true,
                        ..
                    } = request.mode
                {
                    return Some(expected_epoch);
                }
                None
            })
            && retire_displaced_release(&mut next, expected_epoch)
        {
            return self.persist(next);
        }
        let pending = next
            .pending
            .get_mut(index)
            .ok_or_else(|| refused("IntentRequestNotRetained"))?;
        if time >= pending.expires {
            if next.phase == Phase::Releasing
                && pending.attempts > 0
                && let Ok(current) = intent::decode_receipt(&next.current)
                && intent::decode_release(&pending.body).is_ok_and(|release| {
                    (release.epoch, release.instance) == (current.epoch, current.instance)
                })
            {
                let bound = u64::try_from(DEFAULT_RESOLUTION_BOUND.as_millis())
                    .map_err(|_| refused("IntentDeadlineOverflow"))?;
                pending.eligible = time;
                pending.expires = time
                    .checked_add(bound)
                    .ok_or_else(|| refused("IntentDeadlineOverflow"))?;
            } else {
                pending.terminal = true;
            }
            self.persist(next)?;
        }
        Ok(())
    }

    /// At mount or explicit recovery, retire a handshake at its persisted expiry.
    /// Keep its unanswered evidence and restore any retained fence. The
    /// zero-tick, never-dispatched consent marker has no horizon yet.
    pub(crate) fn settle_expired_handshake(
        &mut self,
        clock: &impl Clock,
    ) -> Result<(), CoordinationError> {
        self.check()?;
        if self.carrier.phase != Phase::Handshake {
            return Ok(());
        }
        let time = now(clock)?;
        let Some(index) = self.carrier.pending.iter().position(|pending| {
            pending.operation == Operation::Ownership
                && !pending.terminal
                && !is_unstarted_takeover(pending)
                && time >= pending.expires
        }) else {
            return Ok(());
        };
        let mut next = self.carrier.clone();
        let pending = next
            .pending
            .get_mut(index)
            .ok_or_else(|| refused("IntentRequestNotRetained"))?;
        pending.terminal = true;
        next.phase = failed_handshake_phase(next.fence);
        self.persist(next)
    }

    /// Settle an expired landed refresh from one authenticated intent row.
    /// Only the exact refresh or exact retained pre-refresh tuple is evidence.
    pub(crate) fn settle_expired_landed_replay(
        &mut self,
        replay: &LandedReplay,
        row: Option<&intent::ReadbackRow<'_>>,
        clock: &impl Clock,
    ) -> Result<(), CoordinationError> {
        self.check()?;
        let index = self.locate(replay.request())?;
        let pending = self
            .carrier
            .pending
            .get(index)
            .ok_or_else(|| refused("IntentRequestNotRetained"))?;
        if now(clock)? < pending.expires {
            return Err(refused("IntentReplayPending"));
        }
        let sent =
            intent::decode_register(replay.request().bytes(), &self.config.volume, |_, _| true)
                .map_err(|_| refused("IntentLandedReplayInvalid"))?;
        let current = intent::decode_receipt(&self.carrier.current)
            .map_err(|_| refused("IntentLandedReplayInvalid"))?;
        let exact_refresh = row.is_some_and(|row| {
            row.writer == sent.writer
                && row.epoch == sent.epoch
                && row.generation == sent.generation
                && row.root == sent.root
        });
        let exact_current = row.is_some_and(|row| {
            row.writer == current.writer
                && row.epoch == current.epoch
                && row.generation == current.generation
                && row.root == self.carrier.root
        });
        if !exact_refresh && !exact_current {
            return Err(refused("IntentExpiredRegisterUnresolved"));
        }
        let mut next = self.carrier.clone();
        let settled = next
            .pending
            .get_mut(index)
            .ok_or_else(|| refused("IntentRequestNotRetained"))?;
        settled.terminal = true;
        if exact_refresh {
            let receipt = Receipt {
                writer: sent.writer,
                epoch: sent.epoch,
                instance: sent.instance,
                generation: sent.generation,
                state: ReceiptState::Live {
                    prepared_root_id: sent.root_id(),
                },
            };
            let answer = intent::encode_receipt(receipt)
                .map_err(|_| refused("IntentLandedReplayInvalid"))?;
            settled.answered = true;
            settled.answer.clone_from(&answer);
            next.current = answer;
            next.root = sent.root.to_vec();
        }
        next.pending.retain(|pending| {
            !(pending.operation == Operation::Register
                && pending.terminal
                && pending.context.is_empty())
        });
        self.persist(next)
    }
    /// Retained unresolved bytes, including a prior process's ownership handshake.
    #[must_use]
    pub fn retained_requests(&self) -> Vec<PendingIntent> {
        self.carrier
            .pending
            .iter()
            .filter(|p| !p.terminal)
            .map(|p| self.pending(p.operation, p.body.clone()))
            .collect()
    }
    fn locate(&self, request: &PendingIntent) -> Result<usize, CoordinationError> {
        if request.scope != self.carrier.scope
            || request.volume != self.carrier.volume
            || request.process != self.config.instance
        {
            return Err(refused("IntentCompletionBinding"));
        }
        self.carrier
            .pending
            .iter()
            .position(|p| p.operation == request.operation && p.body == request.body)
            .ok_or_else(|| refused("IntentRequestNotRetained"))
    }
    /// Persist attempt/backoff evidence before yielding bytes to the transport.
    /// A retry before its wall-clock eligibility returns an unavailable refusal
    /// without spending an attempt.
    /// # Errors
    /// Fence, stale token, retired send, startup budget, `IntentRetryNotEligible`
    /// or deadline refusal.
    pub fn dispatch(
        &mut self,
        request: &PendingIntent,
        clock: &impl Clock,
    ) -> Result<(), CoordinationError> {
        self.dispatch_inner(request, clock, false)?
            .map_or(Ok(()), |_| Err(refused("IntentRetryNotEligible")))
    }

    /// Persist a landed replay's startup-budgeted dispatch.
    /// A retry before its wall-clock eligibility is refused without spending an attempt.
    ///
    /// # Errors
    /// As [`Self::dispatch`].
    #[doc(hidden)]
    pub fn dispatch_landed_replay(
        &mut self,
        request: &PendingIntent,
        clock: &impl Clock,
    ) -> Result<(), CoordinationError> {
        self.dispatch_inner(request, clock, true)?
            .map_or(Ok(()), |_| Err(refused("IntentRetryNotEligible")))
    }

    /// Check expiry, token binding and startup exhaustion before deferring an
    /// early retry. Deferral returns the remaining wall-clock milliseconds
    /// without emitting a failure or spending an attempt. A dispatch returns
    /// `None` after persisting the attempt.
    pub(crate) fn dispatch_inner(
        &mut self,
        request: &PendingIntent,
        clock: &impl Clock,
        landed_replay: bool,
    ) -> Result<Option<u64>, CoordinationError> {
        self.check()?;
        if request.operation == Operation::Register {
            let sent = intent::decode_register(&request.body, &self.config.volume, |_, _| true)
                .map_err(|_| refused("IntentRegister"))?;
            let current = intent::decode_receipt(&self.carrier.current)
                .map_err(|_| refused("IntentOwnershipPending"))?;
            if (sent.epoch, sent.instance) == (current.epoch, current.instance)
                && sent.generation <= current.generation
            {
                return Err(refused("IntentRequestRetired"));
            }
        }
        let index = self.locate(request)?;
        let p = self
            .carrier
            .pending
            .get(index)
            .ok_or_else(|| refused("IntentRequestNotRetained"))?;
        let time = now(clock)?;
        if p.terminal {
            return Err(refused("IntentRequestRetired"));
        }
        if time >= p.expires {
            return Err(refused("IntentRetryDeadline"));
        }
        if request.operation != Operation::Ownership {
            let r = intent::decode_receipt(&self.carrier.current)
                .map_err(|_| refused("IntentOwnershipPending"))?;
            let (epoch, instance) = if request.operation == Operation::Register {
                let p = intent::decode_register(&request.body, &self.config.volume, |_, _| true)
                    .map_err(|_| refused("IntentRegister"))?;
                (p.epoch, p.instance)
            } else {
                let p =
                    intent::decode_release(&request.body).map_err(|_| refused("IntentRelease"))?;
                (p.epoch, p.instance)
            };
            if (epoch, instance) != (r.epoch, r.instance) {
                return Err(refused("IntentTokenDisplaced"));
            }
        }
        let startup = (landed_replay || self.carrier.phase != Phase::Serving)
            && request.operation != Operation::Release;
        if startup && self.startup_attempts >= STARTUP_ATTEMPTS {
            return Err(refused("IntentStartupAttemptsExhausted"));
        }
        if time < p.eligible {
            return Ok(Some(p.eligible - time));
        }
        if startup {
            self.startup_attempts += 1;
        }
        let mut next = self.carrier.clone();
        let p = next
            .pending
            .get_mut(index)
            .ok_or_else(|| refused("IntentRequestNotRetained"))?;
        p.eligible = time;
        p.attempts = p
            .attempts
            .checked_add(1)
            .ok_or_else(|| refused("IntentAttemptsExhausted"))?;
        self.persist(next)?;
        overlay_store::point(&self.faults, "intent.send", "before", self.carrier.sent)?;
        Ok(None)
    }

    /// Judge exact retained bytes, persist evidence, then permit local reliance.
    /// An absent answer to an unconsented Released takeover settles a nonterminal
    /// handshake to `Unowned` or leaves an expiry-settled carrier unchanged when
    /// the carrier is unfenced and has no other pending work.
    /// Other owned-request absence fences.
    /// `retry_after_ms` has already been interpreted against the caller's wall clock.
    /// `elapsed` is a caller-measured monotonic exchange sample; `None` counts
    /// the exchange without inventing a duration. Repeated completion of one
    /// dispatched attempt does not record the sample twice.
    /// # Errors
    /// Terminal refusal, fencing, disagreement, stale completion or persistence.
    pub fn complete(
        &mut self,
        request: &PendingIntent,
        response: Result<&IntentReply, IntentTransportError>,
        clock: &impl Clock,
        rng: &mut impl Rng,
        retry_after_ms: u64,
        elapsed: Option<Duration>,
    ) -> Result<IntentCompletion, CoordinationError> {
        self.complete_reported(request, response, clock, rng, retry_after_ms, elapsed)
            .map_err(|(error, _)| error)
    }

    /// The flag reports whether this completion emitted its `op.failed` event.
    pub(crate) fn complete_reported(
        &mut self,
        request: &PendingIntent,
        response: Result<&IntentReply, IntentTransportError>,
        clock: &impl Clock,
        rng: &mut impl Rng,
        retry_after_ms: u64,
        elapsed: Option<Duration>,
    ) -> Result<IntentCompletion, (CoordinationError, bool)> {
        self.complete_reported_inner(
            request,
            response,
            clock,
            rng,
            retry_after_ms,
            elapsed,
            false,
        )
    }

    /// Complete a landed replay while deferring expiry to startup readback.
    ///
    /// # Errors
    /// As [`Self::complete`].
    #[doc(hidden)]
    pub fn complete_landed_replay(
        &mut self,
        request: &PendingIntent,
        response: Result<&IntentReply, IntentTransportError>,
        clock: &impl Clock,
        rng: &mut impl Rng,
        retry_after_ms: u64,
        elapsed: Option<Duration>,
    ) -> Result<IntentCompletion, CoordinationError> {
        self.complete_reported_inner(request, response, clock, rng, retry_after_ms, elapsed, true)
            .map_err(|(error, _)| error)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "completion carries the retained request, transport, deterministic seams, measurement and local-effect mode"
    )]
    fn complete_reported_inner(
        &mut self,
        request: &PendingIntent,
        response: Result<&IntentReply, IntentTransportError>,
        clock: &impl Clock,
        rng: &mut impl Rng,
        retry_after_ms: u64,
        elapsed: Option<Duration>,
        defer_local: bool,
    ) -> Result<IntentCompletion, (CoordinationError, bool)> {
        let unknown = response.as_ref().map_or_else(
            |error| {
                matches!(
                    error,
                    IntentTransportError::Transport | IntentTransportError::Deadline
                )
            },
            |reply| reply.status >= 500 || reply.status == 429,
        );
        let attempt = self
            .locate(request)
            .ok()
            .and_then(|index| self.carrier.pending.get(index))
            .map_or(0, |pending| pending.attempts);
        let key = granary_core::hash::GrainId::of(request.bytes());
        let fresh_sample = attempt > self.measured_attempts.get(&key).copied().unwrap_or(0);
        let result =
            match self.complete_inner(request, response, clock, rng, retry_after_ms, defer_local) {
                Ok(Ok(completion)) => Ok(completion),
                Ok(Err(error)) => Err((error, true)),
                Err(error) => Err((error, false)),
            };
        if request.operation == Operation::Register
            && fresh_sample
            && let Some(metrics) = &self.metrics
        {
            self.measured_attempts.insert(key, attempt);
            metrics.record_registration_sample(
                if matches!(&result, Ok(IntentCompletion::Unknown))
                    || (unknown
                        && matches!(
                            &result,
                            Err((CoordinationError::Refused("IntentRetryDeadline"), _))
                        ))
                {
                    RegistrationResult::Unknown
                } else if result.is_ok() {
                    RegistrationResult::Ok
                } else {
                    RegistrationResult::Failed
                },
                elapsed,
            );
        }
        retain_measurements(
            &self.carrier.pending,
            &mut self.measured_attempts,
            granary_core::hash::GrainId::of,
        );
        result
    }

    /// Outer errors emit nothing; inner errors are judged failures already emitted.
    /// For ownership and Release, a backend disagreement or a refusal of a
    /// replay keeps the request unresolved, and an unresolved handshake stays
    /// in `Handshake`. Validated absence settles an unconsented Released
    /// takeover only when its unfenced carrier owes nothing.
    #[expect(
        clippy::too_many_lines,
        reason = "one durable judged completion transaction"
    )]
    fn complete_inner(
        &mut self,
        request: &PendingIntent,
        response: Result<&IntentReply, IntentTransportError>,
        clock: &impl Clock,
        rng: &mut impl Rng,
        retry_after_ms: u64,
        defer_local: bool,
    ) -> Result<Result<IntentCompletion, CoordinationError>, CoordinationError> {
        self.check()?;
        if response
            .as_ref()
            .is_ok_and(|reply| !reply.matches_scope(&self.carrier.scope, &self.carrier.volume))
        {
            return Err(refused("IntentCompletionBinding"));
        }
        // A reclaimed registration can still carry authenticated displacement
        // evidence. The private request binding and current owner are checked
        // below; no other outcome may rely on a reclaimed slot.
        let index = match self.locate(request) {
            Ok(index) => index,
            Err(CoordinationError::Refused("IntentRequestNotRetained"))
                if request.operation == Operation::Register =>
            {
                self.carrier.pending.len()
            }
            Err(error) => return Err(error),
        };
        overlay_store::point(&self.faults, "intent.reply", "before", self.carrier.sent)?;
        let mut next = self.carrier.clone();
        let p = next.pending.get(index);
        if p.is_some_and(|p| p.attempts == 0) {
            return Err(refused("IntentAttemptNotStarted"));
        }
        let mut grant = None;
        let verdict = match response {
            Err(_) => Verdict::Unknown(intent::UnknownCause::Other(0)),
            Ok(reply) => match request.operation {
                Operation::Ownership => match reply
                    .ownership(&request.body)
                    .map_err(|_| refused("IntentOwnershipRequest"))?
                {
                    Verdict::Accepted(g) => {
                        grant = Some(g);
                        Verdict::Accepted(g.receipt)
                    }
                    other => ownership_verdict(other),
                },
                Operation::Register => {
                    let r =
                        intent::decode_register(&request.body, &self.config.volume, |_, _| true)
                            .map_err(|_| refused("IntentRegister"))?;
                    reply.registration(&intent::RegisterRequest {
                        writer: r.writer,
                        epoch: r.epoch,
                        instance: r.instance,
                        generation: r.generation,
                        root_id: r.root_id(),
                    })
                }
                Operation::Release => {
                    let r = intent::decode_release(&request.body)
                        .map_err(|_| refused("IntentRelease"))?;
                    reply.release(&intent::ReleaseRequest {
                        writer: r.writer,
                        epoch: r.epoch,
                        instance: r.instance,
                        generation: r.generation,
                    })
                }
            },
        };
        // Retirement is a send decision. A valid current-owner displacement
        // still fences when its reply arrives after a higher generation proof.
        if p.is_none() && !matches!(verdict, Verdict::Superseded(_) | Verdict::Absent) {
            return Err(refused("IntentRequestNotRetained"));
        }
        if p.is_some_and(|p| p.terminal)
            && !matches!(verdict, Verdict::Superseded(_) | Verdict::Absent)
        {
            return Err(refused("IntentRequestRetired"));
        }
        if request.operation != Operation::Ownership {
            let current = intent::decode_receipt(&self.carrier.current)
                .map_err(|_| refused("IntentOwnershipPending"))?;
            let (epoch, instance) = match request.operation {
                Operation::Register => {
                    let sent =
                        intent::decode_register(&request.body, &self.config.volume, |_, _| true)
                            .map_err(|_| refused("IntentRegister"))?;
                    (sent.epoch, sent.instance)
                }
                Operation::Release => {
                    let sent = intent::decode_release(&request.body)
                        .map_err(|_| refused("IntentRelease"))?;
                    (sent.epoch, sent.instance)
                }
                Operation::Ownership => return Err(refused("IntentVerdictMismatch")),
            };
            if (epoch, instance) != (current.epoch, current.instance) {
                return Err(refused("IntentCompletionOwner"));
            }
        }
        if verdict.resend() != Resend::Never {
            let time = now(clock)?;
            let attempts = p
                .ok_or_else(|| refused("IntentRequestNotRetained"))?
                .attempts
                .min(6);
            let delay = (100u64
                .checked_shl(attempts.saturating_sub(1))
                .unwrap_or(5000))
            .min(5000)
                + rng.below(101);
            let eligible = time
                .checked_add(delay.max(retry_after_ms))
                .ok_or_else(|| refused("IntentDeadlineOverflow"))?;
            let p = next
                .pending
                .get_mut(index)
                .ok_or_else(|| refused("IntentRequestNotRetained"))?;
            if eligible >= p.expires {
                if !defer_local {
                    return Err(refused("IntentRetryDeadline"));
                }
                p.eligible = p.expires;
                self.persist(next)?;
                return Ok(Ok(IntentCompletion::Unknown));
            }
            p.eligible = eligible;
            self.persist(next)?;
            observe::op_retry(
                if request.operation == Operation::Release {
                    OperationKind::Unmount
                } else {
                    OperationKind::IntentRegister
                },
                self.carrier.pending.get(index).map_or(0, |p| p.attempts),
                RetryReason::Transient,
            );
            return Ok(Ok(IntentCompletion::Unknown));
        }
        // A refusal cannot settle an earlier dispatch. A backend
        // disagreement cannot settle even the first dispatch.
        let keep_unresolved =
            matches!(request.operation, Operation::Ownership | Operation::Release)
                && match verdict {
                    Verdict::Backend(_) => true,
                    Verdict::NotImplemented | Verdict::Refused(_) => {
                        p.is_some_and(|p| p.attempts > 1)
                    }
                    _ => false,
                };
        let settle_absent = matches!(verdict, Verdict::Absent)
            && request.operation == Operation::Ownership
            && intent::decode_ownership(&request.body).is_ok_and(|request| {
                matches!(
                    request.mode,
                    OwnershipMode::Takeover {
                        state: ReceiptState::Released,
                        recovery_ack: false,
                        ..
                    }
                )
            })
            && next.fence == 0
            && p.is_some_and(|pending| match next.phase {
                Phase::Handshake => !pending.terminal,
                Phase::Unowned => pending.terminal && !pending.answered,
                _ => false,
            })
            && next
                .pending
                .iter()
                .enumerate()
                .all(|(other, pending)| other == index || pending.terminal)
            && self.landed_replay().is_ok_and(|replay| replay.is_none())
            && self.owes_nothing();
        if settle_absent && next.phase == Phase::Unowned {
            // Expiry already settled the handshake and preserved its unanswered evidence.
            return Ok(Ok(IntentCompletion::TakeoverAbsent));
        }
        if !keep_unresolved && let Some(completed) = next.pending.get_mut(index) {
            completed.terminal = true;
            completed.answered = true;
        }
        let mut result = Ok(());
        let mut completion = IntentCompletion::Unknown;
        let overtaken = matches!(&verdict, Verdict::Overtaken(_));
        match verdict {
            Verdict::Accepted(receipt) | Verdict::Overtaken(receipt) => {
                completion = if overtaken {
                    IntentCompletion::Overtaken(receipt)
                } else {
                    IntentCompletion::Accepted(receipt)
                };
                let bytes =
                    intent::encode_receipt(receipt).map_err(|_| refused("IntentReceipt"))?;
                next.pending
                    .get_mut(index)
                    .ok_or_else(|| refused("IntentRequestNotRetained"))?
                    .answer
                    .clone_from(&bytes);
                if let Some(g) = grant {
                    next.handshake.clone_from(&request.body);
                    next.grant = intent::encode_grant(g).map_err(|_| refused("IntentGrant"))?;
                    next.instance = receipt.instance;
                    next.current = bytes;
                    next.root.clone_from(&next.selected_root);
                    if receipt.state == ReceiptState::Released {
                        next.root.clear();
                    }
                    // A conditional transfer binds the complete selected receipt. Old
                    // registrations remain evidence, but may never send under the new owner.
                    if matches!(
                        intent::decode_ownership(&request.body).map(|request| request.mode),
                        Ok(OwnershipMode::Takeover { .. })
                    ) {
                        for pending in &mut next.pending {
                            if pending.operation == Operation::Register {
                                pending.terminal = true;
                            }
                        }
                    }
                    // Reclaim the Release slot in the same revision as the new grant.
                    next.pending.retain(|p| {
                        !(p.operation == Operation::Release
                            && p.terminal
                            && intent::decode_release(&p.body)
                                .is_ok_and(|r| r.epoch < receipt.epoch))
                    });
                    next.fence = 0;
                    next.fence_evidence.clear();
                    next.phase = Phase::OwnedStart;
                } else {
                    let current = intent::decode_receipt(&next.current)
                        .map_err(|_| refused("IntentOwnershipPending"))?;
                    if (receipt.epoch, receipt.instance) != (current.epoch, current.instance) {
                        return Err(refused("IntentCompletionOwner"));
                    }
                    if receipt.generation >= current.generation {
                        if let ReceiptState::Live { prepared_root_id } = receipt.state {
                            let covering = next
                                .pending
                                .iter()
                                .find_map(|p| {
                                    if p.operation != Operation::Register {
                                        return None;
                                    }
                                    intent::decode_register(&p.body, &self.config.volume, |_, _| {
                                        true
                                    })
                                    .ok()
                                    .filter(|r| {
                                        r.generation == receipt.generation
                                            && r.root_id() == prepared_root_id
                                    })
                                    .map(|r| r.root.to_vec())
                                })
                                .ok_or_else(|| refused("IntentCoveringRootUnknown"))?;
                            next.root = covering;
                        } else {
                            next.root.clear();
                        }
                        next.current.clone_from(&bytes);
                    }
                    for p in &mut next.pending {
                        if p.operation == Operation::Register
                            && !p.answered
                            && p.generation()? <= receipt.generation
                        {
                            p.terminal = true;
                            p.answer.clone_from(&bytes);
                        }
                    }
                    if request.operation == Operation::Release {
                        next.phase = Phase::Released;
                    }
                }
            }
            Verdict::Superseded(receipt) => {
                next.phase = Phase::Fenced;
                next.fence = 1;
                next.fence_evidence =
                    intent::encode_receipt(receipt).map_err(|_| refused("IntentFenceReceipt"))?;
                result = Err(CoordinationError::Fenced {
                    recorded_generation: Some(receipt.generation),
                });
            }
            Verdict::Absent if settle_absent => {
                next.phase = Phase::Unowned;
                completion = IntentCompletion::TakeoverAbsent;
            }
            Verdict::Absent => {
                next.phase = Phase::Fenced;
                next.fence = 2;
                next.fence_evidence.clear();
                result = Err(CoordinationError::Fenced {
                    recorded_generation: None,
                });
            }
            Verdict::NotImplemented => result = Err(refused("IntentNotImplemented")),
            Verdict::Refused(intent::Refusal::UnknownVolume) => {
                result = Err(refused("IntentUnknownVolume"));
            }
            Verdict::Changed(_) => result = Err(refused("IntentSelectionChanged")),
            Verdict::CursorChanged => {
                next.phase = Phase::Unowned;
                result = Err(refused("IntentCursorChanged"));
            }
            Verdict::EpochExhausted => result = Err(refused("IntentEpochExhausted")),
            Verdict::OverQuota => result = Err(refused("IntentOverQuota")),
            Verdict::Bound(_) => result = Err(refused("IntentBound")),
            Verdict::Backend(_) => result = Err(refused("IntentBackendDisagreement")),
            Verdict::Refused(reason) if request.operation == Operation::Register => {
                result = Err(CoordinationError::SyncRefusal(match reason {
                    intent::Refusal::NoPrincipal | intent::Refusal::NotEnrolled => {
                        SyncRefusalKind::Authorization
                    }
                    _ => SyncRefusalKind::Other,
                }));
            }
            Verdict::Refused(_) => result = Err(refused("IntentTerminalRefusal")),
            Verdict::RateLimited | Verdict::EnrollmentUnavailable | Verdict::Unknown(_) => {
                return Err(refused("IntentVerdictMismatch"));
            }
        }
        if result.is_err()
            && next.phase == Phase::Handshake
            && request.operation == Operation::Ownership
            && !keep_unresolved
        {
            next.phase = failed_handshake_phase(next.fence);
        }
        if next.phase == Phase::Fenced {
            // Keep dispatched, unanswered unconsented takeovers as terminal
            // evidence. Retire answered or never-dispatched ones.
            next.pending.retain_mut(|pending| {
                if pending.operation == Operation::Ownership
                    && matches!(
                        intent::decode_ownership(&pending.body).map(|ownership| ownership.mode),
                        Ok(OwnershipMode::Takeover {
                            recovery_ack: false,
                            ..
                        })
                    )
                {
                    if pending.answered || pending.attempts == 0 {
                        return false;
                    }
                    pending.terminal = true;
                }
                true
            });
        }
        // Contexts retain the exact receipts needed by captured callers. Other
        // terminal registrations no longer consume pipeline slots, whether
        // answered directly or retired by a covering receipt.
        next.pending.retain(|p| {
            !(p.operation == Operation::Register && p.terminal && p.context.is_empty())
        });
        let fenced = next.phase == Phase::Fenced;
        let persisted = (|| -> Result<(), CoordinationError> {
            overlay_store::point(&self.faults, "intent.evidence", "before", next.sent)?;
            overlay_store::point(
                &self.faults,
                if fenced {
                    "intent.fence"
                } else {
                    "intent.retire"
                },
                "before",
                next.sent,
            )?;
            self.persist(next)?;
            overlay_store::point(
                &self.faults,
                if fenced {
                    "intent.fence"
                } else {
                    "intent.retire"
                },
                "after",
                self.carrier.sent,
            )?;
            Ok(())
        })();
        if fenced && persisted.is_err() {
            self.poisoned = true;
        }
        persisted?;
        overlay_store::point(&self.faults, "intent.evidence", "after", self.carrier.sent)?;
        if !defer_local && request.operation == Operation::Register && result.is_ok() {
            let r = intent::decode_receipt(&self.carrier.current)
                .map_err(|_| refused("IntentReceipt"))?;
            if let ReceiptState::Live { prepared_root_id } = r.state {
                let permission = self.permission()?;
                let landed_refresh = self.commit_lane.is_some()
                    && self.stored_landing(&self.carrier.root.clone())?.is_some();
                let overlay = self
                    .overlay
                    .as_mut()
                    .ok_or_else(|| refused("IntentReplayPending"))?;
                if self.capture_queue.is_empty()
                    && !self.carrier.pending.iter().any(|p| !p.context.is_empty())
                    && !landed_refresh
                {
                    let result = overlay.record_intent_registered(
                        &mut self.store,
                        &permission,
                        r.generation,
                        prepared_root_id,
                        granary_core::overlay_journal::IntentCause::DirectorySync,
                    );
                    self.retain_overlay_bundle(result.as_ref().err());
                    result?;
                }
                if self
                    .overlay
                    .as_ref()
                    .is_some_and(|overlay| overlay.readiness() == OverlayReadiness::Ready)
                    && r.instance == self.config.instance
                {
                    let record = self
                        .store
                        .publications(self.config.euid)?
                        .load(&self.config.scope, &self.config.volume)?;
                    if self.carrier.phase == Phase::OwnedStart
                        && record.is_none_or(|r| {
                            r.is_complete() || crate::sync::terminal_non_landing(&r)
                        })
                    {
                        let mut next = self.carrier.clone();
                        next.phase = Phase::Serving;
                        self.persist(next)?;
                    }
                }
            }
        }
        if result.is_err() {
            observe::op_failed(
                if request.operation == Operation::Release {
                    OperationKind::Unmount
                } else {
                    OperationKind::IntentRegister
                },
                if matches!(result, Err(CoordinationError::Fenced { .. })) {
                    FailureClass::Conflict
                } else {
                    FailureClass::Refused
                },
            );
        }
        Ok(result.map(|()| completion))
    }

    /// Explicit acknowledgement seals the imported writer primitive.
    /// # Errors
    /// Missing selected receipt or incomplete bound consent.
    pub fn selected_writer(&self) -> Result<SelectedWriter, CoordinationError> {
        Ok(SelectedWriter::acknowledged(&self.carrier)?)
    }
}

fn ownership_verdict(v: Verdict<intent::Grant>) -> Verdict<Receipt> {
    match v {
        Verdict::Accepted(g) => Verdict::Accepted(g.receipt),
        Verdict::Superseded(r) => Verdict::Superseded(r),
        Verdict::Bound(r) => Verdict::Bound(r),
        Verdict::Overtaken(r) => Verdict::Overtaken(r),
        Verdict::Changed(r) => Verdict::Changed(r),
        Verdict::Absent => Verdict::Absent,
        Verdict::CursorChanged => Verdict::CursorChanged,
        Verdict::EpochExhausted => Verdict::EpochExhausted,
        Verdict::OverQuota => Verdict::OverQuota,
        Verdict::Refused(r) => Verdict::Refused(r),
        Verdict::RateLimited => Verdict::RateLimited,
        Verdict::NotImplemented => Verdict::NotImplemented,
        Verdict::EnrollmentUnavailable => Verdict::EnrollmentUnavailable,
        Verdict::Unknown(c) => Verdict::Unknown(c),
        Verdict::Backend(d) => Verdict::Backend(d),
    }
}

// Hash each pending body once, independently of the number of retained samples.
fn retain_measurements(
    pending: &[Pending],
    measured: &mut std::collections::BTreeMap<granary_core::hash::GrainId, u32>,
    mut digest: impl FnMut(&[u8]) -> granary_core::hash::GrainId,
) {
    let pending_ids: std::collections::BTreeSet<_> = pending
        .iter()
        .map(|pending| digest(&pending.body))
        .collect();
    measured.retain(|id, _| pending_ids.contains(id));
}

#[cfg(test)]
mod round1_tests {
    use super::*;

    #[test]
    fn landed_publication_errors_preserve_unavailable_and_fail_closed_otherwise() {
        let error = |kind| PublicationStoreError {
            path: std::path::PathBuf::from("publication"),
            reason: "injected".to_owned(),
            kind,
        };
        let unavailable =
            landed_publication_error(error(crate::PublicationStoreErrorKind::Unavailable));
        let io = landed_publication_error(error(crate::PublicationStoreErrorKind::Io));
        let malformed = landed_publication_error(error(crate::PublicationStoreErrorKind::Refused));
        assert_eq!(
            (
                matches!(
                    unavailable,
                    CoordinationError::Publication(PublicationStoreError {
                        kind: crate::PublicationStoreErrorKind::Unavailable,
                        ..
                    })
                ),
                matches!(
                    &io,
                    CoordinationError::Publication(PublicationStoreError {
                        kind: crate::PublicationStoreErrorKind::Io,
                        ..
                    })
                ),
                crate::writable_start::coordination_class(&io),
                malformed.to_string(),
                3,
            ),
            (
                true,
                true,
                FailureClass::Io,
                "intent refused: IntentLandedReplayInvalid".to_owned(),
                3,
            ),
            "transient publication failure must retain its class while malformed facts fail closed"
        );
    }

    #[test]
    fn coordination_measurement_cleanup_hashes_each_body_once() {
        let pending: Vec<_> = (0..8)
            .map(|n| Pending {
                operation: Operation::Register,
                body: vec![n],
                context: vec![],
                first: 0,
                expires: 1,
                eligible: 0,
                attempts: 1,
                terminal: false,
                answered: false,
                answer: vec![],
            })
            .collect();
        let mut measured = (0..16)
            .map(|n| (granary_core::hash::GrainId::of(&[n]), 1))
            .collect();
        let mut hashes = 0;
        retain_measurements(&pending, &mut measured, |body| {
            hashes += 1;
            granary_core::hash::GrainId::of(body)
        });
        assert_eq!(hashes, pending.len(), "linear pending-body hashing");
        assert_eq!(
            measured.len(),
            pending.len(),
            "only live measurement identities"
        );
    }
}
