// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Non-evictable overlay component. Transactions borrow the mediator's Store;
//! ownership permission and verified remote evidence are supplied by its caller.

mod accounting;
mod bundle;
mod commit;
mod fault;
mod io;
pub(crate) mod local_content;
mod projection;
mod provenance;
mod query;
mod recovery;
mod replacement;
pub(crate) use replacement::{RecoveredSuffix, RecoveryPrefix};
mod residual;
mod residual_inventory;
mod residual_validation;
mod snapshot;
mod state;
#[cfg(test)]
pub(crate) mod tests;
mod unmerged;
pub(crate) use unmerged::validate_payload as validate_unmerged_payload;
pub(crate) mod verified_range;

use crate::{observe, store::Store};
#[cfg(any(test, feature = "overlay-fault-tests"))]
pub use fault::RenameDirectoryFaultContext;
pub use fault::{FaultAction, FaultControl, FaultEvent, SyncFaultEvent};
use granary_core::hash::GrainId;
use granary_core::manifest::{self, EntryKind, Name, SymlinkTarget};
use granary_core::overlay_journal::{
    self as codec, JournalHeader, JournalState, MarkState, Record, StagingHeader, SyncedMark,
    WriterRecord,
};
use granary_core::retained_submission::Scope;
use granary_core::root::VolumeName;
use granary_core::support::BundleRefusal;
pub use io::{OverlayDisk, OverlayIo};
#[doc(hidden)]
pub use io::{UnmergedEntry, UnmergedInventory};
pub use projection::{DurableFile, PreparedProjection};
pub use provenance::NamespaceEffect;
pub use query::{
    OVERLAY_PAGE_ROWS, OverlayCursor, OverlayDirectoryQuery, OverlayPage, OverlayQuery,
    OverlayQueryEntry,
};
pub(crate) use recovery::{LandedJournal, journal_condition, landed_commits, settle_area};
pub use replacement::ReplacementPlan;
pub(crate) use replacement::scan_clean;
pub(crate) use residual::{ResidualAnchors, ResidualSnapshot};
pub(crate) use residual_inventory::{
    RESIDUAL_PREFLIGHT_WORKSPACE_BYTES, ResidualInventory, inventory,
};
pub(crate) use residual_validation::validate_residual_sources;
pub(crate) use snapshot::ShutdownWork;
pub use snapshot::{CapturedFile, CapturedPart, CapturedRange, SyncBoundary, SyncTarget};
use state::Namespace;

#[cfg(test)]
pub(crate) mod work;

#[cfg(test)]
pub(crate) fn measure_query<T>(action: impl FnOnce() -> T) -> (T, (usize, usize, usize)) {
    let (answer, query, _) = work::measure(action);
    (
        answer,
        (
            query.namespace_copies,
            query.primary_visits,
            query.entry_copies,
        ),
    )
}
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(crate) fn area_path(
    root: &Path,
    scope: &Scope,
    volume: &VolumeName,
) -> Result<PathBuf, OverlayError> {
    let digest = scope.digest().map_err(|_| OverlayError::refused("scope"))?;
    Ok(root.join("overlay").join(digest).join(volume.as_str()))
}

const BUFFER: usize = 65536;
const MAX_REBIND: u64 = 4577;
/// A parent's greatest legal encoding: its depth, a length byte for each of
/// 128 names and 4096 name bytes.
const MAX_PARENT: u64 = 4226;
/// A recreate's two optional-field tags make its greatest frame two bytes
/// longer than a rebind's.
const MAX_RECREATE: u64 = MAX_REBIND + 2;

#[derive(Debug)]
pub enum OverlayError {
    Conflict,
    PendingReconciliation,
    ContentUnavailable,
    ContentCorrupt,
    CaptureCoverageLost,
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    InjectedCrash,
    PendingShrink,
    PendingBoundary,
    /// The mount's shutdown has closed it to user mutations.
    MutationsClosed,
    Poisoned,
    NoSpace,
    Refused(&'static str),
    Io(std::io::Error),
}
impl std::fmt::Display for OverlayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict => f.write_str("overlay namespace conflict"),
            #[cfg(any(test, feature = "overlay-fault-tests"))]
            Self::InjectedCrash => f.write_str("overlay simulated crash"),
            Self::PendingReconciliation => f.write_str("overlay pending ownership reconciliation"),
            Self::CaptureCoverageLost => f.write_str("capture coverage lost (EIO)"),
            Self::ContentUnavailable => f.write_str("overlay recovery awaits verified content"),
            Self::ContentCorrupt => f.write_str("overlay content authentication failed"),
            Self::PendingShrink => f.write_str("overlay shrink awaits captured sync"),
            Self::PendingBoundary => {
                f.write_str("overlay boundary awaits detached handles or captures")
            }
            Self::MutationsClosed => f.write_str("overlay closed to mutations (EROFS)"),
            Self::Poisoned => f.write_str("overlay persistence poisoned"),
            Self::NoSpace => f.write_str("overlay cap exhausted (ENOSPC)"),
            Self::Refused(reason) => write!(f, "overlay refused: {reason}"),
            Self::Io(e) => write!(f, "overlay I/O: {e}"),
        }
    }
}
impl std::error::Error for OverlayError {}
impl OverlayError {
    pub(crate) fn no_space() -> Self {
        observe::op_failed(
            observe::OperationKind::OverlayWrite,
            observe::FailureClass::Refused,
        );
        Self::NoSpace
    }
    pub(crate) fn poisoned() -> Self {
        observe::op_failed(
            observe::OperationKind::OverlayWrite,
            observe::FailureClass::Io,
        );
        Self::Poisoned
    }
    pub(crate) fn refused(reason: &'static str) -> Self {
        observe::op_failed(
            observe::OperationKind::OverlayWrite,
            observe::FailureClass::Refused,
        );
        Self::Refused(reason)
    }
}
impl From<std::io::Error> for OverlayError {
    fn from(e: std::io::Error) -> Self {
        observe::op_failed(
            observe::OperationKind::OverlayWrite,
            observe::FailureClass::Io,
        );
        Self::Io(e)
    }
}

/// Permission is produced by the ownership layer, never by this component.
/// Durable asserts that the canonical carrier and initial prepared start gate
/// were validated/persisted for this exact scope, volume and writer.
#[derive(Debug, Clone)]
pub enum OwnershipStatus {
    PendingReconciliation,
    /// Durable canonical grant; only replay and control reservation are permitted.
    Owned(OwnershipPermission),
    /// Completed replay and persisted initial registration under the fresh token.
    Durable(OwnershipPermission),
}

/// Binding sealed by the ownership mediator; application callers cannot mint readiness.
#[derive(Debug, Clone)]
pub struct OwnershipPermission {
    scope: String,
    volume: VolumeName,
    writer: [u8; 16],
    high_water: u64,
}
impl OwnershipPermission {
    pub(crate) fn new(
        scope: String,
        volume: VolumeName,
        writer: [u8; 16],
        high_water: u64,
    ) -> Self {
        Self {
            scope,
            volume,
            writer,
            high_water,
        }
    }
}

/// Recovery selection sealed by the coordinator's bound acknowledgement.
#[derive(Debug, Clone)]
pub struct SelectedWriter {
    scope: String,
    volume: VolumeName,
    writer: [u8; 16],
    ceiling: u64,
}
impl SelectedWriter {
    pub(crate) fn acknowledged(
        carrier: &granary_core::overlay_ownership::Carrier,
    ) -> Result<Self, OverlayError> {
        carrier
            .validate()
            .map_err(|_| OverlayError::refused("selected ownership"))?;
        if carrier.consent.is_empty()
            || !carrier.pending.iter().any(|p| {
                p.operation == granary_core::overlay_ownership::Operation::Ownership
                    && matches!(
                        granary_core::intent::decode_ownership(&p.body),
                        Ok(granary_core::intent::Ownership {
                            mode: granary_core::intent::OwnershipMode::Takeover {
                                recovery_ack: true,
                                ..
                            },
                            ..
                        })
                    )
            })
        {
            return Err(OverlayError::refused("selected consent missing"));
        }
        let receipt = granary_core::intent::decode_receipt(&carrier.selected)
            .map_err(|_| OverlayError::refused("selected receipt"))?;
        Ok(Self {
            scope: carrier
                .scope
                .digest()
                .map_err(|_| OverlayError::refused("scope"))?,
            volume: carrier.volume.clone(),
            writer: receipt.writer,
            ceiling: receipt.generation,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayReadiness {
    PendingReconciliation,
    PendingRecovery,
    Ready,
    Poisoned,
}

#[derive(Debug, Clone)]
pub struct OverlayConfig {
    pub scope: Scope,
    pub volume: VolumeName,
    pub euid: u32,
    pub cap: u64,
    /// Worst-case replacement/completion bytes of the externally owned carrier.
    pub ownership_completion_reserve: u64,
    /// The mediator's fresh process identity, retained across transaction facades.
    pub instance: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayKind {
    File { content: Option<GrainId> },
    Directory,
    Symlink { target: SymlinkTarget },
}

impl OverlayKind {
    /// Overlay kind and file attributes for a supported manifest entry.
    pub(crate) fn from_manifest(kind: EntryKind) -> Option<(Self, u64, bool)> {
        match kind {
            EntryKind::Dir { .. } => Some((Self::Directory, 0, false)),
            EntryKind::File { size, exec, grains } => {
                let bytes = manifest::node::file_payload(size, &grains).ok()?;
                Some((
                    Self::File {
                        content: Some(GrainId::of(&bytes)),
                    },
                    size,
                    exec,
                ))
            }
            EntryKind::Symlink { target } => Some((Self::Symlink { target }, 0, false)),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(test), derive(Clone))]
pub struct OverlayEntry {
    pub path: Vec<Name>,
    pub inode: u64,
    pub kind: OverlayKind,
    pub stage_id: Option<u64>,
    pub size: u64,
    pub exec: bool,
}

#[cfg(test)]
impl Clone for OverlayEntry {
    fn clone(&self) -> Self {
        state::CLONED_ENTRY_VALUES.set(state::CLONED_ENTRY_VALUES.get() + 1);
        work::entry_copy();
        Self {
            path: self.path.clone(),
            inode: self.inode,
            kind: self.kind.clone(),
            stage_id: self.stage_id,
            size: self.size,
            exec: self.exec,
        }
    }
}

/// The provider authenticates the manifest/grain-list/grain chain under the
/// pinned content identity, using already local immutable data without network
/// work or reentrant store callbacks. The overlay checks exact range length;
/// it never substitutes bytes from an unavailable or malformed provider.
pub trait ContentSource {
    /// # Errors
    /// Returns `OverlayError::ContentUnavailable` for content awaiting local readback; refuses
    /// unauthenticated or malformed content. No network work occurs here.
    fn read_verified(
        &mut self,
        content: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError>;
}

#[derive(Debug, Clone)]
pub struct CaptureToken {
    id: u64,
    instance: [u8; 16],
    incarnation: u64,
    scope: String,
    volume: VolumeName,
    writer: [u8; 16],
    at_capture: Option<Vec<Name>>,
    stage_id: u64,
    size: u64,
    through_seq: u64,
    /// Immutable bytes shared with the engine; each allocation is bounded.
    chunks: std::sync::Arc<Vec<Vec<u8>>>,
}

impl CaptureToken {
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
    /// Journal incarnation paired with the stage number.
    #[must_use]
    pub fn incarnation(&self) -> u64 {
        self.incarnation
    }

    #[must_use]
    pub fn stage_id(&self) -> u64 {
        self.stage_id
    }
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }
    #[must_use]
    pub fn through_seq(&self) -> u64 {
        self.through_seq
    }
    #[must_use]
    pub fn chunks(&self) -> &[Vec<u8>] {
        &self.chunks
    }
    #[must_use]
    pub fn captured_path(&self) -> Option<&[Name]> {
        self.at_capture.as_deref()
    }
}

/// Sealed exact receipt/root/content binding for one captured request.
#[derive(Debug, Clone)]
pub struct RegisteredCapture {
    pub(crate) capture: CaptureToken,
    pub(crate) writer: [u8; 16],
    pub(crate) generation: u64,
    pub(crate) prepared_root: GrainId,
    pub(crate) content: GrainId,
}

/// A sealed commit prefix, moved between local transactions during preparation.
/// Candidate construction must use these entries and matching immutable captures.
#[derive(Debug, Clone)]
pub struct BoundaryCapture {
    header: JournalHeader,
    instance: [u8; 16],
    incarnation: u64,
    through_seq: u64,
    entries: Vec<OverlayEntry>,
}
impl BoundaryCapture {
    #[must_use]
    pub fn through_seq(&self) -> u64 {
        self.through_seq
    }
    #[must_use]
    pub fn entries(&self) -> &[OverlayEntry] {
        &self.entries
    }
}

/// Caller-verified landed root/tree, tied to the durable boundary and landing.
#[derive(Debug, Clone)]
pub struct LandedProof {
    pub boundary_seq: u64,
    pub landed_root: GrainId,
    pub landed_seq: u64,
    /// The sealed boundary's namespace, with immutable file content resolved
    /// from the retained frozen manifest before replacement; for a projected
    /// boundary, its projection.
    pub captured_entries: Vec<OverlayEntry>,
    pub entries: Vec<OverlayEntry>,
}

/// The identities a replacement did not carry from the view it replaced.
///
/// A path keeps its overlay inode only when its identity is unchanged:
/// the same kind discriminant, and the same stage, or a retired stage whose
/// captured version is what landed, or the same kind and exec bit.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ViewChange {
    /// Sorted by path: every new path given a fresh inode, and every old path
    /// absent from the new view whose ancestors are not listed themselves.
    pub paths: Vec<PathChange>,
    /// Each old inode the replacement did not carry, with its old entry,
    /// including every entry under a removed directory.
    pub retired: BTreeMap<u64, OverlayEntry>,
}

/// One path whose identity a replacement changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChange {
    pub path: Vec<Name>,
    /// The old view's inode at this path, if it had an entry there.
    pub old: Option<u64>,
    /// The fresh inode, or `None` where the new view has no entry here.
    pub new: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OverlaySummary {
    pub charged_bytes: u64,
    pub reserved_bytes: u64,
    pub orphan_bytes: u64,
    pub captured_bytes: u64,
    /// Retained record count; frame sequences are contiguous and start at one.
    pub records: u64,
    pub swept_files: u64,
    pub swept_bytes: u64,
    /// Stages whose last payload action on this replay was a rollback.
    pub rolled_back_stages: u64,
    /// Live extent bytes discarded by those rollbacks.
    pub rolled_back_bytes: u64,
    pub commit_requested: bool,
    /// What the measured total owes above the cap, with its reserve terms.
    pub owed: observe::OverlayOwed,
}

/// One live capacity observation without cloning namespace entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayObservation {
    /// Named entries, including the pinned root and excluding open orphans.
    pub namespace_len: u64,
    pub summary: OverlaySummary,
    pub cap: u64,
    /// Conservative room for new empty staged files, including journal reserves.
    pub free_entries: u64,
}

/// Opaque file observation included in the typed sweep report, never in logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepEntry {
    pub stage_id: u64,
    pub bytes: u64,
    pub modified: Option<(i64, i64)>,
}

#[derive(Debug, Clone)]
pub(crate) struct RecoveryStageRow {
    pub(crate) path: Option<Vec<Name>>,
    pub(crate) id: u64,
    pub(crate) size: u64,
}

/// What a recovered boundary's candidate holds: the whole prefix, or the
/// per-file projection of it with the sync's selection, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundarySelection {
    Tree,
    Projected(Option<codec::ProjectedSelection>),
}

/// Commit evidence admitted by replay; publication drives its resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryCommit {
    Boundary {
        index: u64,
        candidate: GrainId,
        through_seq: u64,
        publication_id: [u8; 16],
        selection: BoundarySelection,
    },
    Landed {
        index: u64,
        boundary_seq: u64,
        root: GrainId,
        seq: u64,
    },
}

#[derive(Debug)]
struct Journal {
    header: JournalHeader,
    state: JournalState,
    length: u64,
    incarnation: u64,
    completion: CompletionReserve,
}

#[derive(Debug, Default, Clone)]
struct CompletionReserve {
    commits: BTreeMap<u64, CompletionSlot>,
}
#[derive(Debug, Default, Clone)]
struct CompletionSlot {
    /// A projected boundary's cursor: its residual replacement is reserved.
    projected: Option<u64>,
    landed: Option<GrainId>,
    refreshed: bool,
    attempts: u64,
    fenced: bool,
}
impl CompletionReserve {
    fn fold(&mut self, index: u64, record: &Record) -> Result<(), OverlayError> {
        match record {
            Record::CommitBoundary { .. } => {
                self.commits.insert(index, CompletionSlot::default());
            }
            Record::ProjectedBoundary { through_seq, .. } => {
                self.commits.insert(
                    index,
                    CompletionSlot {
                        projected: Some(*through_seq),
                        ..CompletionSlot::default()
                    },
                );
            }
            Record::CommitAttempt {
                boundary_seq,
                attempt,
                ..
            } => {
                self.commits
                    .get_mut(boundary_seq)
                    .ok_or_else(|| OverlayError::refused("completion boundary"))?
                    .attempts = *attempt;
            }
            Record::CommitFence { boundary_seq, .. } => {
                self.commits
                    .get_mut(boundary_seq)
                    .ok_or_else(|| OverlayError::refused("completion boundary"))?
                    .fenced = true;
            }
            Record::LandedCommit {
                boundary_seq,
                landed_root,
                ..
            } => {
                self.commits
                    .get_mut(boundary_seq)
                    .ok_or_else(|| OverlayError::refused("completion boundary"))?
                    .landed = Some(*landed_root);
            }
            Record::IntentRegistered {
                prepared_root,
                cause: codec::IntentCause::LandedRefresh,
                ..
            } => {
                if let Some((_, slot)) = self
                    .commits
                    .iter_mut()
                    .rev()
                    .find(|(_, slot)| slot.landed == Some(*prepared_root) && !slot.refreshed)
                {
                    slot.refreshed = true;
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn slots(&self) -> u64 {
        (self.commits.len() as u64).max(1)
    }
    fn consumed(&self) -> u64 {
        self.commits
            .values()
            .map(|slot| {
                slot.attempts.min(8) * 154
                    + u64::from(slot.fenced) * 138
                    + if slot.landed.is_some() {
                        188 + u64::from(slot.refreshed) * 174
                    } else {
                        0
                    }
            })
            .sum()
    }
}

#[derive(Clone)]
pub(crate) struct CoalesceClock(
    pub(crate) std::sync::Arc<dyn Fn() -> tokio::time::Instant + Send + Sync>,
);
impl std::fmt::Debug for CoalesceClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CoalesceClock").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DirtySpan {
    pub(crate) first_seq: u64,
    pub(crate) last_seq: u64,
    pub(crate) first_at: Option<tokio::time::Instant>,
    pub(crate) last_at: Option<tokio::time::Instant>,
}

/// Owned state survives facade drops. The owner retains the sole Store flock.
#[derive(Debug)]
pub struct OverlayStore<P: OverlayIo = OverlayDisk> {
    io: accounting::Accounted<P>,
    root: PathBuf,
    area: PathBuf,
    config: OverlayConfig,
    scope: String,
    writer: WriterRecord,
    journal: Mutex<Journal>,
    query_incarnation: u64,
    namespace: Namespace,
    base: Vec<OverlayEntry>,
    readiness: OverlayReadiness,
    next_capture: u64,
    snapshots: BTreeMap<u64, u64>,
    versions: snapshot::Versions,
    history: provenance::History,
    flushed: std::collections::BTreeSet<u64>,
    summary: OverlaySummary,
    bundle_failure: Option<BundleRefusal>,
    faults: FaultControl,
    completion_credit: u64,
    replayed: bool,
    // Whether the overlay has served since its last replay, on open or during
    // recover(). A replacement installed before service repairs carried stages
    // from its checkpoint. This repair also runs after an in-process recover().
    // replace_landed() reads the checkpoint content from the local store and
    // fails closed if it is missing.
    served: bool,
    sweep_manifest: Vec<SweepEntry>,
    dirty_spans: Vec<DirtySpan>,
    last_boundary_seq: u64,
    dirty_split_seq: u64,
    /// The cursor of a projected seal whose lane has recorded no boundary
    /// yet; its residual replacement is reserved until the lane ends.
    projected_seal: Option<u64>,
    coalesce_clock: Option<CoalesceClock>,
    coalesce_wake: std::sync::Arc<tokio::sync::Notify>,
    /// A commit refused for room, while nothing that frees room has happened
    /// since: no handle closed, no landing installed, no room measured free.
    capacity_refused: Option<CapacityRefusal>,
    capacity_exhaustion: Option<CapacityExhaustion>,
}

/// The room left when a commit was refused for it, and when the coalescer
/// first saw the refusal.
#[derive(Clone, Copy, Debug)]
struct CapacityRefusal {
    headroom: i128,
    seen: Option<tokio::time::Instant>,
}

#[derive(Clone, Copy, Debug)]
struct CapacityExhaustion {
    cap: u64,
    charged: u64,
    reserved: u64,
    captured: u64,
    needed: u64,
}

/// One measurement against the cap: the area's charge, its unspent reserve,
/// the snapshot charge, and what their total owes above the cap.
#[derive(Clone, Copy)]
struct Measured {
    charged: u64,
    reserved: u64,
    captured: u64,
    owed: observe::OverlayOwed,
}

fn reserve_total(terms: &observe::OverlayOwed) -> Result<u64, OverlayError> {
    [
        terms.journal,
        terms.stages,
        terms.projected,
        terms.completion,
        terms.writer,
        terms.ownership,
    ]
    .into_iter()
    .try_fold(0u64, |a, b| {
        a.checked_add(b).ok_or_else(OverlayError::no_space)
    })
}

/// Bytes a commit lane reserves for the entries it carries; capture and
/// recovery must charge the same amount.
pub(crate) fn commit_graph_charge_of<'a>(
    entries: impl IntoIterator<Item = &'a OverlayEntry>,
) -> Option<u64> {
    entries.into_iter().try_fold(4096_u64, |total, entry| {
        let path = entry.path.iter().try_fold(0_u64, |bytes, name| {
            bytes.checked_add(name.as_bytes().len() as u64 + 64)
        })?;
        total.checked_add(path.checked_mul(4)?.checked_add(1024)?)
    })
}

impl<P: OverlayIo> OverlayStore<P> {
    pub(crate) fn recovery_stages(&self) -> Vec<RecoveryStageRow> {
        self.namespace
            .stages
            .iter()
            .map(|(id, stage)| RecoveryStageRow {
                path: stage.path.clone(),
                id: *id,
                size: stage.size,
            })
            .collect()
    }

    #[must_use]
    pub(crate) fn initial_state_ready(&self) -> bool {
        self.replayed
            && self.readiness == OverlayReadiness::Ready
            && self.namespace.entries.len() == self.base.len()
            && self.base.iter().all(|entry| {
                self.namespace
                    .entries
                    .get(&entry.path)
                    .is_some_and(|current| {
                        current.kind == entry.kind
                            && current.size == entry.size
                            && current.exec == entry.exec
                            && current.stage_id.is_none_or(|id| {
                                if !self.dirty_spans.is_empty() {
                                    return false;
                                }
                                self.namespace.stages.get(&id).is_some_and(|stage| {
                                    matches!(entry.kind, OverlayKind::File { content: Some(content) }
                                        if stage.inherited() == (Some(content), entry.size)
                                            && stage.mark.is_none_or(|mark| {
                                                mark.content == content
                                                    && mark.synced_size == entry.size
                                            }))
                                        && stage.size == entry.size
                                        && stage.extents.is_empty()
                                        && stage.zeros.is_empty()
                                })
                            })
                    })
            })
            && self
                .journal
                .lock()
                .is_ok_and(|journal| journal.completion.commits.is_empty())
    }
    #[must_use]
    pub fn readiness(&self) -> OverlayReadiness {
        self.readiness
    }
    #[must_use]
    pub fn summary(&self) -> OverlaySummary {
        self.summary
    }
    #[cfg(test)]
    pub(crate) fn projected_tree_seal_charge_for_test(&self) -> Result<u64, OverlayError> {
        self.projected_tree_seal_charge()
    }
    #[cfg(test)]
    pub(crate) fn cap_for_test(&mut self, cap: u64) {
        self.config.cap = cap;
    }
    pub(crate) fn report_commit_fenced(&self, class: observe::FailureClass) {
        observe::overlay_refused(
            class,
            self.summary.records,
            self.namespace.stages.len() as u64,
            self.summary.charged_bytes,
        );
    }
    #[must_use]
    pub fn writer(&self) -> &WriterRecord {
        &self.writer
    }
    #[must_use]
    pub fn fault_control(&self) -> FaultControl {
        self.faults.clone()
    }
    #[must_use]
    pub fn sweep_manifest(&self) -> &[SweepEntry] {
        &self.sweep_manifest
    }

    /// Read only admitted commit evidence after replay, including completed pairs
    /// whose replacement remains owed. This does not enable namespace service.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn recovery_commits(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
    ) -> Result<Vec<RecoveryCommit>, OverlayError> {
        self.check(store, ownership)?;
        if !self.replayed {
            return Err(OverlayError::PendingReconciliation);
        }
        let mut evidence = Vec::new();
        codec::scan_journal_with(&self.journal_bytes()?, |index, record| match record {
            Record::CommitBoundary {
                candidate,
                through_seq,
                publication_id,
            } => evidence.push(RecoveryCommit::Boundary {
                index,
                candidate: *candidate,
                through_seq: *through_seq,
                publication_id: *publication_id,
                selection: BoundarySelection::Tree,
            }),
            Record::ProjectedBoundary {
                candidate,
                through_seq,
                publication_id,
                selection,
            } => evidence.push(RecoveryCommit::Boundary {
                index,
                candidate: *candidate,
                through_seq: *through_seq,
                publication_id: *publication_id,
                selection: BoundarySelection::Projected(*selection),
            }),
            Record::LandedCommit {
                boundary_seq,
                landed_root,
                landed_seq,
            } => evidence.push(RecoveryCommit::Landed {
                index,
                boundary_seq: *boundary_seq,
                root: *landed_root,
                seq: *landed_seq,
            }),
            _ => {}
        })
        .map_err(|_| OverlayError::refused("recovery commit scan"))?;
        Ok(evidence)
    }
    fn journal_path(&self) -> PathBuf {
        self.area.join("journal")
    }
    fn stage_path(&self, id: u64) -> PathBuf {
        self.area.join("staging").join(format!("{id:016x}"))
    }
    fn lock_error<T>(_: std::sync::PoisonError<T>) -> OverlayError {
        OverlayError::poisoned()
    }
    fn poison(&mut self) {
        self.readiness = OverlayReadiness::Poisoned;
    }
    fn point(&self, name: &'static str, phase: &'static str, seq: u64) -> Result<(), OverlayError> {
        point(&self.faults, name, phase, seq)
    }
    fn check_context(&mut self, store: &Store) -> Result<(), OverlayError> {
        if self.readiness == OverlayReadiness::Poisoned {
            return Err(OverlayError::poisoned());
        }
        if store.publication_root() != self.root {
            return Err(OverlayError::refused("Store binding"));
        }
        self.io.check_root(&self.root, self.config.euid)?;
        self.io.directory(&self.area)?;
        Ok(())
    }
    fn check(&mut self, store: &Store, ownership: &OwnershipStatus) -> Result<(), OverlayError> {
        self.check_context(store)?;
        self.check_evidence(ownership)
    }
    fn check_evidence(&mut self, ownership: &OwnershipStatus) -> Result<(), OverlayError> {
        if recovery::read_writer(&mut self.io, &self.area.join("writer"))? != self.writer {
            self.poison();
            return Err(OverlayError::refused("writer changed"));
        }
        let carrier = self.io.length(&self.area.join("ownership"))?;
        self.io.length(&self.area.join("ownership.tmp"))?;
        let valid = match ownership {
            OwnershipStatus::Owned(OwnershipPermission {
                scope,
                volume,
                writer,
                high_water,
            })
            | OwnershipStatus::Durable(OwnershipPermission {
                scope,
                volume,
                writer,
                high_water,
            }) => {
                carrier.is_some()
                    && scope == &self.scope
                    && volume == &self.config.volume
                    && writer == &self.writer.writer
                    && *high_water <= self.writer.ceiling
            }
            OwnershipStatus::PendingReconciliation => false,
        };
        if !valid {
            return Err(OverlayError::PendingReconciliation);
        }
        Ok(())
    }
    fn ready(&mut self, store: &Store, ownership: &OwnershipStatus) -> Result<(), OverlayError> {
        self.check(store, ownership)?;
        if self.readiness != OverlayReadiness::Ready
            || !matches!(ownership, OwnershipStatus::Durable(_))
        {
            return Err(OverlayError::PendingReconciliation);
        }
        #[cfg(test)]
        if state::exhaustive_query_checks() && self.namespace.check_indexes().is_err() {
            self.poison();
            return Err(OverlayError::poisoned());
        }
        Ok(())
    }
    fn ready_to_serve(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
    ) -> Result<(), OverlayError> {
        self.ready(store, ownership)?;
        self.served = true;
        Ok(())
    }
    /// A copy of the ready namespace; provisional recovery state never escapes.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn entries(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
    ) -> Result<Vec<OverlayEntry>, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        if self.namespace.check_indexes().is_err() {
            self.poison();
            return Err(OverlayError::poisoned());
        }
        #[cfg(test)]
        {
            state::QUERY_COPIES.set(state::QUERY_COPIES.get() + 1);
            work::namespace_copy();
        }
        Ok(self.namespace.entries.values().cloned().collect())
    }

    pub(crate) fn observation(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
    ) -> Result<OverlayObservation, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        self.settle_summary()?;
        Ok(OverlayObservation {
            namespace_len: u64::try_from(self.namespace.entries.len())
                .ok()
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| OverlayError::refused("namespace count overflow"))?,
            summary: self.summary,
            cap: self.config.cap,
            free_entries: self.free_entry_capacity()?,
        })
    }

    fn free_entry_capacity(&self) -> Result<u64, OverlayError> {
        let journal = self.journal.lock().map_err(Self::lock_error)?;
        let completion = &journal.completion;
        let stages = self.namespace.stages.len() as u64;
        let held = stages
            .saturating_mul(61)
            .saturating_sub(self.completion_credit / 2);
        let remaining = (866 * completion.slots()).saturating_sub(completion.consumed() / 2);
        let journal_used = journal
            .length
            .saturating_add(stages.saturating_mul(MAX_REBIND))
            .saturating_add(held)
            .saturating_add(remaining)
            .saturating_add(self.versions.journal_reserve())
            .saturating_add(self.projected_growth(self.namespace.stages.len(), completion)?);
        // One worst-case create frame is charged physically and reserved for
        // replacement. A new stage also reserves its header, rebind and completion.
        let frame = u64::from(codec::LEN_MAX) + 4;
        let per_entry = 2 * frame + 160 + MAX_REBIND + 122;
        let free_bytes = self
            .config
            .cap
            .saturating_sub(self.summary.charged_bytes)
            .saturating_sub(self.summary.reserved_bytes)
            .saturating_sub(self.summary.captured_bytes);
        Ok((free_bytes / per_entry)
            .min(
                (codec::JOURNAL_MAX as u64).saturating_sub(journal_used)
                    / (frame + MAX_REBIND + 61),
            )
            .min((codec::STAGE_ID_MAX + 1).saturating_sub(journal.state.next_stage_id()))
            .min(self.namespace.remaining_inodes()))
    }

    fn charge(&mut self) -> Result<u64, OverlayError> {
        let mut total = 0u64;
        for name in self.io.entries(&self.area)? {
            if matches!(name.as_str(), "staging" | "unmerged") {
                continue;
            }
            if !matches!(
                name.as_str(),
                "writer"
                    | "writer.tmp"
                    | "journal"
                    | "journal.next"
                    | "ownership"
                    | "ownership.tmp"
            ) {
                return Err(OverlayError::refused("foreign volume entry"));
            }
            total = total
                .checked_add(
                    self.io
                        .length(&self.area.join(name))?
                        .ok_or_else(|| OverlayError::refused("entry vanished"))?,
                )
                .ok_or_else(OverlayError::no_space)?;
        }
        for (&id, &physical) in self.io.stages() {
            let logical = self.namespace.stages.get(&id).map_or(0, |s| 160 + s.size);
            total = total
                .checked_add(physical.max(logical))
                .ok_or_else(OverlayError::no_space)?;
        }
        for &physical in self.io.unmerged().values() {
            total = total
                .checked_add(physical)
                .ok_or_else(OverlayError::no_space)?;
        }
        Ok(total)
    }
    pub(crate) fn unmerged_lengths(&self) -> &BTreeMap<String, u64> {
        self.io.unmerged()
    }
    #[cfg(test)]
    fn reserve(&self, journal_length: u64, stages: usize) -> Result<u64, OverlayError> {
        let completion = self
            .journal
            .lock()
            .map_err(Self::lock_error)?
            .completion
            .clone();
        self.reserve_with(journal_length, stages, &completion)
    }
    #[cfg(test)]
    fn reserve_with(
        &self,
        journal_length: u64,
        stages: usize,
        completion: &CompletionReserve,
    ) -> Result<u64, OverlayError> {
        reserve_total(&self.reserve_terms(journal_length, stages, completion)?)
    }
    /// The reserve's terms by the resource that holds them; nothing is owed yet.
    fn reserve_terms(
        &self,
        journal_length: u64,
        stages: usize,
        completion: &CompletionReserve,
    ) -> Result<observe::OverlayOwed, OverlayError> {
        // Every bound stage can need a re-bind at a future boundary. Reserving
        // the maximum encoded path covers rename growth without guessing names.
        let binds = (stages as u64)
            .checked_mul(MAX_REBIND)
            .ok_or_else(OverlayError::no_space)?;
        let writer = self
            .writer
            .encode()
            .map_err(|_| OverlayError::refused("writer encode"))?
            .len() as u64;
        Ok(observe::OverlayOwed {
            owed: 0,
            stages: binds
                .checked_add((stages as u64).saturating_mul(122))
                .ok_or_else(OverlayError::no_space)?,
            projected: self.projected_growth(stages, completion)?,
            ownership: self.config.ownership_completion_reserve,
            completion: 1732 * completion.slots(),
            writer,
            journal: journal_length.max(117),
        })
    }
    /// What a projected boundary's residual replacement can add beyond the
    /// old journal and a rebind per stage, while a projected seal or boundary
    /// is retained: each namespace record through its cursor keeps its names
    /// but may take a lifted parent of the greatest legal length at each
    /// location, and each stage may need a recreate rather than a rebind.
    fn projected_growth(
        &self,
        stages: usize,
        completion: &CompletionReserve,
    ) -> Result<u64, OverlayError> {
        let Some(through) = self.projected_through(completion) else {
            return Ok(0);
        };
        Self::growth_of(self.history.locations_through(through), stages)
    }
    /// The cursor the reserve covers: the later of the projected seal and
    /// every projected boundary `completion` retains.
    fn projected_through(&self, completion: &CompletionReserve) -> Option<u64> {
        self.projected_seal.max(
            completion
                .commits
                .values()
                .filter_map(|slot| slot.projected)
                .max(),
        )
    }
    fn growth_of(locations: u64, stages: usize) -> Result<u64, OverlayError> {
        locations
            .checked_mul(MAX_PARENT)
            .and_then(|n| n.checked_add((stages as u64).checked_mul(MAX_RECREATE - MAX_REBIND)?))
            .ok_or_else(OverlayError::no_space)
    }
    /// `projected_growth` by a full scan of the history, as the oracle for
    /// the prefix it reads.
    #[cfg(test)]
    fn projected_growth_by_scan(
        &self,
        stages: usize,
        completion: &CompletionReserve,
    ) -> Result<u64, OverlayError> {
        let Some(through) = self.projected_through(completion) else {
            return Ok(0);
        };
        Self::growth_of(self.history.locations_through_by_scan(through), stages)
    }
    /// Reserve a projected seal's residual replacement at this cursor before
    /// it seals, refusing `NoSpace` if the current work would not fit both
    /// images.
    pub(crate) fn reserve_projected(&mut self) -> Result<(), OverlayError> {
        let (through, length, completion) = {
            let journal = self.journal.lock().map_err(Self::lock_error)?;
            (
                journal.state.next_seq() - 1,
                journal.length,
                journal.completion.clone(),
            )
        };
        let stages = self.namespace.stages.len();
        let baseline = self.measure(length, stages, &completion)?;
        let previous = self.projected_seal.replace(through);
        if let Err(error) = self.capacity_with(0, length, stages, &completion) {
            self.rebase_capacity_exhaustion(baseline);
            self.projected_seal = previous;
            return Err(self.name_capacity_error(error));
        }
        Ok(())
    }
    pub(crate) fn release_projected(&mut self) {
        self.projected_seal = None;
        self.room_released();
    }
    fn capacity(
        &mut self,
        extra: u64,
        journal_length: u64,
        stages: usize,
    ) -> Result<(), OverlayError> {
        let completion = self
            .journal
            .lock()
            .map_err(Self::lock_error)?
            .completion
            .clone();
        self.capacity_with(extra, journal_length, stages, &completion)
    }
    fn capacity_with(
        &mut self,
        extra: u64,
        journal_length: u64,
        stages: usize,
        completion: &CompletionReserve,
    ) -> Result<(), OverlayError> {
        let measured = self
            .admits(extra, journal_length, stages, completion)?
            .ok_or_else(OverlayError::no_space)?;
        self.record_summary(journal_length, measured);
        Ok(())
    }

    /// The measured charges when `extra` more bytes fit both the journal bound
    /// and the cap, or `None` when they do not.
    fn admits(
        &mut self,
        extra: u64,
        journal_length: u64,
        stages: usize,
        completion: &CompletionReserve,
    ) -> Result<Option<Measured>, OverlayError> {
        self.capacity_exhaustion = None;
        let remaining = (866 * completion.slots()).saturating_sub(completion.consumed() / 2);
        let held = (stages as u64)
            .saturating_mul(61)
            .saturating_sub(self.completion_credit / 2);
        if journal_length
            .checked_add((stages as u64).saturating_mul(MAX_REBIND))
            .and_then(|n| n.checked_add(self.projected_growth(stages, completion).ok()?))
            .and_then(|n| n.checked_add(held))
            .and_then(|n| n.checked_add(remaining))
            .and_then(|n| n.checked_add(self.versions.journal_reserve()))
            .is_none_or(|n| n > codec::JOURNAL_MAX as u64)
        {
            return Ok(None);
        }
        let measured = self.measure(journal_length, stages, completion)?;
        let attempted = measured
            .charged
            .checked_add(extra)
            .and_then(|n| n.checked_add(measured.reserved))
            .and_then(|n| n.checked_add(measured.captured));
        let admitted = attempted.is_some_and(|n| n <= self.config.cap);
        if !admitted {
            let held = measured
                .charged
                .saturating_add(measured.reserved)
                .saturating_add(measured.captured);
            self.capacity_exhaustion = Some(CapacityExhaustion {
                cap: self.config.cap,
                charged: measured.charged,
                reserved: measured.reserved,
                captured: measured.captured,
                needed: attempted.unwrap_or(u64::MAX).saturating_sub(held),
            });
        }
        Ok(admitted.then_some(measured))
    }

    fn rebase_capacity_exhaustion(&mut self, measured: Measured) {
        let Some(exhausted) = self.capacity_exhaustion else {
            return;
        };
        let attempted = exhausted
            .charged
            .saturating_add(exhausted.reserved)
            .saturating_add(exhausted.captured)
            .saturating_add(exhausted.needed);
        let held = measured
            .charged
            .saturating_add(measured.reserved)
            .saturating_add(measured.captured);
        self.capacity_exhaustion = Some(CapacityExhaustion {
            cap: exhausted.cap,
            charged: measured.charged,
            reserved: measured.reserved,
            captured: measured.captured,
            needed: attempted.saturating_sub(held),
        });
    }

    /// The area's charge, its unspent reserve and the snapshot charge, which
    /// together are checked against the cap, and what they owe above it.
    fn measure(
        &mut self,
        journal_length: u64,
        stages: usize,
        completion: &CompletionReserve,
    ) -> Result<Measured, OverlayError> {
        let charged = self.charge()?;
        let mut owed = self.reserve_terms(journal_length, stages, completion)?;
        let full_reserve = reserve_total(&owed)?;
        let next = self
            .io
            .length(&self.area.join("journal.next"))?
            .unwrap_or(0);
        let reserved = full_reserve
            .saturating_sub(next)
            .saturating_sub(self.completion_credit)
            .saturating_sub(completion.consumed());
        let captured = self.capture_charge()?;
        owed.owed = charged
            .saturating_add(reserved)
            .saturating_add(captured)
            .saturating_sub(self.config.cap);
        Ok(Measured {
            charged,
            reserved,
            captured,
            owed,
        })
    }

    fn record_summary(&mut self, journal_length: u64, measured: Measured) {
        let Measured {
            charged,
            reserved,
            captured,
            owed,
        } = measured;
        self.summary.charged_bytes = charged;
        self.summary.reserved_bytes = reserved;
        self.summary.captured_bytes = captured;
        self.summary.owed = owed;
        self.summary.commit_requested =
            journal_length >= 50_331_648 || charged >= (self.config.cap / 4).saturating_mul(3);
        self.summary.orphan_bytes = self
            .namespace
            .stages
            .values()
            .filter(|s| s.path.is_none())
            .fold(0u64, |a, s| a.saturating_add(160 + s.size));
    }

    fn refresh_commit_requested(&mut self) {
        let projected_seal = self
            .summary
            .charged_bytes
            .saturating_add(self.summary.reserved_bytes)
            .saturating_add(self.summary.captured_bytes)
            .saturating_add(self.projected_tree_seal_charge().unwrap_or(u64::MAX));
        self.summary.commit_requested = self.summary.commit_requested
            || self.summary.owed.owed > 0
            || projected_seal >= (self.config.cap / 4).saturating_mul(3);
    }

    /// No generic public append exists: callers cannot bypass staging/mark gates.
    fn append(&mut self, record: &Record) -> Result<u64, OverlayError> {
        self.append_effect(record, true)
    }

    fn fold_candidate(&mut self, ns: &mut Namespace, record: &Record) -> Result<(), OverlayError> {
        let result = ns.fold(record);
        if matches!(result, Err(OverlayError::Poisoned)) {
            self.poison();
        }
        result
    }

    fn append_effect(
        &mut self,
        record: &Record,
        content_change: bool,
    ) -> Result<u64, OverlayError> {
        #[cfg(test)]
        let _storage = work::StorageScope::enter();
        let mut ns = self.namespace.clone();
        self.fold_candidate(&mut ns, record)?;
        let (header, length, state, mut completion) = {
            let journal = self.journal.lock().map_err(Self::lock_error)?;
            (
                journal.header,
                journal.length,
                journal.state.clone(),
                journal.completion.clone(),
            )
        };
        let mut prospective = state;
        prospective
            .admit(record)
            .map_err(|_| OverlayError::refused("journal value rule"))?;
        let seq = prospective.next_seq() - 1;
        let before = provenance::touched(&self.namespace, record);
        let mut effect = self.history.annotate(seq, record, &before, &ns)?;
        effect.content_change = content_change;
        let bytes = codec::encode_record(&header, seq, record)
            .map_err(|_| OverlayError::refused("record encode"))?;
        let new_length = length
            .checked_add(bytes.len() as u64)
            .ok_or_else(OverlayError::no_space)?;
        completion.fold(seq, record)?;
        self.capacity_with(bytes.len() as u64, new_length, ns.stages.len(), &completion)?;
        let path = self.journal_path();
        let mut journal = self.journal.lock().map_err(Self::lock_error)?;
        // Exclusive namespace access is the outer transaction gate; this mutex
        // covers sequence assignment, both distinct barriers and append rollback.
        let result = (|| {
            if self.io.length(&path)? != Some(length) {
                return Err(OverlayError::poisoned());
            }
            if record.is_sync_class() {
                point(&self.faults, "overlay.journal.pre_sync", "before", seq)?;
                self.io.sync(&path)?;
                point(&self.faults, "overlay.journal.pre_sync", "after", seq)?;
            }
            if let Err(e) = write_step(
                &mut self.io,
                &self.faults,
                "overlay.journal.append",
                &path,
                length,
                &bytes,
                seq,
            ) {
                #[cfg(any(test, feature = "overlay-fault-tests"))]
                if matches!(e, OverlayError::InjectedCrash) {
                    return Err(e);
                }
                let rollback = (|| {
                    point(&self.faults, "overlay.append.rollback", "before", seq)?;
                    self.io.resize(&path, length)?;
                    point(&self.faults, "overlay.append.rollback", "after-cut", seq)?;
                    self.io.sync(&path)?;
                    point(&self.faults, "overlay.append.rollback", "after-sync", seq)
                })();
                if rollback.is_err() {
                    return Err(OverlayError::poisoned());
                }
                return Err(e);
            }
            if record.is_sync_class() {
                point(&self.faults, "overlay.journal.post_sync", "before", seq)?;
                self.io.sync(&path)?;
                point(&self.faults, "overlay.journal.post_sync", "after", seq)?;
            }
            Ok(())
        })();
        if result.is_ok() {
            journal.state = prospective;
            journal.length = new_length;
            journal.completion = completion;
            self.history.accept(effect, &before, &ns);
            self.namespace = ns;
            self.summary.records = seq;
            self.summary.charged_bytes = self
                .summary
                .charged_bytes
                .saturating_add(bytes.len() as u64);
        }
        drop(journal);
        if result.is_err()
            && (record.is_sync_class() || matches!(result, Err(OverlayError::Poisoned)))
        {
            self.poison();
        }
        if result.is_err() {
            observe::op_failed(
                observe::OperationKind::JournalAppend,
                observe::FailureClass::Io,
            );
        }
        result?;
        Ok(seq)
    }

    /// Durable writer-file primitive; the caller is the sole generation allocator.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn raise_ceiling(&mut self, store: &mut Store, ceiling: u64) -> Result<(), OverlayError> {
        if self.readiness == OverlayReadiness::Poisoned {
            return Err(OverlayError::poisoned());
        }
        if !self.replayed {
            return Err(OverlayError::PendingReconciliation);
        }
        if store.publication_root() != self.root {
            return Err(OverlayError::refused("Store binding"));
        }
        self.io
            .check_root(store.publication_root(), self.config.euid)?;
        if ceiling < self.writer.ceiling || ceiling > codec::GENERATION_MAX {
            return Err(OverlayError::refused("writer ceiling rollback/exhaustion"));
        }
        let mut writer = self.writer.clone();
        writer.ceiling = ceiling;
        let bytes = writer
            .encode()
            .map_err(|_| OverlayError::refused("writer encode"))?;
        let len = self.journal.lock().map_err(Self::lock_error)?.length;
        self.capacity(bytes.len() as u64, len, self.namespace.stages.len())?;
        let previous = self.readiness;
        self.poison();
        durable_file(
            &mut self.io,
            &self.faults,
            &self.area,
            "writer.tmp",
            "writer",
            &bytes,
            "overlay.writer",
            0,
        )?;
        self.writer = writer;
        self.readiness = previous;
        Ok(())
    }

    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the API consumes the requested mutation"
    )]
    pub fn namespace_record(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        record: Record,
    ) -> Result<u64, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        if !matches!(
            record,
            Record::Create {
                kind: codec::CreateKind::Dir | codec::CreateKind::Symlink { .. },
                ..
            } | Record::Move { .. }
                | Record::Replace { .. }
                | Record::Delete { .. }
                | Record::SetattrExec { .. }
        ) {
            return Err(OverlayError::refused("namespace record kind"));
        }
        let seq = self.append(&record)?;
        self.update_summary()?;
        self.note_dirty_mutation(seq);
        Ok(seq)
    }
    pub(crate) fn install_coalescer(
        &mut self,
        clock: Option<CoalesceClock>,
        wake: std::sync::Arc<tokio::sync::Notify>,
    ) {
        if let Some(clock) = &clock {
            let now = (clock.0)();
            for span in &mut self.dirty_spans {
                span.first_at.get_or_insert(now);
                span.last_at.get_or_insert(now);
            }
        }
        self.coalesce_clock = clock;
        self.coalesce_wake = wake;
    }

    /// Records a commit refused for room, so the coalescer backs off instead
    /// of retrying it, until a handle closes, a landing installs, a reopen
    /// declares another cap, or a measurement finds more room than the
    /// refusal had. A refusal whose measurement fails records nothing.
    /// Returns whether the refusal was recorded.
    pub(crate) fn note_capacity_refusal(&mut self) -> bool {
        self.capacity_refused = self.settle_summary().is_ok().then(|| CapacityRefusal {
            headroom: self.headroom(),
            seen: None,
        });
        self.capacity_exhaustion = None;
        self.capacity_refused.is_some()
    }

    fn named_capacity_exhaustion(&mut self) -> Option<OverlayError> {
        let exhausted = self.capacity_exhaustion.take()?;
        crate::ClientEvent::overlay_cap_exhausted(
            exhausted.cap,
            exhausted.charged,
            exhausted.reserved,
            exhausted.captured,
            exhausted.needed,
        )
        .emit();
        Some(OverlayError::Refused("OverlayCapacityExhausted"))
    }

    fn name_capacity_error(&mut self, error: OverlayError) -> OverlayError {
        if matches!(error, OverlayError::NoSpace) {
            self.named_capacity_exhaustion().unwrap_or(error)
        } else {
            error
        }
    }

    /// When a refused commit may next be attempted, or `None` when nothing
    /// holds it back. The backoff runs from the first time the coalescer
    /// sees the refusal, so a long-held handle cannot stop commits for good.
    pub(crate) fn capacity_retry_at(
        &mut self,
        now: tokio::time::Instant,
        backoff: std::time::Duration,
    ) -> Option<tokio::time::Instant> {
        let headroom = self.headroom();
        let refusal = self
            .capacity_refused
            .as_mut()
            .filter(|refusal| headroom <= refusal.headroom)?;
        refusal.seen.get_or_insert(now).checked_add(backoff)
    }

    /// Cap minus the last measured charged, reserved and captured bytes;
    /// negative above the cap. A refusal is recorded after its lane has
    /// released its own charges, so only room freed elsewhere raises it.
    fn headroom(&self) -> i128 {
        let s = &self.summary;
        i128::from(self.config.cap)
            - i128::from(s.charged_bytes)
            - i128::from(s.reserved_bytes)
            - i128::from(s.captured_bytes)
    }

    /// A released reservation may have freed room: a recorded refusal that
    /// now measures more room than it had is retried on a wake, not at the
    /// end of its backoff.
    fn room_released(&mut self) {
        let Some(refusal) = self.capacity_refused else {
            return;
        };
        if self.settle_summary().is_ok() && self.headroom() > refusal.headroom {
            self.capacity_changed();
        }
    }

    /// Room may have been freed: a refused commit is worth one more attempt.
    fn capacity_changed(&mut self) {
        if self.capacity_refused.take().is_some() {
            self.coalesce_wake.notify_waiters();
        }
    }

    pub(crate) fn has_open_stage_handles(&self) -> bool {
        self.namespace.stages.values().any(|s| s.handles > 0)
    }

    pub(crate) fn active_dirty_span(
        &mut self,
        now: tokio::time::Instant,
    ) -> Option<(tokio::time::Instant, tokio::time::Instant, bool)> {
        let first_idx = self
            .dirty_spans
            .iter()
            .position(|span| span.last_seq > self.last_boundary_seq)?;
        if !self.summary.commit_requested {
            self.refresh_commit_requested();
        }
        let requested = self.summary.commit_requested;
        for span in self.dirty_spans.get_mut(first_idx..)? {
            span.first_at.get_or_insert(now);
            span.last_at.get_or_insert(now);
        }
        let first_at = self.dirty_spans.get(first_idx)?.first_at?;
        let last_at = self.dirty_spans.last()?.last_at?;
        Some((first_at, last_at, requested))
    }

    fn note_dirty_mutation(&mut self, seq: u64) {
        let now = self.coalesce_clock.as_ref().map(|clock| (clock.0)());
        if let Some(span) = self
            .dirty_spans
            .last_mut()
            .filter(|span| span.last_seq > self.dirty_split_seq)
        {
            span.last_seq = seq;
            span.last_at = now;
        } else {
            self.dirty_spans.push(DirtySpan {
                first_seq: seq,
                last_seq: seq,
                first_at: now,
                last_at: now,
            });
        }
        self.coalesce_wake.notify_waiters();
    }

    fn update_summary(&mut self) -> Result<(), OverlayError> {
        let len = self.journal.lock().map_err(Self::lock_error)?.length;
        self.capacity(0, len, self.namespace.stages.len())
    }

    #[cfg(test)]
    pub(crate) fn set_coalescing_journal_length(
        &mut self,
        length: u64,
    ) -> Result<(), OverlayError> {
        self.capacity(0, length, self.namespace.stages.len())
    }

    /// Refreshes the summary where recorded work may already exceed the cap: a
    /// landed replacement can be larger than the journal it replaced, and a
    /// reopen can declare a smaller cap. Neither undoes recorded work. The
    /// overlay stays readable, every admission keeps refusing `NoSpace`, and a
    /// commit is requested so a landing can retire stages.
    /// Unlike an admission, it records no failed operation: an observation
    /// answers above the cap as often as it is asked.
    fn settle_summary(&mut self) -> Result<(), OverlayError> {
        let result = (|| {
            let (length, completion) = {
                let journal = self.journal.lock().map_err(Self::lock_error)?;
                (journal.length, journal.completion.clone())
            };
            let stages = self.namespace.stages.len();
            if let Some(measured) = self.admits(0, length, stages, &completion)? {
                self.record_summary(length, measured);
            } else {
                let measured = self.measure(length, stages, &completion)?;
                self.record_summary(length, measured);
                self.summary.commit_requested = true;
            }
            self.capacity_exhaustion = None;
            Ok(())
        })();
        if let Err(error) = &result {
            self.record_bundle_failure(error);
        }
        result
    }

    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn create_file(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        at: codec::Location,
        exec: bool,
    ) -> Result<u64, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        let id = self
            .journal
            .lock()
            .map_err(Self::lock_error)?
            .state
            .next_stage_id();
        let record = Record::Create {
            at,
            kind: codec::CreateKind::File { exec, stage_id: id },
        };
        self.prepare_stage(&record, id, 0, None)?;
        Ok(id)
    }
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn copy_up(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        at: codec::Location,
        source: &mut impl ContentSource,
    ) -> Result<u64, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        self.copy_up_ready(at, source)
    }

    fn copy_up_ready(
        &mut self,
        at: codec::Location,
        source: &mut impl ContentSource,
    ) -> Result<u64, OverlayError> {
        let node = self
            .namespace
            .entries
            .get(&state::path(&at))
            .ok_or_else(|| OverlayError::refused("copy-up missing"))?;
        let OverlayKind::File {
            content: Some(content),
        } = node.kind
        else {
            return Err(OverlayError::refused("copy-up content missing"));
        };
        let size = node.size;
        let id = self
            .journal
            .lock()
            .map_err(Self::lock_error)?
            .state
            .next_stage_id();
        let record = Record::StageBind {
            at,
            cause: codec::BindCause::CopyUp,
            stage_id: id,
            staged_size: size,
            base_content: content,
        };
        self.prepare_stage(&record, id, size, Some((content, source)))?;
        Ok(id)
    }
    fn prepare_stage(
        &mut self,
        record: &Record,
        id: u64,
        size: u64,
        mut source: Option<(GrainId, &mut dyn ContentSource)>,
    ) -> Result<(), OverlayError> {
        #[cfg(test)]
        let _storage = work::StorageScope::enter();
        let mut ns = self.namespace.clone();
        self.fold_candidate(&mut ns, record)?;
        let journal = self.journal.lock().map_err(Self::lock_error)?;
        let mut candidate = journal.state.clone();
        candidate
            .admit(record)
            .map_err(|_| OverlayError::refused("stage id"))?;
        let frame = codec::encode_record(&journal.header, journal.state.next_seq(), record)
            .map_err(|_| OverlayError::refused("stage encode"))?;
        let new_length = journal.length + frame.len() as u64;
        drop(journal);
        self.capacity(
            160u64
                .checked_add(size)
                .and_then(|n| n.checked_add(frame.len() as u64))
                .ok_or_else(OverlayError::no_space)?,
            new_length,
            ns.stages.len(),
        )?;
        let path = self.stage_path(id);
        let result = (|| {
            self.point("overlay.stage.create", "before", 0)?;
            self.io.create(&path)?;
            let header = StagingHeader {
                writer: self.writer.writer,
                stage_id: id,
                mark: MarkState::Absent,
            }
            .encode()
            .map_err(|_| OverlayError::refused("stage header"))?;
            write_step(
                &mut self.io,
                &self.faults,
                "overlay.stage.create",
                &path,
                0,
                &header,
                0,
            )?;
            if let Some((content, source)) = &mut source {
                let mut offset = 0;
                while offset < size {
                    let n = usize_bound((size - offset).min(BUFFER as u64))?;
                    let bytes = verified(*source, *content, offset, n)?;
                    write_step(
                        &mut self.io,
                        &self.faults,
                        "overlay.stage.write",
                        &path,
                        160 + offset,
                        &bytes,
                        0,
                    )?;
                    offset += n as u64;
                }
            }
            sync_step(&mut self.io, &self.faults, "overlay.stage.sync", &path, 0)?;
            point(&self.faults, "overlay.stage.dir_sync", "before", 0)?;
            self.io.sync_directory(&self.area.join("staging"))?;
            point(&self.faults, "overlay.stage.dir_sync", "after", 0)?;
            let seq = self.append(record)?;
            self.update_summary()?;
            self.note_dirty_mutation(seq);
            Ok(())
        })();
        if matches!(result, Err(OverlayError::ContentUnavailable)) {
            // This stage has no admitted binding or handles. Release it before
            // retrying the same id; uncertain cleanup still fences persistence.
            if let Err(e) = self
                .io
                .remove(&path)
                .and_then(|()| self.io.sync_directory(&self.area.join("staging")))
            {
                self.poison();
                return Err(e.into());
            }
        } else if result.is_err() {
            self.poison();
        }
        result
    }

    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn open_stage(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        path: &[Name],
    ) -> Result<u64, OverlayError> {
        self.open_stage_holds(store, ownership, path, 1)
    }

    /// Transfer existing object handles to one stage without partial holds.
    pub(crate) fn open_stage_holds(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        path: &[Name],
        holds: u64,
    ) -> Result<u64, OverlayError> {
        self.ready(store, ownership)?;
        let id = self
            .namespace
            .entries
            .get(path)
            .and_then(|e| e.stage_id)
            .ok_or_else(|| OverlayError::refused("open unstaged/missing file"))?;
        self.hold_stage(store, ownership, id, holds)
    }

    pub(crate) fn hold_stage(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        id: u64,
        holds: u64,
    ) -> Result<u64, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        self.accessible_stage(id)?;
        self.header(id)?;
        let stage = self
            .namespace
            .stages
            .get_mut(&id)
            .ok_or_else(|| OverlayError::refused("open stage"))?;
        stage.handles = stage
            .handles
            .checked_add(holds)
            .ok_or_else(|| OverlayError::refused("handle exhaustion"))?;
        Ok(id)
    }
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn close_stage(&mut self, store: &mut Store, id: u64) -> Result<(), OverlayError> {
        self.io
            .check_root(store.publication_root(), self.config.euid)?;
        self.release_stage_hold(id)
    }

    pub(crate) fn release_stage_hold(&mut self, id: u64) -> Result<(), OverlayError> {
        let stage = self
            .namespace
            .stages
            .get_mut(&id)
            .ok_or_else(|| OverlayError::refused("close stage"))?;
        stage.handles = stage
            .handles
            .checked_sub(1)
            .ok_or_else(|| OverlayError::refused("close without handle"))?;
        self.capacity_changed();
        if !self.has_open_stage_handles() {
            self.coalesce_wake.notify_waiters();
        }
        // Last close does not authorize physical deletion of journal evidence.
        Ok(())
    }
    fn accessible_stage(&self, id: u64) -> Result<&state::Stage, OverlayError> {
        self.namespace
            .stages
            .get(&id)
            .filter(|s| s.path.is_some() || s.handles > 0)
            .ok_or_else(|| OverlayError::refused("detached stage has no handle"))
    }
    fn header(&mut self, id: u64) -> Result<StagingHeader, OverlayError> {
        let bytes = self.io.read_at(&self.stage_path(id), 0, 160)?;
        let header =
            StagingHeader::decode(&bytes).map_err(|_| OverlayError::refused("staging header"))?;
        header
            .check_binding(&self.writer.writer, id)
            .map_err(|_| OverlayError::refused("staging binding"))?;
        if matches!(header.mark,MarkState::Present(mark) if mark.generation>self.writer.ceiling) {
            self.poison();
            return Err(OverlayError::refused("mark above ceiling"));
        }
        Ok(header)
    }

    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn read_stage(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        id: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        let stage = self.accessible_stage(id)?;
        let n = usize_bound(
            stage
                .size
                .saturating_sub(offset)
                .min(length as u64)
                .min(BUFFER as u64),
        )?;
        self.header(id)?;
        let bytes = self.io.read_at(
            &self.stage_path(id),
            160u64
                .checked_add(offset)
                .ok_or_else(|| OverlayError::refused("read offset"))?,
            n,
        )?;
        if bytes.len() != n {
            return Err(OverlayError::refused("short staged read"));
        }
        Ok(bytes)
    }
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn read_base(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        path: &[Name],
        offset: u64,
        length: usize,
        source: &mut impl ContentSource,
    ) -> Result<Vec<u8>, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        self.read_base_ready(path, offset, length, source)
    }

    fn read_base_ready(
        &mut self,
        path: &[Name],
        offset: u64,
        length: usize,
        source: &mut impl ContentSource,
    ) -> Result<Vec<u8>, OverlayError> {
        let entry = self
            .namespace
            .entries
            .get(path)
            .ok_or_else(|| OverlayError::refused("base read missing"))?;
        if entry.stage_id.is_some() {
            return Err(OverlayError::refused("read requires staged routing"));
        }
        let OverlayKind::File {
            content: Some(content),
        } = entry.kind
        else {
            return Err(OverlayError::refused("base read type"));
        };
        verified(
            source,
            content,
            offset,
            usize_bound(
                entry
                    .size
                    .saturating_sub(offset)
                    .min(length as u64)
                    .min(BUFFER as u64),
            )?,
        )
    }

    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn write(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        id: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<usize, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= codec::SIZE_MAX)
            .ok_or_else(|| OverlayError::refused("write bounds"))?;
        if bytes.len() as u64 > codec::EXTENT_LEN_MAX {
            return Err(OverlayError::refused("write extent bound"));
        }
        let size = self.accessible_stage(id)?.size;
        let record = Record::WriteExtent {
            stage_id: id,
            offset,
            length: bytes.len() as u64,
            check: codec::extent_check(id, offset, bytes),
        };
        let fragments = self.fragments(id, &record)?;
        self.admit_data(&record, &fragments, end.saturating_sub(size))?;
        let path = self.stage_path(id);
        self.header(id)?;
        self.preserve_versions(id, offset, end)?;
        let result = (|| {
            if offset > size {
                dense_zero(&mut self.io, &self.faults, &path, size, offset)?;
            }
            write_step(
                &mut self.io,
                &self.faults,
                "overlay.stage.write",
                &path,
                160 + offset,
                bytes,
                0,
            )?;
            let seq = self.append(&record)?;
            for fragment in fragments {
                self.append_effect(&fragment, false)?;
            }
            self.invalidate_versions(id, offset, end)?;
            self.update_summary()?;
            self.note_dirty_mutation(seq);
            Ok::<(), OverlayError>(())
        })();
        if result.is_err() {
            self.poison();
        }
        result?;
        Ok(bytes.len())
    }
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub(crate) fn journal_cursor(&self) -> Result<u64, OverlayError> {
        Ok(self
            .journal
            .lock()
            .map_err(|_| OverlayError::Poisoned)?
            .state
            .next_seq()
            - 1)
    }

    pub(crate) fn stage_floor_ready(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        id: u64,
        size: u64,
    ) -> Result<bool, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        Ok(!self
            .accessible_stage(id)?
            .captures
            .values()
            .any(|floor| size < *floor))
    }

    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn truncate(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        id: u64,
        size: u64,
    ) -> Result<(), OverlayError> {
        self.ready_to_serve(store, ownership)?;
        if size > codec::SIZE_MAX {
            return Err(OverlayError::refused("truncate size"));
        }
        let stage = self.accessible_stage(id)?;
        if stage.captures.values().any(|floor| size < *floor) {
            return Err(OverlayError::PendingShrink);
        }
        let previous = stage.size;
        let record = Record::Truncate {
            stage_id: id,
            new_size: size,
        };
        let fragments = self.fragments(id, &record)?;
        self.admit_data(&record, &fragments, size.saturating_sub(previous))?;
        let path = self.stage_path(id);
        self.header(id)?;
        let result = (|| {
            let seq = self.append(&record)?;
            if size > previous {
                dense_zero(&mut self.io, &self.faults, &path, previous, size)?;
            } else {
                self.point("overlay.stage.truncate", "before", 0)?;
                self.io.resize(&path, 160 + size)?;
                self.point("overlay.stage.truncate", "after", 0)?;
            }
            for fragment in fragments {
                self.append_effect(&fragment, false)?;
            }
            self.update_summary()?;
            if size != previous {
                self.note_dirty_mutation(seq);
            }
            Ok(())
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
    fn fragments(&mut self, id: u64, later: &Record) -> Result<Vec<Record>, OverlayError> {
        let extents: Vec<_> = self
            .accessible_stage(id)?
            .extents
            .values()
            .filter(|e| e.extent_superseded_by(later))
            .cloned()
            .collect();
        let mut fragments = Vec::new();
        for old in extents {
            let Record::WriteExtent { offset, length, .. } = old else {
                continue;
            };
            let bytes = self.verify_extent(id, &old)?;
            let cut = match later {
                Record::WriteExtent { offset, length, .. } => (*offset, offset + length),
                Record::Truncate { new_size, .. } => (*new_size, u64::MAX),
                _ => return Err(OverlayError::refused("fragment supersession")),
            };
            for (a, b) in state::subtract(&[(offset, offset + length)], cut.0, cut.1) {
                let range = bytes
                    .get(usize_bound(a - offset)?..usize_bound(b - offset)?)
                    .ok_or_else(|| OverlayError::refused("fragment length"))?;
                fragments.push(Record::WriteExtent {
                    stage_id: id,
                    offset: a,
                    length: b - a,
                    check: codec::extent_check(id, a, range),
                });
            }
        }
        Ok(fragments)
    }
    fn verify_extent(&mut self, id: u64, record: &Record) -> Result<Vec<u8>, OverlayError> {
        if let Some(bytes) = self.check_extent(id, record)? {
            return Ok(bytes);
        }
        self.poison();
        Err(OverlayError::refused("live extent mismatch"))
    }
    fn check_extent(&mut self, id: u64, record: &Record) -> Result<Option<Vec<u8>>, OverlayError> {
        let Record::WriteExtent {
            offset,
            length,
            check,
            ..
        } = record
        else {
            return Err(OverlayError::refused("not extent"));
        };
        let bytes = self.io.read_at(
            &self.stage_path(id),
            160 + offset,
            usize::try_from(*length).map_err(|_| OverlayError::refused("extent size"))?,
        )?;
        Ok(
            (bytes.len() as u64 == *length && codec::extent_check(id, *offset, &bytes) == *check)
                .then_some(bytes),
        )
    }
    fn admit_data(
        &mut self,
        record: &Record,
        fragments: &[Record],
        growth: u64,
    ) -> Result<(), OverlayError> {
        let journal = self.journal.lock().map_err(Self::lock_error)?;
        let mut state = journal.state.clone();
        let mut added = 0u64;
        for record in std::iter::once(record).chain(fragments) {
            let seq = state.next_seq();
            state
                .admit(record)
                .map_err(|_| OverlayError::refused("data value rule"))?;
            added += codec::encode_record(&journal.header, seq, record)
                .map_err(|_| OverlayError::refused("data encode"))?
                .len() as u64;
        }
        let length = journal.length + added;
        drop(journal);
        self.capacity(
            growth
                .checked_add(added)
                .ok_or_else(OverlayError::no_space)?,
            length,
            self.namespace.stages.len(),
        )
    }

    /// Copy the staged bytes. Replay reconciles the unchecked ranges with the
    /// checkpoint before making the stage readable again.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn capture(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        id: u64,
    ) -> Result<CaptureToken, OverlayError> {
        self.ready(store, ownership)?;
        let size = self.accessible_stage(id)?.size;
        let at_capture = self.accessible_stage(id)?.path.clone();
        let journal = self.journal.lock().map_err(Self::lock_error)?;
        let (through_seq, incarnation, len) = (
            journal.state.next_seq() - 1,
            journal.incarnation,
            journal.length,
        );
        drop(journal);
        self.capacity(size, len, self.namespace.stages.len())?;
        self.header(id)?;
        let mut chunks = Vec::new();
        let mut offset = 0;
        while offset < size {
            let n = usize_bound((size - offset).min(BUFFER as u64))?;
            let bytes = self.io.read_at(&self.stage_path(id), 160 + offset, n)?;
            if bytes.len() != n {
                self.poison();
                return Err(OverlayError::refused("short capture read"));
            }
            offset += n as u64;
            chunks.push(bytes);
        }
        // Verify the immutable bytes handed to the engine, without rereading
        // extents or repeating ownership/header checks for each chunk.
        for extent in self.accessible_stage(id)?.extents.values() {
            let Record::WriteExtent {
                offset,
                length,
                check,
                ..
            } = extent
            else {
                continue;
            };
            let mut hasher = codec::ExtentHasher::new(id, *offset, *length);
            let mut count = 0u64;
            let first = offset / BUFFER as u64;
            let touched = (offset % BUFFER as u64)
                .saturating_add(*length)
                .div_ceil(BUFFER as u64);
            let mut start = first.saturating_mul(BUFFER as u64);
            for chunk in chunks
                .iter()
                .skip(usize_bound(first)?)
                .take(usize_bound(touched)?)
            {
                let end = start + chunk.len() as u64;
                let a = start.max(*offset);
                let b = end.min(offset + length);
                if a < b {
                    let bytes = chunk
                        .get(usize_bound(a - start)?..usize_bound(b - start)?)
                        .ok_or_else(|| OverlayError::refused("capture extent range"))?;
                    hasher.update(bytes);
                    count += bytes.len() as u64;
                }
                start = end;
            }
            if count != *length || hasher.finalize() != *check {
                self.poison();
                return Err(OverlayError::refused("capture extent mismatch"));
            }
        }
        let token = self.next_capture;
        self.next_capture = token
            .checked_add(1)
            .ok_or_else(|| OverlayError::refused("capture exhaustion"))?;
        self.namespace
            .stages
            .get_mut(&id)
            .ok_or_else(|| OverlayError::refused("capture stage"))?
            .captures
            .insert(token, size);
        self.snapshots.insert(token, size);
        self.update_summary()?;
        Ok(CaptureToken {
            id: token,
            instance: self.config.instance,
            incarnation,
            scope: self.scope.clone(),
            volume: self.config.volume.clone(),
            writer: self.writer.writer,
            at_capture,
            stage_id: id,
            size,
            through_seq,
            chunks: std::sync::Arc::new(chunks),
        })
    }
    pub(crate) fn validate_capture(&self, token: &CaptureToken) -> Result<(), OverlayError> {
        self.validate_capture_context(token)?;
        if self.versions.lost.contains(&token.id) {
            return Err(OverlayError::CaptureCoverageLost);
        }
        Ok(())
    }
    fn validate_capture_context(&self, token: &CaptureToken) -> Result<(), OverlayError> {
        let incarnation = self.journal.lock().map_err(Self::lock_error)?.incarnation;
        if token.scope != self.scope
            || token.volume != self.config.volume
            || token.writer != self.writer.writer
            || token.instance != self.config.instance
            || token.incarnation != incarnation
            || self
                .namespace
                .stages
                .get(&token.stage_id)
                .and_then(|s| s.captures.get(&token.id))
                != Some(&token.size)
            || self.snapshots.get(&token.id) != Some(&token.size)
        {
            return Err(OverlayError::refused("capture context"));
        }
        Ok(())
    }
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn complete_failed_capture(&mut self, token: &CaptureToken) -> Result<(), OverlayError> {
        self.validate_capture_context(token)?;
        self.namespace
            .stages
            .get_mut(&token.stage_id)
            .ok_or_else(|| OverlayError::refused("capture stage"))?
            .captures
            .remove(&token.id);
        self.snapshots.remove(&token.id);
        self.versions.release_file(token.id);
        self.flushed.remove(&token.id);
        self.summary.captured_bytes = self.capture_charge()?;
        Ok(())
    }
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn flush_boundary(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        token: &CaptureToken,
    ) -> Result<(), OverlayError> {
        self.ready(store, ownership)?;
        self.validate_capture(token)?;
        let path = self.stage_path(token.stage_id);
        let result = (|| {
            self.header(token.stage_id)?;
            sync_step(
                &mut self.io,
                &self.faults,
                "overlay.stage.sync",
                &path,
                token.through_seq,
            )?;
            point(
                &self.faults,
                "overlay.stage.dir_sync",
                "before",
                token.through_seq,
            )?;
            self.io.sync_directory(&self.area.join("staging"))?;
            point(
                &self.faults,
                "overlay.stage.dir_sync",
                "after",
                token.through_seq,
            )?;
            let _journal = self.journal.lock().map_err(Self::lock_error)?;
            self.io.sync(&self.journal_path())?;
            Ok(())
        })();
        if result.is_err() {
            self.poison();
        } else {
            self.flushed.insert(token.id);
        }
        result
    }
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn record_file_synced(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        receipt: &RegisteredCapture,
    ) -> Result<(), OverlayError> {
        self.ready(store, ownership)?;
        self.validate_capture(&receipt.capture)?;
        if !self.flushed.contains(&receipt.capture.id) {
            return Err(OverlayError::refused("capture was not flushed"));
        }
        if receipt.writer != self.writer.writer || receipt.generation > self.writer.ceiling {
            return Err(OverlayError::refused("receipt writer/ceiling"));
        }
        let id = receipt.capture.stage_id;
        if receipt.capture.at_capture.is_none() {
            return Err(OverlayError::refused(
                "orphan capture has no prepared-root name",
            ));
        }
        let record = Record::FileSynced {
            stage_id: id,
            synced_size: receipt.capture.size,
            content: receipt.content,
            generation: receipt.generation,
            prepared_root: receipt.prepared_root,
        };
        self.admit_data(&record, &[], 0)?;
        let mut header = self.header(id)?;
        let mark = SyncedMark {
            synced_size: receipt.capture.size,
            content: receipt.content,
            generation: receipt.generation,
        };
        if let MarkState::Present(previous) = header.mark
            && (previous.generation > mark.generation
                || (previous.generation == mark.generation && previous != mark))
        {
            return Err(OverlayError::refused("mark generation conflict"));
        }
        if header.mark == MarkState::Damaged {
            return Err(OverlayError::refused("damaged mark evidence"));
        }
        header.mark = MarkState::Present(mark);
        let bytes = header
            .encode()
            .map_err(|_| OverlayError::refused("mark encode"))?;
        let block = bytes
            .get(68..149)
            .ok_or_else(|| OverlayError::refused("mark block"))?;
        let path = self.stage_path(id);
        let result = (|| {
            write_step(
                &mut self.io,
                &self.faults,
                "overlay.mark.write",
                &path,
                68,
                block,
                receipt.capture.through_seq,
            )?;
            sync_step(
                &mut self.io,
                &self.faults,
                "overlay.mark.sync",
                &path,
                receipt.capture.through_seq,
            )?;
            self.append(&record)?;
            self.namespace
                .stages
                .get_mut(&id)
                .ok_or_else(|| OverlayError::refused("checkpoint stage missing"))?
                .checkpoint_boundary = Some(receipt.capture.through_seq);
            let inode = self
                .namespace
                .stages
                .get(&id)
                .ok_or_else(|| OverlayError::refused("checkpoint stage missing"))?
                .inode;
            self.history.checkpoints.insert(
                inode,
                DurableFile {
                    inode,
                    size: receipt.capture.size,
                    content: receipt.content,
                    content_boundary: receipt.capture.through_seq,
                },
            );
            self.complete_failed_capture(&receipt.capture)?;
            self.update_summary()
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn record_intent_registered(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        generation: u64,
        root: GrainId,
        cause: codec::IntentCause,
    ) -> Result<u64, OverlayError> {
        self.check(store, ownership)?;
        if !self.replayed
            || (self.readiness != OverlayReadiness::Ready
                && cause != codec::IntentCause::LandedRefresh)
        {
            return Err(OverlayError::PendingReconciliation);
        }
        if generation > self.writer.ceiling {
            return Err(OverlayError::refused("receipt ceiling"));
        }
        self.append(&Record::IntentRegistered {
            generation,
            prepared_root: root,
            cause,
        })
    }
    /// Seal the prefix before candidate preparation releases its transaction.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn capture_boundary(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
    ) -> Result<BoundaryCapture, OverlayError> {
        self.ready(store, ownership)?;
        if self
            .namespace
            .stages
            .values()
            .any(|s| s.path.is_none() && (s.handles > 0 || !s.captures.is_empty()))
        {
            return Err(OverlayError::PendingBoundary);
        }
        let journal = self.journal.lock().map_err(Self::lock_error)?;
        let mut entries: Vec<_> = self.namespace.entries.values().cloned().collect();
        for entry in &mut entries {
            if let Some(stage_id) = entry.stage_id {
                let stage = self
                    .namespace
                    .stages
                    .get(&stage_id)
                    .ok_or_else(|| OverlayError::refused("commit stage missing"))?;
                if self.checkpoint_dirty(stage_id, stage)?.is_empty() {
                    entry.kind = OverlayKind::File {
                        content: stage.checkpoint().0,
                    };
                } else {
                    entry.kind = OverlayKind::File { content: None };
                }
            }
        }
        let (header, incarnation, through_seq) = (
            journal.header,
            journal.incarnation,
            journal.state.next_seq() - 1,
        );
        drop(journal);
        self.dirty_split_seq = through_seq;
        Ok(BoundaryCapture {
            header,
            instance: self.config.instance,
            incarnation,
            through_seq,
            entries,
        })
    }

    pub(crate) fn commit_graph_charge(&self) -> Result<u64, OverlayError> {
        commit_graph_charge_of(self.namespace.entries.values())
            .ok_or_else(|| OverlayError::refused("commit graph overflow"))
    }
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the one-shot boundary capability must be consumed"
    )]
    pub fn record_boundary(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        capture: BoundaryCapture,
        candidate: GrainId,
        publication_id: [u8; 16],
    ) -> Result<u64, OverlayError> {
        self.ready(store, ownership)?;
        self.check_boundary_capture(&capture)?;
        let appended = self.append(&Record::CommitBoundary {
            candidate,
            through_seq: capture.through_seq,
            publication_id,
        });
        let seq = appended.map_err(|error| self.name_capacity_error(error))?;
        self.last_boundary_seq = seq;
        self.dirty_split_seq = seq;
        Ok(seq)
    }
    /// Record a projected boundary, whose candidate holds the projection of
    /// `capture` with `selection`. Its residual replacement reserve passes
    /// from the seal to the boundary's completion slot. Work after it starts
    /// a new dirty span, while every span before stays whole for the
    /// residual its landing keeps.
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the one-shot boundary capability must be consumed"
    )]
    pub fn record_projected_boundary(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        capture: BoundaryCapture,
        candidate: GrainId,
        publication_id: [u8; 16],
        selection: Option<codec::ProjectedSelection>,
    ) -> Result<u64, OverlayError> {
        self.ready(store, ownership)?;
        self.check_boundary_capture(&capture)?;
        let appended = self.append(&Record::ProjectedBoundary {
            candidate,
            through_seq: capture.through_seq,
            publication_id,
            selection,
        });
        let seq = appended.map_err(|error| self.name_capacity_error(error))?;
        self.projected_seal = None;
        self.dirty_split_seq = seq;
        Ok(seq)
    }
    fn check_boundary_capture(&self, capture: &BoundaryCapture) -> Result<(), OverlayError> {
        let journal = self.journal.lock().map_err(Self::lock_error)?;
        if capture.header != journal.header
            || capture.instance != self.config.instance
            || capture.incarnation != journal.incarnation
            || capture.through_seq >= journal.state.next_seq()
        {
            return Err(OverlayError::refused("boundary capture context"));
        }
        Ok(())
    }
    /// # Errors
    /// Refuses invalid context, pending readiness, custody or persistence failures,
    /// and admission beyond the configured bounds. Evidence is preserved.
    pub fn record_landed(
        &mut self,
        store: &mut Store,
        ownership: &OwnershipStatus,
        proof: &LandedProof,
    ) -> Result<u64, OverlayError> {
        self.check(store, ownership)?;
        if !self.replayed {
            return Err(OverlayError::PendingReconciliation);
        }
        self.append(&Record::LandedCommit {
            boundary_seq: proof.boundary_seq,
            landed_root: proof.landed_root,
            landed_seq: proof.landed_seq,
        })
    }
}

fn usize_bound(value: u64) -> Result<usize, OverlayError> {
    usize::try_from(value).map_err(|_| OverlayError::refused("platform buffer bound"))
}

fn stage_id(name: &str) -> Option<u64> {
    if name.len() != 16
        || !name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    u64::from_str_radix(name, 16)
        .ok()
        .filter(|id| *id > 0 && *id <= codec::STAGE_ID_MAX)
}
fn verified(
    source: &mut dyn ContentSource,
    content: GrainId,
    offset: u64,
    n: usize,
) -> Result<Vec<u8>, OverlayError> {
    let bytes = source.read_verified(content, offset, n)?;
    if bytes.len() != n {
        return Err(OverlayError::refused("verified source range length"));
    }
    Ok(bytes)
}
pub(crate) fn point(
    faults: &FaultControl,
    name: &'static str,
    phase: &'static str,
    seq: u64,
) -> Result<(), OverlayError> {
    if let Some(action) = faults.point(name, phase, seq) {
        let _ = action;
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        if action == FaultAction::Crash {
            return Err(OverlayError::InjectedCrash);
        }
        return Err(OverlayError::Io(std::io::Error::other(
            "overlay injected fault",
        )));
    }
    Ok(())
}
fn write_step<P: OverlayIo>(
    io: &mut P,
    faults: &FaultControl,
    name: &'static str,
    path: &Path,
    offset: u64,
    bytes: &[u8],
    seq: u64,
) -> Result<(), OverlayError> {
    point(faults, name, "before", seq)?;
    if let Some(action) = faults.point(name, "partial", seq) {
        let n = match action {
            FaultAction::Short(n) => n.min(bytes.len()),
            _ => bytes.len() / 2,
        };
        io.write_at(
            path,
            offset,
            bytes
                .get(..n)
                .ok_or_else(|| OverlayError::refused("partial write range"))?,
        )?;
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        if action == FaultAction::Crash {
            return Err(OverlayError::InjectedCrash);
        }
        return Err(OverlayError::Io(std::io::Error::other(
            "overlay injected short write",
        )));
    }
    io.write_at(path, offset, bytes)?;
    point(faults, name, "after", seq)
}
fn sync_step<P: OverlayIo>(
    io: &mut P,
    faults: &FaultControl,
    name: &'static str,
    path: &Path,
    seq: u64,
) -> Result<(), OverlayError> {
    point(faults, name, "before", seq)?;
    io.sync(path)?;
    point(faults, name, "after", seq)
}
fn dense_zero<P: OverlayIo>(
    io: &mut P,
    faults: &FaultControl,
    path: &Path,
    mut start: u64,
    end: u64,
) -> Result<(), OverlayError> {
    let zeros = vec![0u8; BUFFER];
    while start < end {
        let n = usize_bound((end - start).min(BUFFER as u64))?;
        write_step(
            io,
            faults,
            "overlay.stage.write",
            path,
            160 + start,
            zeros
                .get(..n)
                .ok_or_else(|| OverlayError::refused("zero bound"))?,
            0,
        )?;
        start += n as u64;
    }
    Ok(())
}
#[expect(
    clippy::too_many_arguments,
    reason = "the ordered replacement needs both names and its fault context"
)]
pub(crate) fn durable_file<P: OverlayIo>(
    io: &mut P,
    faults: &FaultControl,
    area: &Path,
    temporary: &str,
    canonical: &str,
    bytes: &[u8],
    name: &'static str,
    seq: u64,
) -> Result<(), OverlayError> {
    let tmp = area.join(temporary);
    let dst = area.join(canonical);
    point(faults, name, "build", seq)?;
    io.create(&tmp)?;
    write_step(io, faults, name, &tmp, 0, bytes, seq)?;
    point(faults, name, "sync", seq)?;
    io.sync(&tmp)?;
    point(faults, name, "after_sync", seq)?;
    point(faults, name, "rename", seq)?;
    io.rename(&tmp, &dst)?;
    point(faults, name, "after_rename", seq)?;
    point(faults, name, "dir_sync", seq)?;
    io.sync_directory(area)?;
    point(faults, name, "after_dir_sync", seq)
}
