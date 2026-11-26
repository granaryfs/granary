// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Logical publication ownership; no guard spans transport or writer work.

use super::super::{CommitWalk, PublishedRoot, VerifiedBase, published::readback_refusal};
use super::{
    Arc, AtomicBool, BTreeMap, Clock, Construction, CoordinationError, Duration, FloorWake,
    GrainId, GrainSource, MonotonicClock, Mutex, Notify, OverlayIo, Reply, RuntimeRng, SyncContent,
    SyncEngine, SyncOptions, SyncProjectionQueue, SyncRemote, SyncRuntime, WorkspaceLease,
    WritableStore, before_send, refused, workspace_error,
};
use crate::{BoundaryCapture, LandedProof};
use crate::{http_store::seam_deadline, writable_start::AdoptionWalk};
use granary_core::{
    retained_submission::{Phase, Submission},
    rng::Rng as _,
    rootstore::RootStore,
};
use granary_store::bounds::ROOT_MAX_BYTES;
use std::collections::BTreeSet;

mod driver;
mod live;
mod projected;
mod rebase;
mod reporting;
pub(crate) use driver::{RuntimeSeams, build_landed_entries};
pub use live::LiveEnd;
#[cfg(test)]
pub(crate) use projected::Resumed;

#[derive(Clone, Copy)]
pub(crate) enum CommitDrive {
    Direct(crate::RecoveryIntent),
    Mount(crate::RecoveryIntent),
    Start(crate::RecoveryIntent),
    Background(crate::RecoveryIntent),
}

const SAVE_MARGIN: Duration = crate::DEFAULT_RESOLUTION_BOUND;

/// Allow one status read, one root probe, one publish, and the attempt and answer
/// saves. The start dispatch floor reserves the same allowance for both saves.
pub(crate) fn commit_send_budget() -> Duration {
    seam_deadline(0) + seam_deadline(ROOT_MAX_BYTES) * 2 + SAVE_MARGIN
}

fn startup_retry_ceiling(attempt: u32) -> u64 {
    (40_u64 << attempt.min(7)).min(5_000)
}

/// The operation a supervised construction runs as, and the serial of the
/// lane it opens, which its monitor releases if the construction is lost.
struct ConstructionOwner {
    operation: [u8; 16],
    serial: std::sync::OnceLock<u64>,
}

struct LandingRefresh<P: OverlayIo> {
    store: Arc<Mutex<WritableStore<P>>>,
    generation: u64,
}
impl<P: OverlayIo> LandingRefresh<P> {
    fn begin(
        store: Arc<Mutex<WritableStore<P>>>,
        local: &mut WritableStore<P>,
        generation: u64,
    ) -> Self {
        local.begin_landing_refresh(generation);
        Self { store, generation }
    }
}
impl<P: OverlayIo> Drop for LandingRefresh<P> {
    fn drop(&mut self) {
        if let Ok(mut store) = self.store.lock() {
            store.finish_landing_refresh(self.generation);
        }
    }
}

struct LocalContent<'a, S>(&'a S);
impl<S: SyncContent> GrainSource for LocalContent<'_, S> {
    fn has(&self, id: &GrainId) -> bool {
        self.0.has(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, granary_core::grainsource::GrainSourceError> {
        self.0.get_local(id)
    }
}

async fn bounded<E: SyncRuntime, F: std::future::Future>(
    runtime: &E,
    deadline: tokio::time::Instant,
    work: F,
) -> Result<F::Output, CoordinationError> {
    use std::future::Future as _;
    let mut timer =
        std::pin::pin!(runtime.sleep(deadline.saturating_duration_since(runtime.now())));
    let mut work = std::pin::pin!(work);
    std::future::poll_fn(|cx| {
        if runtime.now() >= deadline || timer.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(Err(refused("SyncDeadline")));
        }
        work.as_mut().poll(cx).map(Ok)
    })
    .await
}

/// Walk a commit candidate's whole manifest and match it against the expected
/// namespace. When `mapped` is given, every directory node, spill node and grain
/// the walk meets must be an id that binmap resolves; one that is not is a
/// corrupt base, refused before it can be adopted.
fn verify_commit_entries(
    root: GrainId,
    expected: &[crate::OverlayEntry],
    source: &dyn GrainSource,
    mapped: Option<&BTreeSet<GrainId>>,
) -> Result<CommitWalk, CoordinationError> {
    use granary_core::manifest::{self, EntryKind};
    manifest::validate_dir_tree(&root, &|id| source.get(id).ok())
        .map_err(|_| refused("SyncCommitManifest"))?;
    let mut contained = |id: &GrainId| -> Result<(), CoordinationError> {
        match mapped {
            Some(mapped) if !mapped.contains(id) => Err(refused("SyncCommitContainment")),
            _ => Ok(()),
        }
    };
    let mut remaining: BTreeMap<_, _> = expected
        .iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let mut work = vec![(root, Vec::new())];
    while let Some((id, prefix)) = work.pop() {
        if prefix.len() > manifest::DEPTH_MAX as usize {
            return Err(refused("SyncCommitNamespace"));
        }
        for entry in
            crate::writable_store::capture::entries_visiting(source, id, 1, &mut contained)?
        {
            let mut path = prefix.clone();
            path.push(entry.name);
            let expected = remaining
                .remove(&path)
                .ok_or_else(|| refused("SyncCommitNamespace"))?;
            match (&entry.kind, &expected.kind) {
                (EntryKind::Dir { child }, crate::OverlayKind::Directory) => {
                    work.push((*child, path));
                }
                (EntryKind::Symlink { target }, crate::OverlayKind::Symlink { target: old })
                    if target == old => {}
                (EntryKind::File { exec, size, grains }, crate::OverlayKind::File { content })
                    if *size == expected.size && *exec == expected.exec =>
                {
                    let payload = manifest::node::file_payload(*size, grains)
                        .map_err(|_| refused("SyncCommitManifest"))?;
                    if content.is_some_and(|id| id != GrainId::of(&payload)) {
                        return Err(refused("SyncCommitCheckpoint"));
                    }
                    crate::writable_store::capture::file_object_ids(
                        source,
                        grains,
                        &mut contained,
                    )?;
                }
                _ => return Err(refused("SyncCommitNamespace")),
            }
        }
    }
    if !remaining.is_empty() {
        return Err(refused("SyncCommitNamespace"));
    }
    Ok(CommitWalk::new(root))
}

/// One process-local commit admission, sealed only after earlier syncs drained.
/// Dropping it leaves admission closed; it never interprets cancellation as loss.
#[derive(Debug)]
pub(crate) struct CommitCapture {
    serial: u64,
    instance: [u8; 16],
    capture: BoundaryCapture,
    charge: u64,
    deadline: tokio::time::Instant,
    snapshot: Option<Arc<crate::SyncBoundary>>,
    /// What the candidate holds: the whole captured prefix, or a sync's
    /// projection of it.
    selection: crate::BoundarySelection,
}
impl CommitCapture {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn boundary(&self) -> &BoundaryCapture {
        &self.capture
    }
}

/// The lane remains owned across submission, retry, landing and refresh.
#[derive(Debug, Clone)]
pub struct RetainedCommit {
    serial: u64,
    instance: [u8; 16],
    publication: [u8; 16],
    boundary: u64,
    /// The boundary is projected: the overlay keeps a residual a rebase must
    /// leave replayable.
    projected: bool,
    entries: Vec<crate::OverlayEntry>,
    charge: u64,
    deadline: tokio::time::Instant,
    /// Every id the candidate's own acceptance mapped, when this process built
    /// it. A lane recovered after a restart has none and reads the landed
    /// binmap instead.
    mapped: Option<Arc<BTreeSet<GrainId>>>,
    /// Reporting and outage timing are shared by lane clones.
    observation: Arc<Mutex<reporting::State>>,
    /// The correlation id drawn when this process constructed the lane.
    operation_id: Option<crate::CorrelationId>,
    /// Recovery cannot reconstruct a process-local first-attempt token.
    recovered: bool,
}
impl RetainedCommit {
    #[must_use]
    pub fn boundary_seq(&self) -> u64 {
        self.boundary
    }
    #[cfg(test)]
    pub(crate) fn charge(&self) -> u64 {
        self.charge
    }
    /// Initial landings retain the exact path/inode set. After a rebase,
    /// same-kind shared paths retain their lane inode. New and kind-changed
    /// paths receive an inode only inside the installation transaction.
    fn check_landed_namespace(
        &self,
        proof: &LandedProof,
        rebased: bool,
    ) -> Result<(), CoordinationError> {
        let identities: BTreeMap<_, _> = self
            .entries
            .iter()
            .map(|entry| (&entry.path, entry))
            .collect();
        let mut paths = BTreeSet::new();
        if (!rebased && proof.entries.len() != self.entries.len())
            || proof.entries.iter().any(|entry| {
                entry.stage_id.is_some()
                    || matches!(entry.kind, crate::OverlayKind::File { content: None })
                    || !paths.insert(&entry.path)
                    || (!rebased
                        && identities
                            .get(&entry.path)
                            .is_none_or(|old| old.inode != entry.inode))
                    || identities.get(&entry.path).is_some_and(|old| {
                        std::mem::discriminant(&old.kind) == std::mem::discriminant(&entry.kind)
                            && old.inode != entry.inode
                    })
            })
        {
            return Err(refused("SyncCommitLandingIdentity"));
        }
        Ok(())
    }
    /// This lane, driven and landed under `deadline` instead of its own: a
    /// later caller takes over a retained lane under that caller's deadline.
    /// Only this clone changes; the retained lane keeps its own.
    #[must_use]
    pub(crate) fn with_deadline(mut self, deadline: tokio::time::Instant) -> Self {
        self.deadline = deadline;
        self
    }
    /// This lane as if its own acceptance had mapped exactly `mapped`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_mapped(mut self, mapped: BTreeSet<GrainId>) -> Self {
        self.mapped = Some(Arc::new(mapped));
        self
    }
}

// Only decision-table refusals qualify. Attempt-local admission failures such
// as a 429 cannot settle a previously accepted or unknown submission. A lost
// tuple is removed only by the coordinator's judged durable-lost transition.
pub(crate) fn terminal_non_landing(record: &Submission) -> bool {
    !crate::recovery::deferred_answer_pending(record)
        && !record.is_complete()
        && record.candidates.iter().all(|c| c.evidence.never_decided())
        && (record.candidates.is_empty()
            || record.last_response.as_ref().is_some_and(|answer| {
                matches!(
                    (answer.status, answer.token.as_slice()),
                    (400, b"invalid-candidate" | b"invalid-reference")
                        | (409, b"stale-base" | b"epoch-mismatch" | b"volume-damaged")
                        | (404, b"no-log")
                        | (413, b"too-large" | b"publish-work-limit")
                )
            }))
}

/// Whether `seq` is the immediate successor of a decoded parent seq; a parent
/// at `u64::MAX` has none.
fn follows(parent: u64, seq: u64) -> bool {
    parent.checked_add(1) == Some(seq)
}

impl<P, R, S, C, M, E> SyncEngine<P, R, S, C, M, E>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    /// Discard construction only while no durable boundary permits submission.
    /// # Errors
    /// A retained candidate, foreign lane, poison or persistence uncertainty.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "disposition consumes the one-shot capture capability"
    )]
    pub(crate) fn discard_commit(&self, capture: CommitCapture) -> Result<(), CoordinationError> {
        self.cancel_construction(capture.serial, capture.snapshot.as_deref(), capture.charge)
    }
    /// Reconstruct the process-local lane using only the durable journal and
    /// retained candidate. Sync admission was closed during engine attachment.
    /// # Errors
    /// No matching retained boundary, capacity, deadline or local persistence.
    pub fn recover_commit(
        &self,
        options: SyncOptions,
    ) -> Result<RetainedCommit, CoordinationError> {
        self.recover_commit_inner(options, None)
    }

    fn recover_commit_inner(
        &self,
        options: SyncOptions,
        stored: Option<&[u8]>,
    ) -> Result<RetainedCommit, CoordinationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?;
        if let Some(lane) = &state.commit {
            return Ok(lane.clone());
        }
        if state.constructing_commit {
            return Err(refused("SyncCommitConstructionPending"));
        }
        let deadline = self.deadline(options)?;
        let workspace = WorkspaceLease::new(&self.workspace_ledger, options.workspace_bytes)?;
        let lane = self.local(|local| {
            let (serial, boundary, projected, entries, record) = match stored {
                Some(stored) => local.recovered_landing_commit(stored)?,
                None => local.recovered_commit()?,
            };
            let charge = if stored.is_some() {
                0
            } else {
                crate::overlay_store::commit_graph_charge_of(&entries)
                    .ok_or_else(|| refused("SyncGraphOverflow"))?
            };
            if charge > options.workspace_bytes {
                return Err(workspace_error(
                    &self.volume,
                    charge,
                    options.workspace_bytes,
                ));
            }
            local.reserve_engine_graph(charge)?;
            Ok(RetainedCommit {
                serial,
                instance: local.snapshot().instance,
                publication: record.publication_id,
                boundary,
                projected,
                entries,
                charge,
                deadline,
                mapped: None,
                observation: Arc::default(),
                operation_id: None,
                recovered: true,
            })
        })?;
        state.commit = Some(lane.clone());
        state.commit_workspace = Some(workspace);
        Ok(lane)
    }
    pub(super) async fn wait_for_commit(
        &self,
        reply: &Reply,
        deadline: tokio::time::Instant,
    ) -> Result<(), CoordinationError> {
        let mut rng = RuntimeRng(self.runtime.as_ref());
        for attempt in 0..crate::STARTUP_ATTEMPTS {
            self.check_waiter(reply, deadline)?;
            if self.local(|local| local.sync_admission_open())? {
                return Ok(());
            }
            self.fault("sync.commit_wait", "before", 0, None, "none")
                .await?;
            let ceiling = startup_retry_ceiling(attempt);
            let delay = Duration::from_millis(rng.below(ceiling + 1));
            before_send(
                self.runtime.as_ref(),
                reply,
                deadline,
                self.runtime.sleep(delay),
            )
            .await?;
        }
        if self.local(|local| local.sync_admission_open())? {
            Ok(())
        } else {
            Err(refused("SyncCommitUnresolved"))
        }
    }

    /// Close new sync admission, drain all previously admitted completions, then
    /// seal a commit cursor. Writers continue while the logical lane is held.
    /// # Errors
    /// Conflict, unresolved registrations, deadline, poison or persistence.
    #[cfg(test)]
    pub(crate) async fn begin_commit(
        self: &Arc<Self>,
        options: SyncOptions,
    ) -> Result<CommitCapture, CoordinationError> {
        self.begin_commit_inner(options, false, None, false).await
    }

    async fn begin_commit_inner(
        self: &Arc<Self>,
        options: SyncOptions,
        snapshot: bool,
        owner: Option<&ConstructionOwner>,
        latched: bool,
    ) -> Result<CommitCapture, CoordinationError> {
        let deadline = self
            .runtime
            .now()
            .checked_add(options.resolution_bound)
            .ok_or_else(|| refused("SyncDeadlineOverflow"))?;
        let deadline = options.deadline.map_or(deadline, |d| deadline.min(d));
        let admission = self
            .runtime
            .timeout_at(deadline, self.admission.lock())
            .await
            .map_err(|_| refused("SyncDeadline"))?;
        let serial = self.close_for_construction(owner, latched, options.workspace_bytes)?;
        drop(admission);
        let mut rng = RuntimeRng(self.runtime.as_ref());
        // Each backoff ends in a poll: the last one too, before the refusal.
        for attempt in 0..=crate::STARTUP_ATTEMPTS {
            if self.runtime.now() >= deadline {
                self.cancel_construction(serial, None, 0)?;
                return Err(refused("SyncDeadline"));
            }
            if self.local(|local| Ok(local.sync_queue_empty()))? {
                let (capture, charge, snapshot) = match self
                    .local(|local| local.capture_commit(serial, options.workspace_bytes, snapshot))
                {
                    Ok(seal) => seal,
                    Err(error) => {
                        let _ = self.cancel_construction(serial, None, 0);
                        return Err(error);
                    }
                };
                let snapshot = snapshot.map(Arc::new);
                if let Err(error) = self.record_capture(serial, charge, snapshot.as_ref()) {
                    let _ = self.cancel_construction(serial, snapshot.as_deref(), charge);
                    return Err(error);
                }
                let instance = match self.local(|local| Ok(local.snapshot().instance)) {
                    Ok(instance) => instance,
                    Err(error) => {
                        let _ = self.cancel_construction(serial, snapshot.as_deref(), charge);
                        return Err(error);
                    }
                };
                let capture = CommitCapture {
                    serial,
                    instance,
                    capture,
                    charge,
                    deadline,
                    snapshot,
                    selection: crate::BoundarySelection::Tree,
                };
                if let Err(error) = self
                    .fault("sync.commit", "captured", serial, None, "none")
                    .await
                {
                    self.discard_commit(capture)?;
                    return Err(error);
                }
                return Ok(capture);
            }
            if attempt == crate::STARTUP_ATTEMPTS {
                break;
            }
            // Drawn from the ceiling's upper half: the drain waits for local
            // work, not a contended peer, so jitter must not cut its budget.
            let ceiling = startup_retry_ceiling(attempt);
            let half = ceiling / 2;
            let delay = Duration::from_millis(half + rng.below(ceiling - half + 1));
            if self
                .runtime
                .timeout_at(deadline, self.runtime.sleep(delay))
                .await
                .is_err()
            {
                self.cancel_construction(serial, None, 0)?;
                return Err(refused("SyncDeadline"));
            }
        }
        self.cancel_construction(serial, None, 0)?;
        Err(refused("SyncCommitUnresolved"))
    }

    /// Close the commit lane for a construction, recording a supervised
    /// construction's `owner`. The state lock spans the closure, so a
    /// takeover that finds the lane closed also finds it constructing, and
    /// no lane is closed for a supervised construction without its record.
    fn close_for_construction(
        &self,
        owner: Option<&ConstructionOwner>,
        latched: bool,
        workspace: u64,
    ) -> Result<u64, CoordinationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?;
        #[cfg(test)]
        if let Some(hook) = self
            .before_close_for_construction
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            hook();
        }
        let workspace = WorkspaceLease::new(&self.workspace_ledger, workspace)?;
        let serial = if latched {
            self.local(WritableStore::close_sync_admission_unless_latched)?
        } else {
            self.local(WritableStore::close_sync_admission)?
        };
        state.constructing_commit = true;
        state.commit_workspace = Some(workspace);
        if let Some(owner) = owner {
            // An owner opens one construction; its serial is set only here.
            let _ = owner.serial.set(serial);
            state.construction = Some(Construction {
                owner: owner.operation,
                serial,
                charge: 0,
                snapshot: None,
            });
        }
        Ok(serial)
    }

    /// Record what construction `serial`'s capture holds, for its release
    /// if its supervised task is lost.
    fn record_capture(
        &self,
        serial: u64,
        charge: u64,
        snapshot: Option<&Arc<crate::SyncBoundary>>,
    ) -> Result<(), CoordinationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?;
        if let Some(construction) = state
            .construction
            .as_mut()
            .filter(|construction| construction.serial == serial)
        {
            construction.charge = charge;
            construction.snapshot = snapshot.cloned();
        }
        Ok(())
    }

    /// Release the construction a lost supervised task opened, if it still
    /// holds the lane: a construction already released, or one another
    /// caller opened since, is never touched. As on a lost retention, a
    /// durable boundary or poison refuses this release and retains the lane
    /// for restart reconciliation.
    fn release_lost_construction(&self, owner: &ConstructionOwner) {
        let Some(&serial) = owner.serial.get() else {
            return;
        };
        let held = self
            .state
            .lock()
            .ok()
            .and_then(|state| state.lost_construction(&owner.operation, serial));
        if let Some((snapshot, charge)) = held {
            let _ = self.cancel_construction(serial, snapshot.as_deref(), charge);
        }
    }

    /// Release construction `serial` only while no durable boundary permits
    /// submission; a refused cancellation leaves the construction held.
    fn cancel_construction(
        &self,
        serial: u64,
        snapshot: Option<&crate::SyncBoundary>,
        charge: u64,
    ) -> Result<(), CoordinationError> {
        let _wake = FloorWake(&self.floor_changed);
        // The state lock spans the lane's release, so no other construction
        // closes the lane before this one's records are cleared.
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?;
        self.local(|local| local.cancel_unsent_commit(serial, snapshot, charge))?;
        state.release_construction(serial);
        Ok(())
    }

    /// Persist a candidate's commit boundary before its retained submission.
    /// Construction must use this capture and explicit store W; signatures and
    /// the captured base are checked here before the candidate can be retained.
    /// # Errors
    /// Foreign lane/base/writer, invalid candidate or local persistence.
    pub(crate) async fn retain_commit_mapped(
        self: &Arc<Self>,
        capture: CommitCapture,
        record: &Submission,
        mapped: Option<Arc<BTreeSet<GrainId>>>,
        operation_id: Option<crate::CorrelationId>,
    ) -> Result<RetainedCommit, CoordinationError>
    where
        R: RootStore,
    {
        // The capture moves into the closure; a lost closure is released
        // from these.
        let (serial, charge, snapshot) = (capture.serial, capture.charge, capture.snapshot.clone());
        let engine = self.clone();
        let record = record.clone();
        let verified = self
            .verify_commit_record(
                &record,
                capture.capture.entries(),
                capture.deadline,
                &reporting::Conflict::default(),
            )
            .await;
        let Ok(retained) = self
            .runtime
            .blocking(move || {
                if let Err(error) = verified {
                    let _ = engine.discard_commit(capture);
                    return Err(error);
                }
                engine.retain_commit_owned(capture, &record, mapped, operation_id)
            })
            .await
        else {
            // The closure was lost with its capture. As on a refused
            // retention, a durable boundary or poison refuses this release and
            // retains the lane for restart reconciliation.
            let _ = self.cancel_construction(serial, snapshot.as_deref(), charge);
            #[cfg(test)]
            self.retention_panics(super::RetentionPanic::AfterLostRetention);
            return Err(refused("SyncMaterializationLost"));
        };
        retained
    }

    fn retain_commit_owned(
        &self,
        capture: CommitCapture,
        record: &Submission,
        mapped: Option<Arc<BTreeSet<GrainId>>>,
        operation_id: Option<crate::CorrelationId>,
    ) -> Result<RetainedCommit, CoordinationError> {
        // A retained lane wakes a caller waiting for its construction.
        let _wake = FloorWake(&self.floor_changed);
        #[cfg(test)]
        self.retention_panics(super::RetentionPanic::BeforeRetain);
        let result = self.retain_commit_inner(&capture, record, mapped, operation_id);
        match result {
            Ok(lane) => {
                #[cfg(test)]
                self.retention_panics(super::RetentionPanic::AfterRetain);
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| refused("SyncStatePoisoned"))?;
                state.commit = Some(lane.clone());
                state.constructing_commit = false;
                state.construction = None;
                state.projected = None;
                Ok(lane)
            }
            Err(error) => {
                // An absent boundary proves that no submission was eligible.
                // A durable boundary or poison refuses this cleanup and retains
                // the lane for restart reconciliation.
                let _ = self.discard_commit(capture);
                Err(error)
            }
        }
    }

    /// Disarm every point a completed construction did not reach, so none
    /// panics a later construction.
    #[cfg(test)]
    fn disarm_retention_panics(&self) {
        self.retention_panic
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Panic here when a test armed this point, holding no lock.
    #[cfg(test)]
    fn retention_panics(&self, at: super::RetentionPanic) {
        let armed = {
            let mut points = self
                .retention_panic
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            points
                .iter()
                .position(|point| *point == at)
                .map(|index| points.swap_remove(index))
        };
        assert!(armed.is_none(), "the commit construction panics at {at:?}");
    }

    #[cfg(test)]
    pub(crate) async fn retain_commit(
        self: &Arc<Self>,
        capture: CommitCapture,
        record: &Submission,
    ) -> Result<RetainedCommit, CoordinationError>
    where
        R: RootStore,
    {
        self.retain_commit_mapped(capture, record, None, None).await
    }

    fn retain_commit_inner(
        &self,
        capture: &CommitCapture,
        record: &Submission,
        mapped: Option<Arc<BTreeSet<GrainId>>>,
        operation_id: Option<crate::CorrelationId>,
    ) -> Result<RetainedCommit, CoordinationError> {
        if self.runtime.now() >= capture.deadline {
            return Err(refused("SyncDeadline"));
        }
        let content = self
            .content
            .with_deadline(self.runtime.clone(), capture.deadline);
        // Provider callbacks never run inside the mediator transaction.
        let initial = granary_core::root::decode_root(&record.frozen.initial_root)
            .map_err(|_| refused("SyncCommitSignature"))?;
        for candidate in &record.candidates {
            let doc = granary_core::root::decode_root(&candidate.root)
                .map_err(|_| refused("SyncCommitSignature"))?;
            if candidate.number == 1 || doc.seq <= initial.seq {
                verify_commit_entries(
                    doc.manifest_root,
                    capture.capture.entries(),
                    &content,
                    None,
                )?;
            }
        }
        self.local(|local| {
            local.check_commit_lane(capture.serial)?;
            if local.snapshot().instance != capture.instance {
                return Err(refused("SyncCommitContext"));
            }
            let base = self.base.lock().map_err(|_| refused("SyncBasePoisoned"))?;
            for candidate in &record.candidates {
                let doc = granary_store::crypto::check_head(
                    &candidate.root,
                    record.volume.as_str(),
                    candidate.seq,
                    &self.trusted,
                )
                .map_err(|_| refused("SyncCommitSignature"))?;
                if doc.writer_uuid != local.writer_uuid()
                    || doc.parent != Some(base.id())
                    || !follows(base.seq(), doc.seq)
                {
                    return Err(refused("SyncCommitCandidateBinding"));
                }
            }
            if !matches!(record.phase, Phase::Ready)
                || record.candidates.len() != 1
                || record
                    .candidates
                    .first()
                    .is_none_or(|c| c.root != record.frozen.initial_root || c.evidence.started != 0)
            {
                return Err(refused("SyncCommitInitialRecord"));
            }
            let serial = capture.serial;
            let instance = capture.instance;
            let entries = capture.capture.entries().to_vec();
            let charge = capture.charge;
            let deadline = capture.deadline;
            if let Some(snapshot) = &capture.snapshot {
                local.overlay_transaction(|t| t.flush_sync_boundary(snapshot))?;
                local.release_sync_boundary(snapshot)?;
            }
            let boundary =
                local.retain_commit(serial, capture.capture.clone(), record, capture.selection)?;
            Ok(RetainedCommit {
                serial,
                instance,
                publication: record.publication_id,
                boundary,
                projected: matches!(capture.selection, crate::BoundarySelection::Projected(_)),
                entries,
                charge,
                deadline,
                mapped,
                observation: Arc::default(),
                operation_id,
                recovered: false,
            })
        })
    }

    /// Whether the engine or the mediator holds work an adoption would lose
    /// or race: a commit lane or its construction, a sync retained, being
    /// prepared or holding a projected lane, or a mediator not ready to
    /// adopt. The state lock is taken, then the mediator in one acquisition,
    /// the order a landing's install takes them.
    ///
    /// # Errors
    /// The mediator's own refusal: a store that refuses its reads and
    /// writes, so the view over it is closed.
    pub(crate) fn adoption_blocked(&self) -> Result<bool, CoordinationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?;
        let lane =
            state.commit.is_some() || state.construction.is_some() || state.constructing_commit;
        let syncs =
            !state.retained.is_empty() || state.preparing.is_some() || state.projected.is_some();
        let ready = self.local(WritableStore::adoption_ready)?;
        drop(state);
        Ok(lane || syncs || !ready)
    }

    /// Hold engine state an adoption waits for, alone: a commit lane under
    /// construction, a projected sync's closed lane, or a registered sync
    /// retained for completion, sealed over a clean overlay and released
    /// from it.
    #[cfg(test)]
    pub(crate) fn hold_adoption_for_test(&self, hold: super::EngineHold) {
        let reply = || {
            Arc::new(Reply {
                sender: Mutex::new(None),
                cancelled: AtomicBool::new(false),
                cancellation: Notify::new(),
                metrics: self.metrics.clone(),
                observed: false,
            })
        };
        let retained = matches!(hold, super::EngineHold::RetainedSync).then(|| {
            self.local(|local| {
                let boundary =
                    local.overlay_transaction(|t| t.seal_sync(crate::SyncTarget::Tree))?;
                local.release_sync_boundary(&boundary)?;
                Ok((local.pending_register_for_test(), boundary))
            })
            .expect("a clean overlay seals and releases a boundary")
        });
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match (hold, retained) {
            (super::EngineHold::Construction, _) => state.constructing_commit = true,
            (super::EngineHold::ProjectedSync, _) => state.projected = Some((None, 0, reply())),
            (super::EngineHold::RetainedSync, Some((request, boundary))) => {
                state.retained.insert(
                    u64::MAX,
                    super::Retained {
                        input: super::CaptureCoverageInput {
                            prepared_root: GrainId::of(b"retained"),
                            boundary: 0,
                            projections: Vec::new(),
                            mutations: Vec::new(),
                            identities: Vec::new(),
                        },
                        reply: reply(),
                        _workspace: Arc::new(
                            WorkspaceLease::new(&self.workspace_ledger, 0).unwrap(),
                        ),
                        request,
                        boundary,
                    },
                );
            }
            (super::EngineHold::RetainedSync, None) => {}
        }
    }

    /// Judge only durable retained evidence, never an invocation error/result.
    /// Unknown sends and admission failures keep the lane closed. Proven refusal
    /// returns the work to the overlay and fences this mount against another commit.
    /// # Errors
    /// Foreign lane or any candidate still able to land.
    pub(crate) fn finish_rejected_commit(
        &self,
        lane: &RetainedCommit,
    ) -> Result<(), CoordinationError> {
        let _wake = FloorWake(&self.floor_changed);
        let mut rejected = false;
        let result = self.local(|local| {
            if local.snapshot().instance != lane.instance {
                return Err(refused("SyncCommitContext"));
            }
            let record = local.commit_record(lane.serial, lane.publication)?;
            if !terminal_non_landing(&record) {
                return Err(refused("SyncCommitUnresolved"));
            }
            local.finish_non_landing(lane.serial, lane.boundary, lane.publication)?;
            local.fence_commit_conflict();
            rejected = true;
            local.release_engine_graph(lane.charge)?;
            Ok(())
        });
        // The proven refusal is terminal even if local bookkeeping could not release.
        if rejected && let Ok(mut state) = lane.observation.lock() {
            state.refusal = Some(crate::FailureClass::Refused);
        }
        result?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?;
        state.commit = None;
        state.commit_workspace = None;
        Ok(())
    }
}

impl<P, R, S, C, M, E> SyncEngine<P, R, S, C, M, E>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + RootStore + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    /// Every id the landed root's binmap resolves. This client's own acceptance
    /// holds it; a lane recovered after a restart has none and reads it back.
    async fn landed_binmap(
        &self,
        lane: &RetainedCommit,
        root: &PublishedRoot,
        deadline: tokio::time::Instant,
    ) -> Result<Arc<BTreeSet<GrainId>>, CoordinationError> {
        let frozen = self
            .local(|local| local.commit_record(lane.serial, lane.publication))?
            .frozen;
        if root.bytes() == frozen.initial_root
            && let Some(mapped) = &lane.mapped
        {
            return Ok(mapped.clone());
        }
        let state = bounded(
            self.runtime.as_ref(),
            deadline,
            crate::publish::state_from_published(self.remote.as_ref(), root),
        )
        .await?
        .map_err(|error| match error {
            crate::PublishError::Remote(error) => readback_refusal(&error),
            _ => refused("SyncCommitReadback"),
        })?;
        Ok(Arc::new(state.known.into_keys().collect()))
    }

    /// Finish a recovered landing directly, without entering publication dispatch.
    pub(crate) async fn finish_recovered_landing(
        self: &Arc<Self>,
        stored: Vec<u8>,
        options: SyncOptions,
    ) -> Result<(), CoordinationError> {
        let mut lane = self.recover_commit_inner(options, Some(&stored))?;
        let record = self.local(|local| local.commit_record(lane.serial, lane.publication))?;
        let Phase::Complete(done) = &record.phase else {
            return Err(refused("SyncCommitUnresolved"));
        };
        let initial = granary_core::root::decode_root(&record.frozen.initial_root)
            .map_err(|_| refused("RecoveryLandedEvidenceMissing"))?;
        let deadline = lane.deadline;
        let engine = self.clone();
        let manifest = granary_core::root::decode_root(&done.root)
            .map_err(|_| refused("SyncCommitSignature"))?
            .manifest_root;
        let captured = self
            .runtime
            .blocking(move || {
                let content = engine
                    .content
                    .with_deadline(engine.runtime.clone(), deadline);
                driver::build_landed_entries(initial.manifest_root, &[], &content)
            })
            .await
            .map_err(|_| refused("SyncMaterializationLost"))??;
        // Rebase verification restores the foreign closure before the landed
        // manifest walk; the ordinary finisher verifies it again before install.
        self.verify_commit_record(
            &record,
            &captured,
            deadline,
            &reporting::Conflict::default(),
        )
        .await
        .map_err(|error| self.commit_error(error, &lane))?;
        let engine = self.clone();
        let entries = self
            .runtime
            .blocking(move || {
                let content = engine
                    .content
                    .with_deadline(engine.runtime.clone(), deadline);
                driver::build_landed_entries(manifest, &captured, &content)
                    .map(|entries| (captured, entries))
            })
            .await
            .map_err(|_| refused("SyncMaterializationLost"))??;
        let (captured, entries) = entries;
        let charge = crate::overlay_store::commit_graph_charge_of(&captured)
            .ok_or_else(|| refused("SyncGraphOverflow"))?;
        if charge > options.workspace_bytes {
            return Err(workspace_error(
                &self.volume,
                charge,
                options.workspace_bytes,
            ));
        }
        self.local(|local| local.reserve_engine_graph(charge))?;
        lane.entries = captured;
        lane.charge = charge;
        self.state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?
            .commit = Some(lane.clone());
        // The ordinary finisher re-reads after durable completion so install
        // remains bound to the current stored witness.
        self.finish_landed_commit(
            &lane,
            LandedProof {
                boundary_seq: lane.boundary,
                landed_root: done.id,
                landed_seq: done.seq,
                captured_entries: lane.entries.clone(),
                entries,
            },
            options,
        )
        .await
    }

    /// Read back the stored landing bound to the retained candidate, refresh
    /// beyond every possible send, install the journal/base replacement, then
    /// reopen syncs.
    /// `proof.entries` is the caller-verified landed namespace, as required by
    /// the overlay replacement interface. A failed step keeps admission closed.
    /// # Errors
    /// Unresolved/foreign completion, readback, refresh or local persistence.
    #[expect(
        clippy::too_many_lines,
        reason = "readback, refresh and installation share one retained landing transaction"
    )]
    pub(crate) async fn finish_landed_commit(
        self: &Arc<Self>,
        lane: &RetainedCommit,
        mut proof: LandedProof,
        options: SyncOptions,
    ) -> Result<(), CoordinationError> {
        let (record, stored) = self.local(|local| {
            if local.snapshot().instance != lane.instance {
                return Err(refused("SyncCommitContext"));
            }
            let record = local.commit_record(lane.serial, lane.publication)?;
            let stored = local
                .recovery_commits()?
                .into_iter()
                .find_map(|commit| match commit {
                    crate::RecoveryCommit::Landed {
                        boundary_seq,
                        root,
                        seq,
                        ..
                    } if boundary_seq == lane.boundary => Some((seq, root)),
                    _ => None,
                });
            Ok((record, stored))
        })?;
        let deadline = self.deadline(options)?.min(lane.deadline);
        let Phase::Complete(done) = &record.phase else {
            return Err(refused("SyncCommitUnresolved"));
        };
        if proof.boundary_seq != lane.boundary
            || proof.landed_seq != done.seq
            || proof.landed_root != done.id
        {
            return Err(refused("SyncCommitLandingBinding"));
        }
        let initial = granary_core::root::decode_root(&record.frozen.initial_root)
            .map_err(|_| refused("SyncCommitSignature"))?;
        lane.check_landed_namespace(&proof, done.seq > initial.seq)?;
        self.verify_commit_record(
            &record,
            &lane.entries,
            deadline,
            &reporting::Conflict::default(),
        )
        .await
        .map_err(|error| self.commit_error(error, lane))?;
        let stored_id = if lane.recovered {
            let (_, stored_id) = bounded(
                self.runtime.as_ref(),
                deadline,
                crate::recovery::refetch_landing(
                    self.remote.as_ref(),
                    &record,
                    stored,
                    &self.trusted,
                ),
            )
            .await?
            .map_err(|error| match error {
                crate::RecoveryError::Remote(error) => readback_refusal(&error),
                crate::RecoveryError::RemoteIntegrity("probe chain root missing") => {
                    refused("ViewRootUnpublished")
                }
                crate::RecoveryError::RemoteIntegrity("stored landing mismatch") => {
                    refused("SyncCommitLandingBinding")
                }
                error => CoordinationError::Recovery(error),
            })?
            .ok_or_else(|| refused("SyncCommitUnresolved"))?;
            stored_id
        } else {
            let published = bounded(
                self.runtime.as_ref(),
                deadline,
                PublishedRoot::read(
                    self.remote.as_ref(),
                    &record.volume,
                    done.seq,
                    stored.map(|(_, id)| id),
                    &self.trusted,
                ),
            )
            .await??;
            if !crate::recovery::same_landing(&done.root, published.bytes()) {
                return Err(refused("SyncCommitLandingBinding"));
            }
            published.id()
        };
        proof.landed_root = stored_id;
        // Persist the chain-verified stored identity before refresh. A restart
        // re-fetches that exact landing rather than resubmitting.
        self.local(|local| local.record_landed_commit(lane.serial, &proof))?;
        self.fault("sync.commit", "landed_readback", lane.serial, None, "none")
            .await?;
        let published = self
            .runtime
            .timeout_at(
                deadline,
                PublishedRoot::read(
                    self.remote.as_ref(),
                    &record.volume,
                    done.seq,
                    Some(stored_id),
                    &self.trusted,
                ),
            )
            .await
            .map_err(|_| refused("SyncDeadline"))??;
        // The landed root is the next base: walk all of it once, checking that
        // its binmap resolves every object the incremental projection will
        // reuse unread.
        let mapped = self.landed_binmap(lane, &published, deadline).await?;
        let engine = self.clone();
        let entries = proof.entries.clone();
        let captured = lane.entries.clone();
        let manifest_root = published.doc().manifest_root;
        let (walk, captured_entries) = self
            .runtime
            .blocking(move || {
                let content = engine
                    .content
                    .with_deadline(engine.runtime.clone(), deadline);
                let captured_entries =
                    driver::build_landed_entries(initial.manifest_root, &captured, &content)?;
                let walk = verify_commit_entries(manifest_root, &entries, &content, Some(&mapped))?;
                Ok::<_, CoordinationError>((walk, captured_entries))
            })
            .await
            .map_err(|_| refused("SyncMaterializationLost"))??;
        proof.captured_entries = captured_entries;
        let landed = VerifiedBase::landed(
            published.bytes().to_vec(),
            record.volume.as_str(),
            &self.trusted,
            &walk,
        )?;
        let refresh = self.local(|local| {
            local.check_commit_lane(lane.serial)?;
            if published.doc().writer_uuid != local.writer_uuid() {
                return Err(refused("SyncCommitCandidateBinding"));
            }
            if local.landed_refresh_registered(published.bytes(), !lane.recovered)? {
                return Ok(None);
            }
            let request = local.prepare_registration_inner(
                published.bytes(),
                vec![],
                self.wall.as_ref(),
                |d, p| granary_store::crypto::check_signatures(d, p, &self.trusted).is_ok(),
            )?;
            let generation = crate::writable_store::sync_engine::generation(&request)?;
            // Returned at once: its drop takes the store, which this closure holds.
            let refresh = LandingRefresh::begin(self.store.clone(), local, generation);
            Ok(Some((request, refresh)))
        })?;
        if let Some((request, refresh)) = refresh {
            self.fault(
                "sync.commit",
                "landed_refresh",
                lane.serial,
                Some(GrainId::of(request.bytes())),
                "none",
            )
            .await?;
            let reply = Reply {
                sender: Mutex::new(None),
                cancelled: AtomicBool::new(false),
                cancellation: Notify::new(),
                metrics: self.metrics.clone(),
                observed: false,
            };
            self.reconcile(&request, &reply, deadline).await?;
            drop(refresh);
        }
        if let Some(hook) = self.view_hook.get().cloned() {
            // A shutdown whose adapter is gone installs without the gate.
            let unattended = self
                .local_install
                .load(std::sync::atomic::Ordering::Acquire);
            // The install owns admission, the view switch and the
            // revocation, so it runs to its end without this caller, which
            // stops waiting at its deadline.
            let engine = self.clone();
            let lane = lane.clone();
            let driver = driver::DriverGuard::share(&self.commit_driver, &self.floor_changed);
            let install = self.runtime.spawn(async move {
                let _driver = driver;
                engine
                    .install_owned(hook, lane, proof, landed, published, deadline, unattended)
                    .await
            });
            return self
                .runtime
                .timeout_at(deadline, install)
                .await
                .map_err(|_| refused("SyncDeadline"))?
                .map_err(|_| refused("SyncSupervisorLost"))?;
        }
        let admission = self
            .runtime
            .timeout_at(deadline, self.admission.lock())
            .await
            .map_err(|_| refused("SyncDeadline"))?;
        let result = self.install_landed(lane, proof, landed, None);
        drop(admission);
        result
            .map(|_| ())
            .map_err(|error| self.commit_error(error, lane))
    }

    /// Run the hook's install under engine admission, gated or `unattended`,
    /// then send its revocation once admission is released.
    #[expect(
        clippy::too_many_arguments,
        reason = "the landing's lane, proof, base and root, its bound and its install mode"
    )]
    async fn install_owned(
        self: Arc<Self>,
        hook: Arc<dyn super::MountViewHook>,
        lane: RetainedCommit,
        proof: LandedProof,
        landed: VerifiedBase,
        published: PublishedRoot,
        deadline: tokio::time::Instant,
        unattended: bool,
    ) -> Result<(), CoordinationError> {
        let admission = self
            .runtime
            .timeout_at(deadline, self.admission.lock())
            .await
            .map_err(|_| refused("SyncDeadline"))?;
        let (publication, observation) = (lane.publication, lane.observation.clone());
        let engine = self.clone();
        let commit: super::LandedCommit =
            Box::new(move |pin| engine.install_landed(&lane, proof, landed, Some(pin)));
        let (result, revocation) = if unattended {
            hook.install_unattended(published, deadline, commit).await
        } else {
            hook.install(published, deadline, commit).await
        };
        drop(admission);
        revocation.send();
        result.map_err(|error| self.lane_error(error, publication, &observation))
    }

    /// Adopt the head another writer published at `seq` as the mount's view.
    /// The root is read before admission, as a landing's readback is; the
    /// install then runs as one supervised operation, which a caller that
    /// stops waiting at the deadline does not stop.
    ///
    /// An unbound hook refuses `ViewHookUnbound`. That arm is an equivalent
    /// mutant, named rather than chased: only the binding that sets the
    /// hook arms the observer that calls this.
    ///
    /// # Errors
    /// "No answer yet": the root read's refusal, `SyncDeadline`,
    /// `SyncSupervisorLost`, or the install's own transient refusal.
    pub(crate) async fn adopt_head(
        self: &Arc<Self>,
        seq: u64,
    ) -> Result<super::Adopted, CoordinationError> {
        let hook = self
            .view_hook
            .get()
            .cloned()
            .ok_or_else(|| refused("ViewHookUnbound"))?;
        let deadline = self.deadline(SyncOptions::default())?;
        // Advisory: a head the pin has already passed, or one a journal
        // cannot carry, is refused before its root is read or its tree
        // walked. The install checks it again under the gate.
        let pin = self.local(|local| Ok(local.mount_pin().map(|pin| pin.base_seq)))?;
        if pin.is_some_and(|pin| !super::head_above_pin(pin, seq)) {
            return Ok(super::Adopted::Refused {
                cause: refused("ViewHeadRefused"),
            });
        }
        let volume = self.local(|local| Ok(local.snapshot().volume.clone()))?;
        let published = self
            .runtime
            .timeout_at(
                deadline,
                PublishedRoot::read(self.remote.as_ref(), &volume, seq, None, &self.trusted),
            )
            .await
            .map_err(|_| refused("SyncDeadline"))??;
        let engine = self.clone();
        let adoption = self
            .runtime
            .spawn(async move { engine.adopt_owned(hook, published, deadline).await });
        self.runtime
            .timeout_at(deadline, adoption)
            .await
            .map_err(|_| refused("SyncDeadline"))?
            .map_err(|_| refused("SyncSupervisorLost"))?
    }

    /// Run the hook's adoption under engine admission, which excludes every
    /// path that could open a lane or admit a sync, then send its revocation
    /// once admission is released.
    async fn adopt_owned(
        self: Arc<Self>,
        hook: Arc<dyn super::MountViewHook>,
        published: PublishedRoot,
        deadline: tokio::time::Instant,
    ) -> Result<super::Adopted, CoordinationError> {
        let admission = self
            .runtime
            .timeout_at(deadline, self.admission.lock())
            .await
            .map_err(|_| refused("SyncDeadline"))?;
        let (check, commit, root) = (self.clone(), self.clone(), published.clone());
        let (result, revocation) = hook
            .adopt(
                published,
                deadline,
                super::AdoptionCommit {
                    check: Box::new(move || check.adoption_blocked()),
                    commit: Box::new(move |pin, walk, entries| {
                        commit.install_adopted(&root, pin, &walk, entries)
                    }),
                },
            )
            .await;
        drop(admission);
        revocation.send();
        result
    }

    /// Close and revoke the view over a store that refuses its own reads,
    /// through the hook under engine admission.
    ///
    /// # Errors
    /// `ViewHookUnbound`; `SyncDeadline` for admission or a slot not
    /// returned in time; `SyncSupervisorLost`; `ViewAdapterLost`. Nothing
    /// was closed on any of them.
    async fn close_dead_store(
        self: &Arc<Self>,
        error: CoordinationError,
    ) -> Result<(), CoordinationError> {
        let hook = self
            .view_hook
            .get()
            .cloned()
            .ok_or_else(|| refused("ViewHookUnbound"))?;
        let deadline = self.deadline(SyncOptions::default())?;
        let engine = self.clone();
        let close = self.runtime.spawn(async move {
            let admission = engine
                .runtime
                .timeout_at(deadline, engine.admission.lock())
                .await
                .map_err(|_| refused("SyncDeadline"))?;
            let (result, revocation) = hook.close(error, deadline).await;
            drop(admission);
            revocation.send();
            result
        });
        self.runtime
            .timeout_at(deadline, close)
            .await
            .map_err(|_| refused("SyncDeadline"))?
            .map_err(|_| refused("SyncSupervisorLost"))?
    }

    /// Replace the clean overlay with the adopted head and bind `pin` as the
    /// mount's view in one mediator acquisition, then set the adopted base.
    /// No lane or queue is released: an adoption runs only when none is held.
    /// The caller holds admission.
    fn install_adopted(
        &self,
        published: &PublishedRoot,
        pin: Arc<crate::writable_store::ViewContext>,
        walk: &AdoptionWalk,
        entries: Vec<crate::OverlayEntry>,
    ) -> Result<crate::ViewChange, CoordinationError> {
        let adopted = VerifiedBase::adopted(published, walk)?;
        let state = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?;
        let change = self.local(|local| {
            let change = local.replace_adopted(published.id(), published.seq(), entries)?;
            local.bind_mount(pin);
            Ok(change)
        })?;
        *self.base.lock().map_err(|_| refused("SyncBasePoisoned"))? = adopted;
        drop(state);
        Ok(change)
    }

    /// Replace the overlay with the landing and bind `pin` as the mount's
    /// view in one mediator acquisition, then release the lane and set the
    /// landed base. The caller holds admission and maps the error.
    fn install_landed(
        &self,
        lane: &RetainedCommit,
        proof: LandedProof,
        landed: VerifiedBase,
        pin: Option<Arc<crate::writable_store::ViewContext>>,
    ) -> Result<crate::ViewChange, CoordinationError> {
        // A reopened lane wakes a projected sync waiting for its drain.
        let _wake = FloorWake(&self.floor_changed);
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?;
        let change = self.local(|local| {
            let change = local.install_commit_base(lane.serial, proof)?;
            if let Some(pin) = pin {
                local.bind_mount(pin);
            }
            Ok(change)
        })?;
        self.local(|local| local.release_engine_graph(state.queue_charge))?;
        state.queue = SyncProjectionQueue::default();
        state.queue_charge = 0;
        self.local(|local| local.release_engine_graph(lane.charge))?;
        state.commit = None;
        state.commit_workspace = None;
        *self.base.lock().map_err(|_| refused("SyncBasePoisoned"))? = landed;
        Ok(change)
    }
}

impl<P, R, S, C, M, E> super::HeadAdopter for Arc<SyncEngine<P, R, S, C, M, E>>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + RootStore + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    fn pin(&self) -> Result<(GrainId, u64), CoordinationError> {
        self.local(|local| {
            // A store that refuses its own base refuses here: poisoned,
            // fenced or in a commit conflict.
            local.mount_base()?;
            let pin = local.mount_pin().ok_or_else(|| refused("ViewPending"))?;
            Ok((pin.base_id, pin.base_seq))
        })
    }
    fn adoption_blocked(&self) -> Result<bool, CoordinationError> {
        SyncEngine::adoption_blocked(self)
    }
    fn adopt(&self, seq: u64) -> super::AdopterFuture<'_, super::Adopted> {
        Box::pin(self.adopt_head(seq))
    }
    fn close(&self, error: CoordinationError) -> super::AdopterFuture<'_, ()> {
        Box::pin(self.close_dead_store(error))
    }
    fn answered(&self) {
        self.answered
            .store(true, std::sync::atomic::Ordering::Release);
        self.floor_changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests;
