// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Sync engine attachment, sync lifecycle, and mount view barriers.

use super::{OverlayIo, WritableMount, mount_error, write_error};
use crate::{
    AuthorityTransport, ClientMetrics, CoordinationError, MonotonicClock, MountViewContext,
    OverlayError, SharedWritableStore, SyncContent, SyncEngine, SyncRemote, SyncRuntime,
    TokioSyncRuntime, ViewCause, ViewOutcome, WritableStore,
    sync::{Adopted, Begin, HeadObserver, Observed, PublishedRoot, VIEW_PROBE_DEADLINE},
    writable_store::{AdmittedSync, ViewContext},
};
use granary_core::{
    binfmt::FRAME_COMP_MAX,
    binmap::ShardEntry,
    binstore::BinStore,
    clock::Clock,
    grainsource::{GrainSource, GrainSourceError},
    hash::GrainId,
    manifest::{self, FileGrains},
    rootstore::{RootStore, RootStoreError},
    secure_random::SecureRandom,
};
use granary_store::{bounds::META_MAX_BYTES, crypto::TrustedKeys};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, Weak},
};

fn refused(reason: &'static str) -> CoordinationError {
    crate::sync::refused(reason)
}

fn overlay_error(error: CoordinationError) -> OverlayError {
    match error {
        CoordinationError::Overlay(err) => err,
        CoordinationError::Refused(reason) => OverlayError::Refused(reason),
        other => OverlayError::Io(std::io::Error::other(other.to_string())),
    }
}

fn source_error(id: GrainId, error: CoordinationError) -> GrainSourceError {
    match error {
        CoordinationError::Overlay(OverlayError::ContentUnavailable) => {
            GrainSourceError::Missing(id)
        }
        CoordinationError::Overlay(OverlayError::ContentCorrupt) => GrainSourceError::Corrupt(id),
        other => GrainSourceError::Backend(other.to_string()),
    }
}

fn sync_write_error(error: granary_fuse::WriteError) -> granary_fuse::MountSyncError {
    match error {
        granary_fuse::WriteError::Backend(error) => granary_fuse::MountSyncError::Backend(error),
        _ => granary_fuse::MountSyncError::InvalidHandle,
    }
}

/// A job owns one object hold independently of every kernel descriptor.
struct ObjectLease<P: OverlayIo> {
    mediator: SharedWritableStore<P>,
    inode: u64,
}

impl<P: OverlayIo> ObjectLease<P> {
    fn acquire(
        mediator: SharedWritableStore<P>,
        node: &crate::OverlayEntry,
    ) -> Result<Self, CoordinationError> {
        mediator.with(|store| {
            store.guard_view()?;
            let (count, stage) = store
                .object_leases
                .get(&node.inode)
                .copied()
                .unwrap_or((0, node.stage_id));
            let count = count
                .checked_add(1)
                .ok_or_else(|| refused("SyncLeaseExhausted"))?;
            if let Some(stage) = stage {
                store.overlay_transaction(|overlay| overlay.hold_stage(stage))?;
            }
            store.object_leases.insert(node.inode, (count, stage));
            Ok(())
        })?;
        Ok(Self {
            mediator,
            inode: node.inode,
        })
    }
}

impl<P: OverlayIo> Drop for ObjectLease<P> {
    fn drop(&mut self) {
        let _ = self.mediator.release_lease(self.inode);
    }
}

pub(super) type SyncSeal<P> = Box<
    dyn FnOnce(&mut WritableStore<P>) -> Result<Option<crate::SyncBoundary>, CoordinationError>
        + Send,
>;
type BeforeSync = Option<Box<dyn FnOnce() -> Result<(), CoordinationError> + Send>>;
/// A job's seal, the hold it keeps until its work ends, the check it runs
/// first, and its admission, which counts it for a shutdown's drain until
/// it has answered.
pub(super) type SyncJobs<P> = Arc<
    dyn Fn(
            SyncSeal<P>,
            Box<dyn Send>,
            BeforeSync,
            AdmittedSync<P>,
        ) -> Box<dyn granary_fuse::MountSyncJob>
        + Send
        + Sync,
>;

type ShrinkAction = Box<dyn FnMut() -> Result<(), CoordinationError> + Send>;
pub(super) type ShrinkJobs<P> = Arc<
    dyn Fn(u64, u64, ShrinkAction, AdmittedSync<P>) -> Box<dyn granary_fuse::MountSyncJob>
        + Send
        + Sync,
>;

/// The mount's one entropy source, shared by every job that draws from it.
struct SharedEntropy<T>(Arc<Mutex<T>>);

impl<T> Clone for SharedEntropy<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: SecureRandom> SecureRandom for SharedEntropy<T> {
    fn fill(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fill(dest)
    }
}

/// Each job seals its file or directory and answers as `profile` says;
/// a published job draws its publication identity from `secure`.
fn mount_sync_jobs<P, R, S, C, M, E, T>(
    engine: Arc<SyncEngine<P, R, S, C, M, E>>,
    reply_faults: &crate::FaultControl,
    secure: SharedEntropy<T>,
    profile: super::SyncProfile,
    workspace_bytes: u64,
) -> SyncJobs<P>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + AuthorityTransport + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
    T: SecureRandom + Send + 'static,
{
    let job_engine = engine;
    let runtime = job_engine.runtime_for_mount();
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    let reply_faults = reply_faults.clone();
    #[cfg(not(any(test, feature = "overlay-fault-tests")))]
    let _ = reply_faults;
    let handle = tokio::runtime::Handle::try_current().ok();
    Arc::new(move |seal, hold, before, admitted| {
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        let reply_faults = reply_faults.clone();
        let engine = job_engine.clone();
        let runtime = runtime.clone();
        let secure = secure.clone();
        let deadline = runtime.now() + crate::DEFAULT_RESOLUTION_BOUND;
        let handle = handle.clone();
        Box::new(ClientMountSyncJob(Box::new(move |completion| {
            let _entered = handle.as_ref().map(tokio::runtime::Handle::enter);
            // The fsync's span encloses the whole job, admission included; the
            // runtime carries it into the spawned work.
            let drawn = crate::CorrelationId::draw(&mut secure.clone());
            let span = if let Ok(id) = drawn {
                crate::operation_span(crate::OperationKind::Fsync, &id)
            } else {
                crate::observe::op_failed(
                    crate::OperationKind::Session,
                    crate::FailureClass::Unavailable,
                );
                tracing::Span::none()
            };
            let _operation = span.enter();
            let task_runtime = runtime.clone();
            drop(runtime.spawn(async move {
                let admission = match before {
                    Some(before) => task_runtime
                        .blocking(before)
                        .await
                        .map_err(|_| refused("SyncLocalTransactionLost"))
                        .and_then(std::convert::identity),
                    None => Ok(()),
                };
                let options = crate::SyncOptions {
                    workspace_bytes,
                    deadline: Some(deadline),
                    ..crate::SyncOptions::default()
                };
                let result = match (admission, profile) {
                    (Ok(()), super::SyncProfile::DurablePrepared) => {
                        engine.sync_sealed(seal, options).wait().await
                    }
                    (Ok(()), super::SyncProfile::Published) => {
                        engine.sync_published(seal, options, secure).wait().await
                    }
                    (Err(error), _) => Err(error),
                };
                #[cfg(any(test, feature = "overlay-fault-tests"))]
                let result = {
                    let delivery = task_runtime
                        .blocking(move || {
                            reply_faults.sync_point("fuse.sync.reply", "before", 0, None, "none")
                        })
                        .await
                        .map_err(|_| refused("SyncLocalTransactionLost"))
                        .and_then(|action| {
                            if action.is_some() {
                                Err(refused("SyncInjectedFault"))
                            } else {
                                Ok(())
                            }
                        });
                    result.and(delivery)
                };
                drop(hold);
                completion(result.map_err(|error| sync_mount_error(&error)));
                drop(admitted);
            }));
        })))
    })
}

fn mount_shrink_jobs<P, R, S, C, M, E>(engine: Arc<SyncEngine<P, R, S, C, M, E>>) -> ShrinkJobs<P>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    let shrink_engine = engine;
    let handle = tokio::runtime::Handle::try_current().ok();
    Arc::new(move |stage, size, action, admitted| {
        let engine = shrink_engine.clone();
        let runtime = engine.runtime_for_mount();
        let deadline = runtime.now() + crate::DEFAULT_RESOLUTION_BOUND;
        let handle = handle.clone();
        Box::new(ClientMountSyncJob(Box::new(move |completion| {
            let _entered = handle.as_ref().map(tokio::runtime::Handle::enter);
            let task_runtime = runtime.clone();
            drop(runtime.spawn(async move {
                let mut retained_action = Some(action);
                let result = loop {
                    if let Err(error) = engine.wait_stage_floor(stage, size, deadline).await {
                        break Err(error);
                    }
                    let Some(mut action) = retained_action.take() else {
                        break Err(refused("SyncLocalTransactionLost"));
                    };
                    let completed = task_runtime
                        .blocking(move || {
                            let result = action();
                            (action, result)
                        })
                        .await;
                    let Ok((next_action, result)) = completed else {
                        break Err(refused("SyncLocalTransactionLost"));
                    };
                    retained_action = Some(next_action);
                    match result {
                        Err(CoordinationError::Overlay(OverlayError::PendingShrink)) => {}
                        result => break result,
                    }
                };
                drop(retained_action);
                completion(result.map_err(|error| sync_mount_error(&error)));
                drop(admitted);
            }));
        })))
    })
}

struct ClientMountSyncJob(Box<dyn FnOnce(granary_fuse::SyncCompletion) + Send>);
impl granary_fuse::MountSyncJob for ClientMountSyncJob {
    fn start(self: Box<Self>, completion: granary_fuse::SyncCompletion) {
        (self.0)(completion);
    }
}

/// The mount's pinned view, read inside the caller's mediator acquisition.
///
/// A store with no pin bound refuses `ViewPending`. That arm is an equivalent
/// mutant, named rather than chased: the start binds the pin before the
/// mediator is shared, nothing unbinds it, and every caller runs on a mount's
/// mediator, so no caller reaches it without a pin.
pub(super) fn pinned<P: OverlayIo>(
    local: &WritableStore<P>,
) -> Result<Arc<ViewContext>, CoordinationError> {
    local.mount_pin().ok_or_else(|| refused("ViewPending"))
}

/// Read `id` from the mediator's sole store, authenticated by id: `None` when
/// it is absent, and a corrupt or failed read as its overlay error.
fn stored_object(
    immutable: &crate::ImmutableContent<'_>,
    id: &GrainId,
) -> Result<Option<Vec<u8>>, CoordinationError> {
    match immutable.get(id) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(GrainSourceError::Missing(_)) => Ok(None),
        Err(GrainSourceError::Corrupt(_)) => Err(OverlayError::ContentCorrupt.into()),
        Err(GrainSourceError::Backend(msg)) => {
            Err(OverlayError::Io(std::io::Error::other(msg)).into())
        }
    }
}

/// Production [`SyncContent`] and [`GrainSource`] bridge over the mount's
/// single [`SharedWritableStore`] mediator. The view it resolves through is
/// the mediator's pin, read in the same acquisition as every content call.
pub struct MountSyncContent<R, P: OverlayIo = crate::OverlayDisk, E = TokioSyncRuntime> {
    mediator: SharedWritableStore<P>,
    remote: Arc<R>,
    operation: Option<(Arc<E>, tokio::time::Instant)>,
    /// Reads past the readiness gate, for a start finishing a store before
    /// it serves.
    recovery: bool,
}

impl<R, P: OverlayIo, E> Clone for MountSyncContent<R, P, E> {
    fn clone(&self) -> Self {
        Self {
            mediator: self.mediator.clone(),
            remote: Arc::clone(&self.remote),
            operation: self
                .operation
                .as_ref()
                .map(|(runtime, deadline)| (runtime.clone(), *deadline)),
            recovery: self.recovery,
        }
    }
}

impl<R, P: OverlayIo, E> std::fmt::Debug for MountSyncContent<R, P, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountSyncContent").finish_non_exhaustive()
    }
}

impl<R, P: OverlayIo> MountSyncContent<R, P> {
    /// The bridge a start finishing what the store holds reads through, on
    /// `mediator`'s pin: the store's own refusals and an open overlay stand
    /// in for readiness, so a commit lane still recovering can be read.
    pub(crate) fn for_recovery(mediator: SharedWritableStore<P>, remote: Arc<R>) -> Self {
        Self {
            mediator,
            remote,
            operation: None,
            recovery: true,
        }
    }
}

impl<R, P: OverlayIo, E> MountSyncContent<R, P, E> {
    /// Return a handle to the sole [`SharedWritableStore`] mediator.
    #[must_use]
    pub const fn shared_mediator(&self) -> &SharedWritableStore<P> {
        &self.mediator
    }

    /// Return the pinned `(base_id, base_seq)` this bridge resolves through.
    ///
    /// # Errors
    /// Mediator lock poison, or `ViewPending` when no pin is bound.
    pub fn pinned_base(&self) -> Result<(GrainId, u64), CoordinationError> {
        self.mediator.with(|local| {
            let pin = pinned(local)?;
            Ok((pin.base_id, pin.base_seq))
        })
    }

    /// Bind remote reads to the operation's attached runtime and deadline.
    /// Cold reads must run through the runtime's blocking seam.
    #[must_use]
    pub fn with_deadline<E2>(
        &self,
        runtime: Arc<E2>,
        deadline: tokio::time::Instant,
    ) -> MountSyncContent<R, P, E2> {
        MountSyncContent {
            mediator: self.mediator.clone(),
            remote: self.remote.clone(),
            operation: Some((runtime, deadline)),
            recovery: self.recovery,
        }
    }

    /// The content facade this bridge reads through: under readiness, or
    /// past it for a store being finished.
    fn content<'a>(
        &self,
        local: &'a mut WritableStore<P>,
    ) -> Result<crate::ImmutableContent<'a>, CoordinationError> {
        if self.recovery {
            local.immutable_content_for_recovery()
        } else {
            local.immutable_content()
        }
    }

    /// One content transaction on the pinned view: the pin and the admitted
    /// base are read in the same acquisition, and a base that has moved away
    /// from the pin refuses `ViewPending` before the action runs.
    fn with_content<T>(
        &self,
        action: impl FnOnce(
            &mut crate::ImmutableContent<'_>,
            &Arc<ViewContext>,
        ) -> Result<T, CoordinationError>,
    ) -> Result<T, CoordinationError> {
        self.mediator.with(|local| {
            let pin = pinned(local)?;
            let mut immutable = self.content(local)?;
            if (immutable.view().base_id, immutable.view().base_seq) != (pin.base_id, pin.base_seq)
            {
                return Err(refused("ViewPending"));
            }
            action(&mut immutable, &pin)
        })
    }

    /// Read `id` from the mediator's sole store without comparing the view:
    /// the store authenticates by id, so the bytes are the id's under every
    /// view. A copy that fails that authentication is a miss, so the caller
    /// fetches the id through its own binmap; the mediator's own readiness,
    /// fencing and poison refusals stand.
    fn get_stored(&self, id: &GrainId) -> Result<Option<Vec<u8>>, CoordinationError> {
        self.mediator
            .with(|local| match stored_object(&self.content(local)?, id) {
                Err(CoordinationError::Overlay(OverlayError::ContentCorrupt)) => Ok(None),
                stored => stored,
            })
    }
}

impl<R: BinStore + Send + Sync + 'static, P: OverlayIo, E: SyncRuntime + 'static>
    MountSyncContent<R, P, E>
{
    /// Resolve `id` from the single mediator [`WritableStore`], or fetch a cold
    /// verified-base object from `R` outside the mediator lock and install it
    /// via [` crate::ImmutableContent::put_object `].
    ///
    /// # Errors
    /// Unready or drifted mediator view, missing or unmapped object, remote
    /// transport failure, absent operation deadline, deadline expiry, or corrupt frame/hash.
    pub fn fetch_immutable(&self, id: GrainId) -> Result<Vec<u8>, CoordinationError> {
        self.fetch_immutable_in(id, None)
    }

    fn fetch_immutable_in(
        &self,
        id: GrainId,
        view: Option<&ViewContext>,
    ) -> Result<Vec<u8>, CoordinationError> {
        let (cached, pin) =
            self.with_content(|immutable, pin| Ok((stored_object(immutable, &id)?, pin.clone())))?;
        let pin = view.unwrap_or(&pin);
        if let Some(bytes) = cached {
            return Ok(bytes);
        }
        if let Some((size, grains)) = pin.pin_files.get(&id) {
            let bytes = manifest::node::file_payload(*size, grains)
                .map_err(|_| OverlayError::ContentCorrupt)?;
            if GrainId::of(&bytes) != id {
                return Err(OverlayError::ContentCorrupt.into());
            }
            self.with_content(|immutable, _| immutable.remember_payload(id, *size, grains))?;
            return Ok(bytes);
        }
        let decoded = self.fetch_mapped(&pin.entries, &pin.bins, id)?;
        self.with_content(|immutable, _| immutable.put_object(id, &decoded))?;
        Ok(decoded)
    }

    /// Read and verify the frame `entries` maps `id` to, under the operation
    /// deadline and outside any mediator acquisition. Nothing is stored. A
    /// store's refused or overflowing range answer is a corrupt frame.
    fn fetch_mapped(
        &self,
        entries: &BTreeMap<GrainId, ShardEntry>,
        bins: &[[u8; 32]],
        id: GrainId,
    ) -> Result<Vec<u8>, CoordinationError> {
        self.fetch_mapped_as(entries, bins, id, corrupt_range)
    }

    /// [`Self::fetch_mapped`], a refused or overflowing range answer given
    /// the class `refused_range` gives it.
    fn fetch_mapped_as(
        &self,
        entries: &BTreeMap<GrainId, ShardEntry>,
        bins: &[[u8; 32]],
        id: GrainId,
        refused_range: fn(RootStoreError) -> CoordinationError,
    ) -> Result<Vec<u8>, CoordinationError> {
        let entry = *entries.get(&id).ok_or(OverlayError::ContentUnavailable)?;
        if entry.id != id || entry.comp_len == 0 || entry.comp_len > FRAME_COMP_MAX {
            return Err(OverlayError::ContentCorrupt.into());
        }
        let ordinal =
            usize::try_from(entry.bin_ordinal).map_err(|_| OverlayError::ContentCorrupt)?;
        let digest = *bins.get(ordinal).ok_or(OverlayError::ContentCorrupt)?;
        let (runtime, deadline) = self
            .operation
            .as_ref()
            .ok_or_else(|| refused("SyncContentDeadlineRequired"))?;
        if runtime.now() >= *deadline {
            return Err(refused("SyncDeadline"));
        }
        let remote = self.remote.clone();
        let worker_runtime = runtime.clone();
        let deadline = *deadline;
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        // Only blocking callbacks use this bound provider. Remote work runs on
        // the attached scheduler, which also drives the transport's connections.
        drop(runtime.spawn(async move {
            let result = worker_runtime
                .timeout_at(
                    deadline,
                    remote.get_bin_range(&digest, entry.offset, entry.comp_len),
                )
                .await
                .map_err(|_| refused("SyncDeadline"));
            let _ = send.send(result);
        }));
        let frame = receive
            .recv()
            .map_err(|_| refused("SyncSupervisorLost"))??
            .map_err(|error| match error {
                RootStoreError::RefusedResponse { .. } | RootStoreError::RangeOverflow => {
                    refused_range(error)
                }
                _ => OverlayError::ContentUnavailable.into(),
            })?;
        let mut codec = granary_store::codec::GrainCodec::new()
            .map_err(|error| OverlayError::Io(std::io::Error::other(error.to_string())))?;
        let max_unpacked = u32::try_from(META_MAX_BYTES).unwrap_or(u32::MAX);
        crate::fetcher::verify_bin_range_frame(id, entry.comp_len, max_unpacked, &frame, &mut codec)
            .map_err(|_| OverlayError::ContentCorrupt.into())
    }
    pub(super) fn read_content_in(
        &self,
        view: Option<&ViewContext>,
        content: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        let mut fetched = BTreeSet::new();
        loop {
            let step = self
                .with_content(|immutable, _| {
                    Ok(immutable.read_content_or_missing(content, offset, length))
                })
                .map_err(overlay_error)?;
            match step {
                Ok(bytes) => return Ok(bytes),
                Err((OverlayError::ContentUnavailable, Some(missing_id))) => {
                    if !fetched.insert(missing_id) {
                        return Err(OverlayError::ContentUnavailable);
                    }
                    self.fetch_immutable_in(missing_id, view)
                        .map_err(overlay_error)?;
                }
                Err((error, _)) => return Err(error),
            }
        }
    }
}

impl<R: BinStore + Send + Sync + 'static, P: OverlayIo + Send, E: SyncRuntime + 'static> GrainSource
    for MountSyncContent<R, P, E>
{
    fn has(&self, id: &GrainId) -> bool {
        self.with_content(|immutable, pin| {
            Ok(immutable.has(id) || pin.pin_files.contains_key(id) || pin.entries.contains_key(id))
        })
        .unwrap_or(false)
    }

    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.fetch_immutable(*id)
            .map_err(|error| source_error(*id, error))
    }
}

impl<R: BinStore + Send + Sync + 'static, P: OverlayIo + Send, E: SyncRuntime + 'static> SyncContent
    for MountSyncContent<R, P, E>
{
    fn with_deadline<E2: SyncRuntime + 'static>(
        &self,
        runtime: Arc<E2>,
        deadline: tokio::time::Instant,
    ) -> impl SyncContent {
        self.with_deadline(runtime, deadline)
    }

    fn get_local(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.with_content(|immutable, _| Ok(immutable.get(id)))
            .map_err(|error| source_error(*id, error))?
    }

    fn payload(&self, content: GrainId) -> Result<FileGrains, CoordinationError> {
        let cached = self.with_content(|immutable, _| match immutable.payload(content) {
            Ok(grains) => Ok(Some(grains)),
            Err(CoordinationError::Overlay(OverlayError::ContentUnavailable))
                if !immutable.has(&content) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        })?;
        if let Some(grains) = cached {
            return Ok(grains);
        }
        self.fetch_immutable(content)?;
        self.with_content(|immutable, _| immutable.payload(content))
    }

    fn read_content(
        &self,
        content: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        self.read_content_in(None, content, offset, length)
    }

    fn put_object(&self, id: GrainId, bytes: &[u8]) -> Result<(), CoordinationError> {
        self.with_content(|immutable, _| immutable.put_object(id, bytes))
    }

    fn remember_payload(
        &self,
        content: GrainId,
        size: u64,
        grains: &FileGrains,
    ) -> Result<(), CoordinationError> {
        self.with_content(|immutable, _| immutable.remember_payload(content, size, grains))
    }
}

/// Rebuild the view for `published` from `previous`, the view it replaces:
/// the new root's binmap is read from the remote, and its manifest structure
/// is walked with every node checked for membership in that binmap and for
/// coverage of what it names. A node is taken from `previous` by id, then
/// from the mount's store by id, and only then from the remote through the
/// new binmap, so the fetch count is the count of nodes new to this client.
/// A stored copy that fails hash authentication counts as absent and is
/// fetched from the remote.
/// Nothing is stored: no object, cache entry or mediator state changes.
///
/// Membership is checked before any source is tried. Checking it after the
/// `previous` source is an equivalent mutant while coverage stands: a parent
/// in the new tree refuses an omitted child before reuse can reach it, so no
/// row distinguishes the two orders. The validator requires a monotone fetch,
/// so a node is recorded on its first answer and answered from that record
/// afterwards; a remote read that failed on a repeat would otherwise turn a
/// refusal into a wrong accept.
///
/// A remote node read that fails without verifying anything keeps its own
/// class, as a failed binmap read and a refused store read do: only a node
/// that fails verification is a bad base.
///
/// # Errors
/// `SyncContentDeadlineRequired` when `content` carries no operation
/// deadline; `SyncDeadline` when the binmap read or a node read exceeds it;
/// the binmap read's own class for a remote transport failure;
/// `ContentUnavailable` for a node read's transport failure and
/// `SyncSupervisorLost` for its lost worker; the mediator's refusal,
/// unchanged, when the store read refuses; `SyncMaterializationLost` when
/// the walk's worker is lost; and `SyncBase` for a binmap, validation,
/// membership or coverage failure, including a node that fails
/// verification or whose range the store refused.
pub(crate) async fn rebuild_view<R, P, E>(
    previous: Arc<ViewContext>,
    published: &PublishedRoot,
    content: &MountSyncContent<R, P, E>,
) -> Result<ViewContext, CoordinationError>
where
    R: BinStore + Send + Sync + 'static,
    P: OverlayIo + Send + 'static,
    E: SyncRuntime + 'static,
{
    rebuild_view_as(previous, published, content, corrupt_range).await
}

/// A refused or overflowing range answer, as a corrupt frame.
fn corrupt_range(_: RootStoreError) -> CoordinationError {
    OverlayError::ContentCorrupt.into()
}

/// A refused or overflowing range answer, as the store misbehaving: the
/// remote's own class, which a binmap read keeps too.
fn kept_range(error: RootStoreError) -> CoordinationError {
    crate::sync::binmap_error(crate::PublishError::Remote(error))
}

/// [`rebuild_view`], a node's refused or overflowing range answer given the
/// class `refused_range` gives it.
async fn rebuild_view_as<R, P, E>(
    previous: Arc<ViewContext>,
    published: &PublishedRoot,
    content: &MountSyncContent<R, P, E>,
    refused_range: fn(RootStoreError) -> CoordinationError,
) -> Result<ViewContext, CoordinationError>
where
    R: BinStore + Send + Sync + 'static,
    P: OverlayIo + Send + 'static,
    E: SyncRuntime + 'static,
{
    use granary_core::{
        encoding::{ObjectType, open_envelope},
        manifest::EntryKind,
    };
    let (runtime, deadline) = content
        .operation
        .as_ref()
        .ok_or_else(|| refused("SyncContentDeadlineRequired"))?;
    let binmap = runtime
        .timeout_at(
            *deadline,
            crate::publish::state_from_published(content.remote.as_ref(), published),
        )
        .await
        .map_err(|_| refused("SyncDeadline"))?
        .map_err(crate::sync::binmap_error)?;
    let manifest_root = published.doc().manifest_root;
    let content = content.clone();
    let (known, bins, pin_nodes, pin_files) = runtime
        .blocking(move || {
            let known = binmap.known;
            let bins: Arc<[[u8; 32]]> = Arc::from(binmap.bins);
            let recorded = std::cell::RefCell::new(BTreeMap::<GrainId, Vec<u8>>::new());
            let failed = std::cell::RefCell::new(None);
            let fetch = |id: &GrainId| -> Option<Vec<u8>> {
                if failed.borrow().is_some() || !known.contains_key(id) {
                    return None;
                }
                if let Some(bytes) = recorded.borrow().get(id) {
                    return Some(bytes.clone());
                }
                let bytes = match previous.pin_nodes.get(id) {
                    Some(bytes) => bytes.clone(),
                    None => match content.get_stored(id) {
                        Ok(Some(bytes)) => bytes,
                        Ok(None) => {
                            match content.fetch_mapped_as(&known, &bins, *id, refused_range) {
                                Ok(bytes) => bytes,
                                // A frame that does not verify is a bad base.
                                Err(CoordinationError::Overlay(OverlayError::ContentCorrupt)) => {
                                    return None;
                                }
                                Err(error) => {
                                    *failed.borrow_mut() = Some(error);
                                    return None;
                                }
                            }
                        }
                        Err(error) => {
                            *failed.borrow_mut() = Some(error);
                            return None;
                        }
                    },
                };
                if !crate::sync::contained(&bytes, &known) {
                    return None;
                }
                recorded.borrow_mut().insert(*id, bytes.clone());
                Some(bytes)
            };
            let validated = manifest::validate_dir_tree(&manifest_root, &fetch);
            if let Some(error) = failed.into_inner() {
                return Err(error);
            }
            validated.map_err(|_| refused("SyncBase"))?;
            let pin_nodes = recorded.into_inner();
            let mut pin_files = BTreeMap::new();
            for bytes in pin_nodes.values() {
                let (kind, cursor) = open_envelope(bytes).map_err(|_| refused("SyncBase"))?;
                if kind != ObjectType::DirLeaf {
                    continue;
                }
                for entry in manifest::decode_dir_leaf(cursor).map_err(|_| refused("SyncBase"))? {
                    if let EntryKind::File { size, grains, .. } = entry.kind {
                        let payload = manifest::node::file_payload(size, &grains)
                            .map_err(|_| refused("SyncBase"))?;
                        pin_files.insert(GrainId::of(&payload), (size, grains));
                    }
                }
            }
            Ok((known, bins, pin_nodes, pin_files))
        })
        .await
        .map_err(|_| refused("SyncMaterializationLost"))??;
    Ok(ViewContext {
        base_id: published.id(),
        base_seq: published.seq(),
        base_bytes: published.bytes().to_vec(),
        bins,
        entries: known,
        pin_files,
        pin_nodes,
    })
}

/// A rebuilt view and the pin it was rebuilt from, or the refusal that
/// closes the mount's view.
pub(crate) type ViewVerdict = Result<(ViewContext, Arc<ViewContext>), CoordinationError>;

/// Rebuild the view for `root` from the mount's pin and check that the
/// mount can serve it. A rebuild that fails on a store still serving its
/// base is transient: the outer error, with which the install refuses and
/// changes nothing. One that fails on a store refusing its own base, which
/// is poisoned or fenced, gives that refusal as the verdict, as does an
/// unservable view; the install closes the view on it.
///
/// # Errors
/// The rebuild's own refusal, when the store still serves its base.
pub(crate) async fn rebuild_verdict<R, P, E>(
    root: &PublishedRoot,
    content: &MountSyncContent<R, P, E>,
) -> Result<ViewVerdict, CoordinationError>
where
    R: BinStore + Send + Sync + 'static,
    P: OverlayIo + Send + 'static,
    E: SyncRuntime + 'static,
{
    let rebuilt = match content.mediator.with(|local| pinned(local)) {
        Ok(previous) => rebuild_view(previous.clone(), root, content)
            .await
            .map(|view| (view, previous)),
        Err(error) => Err(error),
    };
    match rebuilt {
        Ok((view, previous)) => Ok(check_servable(&view, &previous).map(|()| (view, previous))),
        Err(error) => failed_rebuild(&content.mediator, error),
    }
}

/// A rebuild that failed on a store still serving its base is transient:
/// the outer error. On a store refusing its own base, poisoned or fenced,
/// that refusal is the verdict.
fn failed_rebuild<T, P: OverlayIo>(
    mediator: &SharedWritableStore<P>,
    error: CoordinationError,
) -> Result<Result<T, CoordinationError>, CoordinationError> {
    match mediator.with(|local| local.mount_base()) {
        Ok(_) => Err(error),
        Err(refusal) => Ok(Err(refusal)),
    }
}

/// Proof that an adoption's rebuild walked a published head's whole
/// manifest, every node checked for membership in that head's binmap and
/// for coverage: the manifest root walked and the head's `(id, seq)`. Its
/// fields are private to this module and it has no constructor, so only
/// [`adoption_verdict`] makes one, once that walk returned, from the head it
/// walked.
#[derive(Debug)]
pub(crate) struct AdoptionWalk {
    manifest_root: GrainId,
    base: (GrainId, u64),
}
impl AdoptionWalk {
    pub(crate) fn manifest_root(&self) -> GrainId {
        self.manifest_root
    }
    pub(crate) fn base(&self) -> (GrainId, u64) {
        self.base
    }
}

/// A view rebuilt for an adopted head, with its walk, its base entries and
/// the pin it was rebuilt from; or the refusal the adoption decides on under
/// the gate.
pub(crate) type AdoptionVerdict = Result<
    (
        ViewContext,
        AdoptionWalk,
        Vec<crate::OverlayEntry>,
        Arc<ViewContext>,
    ),
    CoordinationError,
>;

/// [`rebuild_verdict`] for a head another writer published, with the walk
/// that rebuilt it and the head's base entries as an overlay holds them,
/// read from the view's own nodes once the view is servable. A node range
/// the store refused keeps the store's class: it says nothing of the head.
///
/// # Errors
/// The rebuild's own refusal, when the store still serves its base, and
/// `SyncMaterializationLost` when the decode's worker is lost.
pub(crate) async fn adoption_verdict<R, P, E>(
    root: &PublishedRoot,
    content: &MountSyncContent<R, P, E>,
) -> Result<AdoptionVerdict, CoordinationError>
where
    R: BinStore + Send + Sync + 'static,
    P: OverlayIo + Send + 'static,
    E: SyncRuntime + 'static,
{
    let rebuilt = match content.mediator.with(|local| pinned(local)) {
        Ok(previous) => rebuild_view_as(previous.clone(), root, content, kept_range)
            .await
            .map(|view| (view, previous)),
        Err(error) => Err(error),
    };
    let (view, previous) = match rebuilt {
        Ok(rebuilt) => rebuilt,
        Err(error) => return failed_rebuild(&content.mediator, error),
    };
    if let Err(refusal) = check_servable(&view, &previous) {
        return Ok(Err(refusal));
    }
    let walk = AdoptionWalk {
        manifest_root: root.doc().manifest_root,
        base: (root.id(), root.seq()),
    };
    let (runtime, _) = content
        .operation
        .as_ref()
        .ok_or_else(|| refused("SyncContentDeadlineRequired"))?;
    let manifest_root = walk.manifest_root;
    let (view, entries) = runtime
        .blocking(move || {
            let entries = view.overlay_entries(manifest_root)?;
            Ok::<_, CoordinationError>((view, entries))
        })
        .await
        .map_err(|_| refused("SyncMaterializationLost"))??;
    Ok(Ok((view, walk, entries, previous)))
}

/// Refuse a view the mount cannot serve: an entry of a reserved kind, or a
/// symlink target longer than the mount can return. Only the directory
/// leaves `previous` does not hold are decoded; one it holds is the same
/// bytes by id, checked when the view that first held it was served.
fn check_servable(context: &ViewContext, previous: &ViewContext) -> Result<(), CoordinationError> {
    use granary_core::{
        encoding::{ObjectType, open_envelope},
        manifest::EntryKind,
    };
    for (id, bytes) in &context.pin_nodes {
        if previous.pin_nodes.contains_key(id) {
            continue;
        }
        let (kind, cursor) = open_envelope(bytes).map_err(|_| refused("SyncBase"))?;
        if kind != ObjectType::DirLeaf {
            continue;
        }
        for entry in manifest::decode_dir_leaf(cursor).map_err(|_| refused("SyncBase"))? {
            let servable = match &entry.kind {
                EntryKind::Fifo | EntryKind::Socket => false,
                EntryKind::Symlink { target } => {
                    target.as_bytes().len()
                        <= granary_fuse::FUSE_SERVE_LIMITS.readlink_target_max_bytes
                }
                _ => true,
            };
            if !servable {
                return Err(refused("ViewUnservable"));
            }
        }
    }
    Ok(())
}

/// Why an install did not leave the mount serving the view it was given.
#[derive(Debug)]
pub(crate) enum ViewInstallError {
    /// Nothing switched, and the open view keeps serving.
    KeptOpen(CoordinationError),
    /// The view is closed, and the landing did not complete.
    Closed(CoordinationError),
    /// The view is closed after the landing completed.
    ClosedAfterLanding,
    /// Nothing changed: the mount holds work of its own, so an adoption
    /// waits for its own landing.
    Deferred,
    /// Nothing changed, and the adopted head can never be installed.
    HeadRefused(CoordinationError),
}

/// Routes the session's reports to their own events, as its drop does.
struct EmitReports;
impl std::io::Write for EmitReports {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl crate::LocalReporter for EmitReports {
    fn report(&mut self, report: &crate::LocalReport) {
        report.emit();
    }
}

/// Whether the install's fault point fails at `phase`; a blocking action
/// holds the install there until it is resumed.
fn view_install_fault(
    faults: &crate::FaultControl,
    phase: &'static str,
    root: &PublishedRoot,
) -> bool {
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    return faults
        .sync_point(
            "fuse.view.install",
            phase,
            root.seq(),
            Some(root.id()),
            "none",
        )
        .is_some();
    #[cfg(not(any(test, feature = "overlay-fault-tests")))]
    {
        let _ = (faults, phase, root);
        false
    }
}

/// What an install leaves under the adapter gate: how it ended, or the
/// refusal that kept the view open or closed it, and the open inodes to
/// revoke when it closed the view.
pub(crate) type GateOutcome = (
    Result<crate::sync::Adopted, CoordinationError>,
    Option<Vec<u64>>,
);

/// An install's work under the adapter gate, on the mount however the
/// adapter's backend wraps it.
pub(crate) type GateAction<R, P> = Box<
    dyn FnOnce(&mut WritableMount<R, P>, &mut granary_fuse::ViewAdapter<'_>) -> GateOutcome + Send,
>;

/// The adapter a mount is served through, as an install reaches it.
pub(crate) trait ViewGate<R, P: OverlayIo>: Send + Sync {
    /// Register the waker a returned slot calls; `false` when one is
    /// already registered.
    fn on_slot_returned(&self, waker: Arc<dyn Fn() + Send + Sync>) -> bool;
    /// Whether a waker is already registered for the slot.
    fn has_slot_waker(&self) -> bool;
    /// Run and take `action` under the gate with the adapter state present.
    /// A busy adapter leaves it in place for the next attempt.
    fn try_install(
        &self,
        action: &mut Option<GateAction<R, P>>,
    ) -> Result<Option<GateOutcome>, granary_fuse::SlotBusy>;
    /// Release the preparations waiting for this install.
    fn finish_install(&self);
    /// Invalidate `inodes` in the kernel, stopping at the first refusal.
    fn revoke(&self, inodes: &[u64]) -> std::io::Result<()>;
    /// Whether `adapter`, reached under this gate, holds a write-capable
    /// descriptor.
    fn write_capable(&self, adapter: &granary_fuse::ViewAdapter<'_>) -> bool;
}

/// A view handle, with the projection from its backend to the mount.
pub(crate) struct Projected<X, R, P: OverlayIo> {
    pub(crate) handle: granary_fuse::ViewHandle<X>,
    pub(crate) project: fn(&mut X) -> &mut WritableMount<R, P>,
}

impl<X, R, P> ViewGate<R, P> for Projected<X, R, P>
where
    X: granary_fuse::MountBackend + Send,
    R: Send,
    P: OverlayIo + Send,
{
    fn on_slot_returned(&self, waker: Arc<dyn Fn() + Send + Sync>) -> bool {
        self.handle.on_slot_returned(waker)
    }
    fn has_slot_waker(&self) -> bool {
        self.handle.has_slot_waker()
    }
    fn try_install(
        &self,
        action: &mut Option<GateAction<R, P>>,
    ) -> Result<Option<GateOutcome>, granary_fuse::SlotBusy> {
        let project = self.project;
        self.handle
            .try_install(|backend, adapter| {
                action
                    .take()
                    .map(|action| action(project(backend), adapter))
            })
            .map_err(|(busy, _)| busy)
    }
    fn finish_install(&self) {
        self.handle.finish_install();
    }
    fn revoke(&self, inodes: &[u64]) -> std::io::Result<()> {
        self.handle.revoke(inodes)
    }
    fn write_capable(&self, adapter: &granary_fuse::ViewAdapter<'_>) -> bool {
        adapter.write_capable()
    }
}

/// The gate of a mount no adapter serves: a start finishing a store before
/// it serves binds its engine's hook here and installs every landing
/// unattended, so nothing runs under this gate. It keeps the waker a
/// binding registers, and refuses a gated install as abandoned without
/// running it.
#[derive(Default)]
pub(super) struct UnattendedGate {
    waker: std::sync::OnceLock<Arc<dyn Fn() + Send + Sync>>,
}

impl<R, P: OverlayIo> ViewGate<R, P> for UnattendedGate {
    fn on_slot_returned(&self, waker: Arc<dyn Fn() + Send + Sync>) -> bool {
        self.waker.set(waker).is_ok()
    }
    fn has_slot_waker(&self) -> bool {
        self.waker.get().is_some()
    }
    fn try_install(
        &self,
        _: &mut Option<GateAction<R, P>>,
    ) -> Result<Option<GateOutcome>, granary_fuse::SlotBusy> {
        Err(granary_fuse::SlotBusy::Abandoned)
    }
    fn finish_install(&self) {}
    fn revoke(&self, _: &[u64]) -> std::io::Result<()> {
        Ok(())
    }
    fn write_capable(&self, _: &granary_fuse::ViewAdapter<'_>) -> bool {
        false
    }
}

/// Releases the preparations waiting for an install, however it ends.
struct FinishInstall<'a, R, P: OverlayIo>(&'a dyn ViewGate<R, P>);
impl<R, P: OverlayIo> Drop for FinishInstall<'_, R, P> {
    fn drop(&mut self) {
        self.0.finish_install();
    }
}

/// The engine's view hook, ready for the adapter its mount is served
/// through.
pub struct ViewBinding<R, P: OverlayIo> {
    bind: BindHook<R, P>,
    live: Option<LiveStart>,
}

pub(super) struct LiveStart {
    handle: Option<tokio::runtime::Handle>,
    spawn: Box<dyn FnOnce() + Send>,
}

impl LiveStart {
    fn new<P, Rem, S, C, M, E, T>(
        engine: Arc<SyncEngine<P, Rem, S, C, M, E>>,
        runtime: Arc<E>,
        entropy: SharedEntropy<T>,
        options: crate::SyncOptions,
        handle: Option<tokio::runtime::Handle>,
    ) -> Self
    where
        P: OverlayIo + Send + 'static,
        Rem: SyncRemote + AuthorityTransport + 'static,
        S: SyncContent + 'static,
        C: Clock + 'static,
        M: MonotonicClock + 'static,
        E: SyncRuntime + 'static,
        T: SecureRandom + Send + 'static,
    {
        Self {
            handle,
            spawn: Box::new(move || {
                drop(runtime.spawn(async move {
                    let end = engine.clone().drive_live(options, entropy).await;
                    engine.report_live_end(end);
                }));
            }),
        }
    }
}

/// Sets the engine's hook over a gate, woken by a returned slot, with the
/// conversion of a root's time to the kernel's.
type BindHook<R, P> = Box<
    dyn FnOnce(
            Arc<dyn ViewGate<R, P>>,
            Arc<tokio::sync::Notify>,
            KernelTime,
        ) -> Result<(), CoordinationError>
        + Send,
>;

/// A root's time as the kernel holds it, if it can.
pub(crate) type KernelTime = fn(granary_core::sheaf::Timestamp) -> Option<std::time::SystemTime>;

impl<R, P: OverlayIo> std::fmt::Debug for ViewBinding<R, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewBinding").finish_non_exhaustive()
    }
}

impl<R: RootStore + BinStore + Send + 'static, P: OverlayIo + Send + 'static> ViewBinding<R, P> {
    /// The binding sets `engine`'s hook, then arms `observer` with the
    /// engine, so a boundary adopts only through a bound hook.
    pub(super) fn new<Rem, S, C, M, E>(
        engine: Arc<SyncEngine<P, Rem, S, C, M, E>>,
        content: MountSyncContent<Rem, P>,
        runtime: Arc<E>,
        observer: Arc<HeadObserver<Rem, E>>,
        live: Option<LiveStart>,
    ) -> Self
    where
        Rem: SyncRemote + RootStore + 'static,
        S: SyncContent + 'static,
        C: Clock + 'static,
        M: MonotonicClock + 'static,
        E: SyncRuntime + 'static,
    {
        Self {
            bind: Box::new(move |gate, returned, kernel_time| {
                engine.set_view_hook(Arc::new(BoundHook {
                    gate,
                    returned,
                    content,
                    runtime,
                    kernel_time,
                    observer: Arc::downgrade(&observer),
                }))?;
                // A refused hook arms nothing; a set hook is never replaced,
                // so neither is the observer's engine.
                observer.arm(Arc::new(engine));
                Ok(())
            }),
            live,
        }
    }

    /// Install every later landing as the view served through `handle`,
    /// whose backend reaches this mount through `project`.
    ///
    /// A handle already bound refuses before anything is set, and so does an
    /// engine already bound. Binding two engines onto handles of the same
    /// adapter concurrently is not supported: the later one can find the
    /// slot taken only after its engine's hook is set.
    ///
    /// # Errors
    /// `ViewHookBound` when the handle or the engine is already bound.
    pub fn bind<X: granary_fuse::MountBackend + Send + 'static>(
        self,
        handle: granary_fuse::ViewHandle<X>,
        project: fn(&mut X) -> &mut WritableMount<R, P>,
    ) -> Result<(), CoordinationError> {
        let Self { bind, live } = self;
        bind_gate(
            bind,
            Arc::new(Projected { handle, project }),
            granary_fuse::kernel_time,
        )?;
        if let Some(LiveStart { handle, spawn }) = live {
            let _entered = handle.as_ref().map(tokio::runtime::Handle::enter);
            spawn();
        }
        Ok(())
    }

    pub(crate) fn bind_gate(
        self,
        gate: Arc<dyn ViewGate<R, P>>,
        kernel_time: KernelTime,
    ) -> Result<(), CoordinationError> {
        bind_gate(self.bind, gate, kernel_time)
    }

    #[cfg(test)]
    pub(crate) fn live_for_test(&self) -> (bool, bool) {
        self.live
            .as_ref()
            .map_or((false, false), |live| (true, live.handle.is_some()))
    }

    #[cfg(test)]
    pub(crate) fn bind_unattended_for_test(self) -> Result<(), CoordinationError> {
        self.bind_gate(
            Arc::new(UnattendedGate::default()),
            granary_fuse::kernel_time,
        )
    }
}

fn bind_gate<R: RootStore + BinStore + Send + 'static, P: OverlayIo + Send + 'static>(
    bind: BindHook<R, P>,
    gate: Arc<dyn ViewGate<R, P>>,
    kernel_time: KernelTime,
) -> Result<(), CoordinationError> {
    let returned = Arc::new(tokio::sync::Notify::new());
    let waker = returned.clone();
    // A bound slot refuses before the engine's hook is set, and a bound
    // engine before the waker is registered, so a refused binding
    // changes neither.
    if gate.has_slot_waker() {
        return Err(refused("ViewHookBound"));
    }
    let slot = gate.clone();
    bind(gate, returned, kernel_time)?;
    if !slot.on_slot_returned(Arc::new(move || waker.notify_waiters())) {
        return Err(refused("ViewHookBound"));
    }
    Ok(())
}

/// The production view hook: it rebuilds the view, waits for the adapter's
/// slot, installs under the gate, re-keys what changed, and revokes a closed
/// view once admission is released.
struct BoundHook<R, P: OverlayIo, Rem, E> {
    gate: Arc<dyn ViewGate<R, P>>,
    /// Signalled whenever a preparation returns or abandons the slot.
    returned: Arc<tokio::sync::Notify>,
    content: MountSyncContent<Rem, P>,
    runtime: Arc<E>,
    kernel_time: KernelTime,
    // Weak: the observer holds the engine once armed, and the engine holds
    // this hook, so a strong edge would keep the engine past the finish.
    observer: Weak<HeadObserver<Rem, E>>,
}

impl<R, P, Rem, E> crate::sync::MountViewHook for BoundHook<R, P, Rem, E>
where
    R: RootStore + BinStore + Send + 'static,
    P: OverlayIo + Send + 'static,
    Rem: BinStore + Send + Sync + 'static,
    E: SyncRuntime + 'static,
{
    fn install(
        &self,
        root: PublishedRoot,
        deadline: tokio::time::Instant,
        commit: crate::sync::LandedCommit,
    ) -> crate::sync::ViewInstall<'_> {
        if let Some(observer) = self.observer.upgrade() {
            observer.reached(root.seq());
        }
        Box::pin(async move {
            let _finish = FinishInstall(&*self.gate);
            let seq = root.seq();
            match self.install_gated(root, deadline, commit).await {
                Ok((result, inodes)) => (
                    result.map(|_| ()),
                    inodes.map_or_else(crate::sync::Revocation::none, |inodes| {
                        self.revocation(inodes)
                    }),
                ),
                Err(error) => {
                    crate::observe::mount_view(ViewCause::Landed, ViewOutcome::Refused, seq);
                    (Err(error), crate::sync::Revocation::none())
                }
            }
        })
    }

    /// [`Self::install`] without the gate: the view is rebuilt from the pin
    /// and the store, then the landing switches the overlay and binds it.
    fn install_unattended(
        &self,
        root: PublishedRoot,
        deadline: tokio::time::Instant,
        commit: crate::sync::LandedCommit,
    ) -> crate::sync::ViewInstall<'_> {
        if let Some(observer) = self.observer.upgrade() {
            observer.reached(root.seq());
        }
        Box::pin(async move {
            let content = self.content.with_deadline(self.runtime.clone(), deadline);
            let result = match rebuild_verdict(&root, &content).await {
                Ok(Ok((view, _))) => commit(Arc::new(view)).map(|_| ()),
                Ok(Err(refusal)) => Err(refusal),
                Err(error) => Err(error),
            };
            (result, crate::sync::Revocation::none())
        })
    }

    fn adopt(
        &self,
        root: PublishedRoot,
        deadline: tokio::time::Instant,
        adoption: crate::sync::AdoptionCommit,
    ) -> crate::sync::ViewInstall<'_, Adopted> {
        Box::pin(async move {
            let _finish = FinishInstall(&*self.gate);
            match self.adopt_gated(root, deadline, adoption).await {
                Ok((result, None)) => (result, crate::sync::Revocation::none()),
                // A close revoked what the view served, whatever closed it.
                Ok((_, Some(inodes))) => (Ok(Adopted::Closed), self.revocation(inodes)),
                Err(error) => (Err(error), crate::sync::Revocation::none()),
            }
        })
    }

    fn close(
        &self,
        error: CoordinationError,
        deadline: tokio::time::Instant,
    ) -> crate::sync::ViewInstall<'_> {
        Box::pin(async move {
            let _finish = FinishInstall(&*self.gate);
            let action: GateAction<R, P> = Box::new(move |mount, adapter| {
                mount.close_view(error);
                (Ok(Adopted::Closed), Some(adapter.open_inodes().collect()))
            });
            match self.run_gated(action, deadline).await {
                Ok((_, inodes)) => (
                    Ok(()),
                    inodes.map_or_else(crate::sync::Revocation::none, |inodes| {
                        self.revocation(inodes)
                    }),
                ),
                Err(error) => (Err(error), crate::sync::Revocation::none()),
            }
        })
    }
}

impl<R, P, Rem, E> BoundHook<R, P, Rem, E>
where
    R: RootStore + BinStore + Send + 'static,
    P: OverlayIo + Send + 'static,
    Rem: BinStore + Send + Sync + 'static,
    E: SyncRuntime + 'static,
{
    /// Rebuild the view, then wait for the adapter's slot and install it
    /// under the gate.
    ///
    /// # Errors
    /// A refusal met before the install ran: the rebuild's own transient
    /// refusal, and [`Self::run_gated`]'s.
    async fn install_gated(
        &self,
        root: PublishedRoot,
        deadline: tokio::time::Instant,
        commit: crate::sync::LandedCommit,
    ) -> Result<GateOutcome, CoordinationError> {
        let time = (self.kernel_time)(root.doc().timestamp);
        let verdict = if time.is_some() {
            let content = self.content.with_deadline(self.runtime.clone(), deadline);
            rebuild_verdict(&root, &content).await?
        } else {
            // A root whose time the kernel cannot hold can never install:
            // its refusal is the verdict, which closes the view.
            Err(refused("ViewTimeUnrepresentable"))
        };
        let action: GateAction<R, P> = Box::new(move |mount, adapter| {
            let result = mount.install_view(&root, verdict, commit);
            gate_outcome(result, adapter, time)
        });
        self.run_gated(action, deadline).await
    }

    /// Rebuild the view for another writer's head, then wait for the
    /// adapter's slot and decide the adoption under the gate. A head that
    /// fails verification is refused before the gate, and any other rebuild
    /// failure on a store still serving its base is "no answer yet".
    ///
    /// # Errors
    /// The rebuild's transient refusal, kept from its transport or runtime,
    /// and [`Self::run_gated`]'s.
    async fn adopt_gated(
        &self,
        root: PublishedRoot,
        deadline: tokio::time::Instant,
        adoption: crate::sync::AdoptionCommit,
    ) -> Result<GateOutcome, CoordinationError> {
        let time = (self.kernel_time)(root.doc().timestamp);
        let verdict = if time.is_some() {
            let content = self.content.with_deadline(self.runtime.clone(), deadline);
            match adoption_verdict(&root, &content).await {
                Ok(verdict) => verdict,
                Err(error @ CoordinationError::Refused("SyncBase")) => {
                    return Ok((Ok(Adopted::Refused { cause: error }), None));
                }
                Err(error) => return Err(error),
            }
        } else {
            // The pin is still served: the head is refused under the gate.
            Err(refused("ViewTimeUnrepresentable"))
        };
        let gate = self.gate.clone();
        let action: GateAction<R, P> = Box::new(move |mount, adapter| {
            let writers = gate.write_capable(adapter);
            let result = mount.adopt_view(&root, verdict, adoption, writers);
            gate_outcome(result, adapter, time)
        });
        self.run_gated(action, deadline).await
    }

    /// Wait for the adapter's slot and run `action` under the gate.
    ///
    /// # Errors
    /// `SyncDeadline` for a slot not returned in time, and
    /// `ViewAdapterLost` for an adapter that is gone.
    async fn run_gated(
        &self,
        action: GateAction<R, P>,
        deadline: tokio::time::Instant,
    ) -> Result<GateOutcome, CoordinationError> {
        let mut action = Some(action);
        loop {
            // Enabled before the attempt, so a slot returned between the
            // attempt and the wait still wakes it.
            let mut returned = std::pin::pin!(self.returned.notified());
            returned.as_mut().enable();
            let gate = self.gate.clone();
            let (ran, unspent) = self
                .runtime
                .blocking(move || (gate.try_install(&mut action), action))
                .await
                .map_err(|_| refused("ViewAdapterLost"))?;
            match ran {
                Ok(Some(outcome)) => return Ok(outcome),
                Err(granary_fuse::SlotBusy::Taken) => action = unspent,
                Ok(None) | Err(_) => return Err(refused("ViewAdapterLost")),
            }
            self.runtime
                .timeout_at(deadline, returned)
                .await
                .map_err(|_| refused("SyncDeadline"))?;
        }
    }

    /// Send the invalidations on a detached task: nothing waits for them.
    fn revocation(&self, inodes: Vec<u64>) -> crate::sync::Revocation {
        let (gate, runtime) = (self.gate.clone(), self.runtime.clone());
        crate::sync::Revocation::new(move || {
            let sends = runtime.clone();
            drop(runtime.spawn(async move {
                sends
                    .blocking(move || send_revocation(&*gate, &inodes))
                    .await
            }));
        })
    }
}

/// How long past its budget a boundary's worker waits for the sync runtime
/// to answer before it serves the view the mount has.
const BOUNDARY_MARGIN: std::time::Duration = std::time::Duration::from_millis(500);

/// How a writable mount's view boundaries behave when the authority's head
/// cannot be confirmed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ViewMode {
    /// Serve the pinned view after the boundary's wait and while the
    /// authority is unreachable.
    #[default]
    Default,
    /// Wait up to the seam deadline for an observation begun after the
    /// request, and fail with `ETIMEDOUT` when none answers or while the
    /// authority is unreachable.
    Strict,
}

/// A writable mount's view boundary: it starts an observation of the
/// authority's head and waits for it, from the request, at most
/// [`VIEW_PROBE_DEADLINE`]. The wait runs on the sync runtime, whose timer is
/// the only clock, and the adapter's worker blocks on its answer.
struct MountViewBoundary<R, E> {
    observer: Arc<HeadObserver<R, E>>,
    runtime: Arc<E>,
    /// The sync executor's handle, entered to start work from the adapter's
    /// worker, which runs outside it.
    handle: Option<tokio::runtime::Handle>,
    mode: ViewMode,
    budget: std::time::Duration,
    #[cfg(test)]
    before_spawn: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl<R, E> std::fmt::Debug for MountViewBoundary<R, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountViewBoundary")
            .field("observer", &self.observer)
            .finish_non_exhaustive()
    }
}

impl<R, E> MountViewBoundary<R, E> {
    fn new(
        observer: Arc<HeadObserver<R, E>>,
        runtime: Arc<E>,
        handle: Option<tokio::runtime::Handle>,
        mode: ViewMode,
    ) -> Self {
        let budget = match mode {
            ViewMode::Default => VIEW_PROBE_DEADLINE,
            ViewMode::Strict => crate::SEAM_DEADLINE_BASE,
        };
        Self::with_budget(observer, runtime, handle, mode, budget)
    }

    fn with_budget(
        observer: Arc<HeadObserver<R, E>>,
        runtime: Arc<E>,
        handle: Option<tokio::runtime::Handle>,
        mode: ViewMode,
        budget: std::time::Duration,
    ) -> Self {
        Self {
            observer,
            runtime,
            handle,
            mode,
            budget,
            #[cfg(test)]
            before_spawn: Mutex::default(),
        }
    }

    #[cfg(test)]
    fn before_spawn_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self.before_spawn.lock().unwrap() = Some(Box::new(hook));
    }
}

impl<R, E> MountViewBoundary<R, E>
where
    R: RootStore + 'static,
    E: SyncRuntime + 'static,
{
    /// Run a boundary's wait on the sync runtime until `deadline`. A lost
    /// task and a timeout answer `unanswered`. The worker waits past the
    /// budget only by the margin, so a runtime that does not run the timer
    /// cannot hold it.
    fn on_runtime(
        &self,
        deadline: tokio::time::Instant,
        unanswered: granary_fuse::BoundaryOutcome,
        wait: impl std::future::Future<Output = granary_fuse::BoundaryOutcome> + Send + 'static,
    ) -> granary_fuse::BoundaryOutcome {
        #[cfg(test)]
        if let Some(hook) = self.before_spawn.lock().unwrap().take() {
            hook();
        }
        let runtime = self.runtime.clone();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        drop(self.runtime.spawn(async move {
            let _ = send.send(runtime.timeout_at(deadline, wait).await);
        }));
        let bound = deadline.saturating_duration_since(self.runtime.now()) + BOUNDARY_MARGIN;
        match receive.recv_timeout(bound) {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(crate::SyncRuntimeError)) | Err(_) => unanswered,
        }
    }
}

impl<R, E> granary_fuse::ViewBoundary for MountViewBoundary<R, E>
where
    R: RootStore + 'static,
    E: SyncRuntime + 'static,
{
    fn wait(
        &self,
        _kind: granary_fuse::BoundaryKind,
        writers: &dyn Fn() -> bool,
    ) -> granary_fuse::BoundaryOutcome {
        use granary_fuse::BoundaryOutcome::{Installed, Served, Unreachable};
        let _entered = self.handle.as_ref().map(tokio::runtime::Handle::enter);
        let deadline = self.runtime.now() + self.budget;
        // The adapter's writers are read at most once, and only for a
        // boundary that observes: by `begin` when it starts an observation,
        // or below when a strict boundary waits one out.
        let read = std::cell::OnceCell::new();
        let read_writers = || *read.get_or_init(writers);
        match (self.mode, self.observer.begin(&read_writers)) {
            (_, Begin::Idle) | (ViewMode::Default, Begin::Unreachable | Begin::InFlight(_)) => {
                Served
            }
            (ViewMode::Strict, Begin::Unreachable) => Unreachable,
            // None in flight, so the probe that answers begins after the
            // request. A lost task, a timeout and every answer but an install
            // serve the view the mount has.
            (ViewMode::Default, Begin::Started(observation)) => {
                self.on_runtime(deadline, Served, async move {
                    match observation.await {
                        Ok(Ok(Observed::Installed(_))) => Installed,
                        _ => Served,
                    }
                })
            }
            // A strict boundary is answered only by an observation begun
            // after its request, and serves no route that ends without one.
            (ViewMode::Strict, mut current) => {
                let writers = read_writers();
                let (observer, runtime) = (self.observer.clone(), self.runtime.clone());
                self.on_runtime(deadline, Unreachable, async move {
                    loop {
                        match current {
                            Begin::Unreachable => return Unreachable,
                            Begin::Idle => return Served,
                            Begin::InFlight(mut settled) => {
                                let _ = settled.changed().await;
                            }
                            Begin::Started(observation) => match observation.await {
                                Ok(Ok(Observed::Installed(_))) => return Installed,
                                Ok(Ok(Observed::Unreachable(_))) => return Unreachable,
                                Ok(Ok(Observed::Discarded)) => {}
                                Ok(Ok(_)) => return Served,
                                Ok(Err(_)) | Err(_) => {
                                    runtime.sleep(crate::fetcher::UNAVAILABLE_RETRY_DELAY).await;
                                }
                            },
                        }
                        current = observer.begin(&|| writers);
                    }
                })
            }
        }
    }

    fn label(&self) -> Option<Result<Vec<u8>, granary_fuse::MountError>> {
        self.observer.label()
    }

    fn unconfirmed(&self) -> bool {
        self.observer.unconfirmed()
    }
}

/// What an install's result leaves under the gate: a switched view re-keys
/// what changed, at the root's `time`, which an installed verdict converted;
/// a closed view collects its open inodes to revoke.
fn gate_outcome(
    result: Result<crate::ViewChange, ViewInstallError>,
    adapter: &mut granary_fuse::ViewAdapter<'_>,
    time: Option<std::time::SystemTime>,
) -> GateOutcome {
    match result {
        Ok(change) => {
            if let Some(time) = time {
                rekey(adapter, &change, time);
            }
            (Ok(Adopted::Installed), None)
        }
        Err(ViewInstallError::KeptOpen(error)) => (Err(error), None),
        Err(ViewInstallError::Closed(error)) => (Err(error), Some(adapter.open_inodes().collect())),
        Err(ViewInstallError::ClosedAfterLanding) => {
            (Ok(Adopted::Closed), Some(adapter.open_inodes().collect()))
        }
        Err(ViewInstallError::Deferred) => (Ok(Adopted::Deferred), None),
        Err(ViewInstallError::HeadRefused(error)) => (Ok(Adopted::Refused { cause: error }), None),
    }
}

/// Invalidate a closed view's held inodes; a refused send is reported once.
pub(crate) fn send_revocation<R, P: OverlayIo>(gate: &dyn ViewGate<R, P>, inodes: &[u64]) {
    if gate.revoke(inodes).is_err() {
        crate::observe::op_failed(crate::OperationKind::View, crate::FailureClass::Io);
    }
}

/// Give each changed path a fresh kernel identity, the new view's `time`,
/// and the metadata its retired entry held for a resident inode under it.
fn rekey(
    adapter: &mut granary_fuse::ViewAdapter<'_>,
    change: &crate::ViewChange,
    time: std::time::SystemTime,
) {
    let paths: Vec<_> = change
        .paths
        .iter()
        .map(|path| (path_key(&path.path), path.new.is_some()))
        .collect();
    let displaced = displaced(change);
    adapter.rekey(
        &paths,
        &|path| {
            displaced
                .get(path)
                .map(|entry| super::overlay_node((*entry).clone()))
        },
        time,
    );
}

/// Every entry the change retired, by its path: a listed path's own, and
/// each one under a removed or replaced directory, whose path is not listed.
fn displaced(change: &crate::ViewChange) -> BTreeMap<granary_vfs::PathKey, &crate::OverlayEntry> {
    change
        .retired
        .values()
        .map(|entry| (path_key(&entry.path), entry))
        .collect()
}

fn path_key(path: &[manifest::Name]) -> granary_vfs::PathKey {
    path.iter().map(|name| name.as_bytes().to_vec()).collect()
}

impl<R, P: OverlayIo> WritableMount<R, P> {
    #[cfg(test)]
    pub(crate) fn set_live_driver_for_test(&mut self, options: crate::SyncOptions) {
        self.live_driver = true;
        self.live_options = options;
    }

    #[cfg(test)]
    pub(crate) fn live_driver_for_test(&self) -> bool {
        self.live_driver
    }

    /// Move out the binding the attached engine left, to bind it to the
    /// adapter this mount is served through.
    #[must_use]
    pub fn take_view_binding(&mut self) -> Option<ViewBinding<R, P>> {
        self.view_binding.take()
    }

    /// Return a handle to the shared mediator store.
    #[must_use]
    pub fn shared_mediator(&self) -> &SharedWritableStore<P> {
        &self.mediator
    }

    /// Check that the mediator serves this mount's pinned base under its
    /// owner, reading the pin in the same acquisition, and return the view
    /// with the pin it was checked against.
    fn check_sync_binding(
        &self,
        invalidate_cache: bool,
    ) -> Result<(MountViewContext, Arc<ViewContext>), CoordinationError> {
        let expected_owner = self.owner;
        self.mediator.with(|local| {
            let pin = pinned(local)?;
            local.check_sync_base(&pin.base_bytes, pin.base_seq)?;
            let view = local.check_mount_binding(expected_owner)?;
            if invalidate_cache {
                local.invalidate_clean_content()?;
                return Ok((local.mount_view_context()?, pin));
            }
            Ok((view, pin))
        })
    }

    /// Build the production [`MountSyncContent`] bridge over this mount's sole
    /// [`SharedWritableStore`] mediator and its pinned view.
    ///
    /// # Errors
    /// Refuses if the mount view is already pending or the mediator is not
    /// ready on this mount's admitted `(base_id, base_seq)` and `(W, E, T)`.
    pub fn sync_content<S>(
        &self,
        remote: Arc<S>,
    ) -> Result<MountSyncContent<S, P>, CoordinationError> {
        if self.view_state == MountViewState::ViewPending {
            return Err(refused("ViewPending"));
        }
        self.check_sync_binding(false)?;
        Ok(MountSyncContent {
            mediator: self.mediator.clone(),
            remote,
            operation: None,
            recovery: false,
        })
    }

    /// The attached engine's shutdown, which this backend's own runs.
    #[cfg(test)]
    pub(crate) fn shutdown_for_test(&self) -> Option<Arc<dyn crate::sync::MountShutdown>> {
        self.shutdown.clone()
    }

    #[cfg(test)]
    pub(crate) fn completion_tokens_for_test(&self) -> (Option<u64>, usize, Option<GrainId>) {
        let (count, first) = self.completion_tokens.retained_for_test();
        (self.completion_tokens.generation_for_test(), count, first)
    }

    #[cfg(test)]
    pub(crate) fn sync_job_counter_for_test(&mut self) -> Arc<std::sync::atomic::AtomicU64>
    where
        P: 'static,
    {
        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let calls = counter.clone();
        let jobs = self.sync_jobs.take().expect("attached sync job factory");
        self.sync_jobs = Some(Arc::new(move |seal, hold, before, admitted| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            jobs(seal, hold, before, admitted)
        }));
        counter
    }

    #[cfg(test)]
    pub(crate) fn range_cache_snapshot_for_test(&self) -> (u64, usize, usize, usize, usize) {
        self.mediator
            .with(|local| Ok(local.range_cache_snapshot_for_test()))
            .expect("range cache snapshot")
    }

    #[cfg(test)]
    pub(crate) const fn owner_for_test(&self) -> ([u8; 16], u64, [u8; 16]) {
        self.owner
    }

    #[cfg(test)]
    pub(crate) fn set_owner_for_test(&mut self, owner: ([u8; 16], u64, [u8; 16])) {
        self.owner = owner;
    }

    /// The material a replaced held object reads from, if it was replaced.
    #[cfg(test)]
    pub(crate) fn replaced_for_test(&self, object: u64) -> Option<Arc<ViewContext>> {
        self.objects.get(&object)?.replaced.clone()
    }

    #[cfg(test)]
    pub(crate) fn view_pending_for_test(&self) -> bool {
        self.view_state == MountViewState::ViewPending
    }

    #[cfg(test)]
    pub(crate) fn pinned_base_for_test(&self) -> (GrainId, u64) {
        self.mediator
            .with(|local| {
                let pin = pinned(local)?;
                Ok((pin.base_id, pin.base_seq))
            })
            .expect("a bound pin")
    }

    /// Rebind the pin at `base_seq` with the current view's id, bytes and
    /// material, so a drifted seq still reaches the binding checks.
    #[cfg(test)]
    pub(crate) fn set_pinned_base_for_test(&mut self, base_seq: u64) {
        self.mediator
            .with(|local| {
                let pin = pinned(local)?;
                local.bind_mount(Arc::new(ViewContext {
                    base_seq,
                    ..(*pin).clone()
                }));
                Ok(())
            })
            .expect("a bound pin");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MountViewState {
    Direct,
    SyncAttached,
    ViewPending,
}

impl<R: RootStore + BinStore + Send + 'static, P: OverlayIo + Send + 'static> WritableMount<R, P> {
    /// Install `root` as this mount's view. `verdict` is the view rebuilt
    /// for it with the pin it was rebuilt from, or the refusal that closes
    /// this view. The session accepts `root` first, then `commit` switches
    /// the overlay and binds the view.
    ///
    /// # Errors
    /// `KeptOpen` when nothing switched; `Closed` when the view is closed:
    /// already, by the verdict, by an equivocating cached root, or by a
    /// commit that failed after part of the switch; `ClosedAfterLanding`
    /// when it is closed after the commit completed.
    pub(crate) fn install_view(
        &mut self,
        root: &PublishedRoot,
        verdict: ViewVerdict,
        commit: crate::sync::LandedCommit,
    ) -> Result<crate::ViewChange, ViewInstallError> {
        let result = self.install_verdict(root, verdict, commit);
        let outcome = if result.is_ok() {
            ViewOutcome::Installed
        } else {
            ViewOutcome::Refused
        };
        crate::observe::mount_view(ViewCause::Landed, outcome, root.seq());
        result
    }

    fn install_verdict(
        &mut self,
        root: &PublishedRoot,
        verdict: ViewVerdict,
        commit: crate::sync::LandedCommit,
    ) -> Result<crate::ViewChange, ViewInstallError> {
        use ViewInstallError::Closed;
        if self.view_state != MountViewState::SyncAttached {
            return Err(Closed(self.close_view(refused("ViewPending"))));
        }
        let (context, previous) = verdict.map_err(|error| Closed(self.close_view(error)))?;
        self.accept_root(root, false)?;
        self.switch_view(root, &previous, move || commit(Arc::new(context)))
    }

    /// Adopt `root`, a head another writer published, as this mount's view.
    /// `verdict` is the view rebuilt for it, or the refusal to decide on;
    /// `writers` says whether the adapter holds a write-capable descriptor.
    /// Every check precedes the session's first write, its private floor
    /// raise: the view open, the verdict, the adapter, the engine and the
    /// mediator, the head against the pin, then the head against both
    /// discovery floors, which the session's acceptance checks before it
    /// writes. The checks hold until the commit: their writers are excluded
    /// by engine admission and by the adapter gate with its slot present.
    ///
    /// # Errors
    /// `Deferred` when the mount holds work of its own; `HeadRefused` for a
    /// head it can never install; `KeptOpen` when nothing switched; `Closed`
    /// when the view is closed: already, by an engine or store that cannot
    /// run the check, by an equivocating cached root, or by a commit that
    /// failed part way; `ClosedAfterLanding` when it is closed after the
    /// commit completed.
    pub(crate) fn adopt_view(
        &mut self,
        root: &PublishedRoot,
        verdict: AdoptionVerdict,
        mut adoption: crate::sync::AdoptionCommit,
        writers: bool,
    ) -> Result<crate::ViewChange, ViewInstallError> {
        use ViewInstallError::{Closed, Deferred, HeadRefused};
        if self.view_state != MountViewState::SyncAttached {
            return Err(Closed(self.close_view(refused("ViewPending"))));
        }
        // The old pin is still verified and served: a head the mount cannot
        // serve is refused rather than closing the view.
        let (context, walk, entries, previous) = match verdict {
            Ok(view) => view,
            Err(
                error @ CoordinationError::Refused("ViewUnservable" | "ViewTimeUnrepresentable"),
            ) => {
                return Err(HeadRefused(error));
            }
            Err(error) => return Err(Closed(self.close_view(error))),
        };
        if writers {
            return Err(Deferred);
        }
        // An engine whose state is poisoned, or a store that refuses this
        // check, serves nothing: terminal.
        if (adoption.check)().map_err(|error| Closed(self.close_view(error)))? {
            return Err(Deferred);
        }
        if !crate::sync::head_above_pin(previous.base_seq, root.seq()) {
            return Err(HeadRefused(refused("ViewHeadRefused")));
        }
        // An adoption is discovery, so both floors apply.
        self.accept_root(root, true)?;
        let commit = adoption.commit;
        self.switch_view(root, &previous, move || {
            commit(Arc::new(context), walk, entries)
        })
    }

    /// Have the session accept `root`, persisting its private floor: an
    /// install's first write. A `discovered` root must reach both floors,
    /// and one below either can never be adopted. An equivocating cached
    /// root closes the view; any other refusal keeps it open.
    fn accept_root(
        &mut self,
        root: &PublishedRoot,
        discovered: bool,
    ) -> Result<(), ViewInstallError> {
        let accepted = if discovered {
            self.session.accept_discovered(root, &mut EmitReports)
        } else {
            self.session.accept_published(root, &mut EmitReports)
        };
        match accepted {
            Ok(()) => Ok(()),
            Err(crate::MountError::StaleHead { .. }) if discovered => {
                Err(ViewInstallError::HeadRefused(refused("ViewHeadRefused")))
            }
            Err(crate::MountError::CachedRootEquivocation { .. }) => {
                self.close(crate::FailureClass::Corrupt);
                Err(ViewInstallError::Closed(refused("ViewRootEquivocation")))
            }
            Err(_) => Err(ViewInstallError::KeptOpen(refused("ViewRootNotAccepted"))),
        }
    }

    /// Switch the overlay and bind the view through `commit`, then let each
    /// held clean object the switch retired keep reading what it opened
    /// from `previous`, the outgoing pin.
    fn switch_view(
        &mut self,
        root: &PublishedRoot,
        previous: &ViewContext,
        commit: impl FnOnce() -> Result<crate::ViewChange, CoordinationError>,
    ) -> Result<crate::ViewChange, ViewInstallError> {
        use ViewInstallError::{Closed, ClosedAfterLanding, KeptOpen};
        // A mediator that refuses here refuses every later read and write:
        // terminal, as a poison or fence met by the rebuild is.
        let faults = self
            .mediator
            .with(|store| Ok(store.fault_control()))
            .map_err(|error| Closed(self.close_view(error)))?;
        if view_install_fault(&faults, "before_switch", root) {
            return Err(KeptOpen(refused("SyncInjectedFault")));
        }
        let change = match commit() {
            Ok(change) => change,
            Err(error) => {
                // A commit that failed before the switch leaves the store on
                // the pin's base; one that failed part way leaves another
                // base, or a store that refuses its own.
                let base = self.mediator.with(|local| local.mount_base());
                return Err(match base {
                    Ok(base) if base == (previous.base_id, previous.base_seq) => KeptOpen(error),
                    _ => Closed(self.close_view(error)),
                });
            }
        };
        // Each held clean object the landing retired keeps reading what it
        // opened: one material per content, from the outgoing pin.
        let mut materials = BTreeMap::new();
        for (key, held) in &mut self.objects {
            // Only a clean object is replaced: a held stage keeps its inode.
            if !held.attached || held.node.stage_id.is_some() || !change.retired.contains_key(key) {
                continue;
            }
            let crate::OverlayKind::File {
                content: Some(opened),
            } = held.node.kind
            else {
                continue;
            };
            let material = materials
                .entry(opened)
                .or_insert_with(|| Arc::new(previous.file_material(&opened)));
            held.attached = false;
            held.replaced = Some(material.clone());
        }
        // A sync already pending on a replaced object owes nothing either.
        let view = self
            .mediator
            .with(|store| {
                let view = store.mount_view_context()?;
                store.replace_leases(&change.retired);
                Ok(view)
            })
            .map_err(|error| {
                self.close_view(error);
                ClosedAfterLanding
            })?;
        self.completion_tokens.admit_generation(view.generation);
        if view_install_fault(&faults, "after_switch", root) {
            self.close_view(refused("SyncInjectedFault"));
            return Err(ClosedAfterLanding);
        }
        Ok(change)
    }

    /// Close the view: every later call it serves answers `EIO`.
    fn close(&mut self, class: crate::FailureClass) {
        self.view_state = MountViewState::ViewPending;
        self.completion_tokens.clear();
        crate::observe::op_failed(crate::OperationKind::View, class);
    }

    fn close_view(&mut self, error: CoordinationError) -> CoordinationError {
        self.close(super::coordination_class(&error));
        error
    }

    /// Close the view, as every terminal refusal does.
    #[cfg(test)]
    pub(crate) fn close_view_for_test(&mut self) {
        self.close(crate::FailureClass::Io);
    }

    pub(super) fn retry_pending_shrink(
        &mut self,
        request: &granary_fuse::MountShrinkRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        use granary_fuse::MountSyncError as S;
        let admitted = self
            .mediator
            .admit_sync()
            .map_err(|error| sync_mount_error(&error))?;
        let jobs = self.shrink_jobs.clone().ok_or(S::InvalidRequest)?;
        self.check_mount_view().map_err(|error| match error {
            granary_fuse::WriteError::Backend(error) => S::Backend(error),
            _ => S::InvalidRequest,
        })?;
        let node = if let Some(object) = request.object {
            self.refresh_bound_object(object)
                .map_err(sync_write_error)?;
            let held = self.objects.get(&object).ok_or(S::InvalidHandle)?;
            if held.replaced.is_some() {
                return Err(S::Backend(granary_fuse::MountError::Stale));
            }
            held.node.clone()
        } else {
            self.path_entry(&request.path)
                .map_err(|_| S::InvalidRequest)?
        };
        if node.inode != request.inode {
            return Err(S::Backend(granary_fuse::MountError::Stale));
        }
        let stage = node.stage_id.ok_or(S::InvalidRequest)?;
        let mediator = self.mediator.clone();
        let lease = ObjectLease::acquire(mediator.clone(), &node)
            .map_err(|error| sync_mount_error(&error))?;
        let size = request.size;
        let exec = request.exec;
        Ok(jobs(
            stage,
            size,
            Box::new(move || {
                let _hold = &lease;
                mediator.with(|store| {
                    store.guard_view()?;
                    store.overlay_transaction(|overlay| {
                        let current = if exec.is_some() {
                            let crate::OverlayQuery::Found(query) =
                                overlay.query_inode(node.inode)?
                            else {
                                return Err(OverlayError::refused("shrink identity"));
                            };
                            Some(
                                query
                                    .entry
                                    .ok_or_else(|| OverlayError::refused("shrink identity"))?,
                            )
                        } else {
                            None
                        };
                        overlay.truncate(stage, size)?;
                        if let (Some(exec), Some(current)) = (exec, current)
                            && exec != current.exec
                        {
                            let at = super::journal_location(&current.path)
                                .map_err(|_| OverlayError::refused("shrink identity"))?;
                            overlay.namespace_record(
                                granary_core::overlay_journal::Record::SetattrExec { at, exec },
                            )?;
                        }
                        Ok(())
                    })
                })
            }),
            admitted,
        ))
    }

    pub(super) fn prepare_sync_job(
        &mut self,
        request: granary_fuse::MountSyncRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        use granary_fuse::{MountSyncError as S, MountSyncRequest as R};
        let admitted = self
            .mediator
            .admit_sync()
            .map_err(|error| sync_mount_error(&error))?;
        self.check_mount_view().map_err(|error| match error {
            granary_fuse::WriteError::Backend(error) => S::Backend(error),
            _ => S::InvalidRequest,
        })?;
        let jobs = self.sync_jobs.clone().ok_or(S::InvalidRequest)?;
        let (seal, hold, before): (SyncSeal<P>, Box<dyn Send>, BeforeSync) = match request {
            R::File { object, .. } => {
                self.refresh_bound_object(object)
                    .map_err(sync_write_error)?;
                let held = self.objects.get(&object).ok_or(S::InvalidHandle)?;
                if held.replaced.is_some() {
                    // A replaced object was clean when it was replaced and
                    // has refused every write since: nothing is owed.
                    return Ok(Box::new(ClientMountSyncJob(Box::new(move |completion| {
                        completion(Ok(()));
                        drop(admitted);
                    }))));
                }
                let node = &held.node;
                let lease = ObjectLease::acquire(self.mediator.clone(), node)
                    .map_err(|error| sync_mount_error(&error))?;
                (
                    Box::new(move |store| store.seal_lease(object)),
                    Box::new(lease),
                    None,
                )
            }
            R::Directory { path, .. } => {
                let target = if path.is_empty() {
                    crate::SyncTarget::Directory(None)
                } else {
                    let node = self.path_entry(&path).map_err(|_| S::InvalidRequest)?;
                    if !matches!(node.kind, crate::OverlayKind::Directory) {
                        return Err(S::InvalidRequest);
                    }
                    crate::SyncTarget::Directory(Some(node.inode))
                };
                #[cfg(any(test, feature = "overlay-fault-tests"))]
                let before: BeforeSync = {
                    let mediator = self.mediator.clone();
                    Some(Box::new(move || {
                        let (faults, journal_cursor) = mediator.with(|store| {
                            store.guard_view()?;
                            let cursor =
                                store.overlay_transaction(|overlay| overlay.journal_cursor())?;
                            Ok((store.fault_control(), cursor))
                        })?;
                        let crate::SyncTarget::Directory(directory_inode) = target else {
                            return Err(refused("SyncDirectoryTarget"));
                        };
                        if faults
                            .rename_directory_point(crate::RenameDirectoryFaultContext {
                                journal_cursor,
                                directory_inode,
                            })
                            .is_some()
                        {
                            return Err(refused("SyncInjectedFault"));
                        }
                        Ok(())
                    }))
                };
                #[cfg(not(any(test, feature = "overlay-fault-tests")))]
                let before = None;
                (
                    Box::new(move |store| {
                        store.guard_view()?;
                        store
                            .overlay_transaction(|overlay| overlay.seal_sync(target))
                            .map(Some)
                    }),
                    Box::new(()),
                    before,
                )
            }
        };
        Ok(jobs(seal, hold, before, admitted))
    }

    /// Attach a [`SyncEngine`] to the same [`SharedWritableStore`] owner using the
    /// default Tokio runtime seam, invalidating both clean-content caches at handoff.
    ///
    /// # Errors
    /// Refuses if a view change is already pending, an engine is already attached,
    /// the admitted `(base_id, base_seq)` or `(W, E, T)` no longer matches, or
    /// engine startup validation fails.
    #[cfg(test)]
    pub(crate) async fn attach_sync<Rem, S, C, M>(
        &mut self,
        remote: Arc<Rem>,
        content: Arc<S>,
        wall: Arc<C>,
        monotonic: Arc<M>,
        metrics: ClientMetrics,
        secure: impl SecureRandom + Send + 'static,
    ) -> Result<Arc<SyncEngine<P, Rem, S, C, M, TokioSyncRuntime>>, CoordinationError>
    where
        Rem: SyncRemote + AuthorityTransport + 'static,
        S: SyncContent + 'static,
        C: Clock + 'static,
        M: MonotonicClock + 'static,
    {
        let live = self.live_options_for_attach();
        self.attach_sync_with_runtime_inner(
            remote,
            content,
            wall,
            monotonic,
            metrics,
            Arc::new(TokioSyncRuntime),
            secure,
            live,
        )
        .await
    }

    /// Attach the production live driver with its default schedule options.
    pub(super) async fn attach_live_sync<Rem, S, C, M>(
        &mut self,
        remote: Arc<Rem>,
        content: Arc<S>,
        wall: Arc<C>,
        monotonic: Arc<M>,
        metrics: ClientMetrics,
        secure: impl SecureRandom + Send + 'static,
    ) -> Result<Arc<SyncEngine<P, Rem, S, C, M, TokioSyncRuntime>>, CoordinationError>
    where
        Rem: SyncRemote + AuthorityTransport + 'static,
        S: SyncContent + 'static,
        C: Clock + 'static,
        M: MonotonicClock + 'static,
    {
        self.attach_sync_with_runtime_inner(
            remote,
            content,
            wall,
            monotonic,
            metrics,
            Arc::new(TokioSyncRuntime),
            secure,
            Some(crate::SyncOptions {
                workspace_bytes: self
                    .mediator
                    .with(|store| Ok(store.construction_workspace_bytes))?,
                ..crate::SyncOptions::default()
            }),
        )
        .await
    }

    /// Attach a [`SyncEngine`] to the same [`SharedWritableStore`] owner with an
    /// explicit [`SyncRuntime`], invalidating both clean-content caches at handoff.
    ///
    /// # Errors
    /// Refuses if a view change is already pending, an engine is already attached,
    /// the admitted `(base_id, base_seq)` or `(W, E, T)` no longer matches, or
    /// engine startup validation fails.
    #[cfg(test)]
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit independent storage, timing, metrics, runtime and entropy seams"
    )]
    pub(crate) async fn attach_sync_with_runtime<Rem, S, C, M, E>(
        &mut self,
        remote: Arc<Rem>,
        content: Arc<S>,
        wall: Arc<C>,
        monotonic: Arc<M>,
        metrics: ClientMetrics,
        runtime: Arc<E>,
        secure: impl SecureRandom + Send + 'static,
    ) -> Result<Arc<SyncEngine<P, Rem, S, C, M, E>>, CoordinationError>
    where
        Rem: SyncRemote + AuthorityTransport + 'static,
        S: SyncContent + 'static,
        C: Clock + 'static,
        M: MonotonicClock + 'static,
        E: SyncRuntime + 'static,
    {
        let live = self.live_options_for_attach();
        self.attach_sync_with_runtime_inner(
            remote, content, wall, monotonic, metrics, runtime, secure, live,
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "explicit independent storage, timing, metrics, runtime, entropy and live-driver seams"
    )]
    async fn attach_sync_with_runtime_inner<Rem, S, C, M, E>(
        &mut self,
        remote: Arc<Rem>,
        content: Arc<S>,
        wall: Arc<C>,
        monotonic: Arc<M>,
        metrics: ClientMetrics,
        runtime: Arc<E>,
        secure: impl SecureRandom + Send + 'static,
        live: Option<crate::SyncOptions>,
    ) -> Result<Arc<SyncEngine<P, Rem, S, C, M, E>>, CoordinationError>
    where
        Rem: SyncRemote + AuthorityTransport + 'static,
        S: SyncContent + 'static,
        C: Clock + 'static,
        M: MonotonicClock + 'static,
        E: SyncRuntime + 'static,
    {
        match self.view_state {
            MountViewState::ViewPending => return Err(refused("ViewPending")),
            MountViewState::SyncAttached => {
                return Err(refused("SyncEngineAlreadyAttached"));
            }
            MountViewState::Direct => (),
        }
        if self.signer.key.is_none() {
            return Err(refused("SyncEngineAlreadyAttached"));
        }
        let (view, pin) = self.check_sync_binding(true)?;
        self.completion_tokens.admit_generation(view.generation);
        let trusted = TrustedKeys::new([self.signer.public]).map_err(|_| refused("SyncBase"))?;
        let view_remote = remote.clone();
        let volume = self
            .mediator
            .with(|store| Ok(store.snapshot().volume.clone()))?;
        let observer = Arc::new(HeadObserver::new(
            remote.clone(),
            runtime.clone(),
            volume,
            wall.clone(),
            self.view,
            Some(metrics.clone()),
        ));
        let (engine, post_generation) = SyncEngine::attach_with_runtime(
            self.mediator.as_arc(),
            remote,
            content,
            wall,
            monotonic,
            &mut self.signer.key,
            trusted,
            pin.base_bytes.clone(),
            metrics,
            runtime.clone(),
            Some(self.owner),
        )
        .await?;
        if let Some(generation) = post_generation {
            self.completion_tokens.admit_generation(generation);
        }
        let faults = self.mediator.with(|store| Ok(store.fault_control()))?;
        let secure = SharedEntropy(Arc::new(Mutex::new(secure)));
        self.sync_jobs = Some(mount_sync_jobs(
            engine.clone(),
            &faults,
            secure.clone(),
            self.sync_profile,
            self.mediator
                .with(|store| Ok(store.construction_workspace_bytes))?,
        ));
        self.shrink_jobs = Some(mount_shrink_jobs(engine.clone()));
        self.shutdown = Some(Arc::new(crate::sync::Shutdown::new(
            engine.clone(),
            self.mediator.clone(),
            runtime.clone(),
            secure.clone(),
            tokio::runtime::Handle::try_current().ok(),
            self.shutdown_bound,
        )));
        let content = MountSyncContent {
            mediator: self.mediator.clone(),
            remote: view_remote,
            operation: None,
            recovery: false,
        };
        self.view_boundary = Some(Arc::new(MountViewBoundary::new(
            observer.clone(),
            runtime.clone(),
            tokio::runtime::Handle::try_current().ok(),
            self.view,
        )));
        let live = live.map(|options| {
            LiveStart::new(
                engine.clone(),
                runtime.clone(),
                secure,
                options,
                tokio::runtime::Handle::try_current().ok(),
            )
        });
        self.view_binding = Some(ViewBinding::new(
            engine.clone(),
            content,
            runtime,
            observer,
            live,
        ));
        self.view_state = MountViewState::SyncAttached;
        Ok(engine)
    }

    #[cfg(test)]
    fn live_options_for_attach(&self) -> Option<crate::SyncOptions> {
        self.live_driver.then_some(self.live_options)
    }

    /// Observe the mediator's current `(base_id, base_seq)` and `range_cache`
    /// generation, clearing stale completion tokens before any reuse and closing
    /// the mount view with `EIO` (`ViewPending`) if the admitted base advanced.
    ///
    /// # Errors
    /// Returns [`granary_fuse::MountError::Io`] (`ViewPending`) when the mount's
    /// pinned snapshot no longer matches the mediator's admitted base, or the
    /// mapped [`granary_fuse::MountError`] on readiness/fencing failure.
    pub fn observe_engine_view(&mut self) -> Result<MountViewContext, granary_fuse::MountError> {
        self.observe_view_inner(true)
    }

    pub(crate) fn check_mount_view(
        &mut self,
    ) -> Result<MountViewContext, granary_fuse::WriteError> {
        let enforce_base = self.view_state != MountViewState::Direct;
        let view = self
            .observe_view_inner(enforce_base)
            .map_err(granary_fuse::WriteError::Backend)?;
        #[cfg(test)]
        if let Some(mut hook) = self.after_view_hook.take() {
            hook(&self.mediator);
        }
        Ok(view)
    }

    /// Observe the mediator's view and admit it against the pin read in the
    /// same acquisition.
    pub(crate) fn admit_mediator_view(
        &mut self,
    ) -> Result<MountViewContext, granary_fuse::WriteError> {
        let (view, engine_attached, pin) = self
            .mediator
            .with(|local| {
                let view = local.mount_view_context()?;
                Ok((view, local.engine_attached(), pinned(local)?))
            })
            .map_err(|error| write_error(&error))?;
        if self.view_state == MountViewState::ViewPending {
            return Err(granary_fuse::WriteError::Backend(
                granary_fuse::MountError::Io,
            ));
        }
        self.admit_captured_view(view, engine_attached, &pin)
    }

    fn admit_captured_view(
        &mut self,
        view: MountViewContext,
        engine_attached: bool,
        pin: &ViewContext,
    ) -> Result<MountViewContext, granary_fuse::WriteError> {
        let enforce_base = self.view_state != MountViewState::Direct || engine_attached;
        self.admit_mount_view_context(view, enforce_base, None, pin)
            .map_err(granary_fuse::WriteError::Backend)
    }

    fn admit_mount_view_context(
        &mut self,
        view: MountViewContext,
        enforce_base: bool,
        faults: Option<&crate::FaultControl>,
        pin: &ViewContext,
    ) -> Result<MountViewContext, granary_fuse::MountError> {
        self.completion_tokens.admit_generation(view.generation);
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        if let Some(faults) = faults
            && faults
                .sync_point(
                    "fuse.sync.view",
                    "cleared",
                    view.generation,
                    Some(view.base_id),
                    "none",
                )
                .is_some()
        {
            return Err(granary_fuse::MountError::Io);
        }
        #[cfg(not(any(test, feature = "overlay-fault-tests")))]
        let _ = faults;
        if enforce_base && (view.base_id, view.base_seq) != (pin.base_id, pin.base_seq) {
            self.completion_tokens.clear();
            self.view_state = MountViewState::ViewPending;
            return Err(granary_fuse::MountError::Io);
        }
        Ok(view)
    }

    /// Admit a view the caller captured against the pin read now. A landing
    /// between the capture and this read passes here and is refused by the
    /// effect's own acquisition; a pin moved between them refuses here.
    pub(crate) fn admit_mount_view(
        &mut self,
        view: MountViewContext,
    ) -> Result<MountViewContext, granary_fuse::WriteError> {
        if self.view_state == MountViewState::ViewPending {
            return Err(granary_fuse::WriteError::Backend(
                granary_fuse::MountError::Io,
            ));
        }
        let (engine_attached, pin) = self
            .mediator
            .with(|local| Ok((local.engine_attached(), pinned(local)?)))
            .map_err(|error| write_error(&error))?;
        self.admit_captured_view(view, engine_attached, &pin)
    }

    fn observe_view_inner(
        &mut self,
        enforce_base: bool,
    ) -> Result<MountViewContext, granary_fuse::MountError> {
        if self.view_state == MountViewState::ViewPending {
            return Err(granary_fuse::MountError::Io);
        }
        let (view, engine_attached, faults, pin) = self
            .mediator
            .with(|local| {
                let view = local.mount_view_context()?;
                Ok((
                    view,
                    local.engine_attached(),
                    local.fault_control(),
                    pinned(local)?,
                ))
            })
            .map_err(|error| mount_error(write_error(&error)))?;
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        let old_generation = self.completion_tokens.generation().unwrap_or(0);
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        if faults
            .sync_point(
                "fuse.sync.view",
                "observed",
                old_generation,
                Some(pin.base_id),
                "none",
            )
            .is_some()
        {
            return Err(granary_fuse::MountError::Io);
        }
        #[cfg(not(any(test, feature = "overlay-fault-tests")))]
        let _ = faults;
        self.admit_mount_view_context(view, enforce_base || engine_attached, Some(&faults), &pin)
    }
}

/// Translate supervised sync failures without interpreting diagnostic text.
#[must_use]
pub fn sync_mount_error(error: &CoordinationError) -> granary_fuse::MountSyncError {
    use crate::SyncRefusalKind;
    use granary_fuse::{MountError as M, MountSyncError as S};
    let backend = match error {
        CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. } => M::Stale,
        CoordinationError::SyncRefusal(SyncRefusalKind::Authorization) => M::Access,
        CoordinationError::SyncRefusal(_) | CoordinationError::Publication(_) => M::Io,
        CoordinationError::Codec(_) => M::Corrupt,
        CoordinationError::Recovery(_) => match crate::sync::failure_class(error) {
            crate::observe::FailureClass::Conflict => M::Stale,
            crate::observe::FailureClass::Corrupt => M::Corrupt,
            crate::observe::FailureClass::Unavailable => M::Unavailable,
            _ => M::Io,
        },
        CoordinationError::Refused(reason) => match *reason {
            "SyncCancelled" => return S::Cancelled,
            "ViewPending" | "SyncBaseBinding" => return S::ViewPending,
            "IntentOverQuota" => M::Quota,
            "IntentCapExhausted"
            | "IntentCapOverflow"
            | "OverlayCapacityExhausted"
            | "SyncWorkspaceExhausted"
            | "RecoveryResidualWorkspace" => M::NoSpace,
            "IntentSelectionChanged"
            | "IntentCursorChanged"
            | "IntentTokenDisplaced"
            | "SyncOwnerBinding" => M::Stale,
            "SyncDeadline"
            | "SyncCommitRebaseUnavailable"
            | "SyncCommitUnresolved"
            | "IntentStartupAttemptsExhausted"
            | "IntentRetryDeadline"
            | "IntentRetryNotEligible"
            | "IntentEntropyUnavailable"
            | "IntentAttemptsExhausted"
            | "ViewRootUnavailable"
            | "RecoveryResidualUnavailable" => M::Unavailable,
            "SyncBase"
            | "SyncRechunkContent"
            | "SyncCommitSignature"
            | "SyncCommitManifest"
            | "SyncCommitRebaseManifest"
            | "SyncCommitContainment"
            | "SyncProjectedBinding"
            | "IntentPreparedRoot"
            | "IntentPreparedSignature"
            | "IntentPendingSignature"
            | "IntentLandedReplayInvalid"
            | "IntentCarrierChanged" => M::Corrupt,
            _ => M::Io,
        },
        CoordinationError::Overlay(error) => match error {
            OverlayError::Conflict => M::Stale,
            OverlayError::NoSpace => M::NoSpace,
            OverlayError::ContentUnavailable => M::Unavailable,
            OverlayError::MutationsClosed => M::Closing,
            OverlayError::ContentCorrupt
            | OverlayError::CaptureCoverageLost
            | OverlayError::Refused(
                "capture extent mismatch" | "short capture extent" | "clean file content",
            ) => M::Corrupt,
            OverlayError::Io(error) => match error.kind() {
                std::io::ErrorKind::PermissionDenied => M::Access,
                std::io::ErrorKind::StorageFull => M::NoSpace,
                std::io::ErrorKind::QuotaExceeded => M::Quota,
                _ => M::Io,
            },
            OverlayError::Refused(
                "sync file identity" | "sync directory identity" | "capture stage",
            ) => return S::InvalidRequest,
            OverlayError::Refused(reason) => {
                return sync_mount_error(&refused(reason));
            }
            _ => M::Io,
        },
    };
    S::Backend(backend)
}

#[cfg(test)]
mod tests;
