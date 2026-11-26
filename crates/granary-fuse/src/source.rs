// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The adapter half of the synchronous seam between the FUSE reader
//! and its content source. `GrainFetch`/`GrainUnavailable` moved to
//! `granary-vfs` — they are the engine's own vocabulary, named here
//! directly through `granary_vfs::`. `MountBackend` stays: it is
//! `Send + 'static` and adapter-shaped, not engine-shaped.

use granary_vfs::GrainFetch;
use std::sync::Arc;

/// Immutable presentation and mutation policy, supplied by the admitted caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountWritability {
    ReadOnly,
    Writable,
}

/// Lifecycle refusal from a mediated backend; never derived from error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountError {
    Stale,
    PlanningExhausted,
    Io,
    NoSpace,
    Access,
    Quota,
    Corrupt,
    Unavailable,
    Unreachable,
    /// The mount has stopped accepting writes: its shutdown has begun.
    Closing,
}

impl std::fmt::Display for MountError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Stale => "mount owner displaced",
            Self::PlanningExhausted => "mount planning attempts exhausted",
            Self::Io => "mount local I/O failed",
            Self::NoSpace => "mount capacity exhausted",
            Self::Access => "mount access refused",
            Self::Quota => "mount quota exhausted",
            Self::Corrupt => "mount content corrupt",
            Self::Unavailable => "mount content unavailable",
            Self::Unreachable => "mount authority unreachable",
            Self::Closing => "mount closing",
        })
    }
}

impl std::error::Error for MountError {}

/// Closed result of sync admission or completed supervised work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountSyncError {
    Cancelled,
    InvalidHandle,
    InvalidRequest,
    Backend(MountError),
    ViewPending,
}
impl std::fmt::Display for MountSyncError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("sync cancelled"),
            Self::InvalidHandle => formatter.write_str("invalid sync handle"),
            Self::InvalidRequest => formatter.write_str("invalid sync request"),
            Self::Backend(error) => error.fmt(formatter),
            Self::ViewPending => formatter.write_str("mount view pending"),
        }
    }
}
impl std::error::Error for MountSyncError {}

impl MountSyncError {
    #[must_use]
    pub const fn errno(self) -> fuser::Errno {
        match self {
            Self::Cancelled => fuser::Errno::EINTR,
            Self::InvalidHandle => fuser::Errno::EBADF,
            Self::InvalidRequest => fuser::Errno::EINVAL,
            Self::Backend(error) => error.errno(),
            Self::ViewPending => fuser::Errno::EIO,
        }
    }
}

/// A bound file object or an attached directory identity supplied by the adapter.
#[derive(Debug, Clone)]
pub enum MountSyncRequest {
    File {
        object: u64,
        datasync: bool,
    },
    Directory {
        path: Vec<granary_core::manifest::Name>,
        datasync: bool,
    },
}

/// The original shrink target and metadata request, retained across a floor wait.
#[derive(Debug, Clone)]
pub struct MountShrinkRequest {
    pub inode: u64,
    pub object: Option<u64>,
    pub path: Vec<granary_core::manifest::Name>,
    pub size: u64,
    pub exec: Option<bool>,
}

/// The sole terminal result of an owned sync job.
pub type SyncCompletion = Box<dyn FnOnce(Result<(), MountSyncError>) + Send>;

/// Admission retains resources; starting work never borrows the adapter.
pub trait MountSyncJob: Send {
    fn start(self: Box<Self>, completion: SyncCompletion);
}

/// Live namespace presentation supplied by the mediated overlay.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(test), derive(Clone))]
pub struct OverlayNode {
    pub path: Vec<granary_core::manifest::Name>,
    pub kind: granary_vfs::NodeKind,
    pub size: u64,
    pub exec: bool,
    pub stage: Option<u64>,
}

#[cfg(test)]
std::thread_local! {
    static ENTRY_COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn entry_copies() -> usize {
    ENTRY_COPIES.get()
}

#[cfg(test)]
impl Clone for OverlayNode {
    fn clone(&self) -> Self {
        ENTRY_COPIES.set(ENTRY_COPIES.get() + 1);
        Self {
            path: self.path.clone(),
            kind: self.kind,
            size: self.size,
            exec: self.exec,
            stage: self.stage,
        }
    }
}

/// Attributes and checked links from one namespace observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayMetadata {
    /// Mediator identity, independent of the kernel inode.
    pub inode: u64,
    pub node: OverlayNode,
    pub nlink: u32,
}

/// Directory attributes and an opaque, callback-local continuation.
#[derive(Debug)]
pub struct OverlayDirectory<C> {
    pub directory: OverlayMetadata,
    pub parent: OverlayMetadata,
    pub cursor: C,
}

/// At most 256 owned children, with links from the same observation.
#[derive(Debug)]
pub struct OverlayChildren<C> {
    pub entries: Vec<OverlayMetadata>,
    pub next: Option<C>,
}

/// One cheap mediated view of local capacity and namespace size.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OverlayCapacity {
    pub cap: u64,
    pub charged: u64,
    pub reserved: u64,
    pub captured: u64,
    pub files: u64,
    pub free_entries: u64,
}

/// Namespace validation is distinct from operational failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError {
    Backend(MountError),
    Missing,
    Exists,
    NotDirectory,
    IsDirectory,
    NotEmpty,
    Invalid,
    TooBig,
    Unsupported,
    Unimplemented,
    PendingShrink,
}
impl WriteError {
    #[must_use]
    pub const fn errno(self) -> fuser::Errno {
        match self {
            Self::Backend(error) => error.errno(),
            Self::Missing => fuser::Errno::ENOENT,
            Self::Exists => fuser::Errno::EEXIST,
            Self::NotDirectory => fuser::Errno::ENOTDIR,
            Self::IsDirectory => fuser::Errno::EISDIR,
            Self::NotEmpty => fuser::Errno::ENOTEMPTY,
            Self::Invalid => fuser::Errno::EINVAL,
            Self::TooBig => fuser::Errno::EFBIG,
            Self::Unsupported => fuser::Errno::ENOTSUP,
            Self::Unimplemented => fuser::Errno::ENOSYS,
            Self::PendingShrink => fuser::Errno::EIO,
        }
    }
}

/// One supported namespace or dense-file operation. No raw stage escapes.
#[derive(Debug, Clone, Copy)]
pub enum OverlayMutation<'a> {
    Create {
        path: &'a [granary_core::manifest::Name],
        kind: granary_vfs::NodeKind,
        exec: bool,
    },
    Symlink {
        path: &'a [granary_core::manifest::Name],
        target: &'a granary_core::manifest::SymlinkTarget,
    },
    BoundWrite {
        object: u64,
        offset: u64,
        bytes: &'a [u8],
        append: bool,
    },
    BoundSetattr {
        object: u64,
        size: Option<u64>,
        exec: Option<bool>,
    },
    Write {
        path: &'a [granary_core::manifest::Name],
        offset: u64,
        bytes: &'a [u8],
        append: bool,
    },
    Setattr {
        path: &'a [granary_core::manifest::Name],
        size: Option<u64>,
        exec: Option<bool>,
    },
    Remove {
        path: &'a [granary_core::manifest::Name],
        directory: bool,
    },
    Rename {
        from: &'a [granary_core::manifest::Name],
        to: &'a [granary_core::manifest::Name],
        no_replace: bool,
    },
}

/// Reply observations have no request-carried strings or object identities.
pub trait CallbackObserver: Send + Sync + std::fmt::Debug {
    /// The callback retains the returned scope through completion or unwinding.
    #[must_use]
    fn begin(&self, callback: crate::Callback) -> Option<Box<dyn CallbackScope>>;
    fn completed(&self, callback: crate::Callback, outcome: crate::CallbackOutcome);
    /// Detach the local scope; the returned owner reports the eventual result.
    fn captured(&self, _callback: crate::Callback) -> Option<Box<dyn DeferredCallbackScope>> {
        None
    }
    fn deferred_completed(&self, callback: crate::Callback, outcome: crate::CallbackOutcome) {
        self.completed(callback, outcome);
    }
    /// Record the raw `WRITE` request flags and the retained open-time handle
    /// flags for test witnesses. The default is a no-op; these values are never
    /// carried in shipping observation labels or values.
    fn write_flags_for_test(&self, _request_flags: i32, _retained_flags: i32) {}
}

/// Owned observation that reports the actual deferred result.
pub trait DeferredCallbackScope: Send + std::fmt::Debug {
    fn completed(self: Box<Self>, outcome: crate::CallbackOutcome);
}

/// A thread-local observation scope whose drop handles callback abandonment.
pub trait CallbackScope: std::fmt::Debug {}

/// The writable callback at which a mount looks for another writer's head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryKind {
    Open,
    Opendir,
    /// A lookup that found no entry.
    LookupMiss,
    /// A directory listing restarted from its first entry.
    Rewind,
}

/// What a view boundary left the callback to serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryOutcome {
    /// The mount now serves a newer view.
    Installed,
    /// The mount serves the view it already had.
    Served,
    /// The authority's head could not be confirmed within the boundary's
    /// budget, or the mount is in the unreachable state under strict mode.
    Unreachable,
}

/// A writable mount's close-to-open seam. The adapter calls it before the
/// callback takes the adapter gate, holding nothing, and it returns within
/// its own bound.
pub trait ViewBoundary: Send + Sync + std::fmt::Debug {
    /// Look for another writer's head and adopt it when the mount can.
    /// `writers` reads, under the adapter gate, whether the adapter holds a
    /// write-capable descriptor; a boundary that observes nothing need not
    /// call it.
    fn wait(&self, kind: BoundaryKind, writers: &dyn Fn() -> bool) -> BoundaryOutcome;

    /// The `user.granary.view` label of a writable mount's root, or `None`
    /// when the boundary carries none.
    fn label(&self) -> Option<Result<Vec<u8>, MountError>> {
        None
    }

    /// Whether a strict writable mount is in the unreachable state and
    /// therefore refuses new names without waiting.
    fn unconfirmed(&self) -> bool {
        false
    }
}

/// What the adapter is generic over. `GranaryFs` cannot own the mutable
/// half directly — that half is granary-client's runtime, store, fetch
/// state and cache, and granary-fuse must not depend on granary-client
/// — so the adapter takes a `B: MountBackend` instead. `Send + 'static`
/// because `fuser::Filesystem` is `Send + Sync + 'static`.
pub trait MountBackend: GrainFetch + 'static {
    /// Owned backend context; never a FUSE cookie or a retained Store borrow.
    type DirectoryCursor: Send;

    /// One attached path, including the explicit root.
    /// # Errors
    /// Missing entry, readiness or index consistency failure.
    fn overlay_path(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<OverlayMetadata, WriteError>;

    /// Parent validation and one child in the same observation.
    /// # Errors
    /// Missing entry, wrong parent kind, readiness or index consistency failure.
    fn overlay_lookup(
        &mut self,
        parent: &[granary_core::manifest::Name],
        name: &granary_core::manifest::Name,
    ) -> Result<OverlayMetadata, WriteError>;

    /// Begin one directory observation, including its parent attributes.
    /// # Errors
    /// Missing entry, wrong kind, readiness or index consistency failure.
    fn overlay_directory(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<OverlayDirectory<Self::DirectoryCursor>, WriteError>;

    /// Continue one observation; context churn is `PlanningExhausted`, never EOF.
    /// # Errors
    /// Changed context, readiness or index consistency failure.
    fn overlay_children(
        &mut self,
        cursor: &Self::DirectoryCursor,
    ) -> Result<OverlayChildren<Self::DirectoryCursor>, WriteError>;

    /// Admit an owned sync operation without waiting or uploading.
    /// # Errors
    /// Invalid binding, read-only policy, readiness or unavailable engine.
    fn prepare_sync(
        &mut self,
        request: MountSyncRequest,
    ) -> Result<Box<dyn MountSyncJob>, MountSyncError>;

    /// Retain a pending shrink and retry it outside the adapter gate.
    /// # Errors
    /// Invalid binding, readiness, missing engine or stage hold failure.
    fn prepare_shrink_retry(
        &mut self,
        request: MountShrinkRequest,
    ) -> Result<Box<dyn MountSyncJob>, MountSyncError>;

    /// Independent reporting handle, called only outside adapter/mediator gates.
    fn callback_observer(&self) -> Option<Arc<dyn CallbackObserver>> {
        None
    }

    /// The view boundary of a writable mount that picks up other writers'
    /// heads, read once when the adapter is built.
    fn view_boundary(&self) -> Option<Arc<dyn ViewBoundary>> {
        None
    }

    /// Explicit immutable-view seam for policy fixtures. Shipping backends keep
    /// this false: an unimplemented live query must never serve the pinned view.
    fn snapshot_fixture(&self) -> bool {
        false
    }

    /// Recheck the admitted owner's lifecycle before even a refused mutation.
    /// # Errors
    /// Displacement, poison, capacity or authorization failure.
    fn mutation_readiness(&mut self) -> Result<(), MountError> {
        Err(MountError::Access)
    }

    /// Explicit whole-tree presentation; indexed queries never default through this seam.
    /// # Errors
    /// Readiness, custody or local I/O failure.
    fn overlay_nodes(&mut self) -> Result<Vec<OverlayNode>, WriteError>;

    /// Read cap, fresh charges and namespace length without cloning entries.
    /// # Errors
    /// Readiness, custody or accounting failure.
    fn overlay_capacity(&mut self) -> Result<OverlayCapacity, WriteError>;

    /// Exact target of a live symlink; never truncated to fit a kernel reply.
    /// # Errors
    /// Missing/wrong-kind entry, readiness or custody failure.
    fn overlay_readlink(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<Vec<u8>, WriteError>;

    /// Bind a file handle to a shared object and acquire exactly one stage hold
    /// when staged. Immutable fixture backends may retain their read seam.
    /// # Errors
    /// Missing/type/readiness errors or stage hold exhaustion.
    fn overlay_open(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<Option<u64>, WriteError>;

    /// Current metadata of a held object, independent of name attachment.
    /// # Errors
    /// Unknown object, readiness or custody failure.
    fn overlay_object(&mut self, _object: u64) -> Result<OverlayNode, WriteError>;

    /// Release exactly one object hold. This is resource cleanup, never sync.
    /// # Errors
    /// Invalid hold, poison or custody failure.
    fn overlay_close(&mut self, _object: u64) -> Result<(), WriteError>;

    /// Prepare the held immutable object outside the adapter gate.
    /// # Errors
    /// Invalid binding, unavailable/corrupt content or ownership failure.
    fn prepare_object(&mut self, _object: u64) -> Result<(), WriteError>;

    /// Prepare a clean held target before unlink or replacement.
    /// # Errors
    /// Unavailable/corrupt content or ownership failure.
    fn prepare_detach(&mut self, _path: &[granary_core::manifest::Name]) -> Result<(), WriteError>;

    /// Read a held object through its shared stage or authenticated local base.
    /// # Errors
    /// Invalid binding, unavailable/corrupt content, custody or readiness failure.
    fn read_object(
        &mut self,
        _object: u64,
        _offset: u64,
        _length: usize,
    ) -> Result<Vec<u8>, WriteError>;

    /// Fetch and land immutable base objects with no adapter gate held.
    /// This step captures no operation and grants no mutation readiness.
    /// # Errors
    /// Unavailable/corrupt content, custody or ownership failure.
    fn prepare_overlay(&mut self, _path: &[granary_core::manifest::Name])
    -> Result<(), WriteError>;

    /// Prepare and capture a path setter, returning its revalidated attributes.
    /// The caller retains exclusive backend ownership without the adapter gate.
    /// # Errors
    /// Typed validation, readiness, content, capacity or persistence refusal.
    fn overlay_setattr(
        &mut self,
        path: &[granary_core::manifest::Name],
        size: Option<u64>,
        exec: Option<bool>,
    ) -> Result<OverlayMetadata, WriteError>;

    /// Capture one ordinary operation through the sole-store mediator.
    /// # Errors
    /// Typed validation, readiness, content, capacity or persistence refusal.
    fn overlay_mutate(&mut self, _operation: OverlayMutation<'_>) -> Result<(), WriteError>;

    /// Called ONCE, from `Filesystem::destroy`. The implementor
    /// flushes and closes whatever it owns — granary-client's
    /// does `Cache::close(self)`, which CONSUMES, so it holds its
    /// cache in an `Option` and takes it. A failure is REPORTED,
    /// never panicked, and travels to `main` through the shared
    /// exit slot `granary-client` owns, because `destroy` returns
    /// `()` and `Session::run` never hands the filesystem back.
    #[expect(
        clippy::missing_errors_doc,
        reason = "the Err arm is documented in the prose above rather than under \
                  a `# Errors` heading, which this trait's own contract \
                  fixes. Scoped to this one declaration: a module-level expect \
                  was silencing every FUTURE fallible fn added here too, which is \
                  a wider hole than the one it was opened for"
    )]
    fn shutdown(&mut self) -> Result<(), String>;

    /// Disarm every clean-shutdown behaviour before this backend is
    /// dropped, because a CRASH was detected: whatever on-disk signal
    /// marks an unclean exit must survive this call and the drop that
    /// follows it. Called INSTEAD of [`Self::shutdown`], never as well
    /// as it.
    ///
    /// This does not itself release the backend — the drop that follows
    /// does that. What it must do is make that drop stop short of any
    /// clean-close persistence: granary-client's implementation takes
    /// its `Cache` and abandons it, so the session's own `Drop` finds
    /// nothing to close and the crash guard stays on disk.
    ///
    /// **Called after an unwind across `&mut self`**, so the state it
    /// sees may be logically inconsistent. It must not panic, and it
    /// must not depend on any invariant a callback could have been
    /// halfway through establishing.
    fn abandon(&mut self);
}
