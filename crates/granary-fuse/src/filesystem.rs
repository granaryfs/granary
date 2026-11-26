// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The `fuser::Filesystem` adapter.
//!
//! The adapter retains a pinned read view and captures ordinary mutations
//! through its mediated backend. Mount policy supplies permission presentation
//! and admission; the backend rechecks ownership before effects.
//! Terminal observations run after reply-free helpers drop their local gates.
//!
//! Most of the `fuser::Filesystem` methods below are unreachable from an
//! in-process test: `fuser::Request` and every `Reply*` type have no public
//! constructor outside `fuser` (verified against the installed 0.18.0
//! source). So each callback is kept to ONE terminal `match` that calls a
//! private, `Request`/`Reply`-free helper method returning a plain
//! `Result` — the helper carries the real logic and IS testable by
//! constructing a [`GranaryFs`] directly; the trait method itself is thin
//! enough that reading it is the review.
//!
//! Not `#[cfg(target_os = "linux")]`: the `Filesystem` impl compiles on
//! macOS under the `macos-no-mount` feature (probed, plan R12), which is
//! what keeps this crate inside clippy and nextest on the dev machine. Only
//! the code that actually MOUNTS is Linux-gated, in `unmount.rs`.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{
    AccessFlags, BsdFileFlags, CopyFileRangeFlags, FileHandle, Filesystem, FopenFlags, Generation,
    INodeNo, IoctlFlags, KernelConfig, LockOwner, OpenAccMode, OpenFlags, PollEvents, PollFlags,
    PollNotifier, RenameFlags, ReplyAttr, ReplyBmap, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyIoctl, ReplyLock, ReplyLseek, ReplyOpen,
    ReplyPoll, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};

#[cfg(target_os = "macos")]
use fuser::ReplyXTimes;

use granary_core::hash::GrainId;
use granary_core::manifest::{EntryKind, Name, TreeStats};
use granary_core::sheaf::Timestamp;

use crate::{
    DirPlusSink, DirSink, MountBackend, SinkOutcome, check_name_length, errno, list_dir,
    list_dir_plus, negotiate,
};
use granary_vfs::{
    Attr, Entry, HandleKind, HandleTable, InodeTable, NodeKind, PathKey, ReaderError, Snapshot,
    dir_and_parent,
};

/// The snapshot is immutable for the whole life of the mount,
/// so entry and attribute TTLs can be long — nothing under a fixed
/// snapshot ever changes, so there is no correctness upside to a shorter
/// value. The one case a longer TTL makes worse is an unmount racing a
/// cached dentry, which is invisible until it happens rather than
/// something a shorter TTL would surface earlier either — so this is not
/// tuned against a measurement, just chosen long because nothing here
/// benefits from short. `from_mins`, not `from_secs(60)`: the latter trips
/// `clippy::duration_suboptimal_units` and fails the lint gate.
const ENTRY_TTL: Duration = Duration::from_mins(1);

/// The `fuser::Filesystem` adapter over an already-validated, immutable
/// [`Snapshot`], generic over the mutable backend `B`.
///
/// The immutable snapshot stays outside the adapter gate. One fuser worker
/// dispatches callbacks; owned deferred completions can reacquire the gate from
/// the client runtime.
///
/// The generic backend keeps storage, fetch state and runtime ownership in the
/// client without a dependency from this adapter to the client crate.
///
/// `inner` shares one mutex over the backend, inode table and handle table so
/// deferred completions revalidate the same consistency domain. Its `Option`
/// permits preparation and shutdown to take exclusive ownership of that state.
///
/// Immutable-object preparation temporarily takes the owned state out of this
/// slot. It holds no adapter mutex during transport; an unwind abandons the
/// backend, and ordinary local capture reacquires the gate after restoration.
///
/// `#[derive(Debug)]` on both this type and `MountInner` is required,
/// not decorative: the workspace lints `missing_debug_implementations`
/// and CI denies warnings.
#[derive(Debug)]
pub struct GranaryFs<B: MountBackend> {
    snapshot: Snapshot,
    writability: crate::MountWritability,
    observer: Option<Arc<dyn crate::CallbackObserver>>,
    /// Where a writable mount looks for another writer's head.
    view_boundary: Option<Arc<dyn crate::ViewBoundary>>,
    snapshot_fixture: bool,
    /// The snapshot's publish [`Timestamp`], converted to the kernel's
    /// timestamp type exactly ONCE, here at construction, and never a
    /// per-callback decision. [`to_file_attr`]
    /// reads the instant its [`Bent`] carries rather than converting — it
    /// cannot convert, having no route back to a `Snapshot` at all. A writable
    /// view reports this time for every path no install has moved.
    mount_time: SystemTime,
    inner: Arc<Mutex<Option<MountInner<B>>>>,
    /// The slot protocol between preparations and a view install.
    view_slot: Arc<view::ViewSlot>,
    /// The armed fault, if any. `None` on every
    /// mount built without `set_breakage` ever being called —
    /// which is every mount this feature is off for, and every
    /// mount this feature is on for but `gran mount --breakage
    /// <name>` was not given (a feature-built `gran mount` refuses to start
    /// without `--breakage`, before it ever reaches this field).
    #[cfg(feature = "conformance-breakage")]
    breakage: Option<crate::Breakage>,
}

#[derive(Debug)]
struct MountInner<B> {
    backend: B,
    inodes: InodeTable,
    handles: HandleTable,
    write_handles: std::collections::BTreeMap<u64, OpenFlags>,
    object_handles: std::collections::BTreeMap<u64, u64>,
    view: view::WritableView,
    directory_cursors: std::collections::BTreeMap<u64, std::collections::BTreeMap<Vec<u8>, u64>>,
}

/// Why [`GranaryFs::new`] refused to admit a [`Snapshot`].
///
/// **`Display`'s match below is written exhaustive, with no wildcard arm**,
/// so adding a variant without adding its own arm is a compile error
/// (`E0004`) rather than a silently-unhandled case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountRefused {
    /// The snapshot was constructed admitting a symlink target longer than
    /// this adapter's own `readlink` reply can carry — see
    /// [`granary_vfs::ServeLimits`]. Admitting it anyway would turn this mount-time
    /// refusal into an opaque per-call `EIO` on whichever `readlink` call
    /// first reached the over-long target.
    ReadlinkBoundExceeded {
        /// The bound the snapshot was built (and already checked) against.
        snapshot_bound: usize,
        /// The bound this adapter's own `readlink` reply can carry.
        adapter_bound: usize,
    },
    /// The snapshot's publish timestamp — valid in the format's own sense,
    /// `nanos` strictly under one second, the bound `Timestamp::is_valid`
    /// checks and the decoder already refuses — does not fit `SystemTime`
    /// on this platform. Representability is the platform's own question —
    /// `SystemTime`'s representable range is i64 seconds on Unix and
    /// `FILETIME`'s 1601-30828 on Windows — never that format validity, which
    /// [`granary_vfs::SnapshotError::InvalidTimestamp`] already refused before a
    /// `Snapshot` could exist to hand this adapter a timestamp at all.
    /// `kernel_time`'s own tests establish that every such valid timestamp
    /// converts on a 64-bit Unix host, so this arm has no reachable input
    /// here; it exists for a platform where that stops being true.
    UnrepresentableTimestamp {
        /// The timestamp this platform's `SystemTime` could not represent.
        timestamp: Timestamp,
    },
}

impl std::fmt::Display for MountRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadlinkBoundExceeded {
                snapshot_bound,
                adapter_bound,
            } => write!(
                f,
                "mount refused: the snapshot admits a readlink target of up to \
                 {snapshot_bound} bytes, but this adapter's readlink reply can carry only \
                 {adapter_bound}"
            ),
            Self::UnrepresentableTimestamp { timestamp } => write!(
                f,
                "mount refused: root publish timestamp (secs {}, nanos {}) does not fit this \
                 platform's timestamp type",
                timestamp.secs, timestamp.nanos
            ),
        }
    }
}

impl std::error::Error for MountRefused {}

/// An extended-attribute query's answer: the size a zero-size buffer asks
/// for, or the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum XattrReply {
    Size(u32),
    Data(Vec<u8>),
}

/// Backend failures retain their class until the terminal reply converts to errno.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyError {
    Errno(fuser::Errno),
    Backend(crate::MountError),
    PendingShrink(u64),
}
impl ReplyError {
    fn errno(self) -> fuser::Errno {
        match self {
            Self::Errno(error) => error,
            Self::PendingShrink(_) => fuser::Errno::EIO,
            Self::Backend(error) => error.errno(),
        }
    }
    fn outcome(self) -> crate::CallbackOutcome {
        match self {
            Self::Backend(crate::MountError::Access) => crate::CallbackOutcome::Refused,
            Self::Backend(error) => crate::CallbackOutcome::Failed(error),
            Self::Errno(error) => crate::CallbackOutcome::from_errno(Some(error)),
            Self::PendingShrink(_) => crate::CallbackOutcome::Failed(crate::MountError::Io),
        }
    }
}
impl From<fuser::Errno> for ReplyError {
    fn from(error: fuser::Errno) -> Self {
        Self::Errno(error)
    }
}
impl From<crate::MountError> for ReplyError {
    fn from(error: crate::MountError) -> Self {
        Self::Backend(error)
    }
}
impl From<crate::MountSyncError> for ReplyError {
    fn from(error: crate::MountSyncError) -> Self {
        match error {
            crate::MountSyncError::Backend(error) => Self::Backend(error),
            error => Self::Errno(error.errno()),
        }
    }
}
impl From<crate::WriteError> for ReplyError {
    fn from(error: crate::WriteError) -> Self {
        match error {
            crate::WriteError::Backend(error) => Self::Backend(error),
            crate::WriteError::PendingShrink => Self::Errno(fuser::Errno::EIO),
            error => Self::Errno(error.errno()),
        }
    }
}
impl PartialEq<fuser::Errno> for ReplyError {
    fn eq(&self, error: &fuser::Errno) -> bool {
        self.errno() == *error
    }
}

impl<B: MountBackend> GranaryFs<B> {
    /// Builds a mount adapter from an already-validated snapshot and a
    /// caller-constructed backend. `generation` seeds the inode table's
    /// per-mount generation stamp (`InodeTable::new`'s own parameter,
    /// unchanged here) — this crate does not choose one itself; the
    /// caller is who knows whether inode numbers need to stay distinct
    /// across remounts (NFS export; `fuser::FileAttr`'s own doc).
    ///
    /// # Errors
    ///
    /// Returns [`MountRefused`] when `snapshot` was built admitting a
    /// `readlink` target bound looser than this adapter's own — see
    /// [`granary_vfs::ServeLimits`] and [`Snapshot::limits`] — or when its
    /// publish timestamp — valid in the format's own sense, `nanos` strictly
    /// under one second — does not fit this platform's timestamp type (see `kernel_time`).
    pub fn new(
        snapshot: Snapshot,
        backend: B,
        generation: u64,
        writability: crate::MountWritability,
    ) -> Result<Self, MountRefused> {
        let snapshot_bound = snapshot.limits().readlink_target_max_bytes;
        let adapter_bound = crate::FUSE_SERVE_LIMITS.readlink_target_max_bytes;
        if snapshot_bound > adapter_bound {
            return Err(MountRefused::ReadlinkBoundExceeded {
                snapshot_bound,
                adapter_bound,
            });
        }
        // Converted ONCE, here, at mount time — never a per-callback
        // decision. `to_file_attr` reads the result from its `Bent` and has
        // no route back to a `Snapshot` to convert again.
        let mount_time =
            kernel_time(snapshot.timestamp()).ok_or(MountRefused::UnrepresentableTimestamp {
                timestamp: snapshot.timestamp(),
            })?;
        let inodes = InodeTable::new(
            snapshot.manifest_root(),
            generation,
            u64::from(fuser::INodeNo::ROOT),
        );
        let observer = backend.callback_observer();
        let view_boundary = backend.view_boundary();
        let snapshot_fixture = backend.snapshot_fixture();
        Ok(Self {
            snapshot,
            writability,
            observer,
            view_boundary,
            snapshot_fixture,
            mount_time,
            inner: Arc::new(Mutex::new(Some(MountInner {
                backend,
                inodes,
                handles: HandleTable::new(),
                write_handles: std::collections::BTreeMap::new(),
                object_handles: std::collections::BTreeMap::new(),
                view: view::WritableView::new(mount_time),
                directory_cursors: std::collections::BTreeMap::new(),
            }))),
            view_slot: Arc::default(),
            #[cfg(feature = "conformance-breakage")]
            breakage: None,
        })
    }

    /// Arms one [`crate::Breakage`] variant for this mount's remaining
    /// life. Callers set this before the mount
    /// ever starts its FUSE read loop (`granary-client`'s daemon body,
    /// right after constructing `Self` and before `fuser::Session::new`
    /// takes ownership); nothing here re-checks that ordering, the same
    /// way `new` itself trusts its caller to hand it an
    /// already-validated `Snapshot`.
    #[cfg(feature = "conformance-breakage")]
    pub fn set_breakage(&mut self, breakage: crate::Breakage) {
        self.breakage = Some(breakage);
    }

    /// The one routing point for the two `Attr`-level faults,
    /// and the ONLY constructor of [`Bent`] — a
    /// FOURTH `Attr`-to-`FileAttr` site added later cannot compile
    /// without calling this, because `to_file_attr` accepts nothing
    /// else. Called from every `Attr` site: `lookup_entry`,
    /// `getattr_attr`, and — for the readdirplus path —
    /// `RealDirPlusSink::offer`, which is where `ExecEverywhere`/
    /// `MisreportSize` are applied for that path (NOT inside the
    /// breakage.rs sink wrapper, which never sees a `GranaryFs` to call
    /// this on; the wrapper's own OmitEntry/DirentTypeLie/FollowSymlink
    /// transforms are unaffected and still run there, exactly once,
    /// before the wrapper delegates to whichever sink — real or, in its
    /// own unit tests, fake — receives the entry). Identical call sites
    /// either way the feature builds: only this method's OWN body
    /// differs.
    #[cfg(feature = "conformance-breakage")]
    fn bend(&self, attr: Attr, time: SystemTime) -> Bent {
        bent::bend(self.breakage, self.present_attr(attr), time)
    }

    #[cfg(not(feature = "conformance-breakage"))]
    fn bend(&self, attr: Attr, time: SystemTime) -> Bent {
        bent::bend(self.present_attr(attr), time)
    }

    fn present_attr(&self, mut attr: Attr) -> Attr {
        attr.perm = granary_vfs::permission_mode(
            self.writability == crate::MountWritability::Writable,
            attr.kind,
            attr.perm & 0o111 != 0,
        );
        attr
    }

    fn ttl(&self) -> Duration {
        match self.writability {
            crate::MountWritability::ReadOnly => ENTRY_TTL,
            crate::MountWritability::Writable => Duration::ZERO,
        }
    }

    fn open_reply_flags(&self, directory: bool) -> FopenFlags {
        if self.writability == crate::MountWritability::Writable {
            FopenFlags::empty()
        } else if directory {
            FopenFlags::FOPEN_CACHE_DIR
        } else {
            FopenFlags::FOPEN_KEEP_CACHE
        }
    }

    fn begin(&self, callback: crate::Callback) -> Option<Box<dyn crate::CallbackScope>> {
        self.observer
            .as_ref()
            .and_then(|observer| observer.begin(callback))
    }

    fn completed<T>(
        &self,
        callback: crate::Callback,
        result: Result<T, ReplyError>,
    ) -> Result<T, fuser::Errno> {
        if let Some(observer) = &self.observer {
            observer.completed(
                callback,
                result
                    .as_ref()
                    .err()
                    .copied()
                    .map_or(crate::CallbackOutcome::Ok, ReplyError::outcome),
            );
        }
        result.map_err(ReplyError::errno)
    }

    fn unimplemented(&self, callback: crate::Callback) -> Result<(), fuser::Errno> {
        let _scope = self.begin(callback);
        self.completed(callback, Err(fuser::Errno::ENOSYS.into()))
    }

    fn mutation_gate(&self) -> Result<(), ReplyError> {
        if self.writability == crate::MountWritability::ReadOnly {
            return Err(fuser::Errno::EROFS.into());
        }
        let mut guard = self.inner.lock().map_err(|_| fuser::Errno::EIO)?;
        let inner = guard.as_mut().ok_or(fuser::Errno::EIO)?;
        inner.backend.mutation_readiness().map_err(ReplyError::from)
    }

    fn refused_mutation(&self) -> Result<(), ReplyError> {
        self.mutation_gate()?;
        Err(fuser::Errno::ENOTSUP.into())
    }

    fn node_refusal(&self, mode: u32) -> Result<(), ReplyError> {
        self.mutation_gate()?;
        match mode & 0o170_000 {
            0o100_000 => Err(fuser::Errno::ENOSYS.into()),
            0o010_000 | 0o020_000 | 0o060_000 | 0o140_000 => Err(fuser::Errno::ENOTSUP.into()),
            _ => Err(fuser::Errno::EINVAL.into()),
        }
    }

    fn rename_refusal(&self, flags: u32) -> Result<(), ReplyError> {
        self.mutation_gate()?;
        match flags {
            0 | 1 => Err(fuser::Errno::ENOSYS.into()),
            2 | 4 => Err(fuser::Errno::ENOTSUP.into()),
            _ => Err(fuser::Errno::EINVAL.into()),
        }
    }

    fn setattr_result(
        &self,
        ino: INodeNo,
        mode: Option<u32>,
        size: Option<u64>,
        unsupported: bool,
        fh: Option<FileHandle>,
    ) -> Result<Bent, ReplyError> {
        self.setattr_overlay(ino, mode, size, unsupported, fh)
    }

    fn xattr_query(
        &self,
        ino: INodeNo,
        name: Option<&OsStr>,
        size: u32,
    ) -> Result<XattrReply, ReplyError> {
        let list = name.is_none();
        if self.writability == crate::MountWritability::Writable {
            if !self.snapshot_fixture
                && ino == INodeNo::ROOT
                && name.is_none_or(|name| name.as_bytes() == b"user.granary.view")
                && let Some(label) = self.live_boundary().and_then(crate::ViewBoundary::label)
            {
                let bytes = match (name, label.map_err(ReplyError::Backend)?) {
                    (Some(_), bytes) => bytes,
                    (None, _) => b"user.granary.view\0".to_vec(),
                };
                let len = u32::try_from(bytes.len()).map_err(|_| fuser::Errno::EIO)?;
                return if size == 0 {
                    Ok(XattrReply::Size(len))
                } else if size < len {
                    Err(fuser::Errno::ERANGE.into())
                } else {
                    Ok(XattrReply::Data(bytes))
                };
            }
            Err(fuser::Errno::ENOTSUP.into())
        } else if list {
            if size == 0 {
                Ok(XattrReply::Size(0))
            } else {
                Ok(XattrReply::Data(Vec::new()))
            }
        } else {
            Err(fuser::Errno::NO_XATTR.into())
        }
    }

    /// The shared gate for `lookup_entry` and `resolve_own_entry`: applies
    /// [`crate::follow_sibling`] when `FollowSymlink` is armed, a no-op
    /// otherwise. `dir` is the directory `entry` was resolved from —
    /// `follow_sibling` needs it to look the target up as a SIBLING.
    #[cfg(feature = "conformance-breakage")]
    fn follow_symlink_if_armed(&self, dir: &GrainId, entry: Entry) -> Entry {
        match self.breakage {
            Some(crate::Breakage::FollowSymlink) => {
                crate::follow_sibling(&self.snapshot, dir, entry)
            }
            _ => entry,
        }
    }

    #[cfg(not(feature = "conformance-breakage"))]
    #[expect(
        clippy::unused_self,
        reason = "identity form of the same method — see `bend`'s identical note just above"
    )]
    fn follow_symlink_if_armed(&self, _dir: &GrainId, entry: Entry) -> Entry {
        entry
    }

    /// `TruncateRead`: pops the last byte of a read that covers
    /// the file's declared final byte — the walker `fstat`s BEFORE
    /// reading, so the size stays honest and only the content diverges.
    /// `covers_final_byte` is computed by the caller from the REQUESTED
    /// range (`offset`/`size`), not from `bytes.len()`: `read_at`
    /// already returns `min(size, declared_size - offset)` bytes, so the
    /// requested range is the one fact this needs and the only one that
    /// avoids a `usize`-to-`u64` cast this crate's lints have no
    /// `#[allow]` for.
    #[cfg(feature = "conformance-breakage")]
    fn truncate_read_if_armed(&self, mut bytes: Vec<u8>, covers_final_byte: bool) -> Vec<u8> {
        if covers_final_byte && self.breakage == Some(crate::Breakage::TruncateRead) {
            bytes.pop();
        }
        bytes
    }

    #[cfg(not(feature = "conformance-breakage"))]
    #[expect(
        clippy::unused_self,
        reason = "identity form of the same method — see `bend`'s identical note above"
    )]
    fn truncate_read_if_armed(&self, bytes: Vec<u8>, _covers_final_byte: bool) -> Vec<u8> {
        bytes
    }

    /// `MangleSymlinkTarget`: appends one byte to a successful `readlink`.
    /// BOUND: never let a target reach
    /// [`crate::FUSE_READLINK_TARGET_MAX_4K_PAGE`] (4095, the kernel's
    /// servable ceiling, `PAGE_SIZE - 1`) — gendir's longest fixture target
    /// is 17 bytes, but the bound is CHECKED here rather than trusted from
    /// that gap: a manifest symlink target may legally BE exactly that
    /// ceiling — well inside
    /// [`granary_core::manifest::name::SYMLINK_TARGET_MAX`]'s own legal
    /// range, which runs one byte further, to 4096 — and this callback is
    /// reachable from any local reader's `readlink()`, so a panicking check
    /// would be reachable from untrusted manifest content. See the function
    /// body's own comment for the guard.
    ///
    /// **Why an honest `st_size` does not hide the appended byte.** Appending
    /// a byte here while leaving
    /// `st_size`
    /// honest could let a walker that sizes its read buffer from
    /// `lstat` truncate the lie back off, so this check would pass
    /// vacuously. REFUTED: the oracle's walker reads a symlink target
    /// through `nix::fcntl::readlinkat` -> `inner_readlink`, which
    /// allocates `Vec::with_capacity(PATH_MAX)` (4096 bytes) UP FRONT
    /// and reads into THAT buffer first — it consults `lstat` only if
    /// the read fills the buffer, so `st_size` is never even read on
    /// the path this variant's targets take, and gendir's longest
    /// target (17 bytes) is nowhere near where that would matter
    /// anyway.
    ///
    /// A 4095-byte target appended to exactly 4096 does not let
    /// `inner_readlink` truncate the appended byte on an
    /// `lstat`-sized retry. The retry loop returns only when
    /// `len < capacity` and otherwise doubles its buffer, so it
    /// reads the full target. Independently, the kernel refuses a
    /// 4096-byte FUSE readlink reply before it reaches userspace,
    /// as detailed below.
    /// Each of the two limits holds on its own.
    ///
    /// 1. `nix` NEVER truncates on that path. `inner_readlink`'s retry
    ///    loop does `reserve_exact(try_size)`, returns only when
    ///    `len < capacity`, and otherwise DOUBLES via
    ///    `checked_shl(1)` — its own comment says "even if lstat's
    ///    apparently valid answer turns out to be wrong, we will still
    ///    read the full symlink no matter what". A 4096-byte target
    ///    comes back whole.
    /// 2. A 4096-byte readlink reply never reaches userspace at all.
    ///    The kernel's `fuse_readlink_page` asks for `PAGE_SIZE - 1`
    ///    (4095) as an `out_argvar`, and `copy_out_args` answers a
    ///    reply larger than that with `-EINVAL`, which
    ///    `fuse_dev_do_write` turns into `-EIO`. The walker's
    ///    `readlinkat` would get EIO and the dump would ABORT — loud,
    ///    not vacuous.
    ///
    /// The guard below checks
    /// `target.len() < FUSE_READLINK_TARGET_MAX_4K_PAGE`, so it
    /// appends a byte only when the resulting reply remains
    /// within the kernel's servable ceiling. A target already
    /// at that ceiling is left honest instead of being pushed
    /// one byte beyond it. This boundary is reachable from a
    /// real mount: `Snapshot::new` refuses only `len >` the
    /// bound it is handed, so a target AT the bound is
    /// ADMITTED. `readlink_bytes` then hands that target to
    /// this transform. The at-the-bound admission is pinned
    /// by the `granary-vfs` test in `snapshot/tests.rs`
    /// named
    /// `a_symlink_target_at_exactly_the_readlink_limit_is_accepted_and_reads_back_whole`.
    /// The test pins `TEST_READLINK_BOUND`, which is derived
    /// from the FORMAT constant. The `const _: () = assert!`
    /// beside the adapter constant in `lib.rs` separately
    /// holds this guard's number. The two values coincide at
    /// 4095 today. Without the strict comparison, a legal
    /// 4095-byte target could be mangled into the 4096-byte
    /// reply that the kernel refuses. The check therefore
    /// leaves the boundary target unchanged and appends only
    /// below that boundary, where the added byte still fits
    /// within the servable reply ceiling.
    #[cfg(feature = "conformance-breakage")]
    fn mangle_symlink_target_if_armed(&self, mut target: Vec<u8>) -> Vec<u8> {
        // The bound is CHECKED, not merely asserted: `target` is a manifest
        // symlink target, and while `SymlinkTarget::new` itself permits up to
        // exactly `SYMLINK_TARGET_MAX` (4096) bytes, the bound this function
        // enforces is stricter — the kernel's own servable ceiling,
        // `FUSE_READLINK_TARGET_MAX_4K_PAGE` (4095). Checking it here rather
        // than trusting `Snapshot::new`'s refusal
        // (`SnapshotError::UnrepresentableSymlinkTarget`) is defence in
        // depth — and the two are NOT identical, which is the point: that
        // gate refuses `len >` the bound it was HANDED (this adapter hands it
        // `FUSE_SERVE_LIMITS`, so 4095) and therefore ADMITS a 4095-byte
        // target, while this guard declines to mangle AT 4095. It is one byte
        // looser upstream, so this check is not duplication and deleting it as
        // such would reintroduce the EIO. The upstream bound is now INJECTED
        // rather than read from this crate's constant, so the two are equal
        // only because `mount.rs` passes `FUSE_SERVE_LIMITS`; this guard reads
        // the constant directly and does not depend on that.
        // This callback is reachable from any local
        // reader's
        // `readlink()`, so a `debug_assert!` here (which would PANIC) is the
        // wrong tool regardless of whether that upstream gate ever regresses;
        // gendir's own fixtures never reach either cap (longest is 17 bytes),
        // but nothing in this function's own contract can rely on gendir's
        // choices. Below the servable ceiling, mangle; at or above it, leave
        // the target honest rather than push past it.
        if self.breakage == Some(crate::Breakage::MangleSymlinkTarget)
            && target.len() < crate::FUSE_READLINK_TARGET_MAX_4K_PAGE
        {
            target.push(b'!');
        }
        target
    }

    #[cfg(not(feature = "conformance-breakage"))]
    #[expect(
        clippy::unused_self,
        reason = "identity form of the same method — see `bend`'s identical note above"
    )]
    fn mangle_symlink_target_if_armed(&self, target: Vec<u8>) -> Vec<u8> {
        target
    }

    /// Resolves `ino`'s OWN manifest entry, for the callbacks that need
    /// an entry of ANY kind rather than only directories:
    /// [`dir_and_parent`](granary_vfs::dir_and_parent) solves the identical
    /// parent-vs-own problem but restricts its result to directories,
    /// since listing always starts from one. The root has no name
    /// inside a parent to look itself up BY, so it synthesises its own
    /// `Dir` entry directly — the same root special case
    /// `dir_and_parent` has, generalised to every entry kind.
    ///
    /// Symlink substitution requires a METHOD rather than the free
    /// function of the same name it replaced, purely so it can
    /// reach `self.breakage` — [`Self::follow_symlink_if_armed`]
    /// is called right after this function's own
    /// `Snapshot::lookup`, unconditional on the feature (its own
    /// cfg'd/non-cfg'd pair is the no-op when the feature is off).
    /// Every other line is unchanged from that free function.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Inconsistent`] when `ino` is unknown, when
    /// its recorded path is empty but it is not the root, or when the
    /// resolved name does not exist in its parent (an inode table entry
    /// the snapshot disagrees with).
    fn resolve_own_entry(&self, inodes: &InodeTable, ino: u64) -> Result<Entry, ReaderError> {
        let (path, dir, _kind) = inodes.resolve(ino)?;
        if ino == inodes.root_ino() {
            return Ok(Entry {
                name: inert_name()?,
                kind: EntryKind::Dir { child: dir },
                leaf: dir,
            });
        }
        let last = path.last().ok_or(ReaderError::Inconsistent)?;
        let entry = self.snapshot.lookup(&dir, last)?;
        Ok(self.follow_symlink_if_armed(&dir, entry))
    }

    /// The reply-FREE half of
    /// `RealDirPlusSink::offer` — everything that function does EXCEPT
    /// the actual `self.reply.add(...)` call, which needs a real
    /// `fuser::ReplyDirectoryPlus` nothing in this crate can construct.
    /// Extracted so `bend` being replaced by a bare `Bent(attr)` (the
    /// silent-bypass mutation) is a REACHABLE
    /// unit-test red instead of invisible behind an untestable trait
    /// method — same "Request/Reply-free helper" shape this module's
    /// own doc states for every other callback, applied here for the
    /// first time to a `DirPlusSink` impl rather than a `Filesystem`
    /// one.
    fn bent_reply_parts(
        &self,
        attr: Attr,
        time: SystemTime,
    ) -> (INodeNo, fuser::FileAttr, Generation) {
        let bent = self.bend(attr, time);
        // EQUIVALENT MUTANT, named rather than chased:
        // `bend_attr` mutates only `perm`/`size` (ExecEverywhere/
        // MisreportSize) — it never touches `.ino` for any of the seven
        // variants — so `INodeNo(bent.ino)` below and a hypothetical
        // `INodeNo(attr.ino)` computed BEFORE the bend are identical on
        // every fixture this crate builds today, and no test can tell
        // them apart. Read from `bent` anyway, on principle (the ONE
        // value this function's own return type commits to using is
        // the post-bend one, and a future breakage variant touching
        // `.ino` would make the distinction real) — not manufactured a
        // fixture to force an observable difference that does not
        // exist in the current variant set.
        //
        // Trap T1: `ReplyDirectoryPlus::add`'s `ino` ARGUMENT IS IGNORED
        // — the encoder reads `attr.ino` for both wire inode fields and
        // `attr.mode >> 12` for the type. `to_file_attr` sets
        // `FileAttr::ino` from this SAME `attr.ino`, so the two can never
        // disagree by construction; the assert exists to catch a future
        // refactor that breaks that, not because it can fail today. A
        // `debug_assert`, not `assert`: this callback is reachable from
        // any local reader issuing `ls`, and the coding standards forbid
        // a panic reachable from untrusted input — the invariant is still
        // checked on a debug build that actually MOUNTS (the mechanism
        // tests), which is where a regression would first show up.
        let ino = INodeNo(bent.ino);
        let file_attr = to_file_attr(&bent);
        debug_assert_eq!(
            file_attr.ino, ino,
            "ReplyDirectoryPlus::add reads attr.ino for both wire fields (trap T1); \
             the ino argument passed to add is ignored, so these must always agree"
        );
        (ino, file_attr, Generation(bent.generation))
    }

    /// `readdirplus`'s ENTIRE
    /// armed/unarmed decision, extracted from the trait method so a
    /// unit test can drive it against a FAKE `DirPlusSink` on a real
    /// `GranaryFs` — deleting this whole
    /// `#[cfg] if let Some(breakage)` arm left the suite at 173/173
    /// green, because `readdirplus` itself cannot be unit-tested (no
    /// public `fuser::ReplyDirectoryPlus`/`Request` constructor exists
    /// outside `fuser`) and nothing else in the crate called it. Generic
    /// over `S: DirPlusSink` so both the real sink (`readdirplus`,
    /// below) and a test fake can drive it.
    ///
    /// # Errors
    ///
    /// Whatever `list_dir_plus`/`list_dir_plus_with_breakage` return.
    fn list_dir_plus_dispatch<S: DirPlusSink>(
        &self,
        inner: &mut MountInner<B>,
        ino: u64,
        offset: u64,
        sink: &mut S,
    ) -> Result<(), ReaderError> {
        // When a breakage is armed, every reply this
        // call makes runs through the cfg'd sink wrapper instead
        // — see `breakage.rs` for the seven variants and the
        // credit-repayment rules this dispatch alone cannot get
        // wrong (they live in `list_dir_plus_with_breakage`,
        // unit tested there against a fake sink; nothing here is
        // a decision, only wiring — the same "thin enough that
        // reading it is the review" rule this module's own doc
        // states for every trait method).
        #[cfg(feature = "conformance-breakage")]
        if let Some(breakage) = self.breakage {
            return crate::list_dir_plus_with_breakage(
                breakage,
                &mut inner.inodes,
                &self.snapshot,
                ino,
                offset,
                sink,
            );
        }
        list_dir_plus(&mut inner.inodes, &self.snapshot, ino, offset, sink)
    }

    /// Locks `inner` for the duration of `f`, then releases the lock
    /// before returning — every caller matches on this function's return
    /// VALUE, computed after the guard implicit in this function's own
    /// stack frame has already dropped, which is what makes "acquire,
    /// work, drop the guard, THEN reply" (R7) structural rather than a
    /// discipline callers have to remember.
    ///
    /// A poisoned lock and an already-shut-down `None` both fold into
    /// `ReaderError::Inconsistent` — the same answer `errno` already
    /// gives every other reader disagreement. Neither happens on a live
    /// mount: a panic that poisons this lock ends the callback thread
    /// under fuser's single-threaded event loop, so no further callback
    /// reaches here afterward, and `destroy` (which handles poison
    /// itself, see its own doc) runs exactly once, last. This fallback
    /// exists for exhaustiveness, not because production reaches it.
    fn with_inner<T>(
        &self,
        f: impl FnOnce(&mut MountInner<B>) -> Result<T, ReaderError>,
    ) -> Result<T, ReaderError> {
        let mut guard = self.inner.lock().map_err(|_| ReaderError::Inconsistent)?;
        let inner = guard.as_mut().ok_or(ReaderError::Inconsistent)?;
        f(inner)
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn observer_for_test(&mut self, observer: Arc<dyn crate::CallbackObserver>) {
        self.observer = Some(observer);
    }

    /// The RUNNING daemon's resident inode-table size, read through
    /// the SAME `inner` mutex every callback takes — so the count
    /// this returns is the count the last callback left, not a
    /// lockless snapshot of a table mid-mutation. Test-only (the
    /// mechanism tests' `Observed` wrapper publishes it after each
    /// table-mutating callback); absent from every non-test build, so
    /// the daemon never carries it. Returns 0 on a poisoned/shut-down
    /// `inner`, which no live mount reaches. Gated to `target_os =
    /// "linux"` as well as `test`, because its only caller is
    /// `mechanism.rs`'s `Observed` wrapper, which is `#[cfg(all(test,
    /// target_os = "linux"))]` — on the macOS dev machine the
    /// mechanism tests are cfg'd out, so a bare `#[cfg(test)]` here
    /// would be dead code and trip the deny-warnings gate.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn resident_count(&self) -> usize {
        self.with_inner(|inner| Ok(inner.inodes.resident_count()))
            .unwrap_or(0)
    }

    /// `lookup`'s logic, `Request`/`Reply`-free. A component over
    /// `NAME_MAX` is refused BEFORE the snapshot is consulted at all
    /// (`check_name_length`'s own doc: the kernel's component cap is
    /// kernel-dependent — up to v6.14 the kernel caps a FUSE name at 1024
    /// bytes; from v6.15 it is `PATH_MAX - 1` once `FUSE_MAX_PAGES` is
    /// negotiated with `max_pages > 1`, which fuser always requests — so
    /// a 256..=1024-byte name REACHES the daemon on every kernel, and
    /// longer ones do on newer kernels). A miss is `NotFound` (->
    /// `ENOENT` via `errno`); an inconsistency is `EIO`.
    fn lookup_entry(&self, parent: INodeNo, name: &[u8]) -> Result<Bent, ReplyError> {
        check_name_length(name)?;
        if self.writability == crate::MountWritability::Writable && !self.snapshot_fixture {
            let found = self.write_inner(|inner| self.lookup_overlay(inner, parent, name));
            // A name not found may be one another writer published since.
            if matches!(&found, Err(error) if *error == fuser::Errno::ENOENT) {
                return match self.boundary(crate::BoundaryKind::LookupMiss) {
                    crate::BoundaryOutcome::Installed => {
                        self.write_inner(|inner| self.lookup_overlay(inner, parent, name))
                    }
                    crate::BoundaryOutcome::Unreachable => {
                        Err(ReplyError::Backend(crate::MountError::Unreachable))
                    }
                    crate::BoundaryOutcome::Served => found,
                };
            }
            return found;
        }
        self.with_inner(|inner| {
            let (dir, _parent_of_parent) =
                dir_and_parent(&inner.inodes, &self.snapshot, u64::from(parent))?;
            let entry = self.snapshot.lookup(&dir, name)?;
            let entry = self.follow_symlink_if_armed(&dir, entry);
            let node_kind = node_kind_of(&self.snapshot, &entry)?;
            let (parent_path, _, _) = inner.inodes.resolve(u64::from(parent))?;
            let mut child_path: PathKey = parent_path.clone();
            child_path.push(name.to_vec());
            let (ino, generation) = inner.inodes.lookup(child_path, dir, node_kind)?;
            self.snapshot
                .attr_for(&entry, ino, generation)
                .map(|attr| self.bend(attr, self.mount_time))
        })
        .map_err(|error| ReplyError::from(errno(error)))
    }

    /// `getattr`'s logic.
    fn getattr_attr(&self, ino: INodeNo) -> Result<Bent, ReplyError> {
        if self.writability == crate::MountWritability::Writable && !self.snapshot_fixture {
            return self.write_inner(|inner| self.overlay_attr(inner, u64::from(ino)));
        }
        self.with_inner(|inner| {
            let entry = self.resolve_own_entry(&inner.inodes, u64::from(ino))?;
            self.snapshot
                .attr_for(&entry, u64::from(ino), inner.inodes.generation())
                .map(|attr| self.bend(attr, self.mount_time))
        })
        .map_err(|error| ReplyError::from(errno(error)))
    }

    /// `readlink`'s logic. `Snapshot::readlink` borrows from its `Entry`
    /// argument, which is local to the closure, so the target is copied
    /// out to an owned `Vec` before the closure (and the borrow) ends.
    fn readlink_bytes(&self, ino: INodeNo) -> Result<Vec<u8>, ReplyError> {
        if self.writability == crate::MountWritability::Writable && !self.snapshot_fixture {
            let result = self.write_inner(|inner| {
                let (path, _, _) = inner.inodes.resolve(u64::from(ino)).map_err(errno)?;
                if !inner.inodes.attached(u64::from(ino)) {
                    return Err(fuser::Errno::ENOENT.into());
                }
                let path = path
                    .iter()
                    .map(|part| {
                        Name::new(part.clone()).map_err(|_| ReplyError::from(fuser::Errno::EINVAL))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                inner
                    .backend
                    .overlay_readlink(&path)
                    .map_err(ReplyError::from)
            });
            return result;
        }
        self.with_inner(|inner| {
            let entry = self.resolve_own_entry(&inner.inodes, u64::from(ino))?;
            let target = self.snapshot.readlink(&entry)?;
            Ok(self.mangle_symlink_target_if_armed(target.to_vec()))
        })
        .map_err(|error| ReplyError::from(errno(error)))
    }

    /// `open`'s logic. Trap T10: `fuser`'s default `open` replies
    /// `opened(FileHandle(0), FopenFlags::empty())` for ANY flags, so a
    /// read-only mount that does not override this accepts `O_WRONLY` at
    /// the FUSE layer — defence against an option regression, since `-o
    /// ro` already refuses writes before FUSE is consulted on a correctly
    /// mounted filesystem. `inodes.open` runs BEFORE `handles.open`
    /// deliberately: if the (astronomically unlikely) monotonic handle
    /// counter were ever exhausted after the inode's own handle count was
    /// already bumped, the failure mode is a benign leak (one inode stays
    /// resident one count longer than it should) rather than the
    /// dangerous direction (a live handle whose inode was never marked
    /// held) — the same "a bounded leak beats an invalidation" reasoning
    /// `list_dir_plus` uses for its own `Full`/`error()` rule.
    fn open_handle(&self, ino: INodeNo, mode: OpenAccMode) -> Result<FileHandle, ReplyError> {
        if mode != OpenAccMode::O_RDONLY {
            return Err(fuser::Errno::EACCES.into());
        }
        self.with_inner(|inner| {
            inner.inodes.open(u64::from(ino))?;
            inner.handles.open(u64::from(ino), HandleKind::File)
        })
        .map(FileHandle)
        .map_err(|error| ReplyError::from(errno(error)))
    }

    fn open_flags_handle(&self, ino: INodeNo, flags: OpenFlags) -> Result<FileHandle, ReplyError> {
        if self.boundary(crate::BoundaryKind::Open) == crate::BoundaryOutcome::Unreachable {
            return Err(ReplyError::Backend(crate::MountError::Unreachable));
        }
        if flags.acc_mode() != OpenAccMode::O_RDONLY {
            if self.writability == crate::MountWritability::ReadOnly {
                return Err(fuser::Errno::EACCES.into());
            }
            self.mutation_gate()?;
        }
        if self.writability == crate::MountWritability::Writable {
            return self.open_overlay(ino, flags);
        }
        self.open_handle(ino, flags.acc_mode())
    }

    fn directory_entries_handle<S: DirSink>(
        &self,
        ino: u64,
        fh: FileHandle,
        offset: u64,
        sink: &mut S,
    ) -> Result<(), ReplyError> {
        self.rewind_boundary(u64::from(fh), offset)?;
        self.write_inner(|inner| {
            if self.writability == crate::MountWritability::Writable && !self.snapshot_fixture {
                return Self::list_overlay(inner, ino, u64::from(fh), offset, sink);
            }
            list_dir(&inner.inodes, &self.snapshot, ino, offset, sink)
                .map_err(|error| ReplyError::from(errno(error)))
        })
    }

    fn directory_entries_plus_handle<S: DirPlusSink>(
        &self,
        ino: u64,
        fh: FileHandle,
        offset: u64,
        sink: &mut S,
    ) -> Result<(), ReplyError> {
        self.rewind_boundary(u64::from(fh), offset)?;
        self.write_inner(|inner| {
            if self.writability == crate::MountWritability::Writable && !self.snapshot_fixture {
                return self.list_overlay_plus(inner, ino, u64::from(fh), offset, sink);
            }
            self.list_dir_plus_dispatch(inner, ino, offset, sink)
                .map_err(|error| ReplyError::from(errno(error)))
        })
    }

    fn fallocate_result(&self, ino: INodeNo, fh: FileHandle, _mode: i32) -> Result<(), ReplyError> {
        self.mutation_gate()?;
        self.write_inner(|inner| Self::fallocate_handle(inner, ino, fh))?;
        Err(fuser::Errno::ENOTSUP.into())
    }

    fn access_attr(&self, ino: INodeNo, mask: AccessFlags) -> Result<(), ReplyError> {
        if mask.contains(AccessFlags::W_OK) && self.writability == crate::MountWritability::ReadOnly
        {
            access_check(mask, 0).map_err(ReplyError::from)
        } else {
            self.getattr_attr(ino)
                .and_then(|attr| access_check(mask, attr.perm).map_err(ReplyError::from))
        }
    }

    /// `opendir`'s logic — the same two-table registration as
    /// `open_handle`, tagged `HandleKind::Directory` so a misdirected
    /// `release`/`releasedir` against the wrong handle kind is a no-op
    /// (`HandleTable::release`'s own guarantee) rather than releasing
    /// something the caller did not name.
    fn opendir_handle(&self, ino: INodeNo) -> Result<FileHandle, ReplyError> {
        if self.boundary(crate::BoundaryKind::Opendir) == crate::BoundaryOutcome::Unreachable {
            return Err(ReplyError::Backend(crate::MountError::Unreachable));
        }
        if self.writability == crate::MountWritability::Writable && !self.snapshot_fixture {
            // A directory a boundary's install replaced is stale, so the
            // kernel looks its name up again.
            self.write_inner(|inner| Self::refuse_replaced(inner, ino))?;
        }
        if self.getattr_attr(ino)?.kind != NodeKind::Dir {
            return Err(fuser::Errno::ENOTDIR.into());
        }
        self.with_inner(|inner| {
            inner.inodes.preflight_open(u64::from(ino))?;
            inner.handles.preflight_open()?;
            let handle = inner.handles.open(u64::from(ino), HandleKind::Directory)?;
            inner.inodes.open(u64::from(ino))?;
            inner
                .directory_cursors
                .insert(handle, std::collections::BTreeMap::default());
            Ok(handle)
        })
        .map(FileHandle)
        .map_err(|error| ReplyError::from(errno(error)))
    }

    /// `read`'s logic. Trap T7: never reply short. `Snapshot::read_at`
    /// already returns exactly `min(size, declared_size - offset)` bytes
    /// or an error; this passes the ORIGINAL `size` through unchanged and
    /// sends whatever comes back unchanged, so there is no truncation
    /// left for this layer to get wrong. An empty `Ok` is EOF, which is
    /// not a short read.
    fn read_bytes(&self, ino: INodeNo, offset: u64, size: u32) -> Result<Vec<u8>, ReplyError> {
        self.with_inner(|inner| {
            let entry = self.resolve_own_entry(&inner.inodes, u64::from(ino))?;
            let EntryKind::File {
                size: declared_size,
                grains,
                ..
            } = &entry.kind
            else {
                return Err(ReaderError::Inconsistent);
            };
            let declared_size = *declared_size;
            let bytes =
                self.snapshot
                    .read_at(&mut inner.backend, grains, declared_size, offset, size)?;
            // `TruncateRead`: final-byte coverage is computed from the REQUESTED range,
            // not `bytes.len()` — see `truncate_read_if_armed`'s doc.
            let covers_final_byte = offset.saturating_add(u64::from(size)) >= declared_size;
            Ok(self.truncate_read_if_armed(bytes, covers_final_byte))
        })
        .map_err(|error| ReplyError::from(errno(error)))
    }

    /// `release`/`releasedir`'s shared logic uses the handle's own inode
    /// BY CONSTRUCTION: this function takes no `ino`
    /// parameter at all, so there is no request-carried ino here for a
    /// call site to reach for by mistake. `HandleTable::release`'s return
    /// is the ONLY ino this function ever sees, and `InodeTable::release`
    /// runs only when that lookup found a live handle of the right kind
    /// (`Some`) — a duplicate, unknown, or wrong-kind release is a no-op,
    /// which is the exactly-one-release-per-open guarantee.
    /// Cleanup failure is replied and observed even when the kernel discards
    /// the release errno instead of surfacing it to close.
    fn release_handle(&self, fh: FileHandle, kind: HandleKind) -> Result<(), ReplyError> {
        self.write_inner(|inner| {
            if let Some(released_ino) = inner.handles.release(u64::from(fh), kind) {
                inner.write_handles.remove(&u64::from(fh));
                inner.directory_cursors.remove(&u64::from(fh));
                let result = if let Some(object) = inner.object_handles.remove(&u64::from(fh)) {
                    if !inner.inodes.attached(released_ino)
                        && let Ok(node) = inner.backend.overlay_object(object)
                        && let Some(record) = inner.view.detached_mut(released_ino)
                    {
                        record.node = Some(node);
                    }
                    inner
                        .backend
                        .overlay_close(object)
                        .map_err(ReplyError::from)
                } else {
                    Ok(())
                };
                inner.inodes.release(released_ino);
                inner.view.prune(&inner.inodes);
                return result;
            }
            Ok(())
        })
    }
}

/// Classify synchronous flags with `O_SYNC` (file sync, `datasync = false`)
/// taking precedence over `O_DSYNC` (data sync, `datasync = true`).
pub(super) fn synchronous_datasync(flags: OpenFlags) -> Option<bool> {
    #[cfg(target_os = "linux")]
    const O_SYNC: i32 = 0x0010_1000;
    #[cfg(target_os = "linux")]
    const O_DSYNC: i32 = 0x0000_1000;
    #[cfg(target_os = "macos")]
    const O_SYNC: i32 = 0x0000_0080;
    #[cfg(target_os = "macos")]
    const O_DSYNC: i32 = 0x0040_0000;
    if flags.0 & O_SYNC == O_SYNC {
        Some(false)
    } else if flags.0 & O_DSYNC == O_DSYNC {
        Some(true)
    } else {
        None
    }
}

/// A [`Name`] used only to satisfy [`Entry`]'s shape when there is no
/// real manifest name to carry — the root's own `getattr`/`readlink`/
/// `read`, which has no parent to look itself up BY name in.
/// `Snapshot::attr_for`/`readlink` read only `entry.kind`
/// (`listing.rs`'s own `placeholder_name` exists for the identical
/// reason inside `.`/`..` synthesis, and is verified there by inspection
/// and by that module's own mutation pass), so the exact bytes here are
/// inert.
fn inert_name() -> Result<Name, ReaderError> {
    Name::new(b"self".to_vec()).map_err(|_| ReaderError::Inconsistent)
}

/// The [`NodeKind`] `InodeTable::lookup` needs before an ino exists to
/// build a full [`Attr`] with. Reuses `Snapshot::attr_for`'s own kind
/// decision — which already refuses Fifo/Socket with
/// `ReaderError::UnsupportedEntry` — rather than re-deriving which
/// `EntryKind`s the inode table can represent; that decision belongs to
/// `attr_for` and already lives in exactly one place. The dummy `ino`/
/// `generation` passed to the probe call are discarded: they are pure
/// output fields on `Attr` and do not affect whether `attr_for` errors or
/// what `kind` it reports.
fn node_kind_of(snapshot: &Snapshot, entry: &Entry) -> Result<NodeKind, ReaderError> {
    Ok(snapshot.attr_for(entry, 0, 0)?.kind)
}

fn to_file_type(kind: NodeKind) -> fuser::FileType {
    match kind {
        NodeKind::Dir => fuser::FileType::Directory,
        NodeKind::File => fuser::FileType::RegularFile,
        NodeKind::Symlink => fuser::FileType::Symlink,
    }
}

/// [`Bent`]'s tuple field lives in THIS
/// submodule, not merely in `filesystem` as a whole. Declared directly
/// in `filesystem.rs`, `Bent(attr)` would be an ordinary, compiling
/// tuple-struct expression anywhere else in that same (large) file, so
/// bypassing `bend` would still compile: another conversion site could
/// only ever exist in `filesystem.rs` anyway (both `Bent` and
/// `to_file_attr` are private to it), and inside that file `Bent(attr)`
/// would need no bending at all. A private field of a `pub(super)` struct is visible
/// ONLY inside the module that declares it (Rust's own privacy rule,
/// not a convention) — so `mod bent` is the actual boundary: [`bend`]
/// is the ONE function inside this module able to write `Bent(attr)`,
/// and [`GranaryFs::bend`] (in the parent module) is the ONE thing
/// allowed to call it. Everywhere else — including elsewhere in
/// `filesystem.rs` — `Bent(attr)` is `error[E0423]: cannot initialize a
/// tuple struct which contains private fields`.
mod bent {
    use granary_vfs::Attr;
    use std::time::SystemTime;

    /// A token only [`bend`] can mint. `to_file_attr` takes `&Bent`,
    /// never `&Attr`, so another `Attr`-to-`FileAttr` conversion site
    /// added later is a compile error, not a silent bypass a
    /// diff-reader could miss.
    ///
    /// `Deref<Target = Attr>` is read-only field access, not a second
    /// way to construct one — `Deref` cannot construct a value, only
    /// read through an existing one, and nothing outside this
    /// submodule can name the private field at all. `Attr` and the
    /// carried host instant are `Copy`, so wrapping them allocates nothing.
    /// The instant is the one the kernel is told for this attribute: the
    /// mount's start time, or a writable view's per-path time.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct Bent(Attr, SystemTime);

    impl Bent {
        /// The host instant the attribute reports for all four kernel times.
        pub(super) fn host_time(&self) -> SystemTime {
            self.1
        }
    }

    impl std::ops::Deref for Bent {
        type Target = Attr;

        fn deref(&self) -> &Attr {
            &self.0
        }
    }

    /// The sole construction seam, shared by local callbacks and owned
    /// deferred completions. Parent visibility keeps construction inside the
    /// filesystem module; every wire conversion still requires a `Bent`.
    #[cfg(feature = "conformance-breakage")]
    pub(super) fn bend(
        breakage: Option<crate::Breakage>,
        mut attr: Attr,
        time: SystemTime,
    ) -> Bent {
        if let Some(breakage) = breakage {
            crate::bend_attr(breakage, &mut attr);
        }
        Bent(attr, time)
    }

    #[cfg(not(feature = "conformance-breakage"))]
    pub(super) fn bend(attr: Attr, time: SystemTime) -> Bent {
        Bent(attr, time)
    }
}
use bent::Bent;
mod live;
mod sync;
mod view;
mod write;
pub use view::{SlotBusy, ViewAdapter, ViewHandle, ViewNotifier};

/// The checked `Timestamp` -> `SystemTime` conversion this adapter performs
/// exactly once per view — at [`GranaryFs::new`] for the start view, and by
/// the install for each later one, before it takes the adapter gate — never a
/// per-callback decision.
/// **Representability only**: the format's own validity (`nanos` strictly
/// under one second) is the engine's own business, refused by
/// `Snapshot::new` as [`granary_vfs::SnapshotError::InvalidTimestamp`]
/// before a `Timestamp` can ever reach here — so this helper does not check
/// it again, and is total over every format-valid input on this platform (its
/// own tests establish that; see below). It answers `None` only when the
/// value does not fit `SystemTime`'s platform-specific range: i64 seconds
/// on Unix, `FILETIME`'s 1601-30828 on Windows — the same signed root that
/// converts on Linux can be refused on a Windows adapter, for a reason
/// about Windows' time type, not about the format.
///
/// `Duration::new` panics when the nanosecond carry overflows its seconds,
/// so the two components are added separately with `from_secs`/
/// `from_nanos`, neither of which can panic. `unsigned_abs` is what makes
/// `i64::MIN` representable as a magnitude at all — `checked_neg` would
/// fail on it and hide the real rejection, which belongs to `checked_sub`.
#[must_use]
pub fn kernel_time(timestamp: Timestamp) -> Option<SystemTime> {
    let magnitude = Duration::from_secs(timestamp.secs.unsigned_abs());
    let base = if timestamp.secs < 0 {
        SystemTime::UNIX_EPOCH.checked_sub(magnitude)?
    } else {
        SystemTime::UNIX_EPOCH.checked_add(magnitude)?
    };
    base.checked_add(Duration::from_nanos(u64::from(timestamp.nanos)))
}

/// The one place a [`Bent`] (an [`Attr`] that has been through
/// [`GranaryFs::bend`]) becomes a [`fuser::FileAttr`]. **Reads the
/// already-converted host instant the `Bent` carries; it does not convert.**
/// `attr.time` stays the format's own `Timestamp` all the way through this
/// adapter — the checked conversion happened ONCE, in
/// [`GranaryFs::new`] ([`kernel_time`]), and this free `fn` has no `self`
/// and so no route back to the `Snapshot` that conversion needs; calling
/// `kernel_time` per callback here would repeat a conversion the mount
/// performs once — and this signature makes it unreachable rather than merely
/// discouraged. Kept a PURE conversion otherwise:
/// no breakage hook lives here — that happens once, in
/// `bend`, before a caller ever reaches this function.
fn to_file_attr(attr: &Bent) -> fuser::FileAttr {
    let time = attr.host_time();
    fuser::FileAttr {
        ino: INodeNo(attr.ino),
        size: attr.size,
        blocks: attr.blocks,
        atime: time,
        mtime: time,
        ctime: time,
        crtime: time,
        kind: to_file_type(attr.kind),
        perm: attr.perm,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: 0,
        blksize: attr.blksize,
        flags: 0,
    }
}

/// The one place a directory-reply `bool` becomes a [`SinkOutcome`].
/// `ReplyDirectory::add` (`#[must_use]`) and `ReplyDirectoryPlus::add`
/// (NOT `#[must_use]`) both return `true` to mean "the buffer is full and
/// the entry was NOT added" — the exact inversion a careless reader
/// expects from a method named `add`. Sharing one mapping is what keeps
/// both sinks from independently getting that inversion backwards, and it
/// is the one piece of the directory path testable without a real
/// `fuser` reply object, which neither sink can construct in-process.
fn outcome_from_full(buffer_is_full: bool) -> SinkOutcome {
    if buffer_is_full {
        SinkOutcome::Full
    } else {
        SinkOutcome::Added
    }
}

/// Direct access callbacks use synthesized permission bits. The kernel handles
/// full user/group DAC when `default_permissions` is negotiated.
fn access_check(mask: AccessFlags, perm: u16) -> Result<(), fuser::Errno> {
    if mask.contains(AccessFlags::W_OK) && perm & 0o222 == 0 {
        return Err(fuser::Errno::EACCES);
    }
    // X_OK is checked against the entry's OWN mode, not waved through.
    // Checking only `W_OK` would approve execute on a non-executable
    // file when the mount lacks `default_permissions`.
    if mask.contains(AccessFlags::X_OK) && perm & 0o111 == 0 {
        return Err(fuser::Errno::EACCES);
    }
    Ok(())
}

/// `statfs`'s logic, as a plain tuple matching `ReplyStatfs::statfs`'s own
/// argument order: `(blocks, bfree, bavail, files, ffree, bsize, namelen,
/// frsize)`. Answers honestly rather than taking `fuser`'s default zeros:
/// `bsize`/`frsize` 4096, `namelen` 255 (the same cap `check_name_length`
/// enforces — `granary_core::manifest::name::NAME_MAX`), and `blocks`/
/// `files` derived from the snapshot's `TreeStats`. `bfree`/`bavail`/
/// `ffree` are genuinely 0: the mount is read-only and immutable for its
/// whole life, so there is no free space or free inode to ever report,
/// which is a different and honest claim from the zeros `fuser`'s
/// default reports for a filesystem that never asked its `Snapshot` at
/// all.
///
/// **Standing note, not a fix**: `Snapshot`'s `stats` field is
/// caller-supplied and never cross-checked against the tree it
/// actually indexes (`granary-vfs`'s `snapshot.rs`), and every
/// existing fixture passes `TreeStats::default()` — all zeros.
/// This is the first consumer of `stats()`. Reporting those
/// zeros here would be exactly the honest answer this
/// function's own doc argues against reporting for `namelen`.
fn statfs_reply(stats: TreeStats) -> (u64, u64, u64, u64, u64, u32, u32, u32) {
    const BSIZE: u32 = 4096;
    // Left a literal rather than derived from `NAME_MAX` (`usize`):
    // `TryFrom` is not yet a stable `const fn` (E0658 on
    // `u32::try_from` in a `const` context, checked against the
    // installed toolchain), so a compile-time derivation has no route
    // that avoids either an `as u32` cast (trips
    // `clippy::cast_possible_truncation`, pedantic-denied, and this
    // crate carries no `#[allow(clippy::...)]` anywhere to break that
    // pattern) or a runtime `.expect()` this is not — this constant is
    // evaluated at compile time from a fixed, known-small value.
    // `statfs_reply_derives_blocks_and_files_from_tree_stats_and_zeros_free_space`
    // asserts this constant against `NAME_MAX` directly, so a future
    // divergence still fails a test rather than silently drifting.
    const NAMELEN: u32 = 255;
    let blocks = stats.bytes.div_ceil(u64::from(BSIZE));
    // +1: the mount root itself, which is nobody's child DirEntry and so
    // is never counted in `TreeStats::entries`.
    let files = stats.entries.saturating_add(1);
    (blocks, 0, 0, files, 0, BSIZE, NAMELEN, BSIZE)
}

type StatfsTuple = (u64, u64, u64, u64, u64, u32, u32, u32);

impl<B: MountBackend> GranaryFs<B> {
    fn statfs_dispatch(&self) -> Result<StatfsTuple, ReplyError> {
        if self.writability == crate::MountWritability::ReadOnly {
            return Ok(statfs_reply(self.snapshot.stats()));
        }
        self.write_inner(|inner| {
            let capacity = inner.backend.overlay_capacity().map_err(ReplyError::from)?;
            let free = capacity
                .cap
                .saturating_sub(capacity.charged)
                .saturating_sub(capacity.reserved)
                .saturating_sub(capacity.captured)
                / 4096;
            Ok((
                capacity.cap / 4096,
                free,
                free,
                capacity.files,
                capacity.free_entries.min(inner.inodes.remaining_inodes()),
                4096,
                255,
                4096,
            ))
        })
    }
}

/// `readdir`'s sink over the real `fuser::ReplyDirectory`.
struct RealDirSink<'a> {
    reply: &'a mut ReplyDirectory,
}

impl DirSink for RealDirSink<'_> {
    fn offer(&mut self, ino: u64, kind: fuser::FileType, name: &[u8], next: u64) -> SinkOutcome {
        let full = self
            .reply
            .add(INodeNo(ino), next, kind, OsStr::from_bytes(name));
        outcome_from_full(full)
    }
}

/// `readdirplus`'s sink over the real `fuser::ReplyDirectoryPlus`, and
/// obligation 3's other half: `any_added` tracks whether ANYTHING was
/// ever sent through this sink, so the caller can tell "nothing offered
/// yet, `error()` is safe" apart from "something was already credited,
/// only `ok()` is safe" — the two cases `list_dir_plus`'s own doc names.
///
/// Holds `fs` so it can call [`GranaryFs::bend`] —
/// the ONLY way to obtain the [`Bent`] `to_file_attr` requires. This is
/// where ExecEverywhere/MisreportSize are applied for the readdirplus
/// path (see `bend`'s own doc): reached exactly once per entry whether
/// or not a breakage wrapper sits upstream, so bending here — and ONLY
/// here, never inside the breakage.rs sink wrapper — is what keeps the
/// two-variant transform applied exactly once, never twice.
struct RealDirPlusSink<'a, B: MountBackend> {
    fs: &'a GranaryFs<B>,
    reply: &'a mut ReplyDirectoryPlus,
    any_added: bool,
}

impl<B: MountBackend> DirPlusSink for RealDirPlusSink<'_, B> {
    fn offer(&mut self, attr: Attr, name: &[u8], next: u64) -> SinkOutcome {
        self.offer_timed(attr, self.fs.mount_time, name, next)
    }

    fn offer_timed(&mut self, attr: Attr, time: SystemTime, name: &[u8], next: u64) -> SinkOutcome {
        // Reply-free logic lives in `bent_reply_parts`
        // — nothing here but the ONE call `fuser` gives no
        // other way to reach: `self.reply.add`.
        let (ino, file_attr, generation) = self.fs.bent_reply_parts(attr, time);
        let full = self.reply.add(
            ino,
            next,
            OsStr::from_bytes(name),
            &self.fs.ttl(),
            &file_attr,
            generation,
        );
        let outcome = outcome_from_full(full);
        if outcome == SinkOutcome::Added {
            self.any_added = true;
        }
        outcome
    }
}

impl<B: MountBackend> Filesystem for GranaryFs<B> {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        // A failure to negotiate FAILS INITIALISATION — the
        // fail-open this check exists to close. Without
        // `FUSE_DO_READDIRPLUS` the kernel never sends a READDIRPLUS,
        // `readdirplus` never fires, and nothing else anywhere reports an
        // error: the mount would pass "does `ls -l` work" while silently
        // failing the spec. The DECISION lives in `negotiate` (in
        // `capability.rs`) so tests can supply capability sets directly.
        let wanted = negotiate(config.capabilities()).map_err(|unsupported| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("kernel does not offer the requested capabilities {unsupported:?}"),
            )
        })?;
        config.add_capabilities(wanted).map_err(|unsupported| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("kernel refused a capability it advertised ({unsupported:?})"),
            )
        })
    }

    fn destroy(&mut self) {
        // Obligation 1. On a worker-thread panic,
        // `fuser::Session::run` never reaches this method at all:
        // `thread::join` returns `Err` and `run()` bails out early, so
        // teardown instead happens through `FilesystemHolder`'s own
        // `Drop`, on the `Session::run` thread — which is NOT
        // panicking (`granary-client`'s `mount.rs` has the full
        // account). `std::thread::panicking()` is therefore always
        // false right here and cannot distinguish a crash from a clean
        // exit. The mutex CAN: a panic that unwound while `inner` was
        // locked poisons it, and every callback that mutates the tables
        // or the backend holds this same lock. On poison, decline the
        // clean shutdown and leave the cache's crash guard on disk —
        // that is the one signal a crash happened. NOT TOTAL: a panic
        // that never took this lock, or one caught upstream via
        // `catch_unwind`, is invisible to this check — and it is
        // CONSERVATIVE rather than total in one more sense: `init`,
        // RO `statfs`, `getxattr` and `listxattr` never take this lock at
        // all, and a panic in a callback's post-lock reply path (the
        // `match` after `with_inner` returns, in every callback but the
        // two below) does not poison it either, because the lock is
        // already released by then. `readdir` and `readdirplus` are the
        // exceptions: their replies run INSIDE the sink callbacks that
        // `with_inner` invokes, so a panic there does poison this lock.
        //
        // The `MutexGuard` is dropped BEFORE any backend method is
        // called: backend code must never run under a lock recovered
        // from a poisoned mutex. `destroy` ALWAYS relinquishes
        // `MountInner`; poison chooses the terminal operation.
        // `abandon` disarms the backend before its ordinary `Drop`.
        let (inner, crashed) = match self.inner.lock() {
            Ok(mut guard) => (guard.take(), false),
            Err(poisoned) => (poisoned.into_inner().take(), true),
        };
        // An install waiting for the slot refuses now, not at its deadline.
        self.view_slot.abandon();
        let Some(mut inner) = inner else {
            return;
        };
        if crashed {
            inner.backend.abandon();
        } else {
            // `shutdown`'s `Err` has no reporting channel reachable
            // from inside `Filesystem::destroy`: this method returns
            // `()`, and granary-fuse depends on neither `tracing` nor
            // the "shared exit slot" `source.rs`'s own doc names,
            // which `granary-client` owns. Calling it and discarding
            // a failure is the most this crate can honestly do
            // without inventing that slot; it must not panic, and
            // there is nowhere else here to hand the error to.
            let _ = inner.backend.shutdown();
        }
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let _scope = self.begin(crate::Callback::Lookup);
        match self.completed(
            crate::Callback::Lookup,
            self.lookup_entry(parent, name.as_bytes()),
        ) {
            Ok(attr) => reply.entry(
                &self.ttl(),
                &to_file_attr(&attr),
                Generation(attr.generation),
            ),
            Err(e) => reply.error(e),
        }
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        let _ = self.with_inner(|inner| {
            inner.inodes.forget(u64::from(ino), nlookup);
            inner.view.prune(&inner.inodes);
            Ok(())
        });
        // Not `batch_forget`: `ForgetOne` is not re-exported from `fuser`,
        // so the type cannot be named from this crate. The default fans out
        // to this method, which is the one the forget-accounting rows drive.
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let _scope = self.begin(crate::Callback::Getattr);
        match self.completed(crate::Callback::Getattr, self.getattr_attr(ino)) {
            Ok(attr) => reply.attr(&self.ttl(), &to_file_attr(&attr)),
            Err(e) => reply.error(e),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let _scope = self.begin(crate::Callback::Readlink);
        match self.completed(crate::Callback::Readlink, self.readlink_bytes(ino)) {
            Ok(bytes) => reply.data(&bytes),
            Err(e) => reply.error(e),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let _scope = self.begin(crate::Callback::Open);
        match self.completed(crate::Callback::Open, self.open_flags_handle(ino, flags)) {
            Ok(fh) => reply.opened(fh, self.open_reply_flags(false)),
            Err(e) => reply.error(e),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let _scope = self.begin(crate::Callback::Read);
        match self.completed(
            crate::Callback::Read,
            self.read_handle_bytes(ino, fh, offset, size),
        ) {
            Ok(bytes) => reply.data(&bytes),
            Err(e) => reply.error(e),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // Obligation 2: `_ino` is unused ON PURPOSE — `release_handle`
        // takes no ino parameter at all, so there is no request-carried
        // value here for a future edit to reach for by mistake. `fh` is
        // the only authoritative name for what is being released.
        let _scope = self.begin(crate::Callback::Release);
        match self.completed(
            crate::Callback::Release,
            self.release_handle(fh, HandleKind::File),
        ) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let _scope = self.begin(crate::Callback::Opendir);
        match self.completed(crate::Callback::Opendir, self.opendir_handle(ino)) {
            Ok(fh) => reply.opened(fh, self.open_reply_flags(true)),
            Err(e) => reply.error(e),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let _scope = self.begin(crate::Callback::Readdir);
        let mut sink = RealDirSink { reply: &mut reply };
        let outcome = self.directory_entries_handle(u64::from(ino), fh, offset, &mut sink);
        match self.completed(crate::Callback::Readdir, outcome) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let _scope = self.begin(crate::Callback::Readdirplus);
        let mut sink = RealDirPlusSink {
            fs: self,
            reply: &mut reply,
            any_added: false,
        };
        // The armed/unarmed decision lives in `list_dir_plus_dispatch`
        // — this is thin wiring, exactly the
        // same "thin enough that reading it is the review" rule this
        // module's own doc states for every trait method; the decision
        // ITSELF is unit-tested directly against a fake sink.
        let outcome = self.directory_entries_plus_handle(u64::from(ino), fh, offset, &mut sink);
        let result = if sink.any_added { Ok(()) } else { outcome };
        match self.completed(crate::Callback::Readdirplus, result) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        let _scope = self.begin(crate::Callback::Releasedir);
        match self.completed(
            crate::Callback::Releasedir,
            self.release_handle(fh, HandleKind::Directory),
        ) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let _scope = self.begin(crate::Callback::Statfs);
        match self.completed(crate::Callback::Statfs, self.statfs_dispatch()) {
            Ok((blocks, bfree, bavail, files, ffree, bsize, namelen, frsize)) => {
                reply.statfs(blocks, bfree, bavail, files, ffree, bsize, namelen, frsize);
            }
            Err(error) => reply.error(error),
        }
    }

    fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        // The mode is now load-bearing (see `access_check`), so this
        // resolves the inode rather than ignoring it. `W_OK` is still
        // refused without a lookup, inside `access_check`, so a write
        // probe on an unknown ino answers EACCES rather than EIO.
        let _scope = self.begin(crate::Callback::Access);
        let outcome = self.access_attr(ino, mask);
        match self.completed(crate::Callback::Access, outcome) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let _scope = self.begin(crate::Callback::Getxattr);
        match self.completed(
            crate::Callback::Getxattr,
            self.xattr_query(ino, Some(name), size),
        ) {
            Ok(XattrReply::Size(len)) => reply.size(len),
            Ok(XattrReply::Data(bytes)) => reply.data(&bytes),
            Err(error) => reply.error(error),
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let _scope = self.begin(crate::Callback::Listxattr);
        match self.completed(
            crate::Callback::Listxattr,
            self.xattr_query(ino, None, size),
        ) {
            Ok(XattrReply::Size(len)) => reply.size(len),
            Ok(XattrReply::Data(bytes)) => reply.data(&bytes),
            Err(error) => reply.error(error),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        accessed: Option<TimeOrNow>,
        modified: Option<TimeOrNow>,
        status_time: Option<SystemTime>,
        fh: Option<FileHandle>,
        birth: Option<SystemTime>,
        changed: Option<SystemTime>,
        backup: Option<SystemTime>,
        flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let scope = self.begin(crate::Callback::Setattr);
        let result = self.setattr_result(
            ino,
            mode,
            size,
            uid.is_some()
                || gid.is_some()
                || accessed.is_some()
                || modified.is_some()
                || status_time.is_some()
                || birth.is_some()
                || changed.is_some()
                || backup.is_some()
                || flags.is_some(),
            fh,
        );
        if let Err(ReplyError::PendingShrink(inode)) = result {
            let observation = self
                .observer
                .as_ref()
                .and_then(|observer| observer.captured(crate::Callback::Setattr));
            drop(scope);
            self.resume_setattr(
                ino,
                fh,
                mode,
                size,
                reply,
                sync::SetattrRetry { inode, observation },
            );
            return;
        }
        match self.completed(crate::Callback::Setattr, result) {
            Ok(attr) => reply.attr(&self.ttl(), &to_file_attr(&attr)),
            Err(error) => reply.error(error),
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        let _scope = self.begin(crate::Callback::Mknod);
        let result = if mode & 0o170_000 == 0o100_000 {
            self.create_overlay(parent, name.as_bytes(), NodeKind::File, mode, None)
                .map(|(attr, _)| attr)
        } else {
            self.node_refusal(mode).and(Err(fuser::Errno::EIO.into()))
        };
        match self.completed(crate::Callback::Mknod, result) {
            Ok(attr) => reply.entry(
                &self.ttl(),
                &to_file_attr(&attr),
                Generation(attr.generation),
            ),
            Err(error) => reply.error(error),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let _scope = self.begin(crate::Callback::Mkdir);
        match self.completed(
            crate::Callback::Mkdir,
            self.create_overlay(parent, name.as_bytes(), NodeKind::Dir, mode, None),
        ) {
            Ok((attr, _)) => reply.entry(
                &self.ttl(),
                &to_file_attr(&attr),
                Generation(attr.generation),
            ),
            Err(error) => reply.error(error),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let _scope = self.begin(crate::Callback::Unlink);
        match self.completed(
            crate::Callback::Unlink,
            self.remove_overlay(parent, name.as_bytes(), false),
        ) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let _scope = self.begin(crate::Callback::Rmdir);
        match self.completed(
            crate::Callback::Rmdir,
            self.remove_overlay(parent, name.as_bytes(), true),
        ) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let _scope = self.begin(crate::Callback::Symlink);
        match self.completed(
            crate::Callback::Symlink,
            self.symlink_overlay(parent, link_name.as_bytes(), target.as_os_str().as_bytes()),
        ) {
            Ok(attr) => reply.entry(
                &self.ttl(),
                &to_file_attr(&attr),
                Generation(attr.generation),
            ),
            Err(error) => reply.error(error),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let _scope = self.begin(crate::Callback::Rename);
        match self.completed(
            crate::Callback::Rename,
            self.rename_overlay(
                parent,
                name.as_bytes(),
                newparent,
                newname.as_bytes(),
                flags.bits(),
            ),
        ) {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(error),
        }
    }

    fn link(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _newparent: INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let _scope = self.begin(crate::Callback::Link);
        let error = self
            .completed(crate::Callback::Link, self.refused_mutation())
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        self.finish_sync_write(ino, fh, offset, data, flags, reply);
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let error = self
            .unimplemented(crate::Callback::Flush)
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.sync_reply(ino, fh, datasync, false, reply);
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.sync_reply(ino, fh, datasync, true, reply);
    }

    fn setxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        let _scope = self.begin(crate::Callback::Setxattr);
        let error = self
            .completed(crate::Callback::Setxattr, self.refused_mutation())
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    fn removexattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        let _scope = self.begin(crate::Callback::Removexattr);
        let error = self
            .completed(crate::Callback::Removexattr, self.refused_mutation())
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let _scope = self.begin(crate::Callback::Create);
        match self.completed(
            crate::Callback::Create,
            self.create_overlay(
                parent,
                name.as_bytes(),
                NodeKind::File,
                mode,
                Some(OpenFlags(flags)),
            ),
        ) {
            Ok((attr, Some(fh))) => reply.created(
                &self.ttl(),
                &to_file_attr(&attr),
                Generation(attr.generation),
                fh,
                self.open_reply_flags(false),
            ),
            Ok((_, None)) => reply.error(fuser::Errno::EIO),
            Err(error) => reply.error(error),
        }
    }

    fn getlk(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        reply: ReplyLock,
    ) {
        let error = self
            .unimplemented(crate::Callback::Getlk)
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    fn setlk(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        _sleep: bool,
        reply: ReplyEmpty,
    ) {
        let error = self
            .unimplemented(crate::Callback::Setlk)
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    fn bmap(&self, _req: &Request, _ino: INodeNo, _blocksize: u32, _idx: u64, reply: ReplyBmap) {
        let error = self
            .unimplemented(crate::Callback::Bmap)
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    fn ioctl(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: IoctlFlags,
        _cmd: u32,
        _in_data: &[u8],
        _out_size: u32,
        reply: ReplyIoctl,
    ) {
        let error = self
            .unimplemented(crate::Callback::Ioctl)
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    fn poll(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _ph: PollNotifier,
        _events: PollEvents,
        _flags: PollFlags,
        reply: ReplyPoll,
    ) {
        let error = self
            .unimplemented(crate::Callback::Poll)
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    fn fallocate(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        _offset: u64,
        _length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        let _scope = self.begin(crate::Callback::Fallocate);
        let error = self
            .completed(
                crate::Callback::Fallocate,
                self.fallocate_result(ino, fh, mode),
            )
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    fn lseek(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: i64,
        _whence: i32,
        reply: ReplyLseek,
    ) {
        let error = self
            .unimplemented(crate::Callback::Lseek)
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    fn copy_file_range(
        &self,
        _req: &Request,
        _ino_in: INodeNo,
        _fh_in: FileHandle,
        _offset_in: u64,
        _ino_out: INodeNo,
        _fh_out: FileHandle,
        _offset_out: u64,
        _len: u64,
        _flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        let error = self
            .unimplemented(crate::Callback::CopyFileRange)
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    #[cfg(target_os = "macos")]
    fn setvolname(&self, _req: &Request, _name: &OsStr, reply: ReplyEmpty) {
        let error = self
            .unimplemented(crate::Callback::Setvolname)
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    #[cfg(target_os = "macos")]
    fn exchange(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _newparent: INodeNo,
        _newname: &OsStr,
        _options: u64,
        reply: ReplyEmpty,
    ) {
        let error = self
            .unimplemented(crate::Callback::Exchange)
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }

    #[cfg(target_os = "macos")]
    fn getxtimes(&self, _req: &Request, _ino: INodeNo, reply: ReplyXTimes) {
        let error = self
            .unimplemented(crate::Callback::Getxtimes)
            .err()
            .unwrap_or(fuser::Errno::EIO);
        reply.error(error);
    }
}

#[cfg(test)]
mod tests;
