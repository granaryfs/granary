// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Grain-per-file local store: content-hash fanout CAS (git/CVMFS
//! idiom), uncompressed bytes, atomic writes. Presence is not an integrity or
//! durability claim — reads are hash-verified.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt,
};
use std::path::{Component, Path, PathBuf};

use crate::fsguard::{self, MarkerProbe};

use granary_core::grainsource::{GrainSource, GrainSourceError};
use granary_core::hash::GrainId;
use granary_core::thresh::CHUNKER_SPEC;
use granary_store::bounds::META_MAX_BYTES;

/// Store format version (marker file). Bump = migration event.
pub(crate) const STORE_VERSION: u32 = 1;
pub const MARKER_NAME: &str = "granary-store";

/// Bound on the marker file read — mirrors `cache.rs`'s
/// identical `MARKER_MAX_BYTES`; a real marker is well under 100 bytes,
/// 64 KiB is generous headroom. `is_store_marker`'s
/// positive-identification guard and `Store::open`'s own compatibility
/// read are both bounded by it; an unbounded `fs::read_to_string`
/// would allocate proportionally to whatever an attacker-writable file
/// happens to hold.
const MARKER_MAX_BYTES: u64 = 64 * 1024;

#[derive(Debug)]
pub enum StoreError {
    Io {
        context: String,
        source: io::Error,
    },
    /// Marker missing or its recorded tuple/version disagrees.
    Incompatible {
        detail: String,
    },
    /// Another harvester holds the lock.
    Locked,
    /// Stored bytes do not hash back to the id they were filed under
    /// (read path = hash-verified).
    Corrupt {
        id: GrainId,
    },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::Incompatible { detail } => write!(f, "incompatible store: {detail}"),
            Self::Locked => write!(f, "store is locked by another harvest"),
            Self::Corrupt { id } => write!(f, "stored bytes for {id} fail hash verification"),
        }
    }
}

impl std::error::Error for StoreError {}

impl StoreError {
    /// The closed class this error reports under, derived from the error itself.
    pub(crate) fn failure_class(&self) -> crate::FailureClass {
        match self {
            Self::Io { .. } => crate::FailureClass::Io,
            Self::Locked => crate::FailureClass::Conflict,
            Self::Incompatible { .. } => crate::FailureClass::Refused,
            Self::Corrupt { .. } => crate::FailureClass::Corrupt,
        }
    }
}

fn io_err(context: impl Into<String>) -> impl FnOnce(io::Error) -> StoreError {
    let context = context.into();
    move |source| StoreError::Io { context, source }
}

/// Rendered marker contents — store version, chunker specification and hash algorithm.
/// Plain `key value` lines; NOT a hashed format (no consensus claim).
fn marker_contents() -> String {
    format!("granary-store-version {STORE_VERSION}\nchunker {CHUNKER_SPEC}\nhash blake3\n")
}

/// Whether `path` looks like a granary store marker, for the CLI's
/// swapped-argument guard.
///
/// Deliberately NOT byte-equality with the rendered marker body (see
/// `marker_contents`, private — the whole-blob comparison belongs to
/// [`Store::open`], not to this guard). Two requirements pull against
/// each other and this is the shape that satisfies both:
///
/// * A source tree that merely contains a file NAMED `granary-store`
///   must not be refused — the reason existence alone is not enough.
/// * A store whose marker was written by a DIFFERENT build must still
///   be recognised as a store. The marker embeds `CHUNKER_SPEC`,
///   so a change to that specification changes the marker, and every
///   store written under a different specification has a marker
///   byte-equality rejects — which would walk straight back into the
///   swapped-argument failure for exactly the stores this tool created.
///
/// So the test is the marker's stable IDENTIFYING line, not the whole
/// blob: the file's first line must be the `granary-store-version`
/// key. [`Store::open`] keeps its strict byte-equality check — the
/// guard's job is "is this a store?", `open`'s job is "is it a store I
/// can use?", and conflating them is what broke.
///
/// An unreadable `path` is `false`: this is a positive identification,
/// so anything it cannot read is simply not a marker. Bounded:
/// an oversized file — even one starting with the right prefix — is
/// refused the same way an unreadable one is, never read past the
/// module's 64 KiB marker bound.
#[must_use]
pub fn is_store_marker(path: &Path) -> bool {
    matches!(probe_store_marker(path), MarkerProbe::Present)
}

/// [`is_store_marker`]'s tri-state form, for `gran verify`'s root-type
/// detection — see [`MarkerProbe`] for why the boolean is not enough
/// there. Every caller that only needs "is this a store?"
/// (`gran harvest`'s source check) keeps the boolean.
#[must_use]
pub(crate) fn probe_store_marker(path: &Path) -> MarkerProbe {
    match read_marker_bounded(path) {
        Ok(MarkerRead::Present(found)) => {
            if found
                .lines()
                .next()
                .is_some_and(|l| l.starts_with(MARKER_KEY))
            {
                MarkerProbe::Present
            } else {
                // A readable, in-bounds file that is simply not this
                // marker. Not being a marker is a different answer from
                // not being readable, and conflating them would make a
                // stray file in a cache root refuse the whole root.
                MarkerProbe::Absent
            }
        }
        Ok(MarkerRead::Absent) => MarkerProbe::Absent,
        Ok(MarkerRead::NotUtf8 | MarkerRead::OverCap | MarkerRead::NotRegular) | Err(_) => {
            MarkerProbe::Unreadable
        }
    }
}

/// The marker's first key — the part that identifies the FILE as a
/// granary store marker regardless of which build wrote it.
const MARKER_KEY: &str = "granary-store-version ";

/// One bounded read attempt of the marker file, keeping every
/// classification [`Store::open`] already distinguishes (absent /
/// non-UTF-8 / a genuine I/O error / present) plus one more: over
/// [`MARKER_MAX_BYTES`] is the SAME
/// untrustworthy class a
/// tampered marker already is, refused before the content is ever
/// compared or echoed into a diagnostic — never an unbounded read of
/// attacker-writable disk (mirrors the cache module's identical
/// `read_index_file_bounded` (`cache/index_load.rs`) / `check_marker`
/// (`cache/marker.rs`) discipline).
enum MarkerRead {
    Absent,
    NotUtf8,
    OverCap,
    /// Something is at the marker's name that is not a regular file — a
    /// FIFO, a socket, a directory, or a symlink. Its OWN variant and
    /// never folded into [`Self::Absent`]: `Store::open`'s `Absent` arm
    /// is the CREATE path, and a FIFO planted at the marker name must
    /// not be able to drive store creation in a directory this build
    /// has to refuse.
    NotRegular,
    Present(String),
}

fn read_marker_bounded(path: &Path) -> io::Result<MarkerRead> {
    // `fsguard`, not a bare `File::open`: a marker name is a path this
    // process rebuilds under a directory it may not own, so the open
    // must refuse a symlink and must not BLOCK on a FIFO. See that
    // module for why a byte cap is no defence against the second.
    let f = match fsguard::open_regular_read(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(MarkerRead::Absent),
        // BOTH spellings of "this is not a regular file". `fsguard`
        // synthesizes `InvalidData` after an fstat refuses a FIFO,
        // socket or directory; a SYMLINK never gets that far — the
        // `O_NOFOLLOW` open itself fails ELOOP. Without this second
        // arm a symlinked marker is still refused, but as a bare I/O
        // error rather than the marker-shaped `Incompatible` an
        // operator can act on.
        //
        // The ELOOP half is matched on the RAW ERRNO, not on
        // `ErrorKind::FilesystemLoop`: that variant is still unstable
        // on this workspace's pinned 1.97.1 (`io_error_more`, rust
        // #86442). Checked by compiling, not assumed.
        Err(e)
            if e.kind() == io::ErrorKind::InvalidData || e.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Ok(MarkerRead::NotRegular);
        }
        Err(e) => return Err(e),
    };
    let mut buf = Vec::new();
    // `take(CAP + 1)`: bounds the bytes actually read regardless of the
    // file's real size, and the `+ 1` is what lets the check below tell
    // "exactly CAP" (legal) from "over" (foreign) without ever reading
    // past CAP + 1 bytes.
    f.take(MARKER_MAX_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MARKER_MAX_BYTES {
        return Ok(MarkerRead::OverCap);
    }
    match String::from_utf8(buf) {
        Ok(s) => Ok(MarkerRead::Present(s)),
        Err(_) => Ok(MarkerRead::NotUtf8),
    }
}

/// An open store with the exclusive writer lock held (flock via
/// `File::try_lock` — std, stable since 1.89). Dropping releases it.
pub struct Store {
    root: PathBuf,
    _lock: File,
    pub(crate) publication_poisoned: bool,
    pub(crate) publication_temporary: u64,
    /// Every publication facade opened on this store fails its file syncs.
    #[cfg(test)]
    pub(crate) publication_fail_file_sync: bool,
    /// Every publication facade opened on this store fails these directories.
    #[cfg(test)]
    pub(crate) publication_fail_directory: DirectoryFaults,
}

/// The directories whose open or enumeration a publication facade fails.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct DirectoryFaults {
    pub(crate) open: Option<PathBuf>,
    pub(crate) read: Option<PathBuf>,
}

/// Hand-written: the derive would print `_lock: File { fd: 3, path: … }`,
/// and the fd number depends on how many files the process had open,
/// which is not a property of the store.
impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

fn absolute_store_root(root: &Path) -> io::Result<PathBuf> {
    if root.is_absolute() {
        return Ok(root.to_owned());
    }
    // getcwd is physical, so leading parent components can be popped exactly.
    // Interior parents may follow symlinks and must remain for the walk to refuse.
    let mut absolute = std::env::current_dir()?;
    let mut components = root.components();
    while matches!(
        components.clone().next(),
        Some(Component::CurDir | Component::ParentDir)
    ) {
        if components.next() == Some(Component::ParentDir) {
            absolute.pop();
        }
    }
    absolute.push(components.as_path());
    Ok(absolute)
}

fn lock_exclusive(lock: &File) -> Result<(), StoreError> {
    match lock.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(StoreError::Locked),
        Err(TryLockError::Error(e)) => Err(io_err("flock")(e)),
    }
}

impl Store {
    /// The absolute root [`Store::open`] resolved, which an overlay io over
    /// this store is rooted at.
    #[must_use]
    pub fn publication_root(&self) -> &Path {
        &self.root
    }

    /// Create-or-open at `root`, refusing an empty path. Store the root as an
    /// absolute path, resolving leading relative `..` against the physical
    /// current directory; interior `..` is preserved for the publication walk
    /// to refuse. Create missing ancestors and the root with mode 0700,
    /// leaving existing directory permissions unchanged.
    /// The flock gates every content mutation: lock
    /// first, then classify the marker byte-exactly (read-only). An
    /// ESTABLISHED store (marker verifies) gets its `txn/` swept of
    /// orphaned staging. The CREATE path (no marker) refuses a
    /// directory that already holds objects — a foreign dir or a
    /// marker-lost store — rather than adopting them under this build's
    /// tuple, and never sweeps: the "orphaned staging" justification
    /// holds only for a real store, and a mistargeted directory's
    /// `txn/` may hold the user's own files (F2/F5 below). A loser of
    /// a concurrent open race gets `Locked`
    /// before anything is staged or swept.
    ///
    /// # Errors
    /// [`StoreError::Locked`] when another process holds the writer
    /// lock; [`StoreError::Incompatible`] when the marker disagrees with
    /// this build's store version, chunker specification or hash algorithm, is not UTF-8, is over the module's
    /// 64 KiB marker bound, or is absent from a directory that already
    /// holds objects; [`StoreError::Io`] for the directory creation
    /// (including a pre-planted symlink at `txn/`/`objects/`),
    /// the flock (including a pre-planted symlink at `lock`),
    /// the marker read and the marker write.
    #[expect(
        clippy::disallowed_methods,
        reason = "find the first existing prefix with symlink_metadata, then create missing \
                  ancestors and the root one component at a time with mode 0700, tolerating \
                  AlreadyExists and leaving existing permissions alone. Publication access \
                  separately walks and judges every component. \
                  read_dir(root.join(\"objects\")) in the no-marker branch is a read-only \
                  emptiness probe, never a write. It is NOT limited to a \
                  pristine-fresh store: the in-body comment states its actual job is detecting \
                  a store whose MARKER was lost or tampered while its objects survived, which \
                  this open then refuses rather than silently adopting under a possibly \
                  different chunker/hash tuple — txn/ and objects/ creation already goes \
                  through the guarded create_structural_dir"
    )]
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        #[cfg(test)]
        OPENS.set(OPENS.get() + 1);
        if root.as_os_str().is_empty() {
            return Err(io_err("store root")(io::Error::new(
                io::ErrorKind::InvalidInput,
                "store root must not be empty",
            )));
        }
        let absolute_root = absolute_store_root(root).map_err(io_err("current directory"))?;
        let root = absolute_root.as_path();
        if let Some(parent) = root.parent().filter(|p| !p.as_os_str().is_empty()) {
            let mut missing = Vec::new();
            let mut prefix = parent;
            loop {
                match fs::symlink_metadata(prefix) {
                    Ok(_) => break,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => missing.push(prefix),
                    Err(e) => return Err(io_err(format!("inspect {}", prefix.display()))(e)),
                }
                prefix = prefix.parent().ok_or_else(|| {
                    io_err("store ancestors")(io::Error::other("no existing prefix"))
                })?;
            }
            for path in missing.into_iter().rev() {
                match fs::DirBuilder::new().mode(0o700).create(path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(io_err(format!("create {}", path.display()))(e)),
                }
            }
        }
        match fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_err(format!("create {}", root.display()))(e)),
        }
        // Symlink-refusing creation: `create_dir_all` FOLLOWS a
        // symlink whose target already exists as a directory, so a
        // pre-planted `txn -> <victim>` made the established-open sweep
        // below delete THAT directory's files, and a pre-planted
        // `objects -> <victim>` would make every object write land
        // outside the store root. See `create_structural_dir`'s own doc.
        create_structural_dir(&root.join("txn"), format!("create {}/txn", root.display()))?;
        create_structural_dir(
            &root.join("objects"),
            format!("create {}/objects", root.display()),
        )?;
        // O_NOFOLLOW: the store never creates a symlink at
        // `lock`, so one there is foreign — following it (the previous
        // `File::create`, which is `OpenOptions::new.create(true).
        // truncate(true)`, FOLLOWS AND TRUNCATES) would destroy a file
        // outside the store root before the flock is ever taken. The
        // cache's own `lock` open carries this same treatment; this is
        // the store's copy of it.
        let lock = fsguard::create_regular_lock(&root.join("lock"), true)
            .map_err(io_err(format!("create {}/lock", root.display())))?;
        lock_exclusive(&lock)?;
        let marker = root.join(MARKER_NAME);
        let expected = marker_contents();
        let create = match read_marker_bounded(&marker).map_err(io_err("read marker"))? {
            MarkerRead::Present(found) if found == expected => false,
            MarkerRead::Present(found) => {
                return Err(StoreError::Incompatible {
                    detail: format!("marker mismatch:\n--- store\n{found}--- expected\n{expected}"),
                });
            }
            MarkerRead::Absent => {
                // No marker: create a store here only if the location
                // is fresh. Pre-existing objects mean a foreign
                // directory or a store whose marker was lost/tampered —
                // refuse rather than silently adopt them under a
                // possibly-different chunker/hash tuple. Harvest
                // writes objects only after open() succeeds, so a
                // legitimately-interrupted create never has any.
                if fs::read_dir(root.join("objects"))
                    .map_err(io_err("read objects/"))?
                    .next()
                    .is_some()
                {
                    return Err(StoreError::Incompatible {
                        detail: "objects present with no marker (not a granary store)".to_owned(),
                    });
                }
                true
            }
            // A torn/tampered marker is an incompatibility diagnosis.
            MarkerRead::NotUtf8 => {
                return Err(StoreError::Incompatible {
                    detail: "marker is not utf-8".to_owned(),
                });
            }
            // over MARKER_MAX_BYTES is the same untrustworthy
            // class — refused with a FIXED-size message, never by
            // echoing the unbounded content into the diagnostic (which
            // the ordinary mismatch arm above would otherwise do).
            MarkerRead::OverCap => {
                return Err(StoreError::Incompatible {
                    detail: format!("marker exceeds {MARKER_MAX_BYTES} bytes"),
                });
            }
            // NOT folded into the `Absent` arm above, which is the
            // CREATE path: a FIFO or a directory at the marker's name
            // must refuse this root, never license creating a store on
            // top of whatever else is in it.
            MarkerRead::NotRegular => {
                return Err(StoreError::Incompatible {
                    detail: "marker is not a regular file".to_owned(),
                });
            }
        };
        if create {
            atomic_write(root, &marker, expected.as_bytes())?;
        } else {
            sweep_established_txn(root)?;
        }
        Ok(Self::locked(root.to_owned(), lock))
    }

    /// Take the existing lock and verify the store without a create, repair or sweep.
    pub(crate) fn open_existing(root: &Path) -> Result<(Self, File), StoreError> {
        use std::os::fd::AsFd as _;
        if root.as_os_str().is_empty() {
            return Err(io_err("store path")(io::Error::other("empty store path")));
        }
        let root: PathBuf = absolute_store_root(root)
            .map_err(io_err("store path"))?
            .components()
            .collect();
        if root.parent().is_none() {
            return Err(io_err("store path")(io::Error::other(
                "missing store directory",
            )));
        }
        let uid = nix::unistd::geteuid().as_raw();
        let directory = fsguard::open_directory(&root).map_err(io_err("open existing store"))?;
        crate::publication_store::check_control_root(&root, uid)
            .map_err(|_| io_err("store custody")(io::Error::other("untrusted store path")))?;
        let open = |leaf, mode| {
            let fd = nix::fcntl::openat(
                &directory,
                leaf,
                nix::fcntl::OFlag::O_RDONLY
                    | nix::fcntl::OFlag::O_NOFOLLOW
                    | nix::fcntl::OFlag::O_NONBLOCK
                    | nix::fcntl::OFlag::O_CLOEXEC,
                nix::sys::stat::Mode::empty(),
            )
            .map_err(|e| io_err("open existing control file")(e.into()))?;
            let file = File::from(fd);
            let meta = file
                .metadata()
                .map_err(io_err("inspect existing control file"))?;
            if !meta.is_file()
                || meta.uid() != uid
                || meta.nlink() != 1
                || meta.mode() & 0o7777 != mode
            {
                return Err(io_err("store custody")(io::Error::other(
                    "untrusted control file",
                )));
            }
            crate::custody::refuse_granting_acl_on_fd(
                file.as_fd(),
                &root.join(leaf),
                "store control file",
            )
            .map_err(|_| io_err("store custody")(io::Error::other("control file ACL")))?;
            Ok(file)
        };
        let lock = open("lock", 0o600)?;
        lock_exclusive(&lock)?;
        let mut bytes = Vec::new();
        open(MARKER_NAME, 0o444)?
            .take(MARKER_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io_err("read existing store marker"))?;
        if bytes != marker_contents().as_bytes() {
            return Err(StoreError::Incompatible {
                detail: "invalid existing store marker".to_owned(),
            });
        }
        Ok((Self::locked(root, lock), directory))
    }

    fn locked(root: PathBuf, lock: File) -> Self {
        Self {
            root,
            _lock: lock,
            publication_poisoned: false,
            publication_temporary: 0,
            #[cfg(test)]
            publication_fail_file_sync: false,
            #[cfg(test)]
            publication_fail_directory: DirectoryFaults::default(),
        }
    }

    /// `gran verify`'s own entry point for a STORE root — does
    /// NOT reuse [`Self::open`]'s pipeline: creates nothing and takes NO
    /// LOCK. A store's objects are write-once (`put` never modifies or
    /// deletes an existing object, and this store never evicts), so a
    /// lockless read is exactly as safe as the cache's own lockless
    /// object-read path — the only mutator that could race a walk is
    /// `put`, which only ever ADDS a new, previously-absent object.
    /// Bounds the marker read the same way [`Self::open`] now does.
    /// Unlike the cache, the store marker carries no origin line
    /// to exempt — this compares it byte-exactly, whole. Refuses a
    /// symlinked `objects/` before the caller ever walks it (see
    /// [`refuse_symlinked_verify_dir`]) — the verify walk itself lives
    /// in `verify.rs`'s `scan_objects`, which refuses one again on its
    /// own regardless of what this open already checked.
    ///
    /// # Errors
    /// [`StoreError::Incompatible`] when the marker is absent, over the
    /// size bound, not UTF-8, or disagrees with this build's store version, chunker specification or hash algorithm;
    /// [`StoreError::Io`] for anything else, including a symlinked
    /// `objects/`.
    pub(crate) fn open_for_verify(root: &Path) -> Result<(), StoreError> {
        let marker = root.join(MARKER_NAME);
        let expected = marker_contents();
        match read_marker_bounded(&marker).map_err(io_err("read marker"))? {
            MarkerRead::Present(found) if found == expected => {}
            MarkerRead::Present(found) => {
                return Err(StoreError::Incompatible {
                    detail: format!("marker mismatch:\n--- store\n{found}--- expected\n{expected}"),
                });
            }
            MarkerRead::Absent => {
                return Err(StoreError::Incompatible {
                    detail: "marker absent (no writer has initialized this store)".to_owned(),
                });
            }
            MarkerRead::NotUtf8 => {
                return Err(StoreError::Incompatible {
                    detail: "marker is not utf-8".to_owned(),
                });
            }
            MarkerRead::OverCap => {
                return Err(StoreError::Incompatible {
                    detail: format!("marker exceeds {MARKER_MAX_BYTES} bytes"),
                });
            }
            MarkerRead::NotRegular => {
                return Err(StoreError::Incompatible {
                    detail: "marker is not a regular file".to_owned(),
                });
            }
        }
        refuse_symlinked_verify_dir(&root.join("objects"), "verify: stat objects/")
    }

    fn object_path(&self, id: &GrainId) -> PathBuf {
        let hex = id.digest_hex();
        // `digest_hex()` is always exactly `DIGEST_LEN * 2` (64) chars,
        // so `..2` always succeeds and "00" is unreachable in
        // practice — kept as a fallback rather than an
        // indexing/unwrap panic (no panic path in `src/`, coding
        // standards rule 3). Its failure mode would be SILENT
        // misfiling into `objects/00/`, not a crash — a defect to fix
        // upstream (a `digest_hex` shorter than 2 chars) if it is ever
        // observed, not something this call site can safely surface.
        let fanout = hex.get(..2).unwrap_or("00");
        self.root.join("objects").join(fanout).join(&hex)
    }

    /// Presence check. Existence only — not an integrity claim. Publish
    /// uses it as a pre-flight over the objects it is about to pack, so
    /// a store missing one of them fails BEFORE any upload.
    ///
    /// Only [`ObjectLeaf::Regular`] is `true`. Both other answers are
    /// `false` and that is the fail-closed direction for a pre-flight:
    /// a `false` makes the caller refuse before uploading, while a
    /// `true` on a leaf that is not really an object would send the
    /// publish on. A foreign or unclassifiable leaf is warned about,
    /// because "absent" and "there is something wrong at this name" are
    /// very different operator problems.
    pub(crate) fn has(&self, id: &GrainId) -> bool {
        let path = self.object_path(id);
        // The FANOUT is classified first, non-followingly: without it
        // the leaf stat below follows a planted `objects/<2hex>` link
        // into another content-addressed tree and reports ITS file as
        // this store's object (see `refuse_foreign_object_fanout`).
        // A foreign fanout is "not present here", which is the same
        // fail-closed direction every other answer this function gives
        // takes.
        let Some(fanout) = path.parent() else {
            crate::observe::OperatorDiagnostic::store_an_object_path_has_no_fanout_parent_reporting().emit_paths(&[crate::observe::PathSlot::Path("path", crate::LogPath::file(&path))]);
            return false;
        };
        if let Err(e) = refuse_foreign_object_fanout(fanout, "has: classify object fanout") {
            crate::observe::OperatorDiagnostic::store_an_object_fanout_is_not_a_real_directory(
                e.failure_class(),
            )
            .emit_paths(&[crate::observe::PathSlot::Path(
                "fanout",
                crate::LogPath::directory(fanout),
            )]);
            return false;
        }
        match classify_object_leaf(&path) {
            Ok(ObjectLeaf::Regular) => true,
            Ok(ObjectLeaf::Absent) => false,
            Ok(ObjectLeaf::Foreign) => {
                crate::observe::OperatorDiagnostic::store_an_object_leaf_is_not_a_regular_file()
                    .emit_paths(&[crate::observe::PathSlot::Path(
                        "path",
                        crate::LogPath::file(&path),
                    )]);
                false
            }
            Err(_) => {
                crate::observe::OperatorDiagnostic::store_an_object_leaf_could_not_be_classified_reporting(crate::FailureClass::Io).emit_paths(&[crate::observe::PathSlot::Path("path", crate::LogPath::file(&path))]);
                false
            }
        }
    }

    /// Write an object if absent. Returns true if it was NOVEL.
    /// Atomic: `O_EXCL` staging in `txn/`, fsync, chmod 0444, rename.
    ///
    /// # Errors
    /// [`StoreError::Io`] for a foreign or unclassifiable leaf (see
    /// [`ObjectLeaf`]) as well as for any failure of the write itself.
    pub(crate) fn put(&self, id: &GrainId, bytes: &[u8]) -> Result<bool, StoreError> {
        // Hot path: no release-mode re-hash — the caller computed `id`
        // from these same bytes in-process (harvest); debug builds
        // verify the invariant.
        debug_assert_eq!(GrainId::of(bytes), *id);
        let dest = self.object_path(id);
        // The FANOUT first, before the leaf is classified at all. A
        // planted `objects/<2hex>` link into another CAS otherwise makes
        // the classification below follow it, find the identically-named
        // object over there and return `Ok(false)` — "already present",
        // written nothing — for a store that holds nothing (see
        // `refuse_foreign_object_fanout`). Non-creating: the directory
        // itself is created further down, once the leaf is known absent.
        let fanout = dest.parent().ok_or_else(|| {
            io_err("classify object fanout")(io::Error::other(
                "an object path has no fanout parent",
            ))
        })?;
        if let Err(e) = refuse_foreign_object_fanout(fanout, "classify object fanout") {
            crate::observe::OperatorDiagnostic::store_put_the_object_fanout_is_not_a_real(
                e.failure_class(),
            )
            .emit_paths(&[crate::observe::PathSlot::Path(
                "fanout",
                crate::LogPath::directory(fanout),
            )]);
            return Err(e);
        }
        // Put-if-absent, three-way: nothing past this point re-checks
        // the leaf, and `atomic_write`'s `rename` replaces whatever
        // name is there. So "present" and "not classifiable" both have
        // to return HERE — the first as a no-op, the second as a
        // refusal — and only a genuine absence may fall through.
        match classify_object_leaf(&dest).map_err(io_err("classify object leaf"))? {
            ObjectLeaf::Regular => return Ok(false),
            ObjectLeaf::Foreign => {
                crate::observe::OperatorDiagnostic::store_put_an_object_leaf_is_not_a_regular()
                    .emit_paths(&[crate::observe::PathSlot::Path(
                        "path",
                        crate::LogPath::file(&dest),
                    )]);
                return Err(io_err("classify object leaf")(io::Error::other(format!(
                    "{} is not a regular file; the store never creates anything else at an \
                     object leaf, so it is foreign",
                    dest.display()
                ))));
            }
            ObjectLeaf::Absent => {}
        }
        // The computed fanout is structural just like `objects/` itself.
        // A static symlink here would otherwise be followed by
        // `create_dir_all`, then again by the final rename. The check
        // above already refused one; this is the create, and it carries
        // its own independent guard rather than relying on that check.
        create_structural_dir(fanout, "create fanout dir")?;
        atomic_write(&self.root, &dest, bytes)?;
        Ok(true)
    }

    /// Read an object fully, hash-verified (read path = verified).
    ///
    /// # Errors
    /// [`StoreError::Io`] for a foreign fanout (see
    /// [`refuse_foreign_object_fanout`]) as well as for any failure of
    /// the read itself; [`StoreError::Corrupt`] when the bytes do not
    /// address `id`.
    pub(crate) fn get(&self, id: &GrainId) -> Result<Vec<u8>, StoreError> {
        let path = self.object_path(id);
        // The FANOUT first, exactly as `has` and `put` classify it. The
        // guarded open below refuses a foreign FINAL component, but
        // every path operation follows a symlinked INTERMEDIATE one —
        // so a planted `objects/<2hex>` link into another CAS makes
        // this open, and its hash verification, describe the far
        // tree's file: identical content at the identical relative
        // path is what content addressing guarantees. Refusing is the
        // same fail-closed direction `has` and `put` take.
        let fanout = path.parent().ok_or_else(|| {
            io_err("classify object fanout")(io::Error::other(
                "an object path has no fanout parent",
            ))
        })?;
        if let Err(e) = refuse_foreign_object_fanout(fanout, "classify object fanout") {
            crate::observe::OperatorDiagnostic::store_get_the_object_fanout_is_not_a_real(
                e.failure_class(),
            )
            .emit_paths(&[crate::observe::PathSlot::Path(
                "fanout",
                crate::LogPath::directory(fanout),
            )]);
            return Err(e);
        }
        let mut buf = Vec::new();
        let context = format!("read {}", path.display());
        let f = fsguard::open_regular_read(&path).map_err(io_err(&context))?;
        // Bound the bytes ACTUALLY read, not only metadata observed before
        // the read: the leaf can be changed by an unsupported concurrent
        // root writer, and `take(CAP + 1)` remains safe in that case. The
        // extra byte distinguishes exactly-at-cap from oversized.
        f.take(META_MAX_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(io_err(&context))?;
        if buf.len() as u64 > META_MAX_BYTES {
            return Err(io_err(context)(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("object exceeds {META_MAX_BYTES} bytes"),
            )));
        }
        if GrainId::of(&buf) != *id {
            return Err(StoreError::Corrupt { id: *id });
        }
        Ok(buf)
    }
}

/// What the reconstructed object leaf IS. **Three answers, because
/// there are three states and a `bool` can only carry two.**
///
/// `symlink_metadata`, never `exists`/`metadata`: both of those follow
/// a symlink with a live target, which would let a planted link
/// suppress `put` by impersonating the object. But not-a-regular-file
/// is not the same answer as not-there: folding them together makes
/// `put` treat a planted symlink (or a FIFO, or a directory) as ABSENT,
/// and `atomic_write` finishes with a `rename` ONTO the leaf name,
/// which replaces the planted entry — tampered state erased instead of
/// reported, with nothing downstream re-checking.
///
/// An error that is not `NotFound` is a third answer again — `ENOTDIR`
/// from a file planted at the fanout name, `EACCES`, a transient I/O
/// failure. It says nothing about whether an object is there, so it
/// cannot be read as "absent" either.
enum ObjectLeaf {
    /// A regular file: the object is present (existence only — this is
    /// not an integrity claim; `get` hash-verifies).
    Regular,
    /// Something is there and it is not a regular file.
    Foreign,
    /// Nothing at the name.
    Absent,
}

fn classify_object_leaf(path: &Path) -> io::Result<ObjectLeaf> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(ObjectLeaf::Regular),
        Ok(_) => Ok(ObjectLeaf::Foreign),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ObjectLeaf::Absent),
        Err(e) => Err(e),
    }
}

/// Clear every NON-DIRECTORY name directly under `txn/` on an
/// ESTABLISHED open — any such entry there is a dead previous writer's
/// staging, or a plant (we hold the only lock). A stray DIRECTORY is
/// the one entry skipped: an anomaly, not staging, `remove_file` cannot
/// remove it anyway, and sweeping directories is how a mistargeted
/// `txn/` holding a user's own files would get deleted (F6).
///
/// **Every other shape has to go, and leaving any is the more dangerous
/// choice.** `atomic_write` stages under `<pid>-<counter>`; numeric
/// pids are reused and every fresh process restarts its counter at
/// zero, so ANY name planted at `txn/<pid>-0` makes `create_new` fail
/// `EEXIST` for that pid forever — a permanent wedge of every object
/// write, and this sweep is the only thing that ever clears a staging
/// name. A symlink, a FIFO, a socket and a device node wedge it
/// identically and `unlink(2)` removes all of them. Removing them is
/// safe because `remove_file` never follows its FINAL component: a
/// link's NAME is unlinked and its target is untouched.
///
/// **`txn/` itself must be a real directory, never a symlink** — a
/// pre-planted `txn -> <victim>` would make the `remove_file` below
/// delete THAT directory's files, which is an arbitrary-deletion
/// primitive reachable by anyone who can create a path inside a store
/// root. `open`'s own `create_structural_dir` call already refuses a
/// symlinked `txn/` earlier in the SAME call, before this function is
/// ever reached — but this is this function's OWN independent guard,
/// not a rely-on-the-earlier-check shortcut: a guard whose failure mode
/// was never demonstrated does not exist (`cache/marker.rs`'s
/// `sweep_orphaned_txn_files` is the precedent this mirrors). It fails
/// CLOSED, like that precedent: a `txn/` that is not a real directory
/// ends the open with an error rather than returning a clean `Ok` that
/// blesses a tampered root. `symlink_metadata`, never `metadata`:
/// reports the link itself rather than following it.
///
/// **An entry that cannot be removed is skipped, not propagated** —
/// the cache's sweep makes the same call. One `EPERM`/`EACCES` would
/// otherwise fail every established open of this store forever, where
/// the entry on its own only wedges the single staging name it
/// occupies.
///
/// **STATED LIMIT: a `txn/` where NOTHING can be staged still reports a
/// usable store.** The skip cannot tell "one stubborn name" from "this
/// process cannot write this directory at all" — a `0o555` `txn/` is
/// both at once — and in the second case every `put` fails at
/// `atomic_write`'s `create_new`, loudly but one write at a time. A
/// store deletes nothing to make room, so all a refused write costs
/// here is the write; `cache/marker.rs`'s `sweep_orphaned_txn_files` states
/// the same limit, and there too a refused write costs only itself,
/// because the cache stages before it evicts. What neither side
/// gives is an operator signal at open. The remedy for that is the
/// same on both sides and is a design change rather than a sweep
/// change — a writer health flag reported at close — and it is not
/// implemented.
#[expect(
    clippy::disallowed_methods,
    reason = "the check below refuses a symlinked txn/ itself (symlink_metadata, fail closed); \
              read_dir over a confirmed-real directory is safe by that check, and the walked \
              entries are classified via DirEntry::file_type(), which never follows — matching \
              cache/marker.rs's sweep_orphaned_txn_files exactly. remove_file acts on the NAME and \
              never follows its final component, so sweeping a symlinked entry unlinks the \
              link, never its target. Every non-directory shape is cleared — unlink removes a \
              FIFO, socket or device node as readily as a regular file, and each wedges \
              create_new for its staging name just as permanently; a directory is the one \
              entry skipped"
)]
fn sweep_established_txn(root: &Path) -> Result<(), StoreError> {
    let txn_dir = root.join("txn");
    match fs::symlink_metadata(&txn_dir) {
        Ok(meta) if meta.is_dir() => {}
        // Fail CLOSED, exactly as the cache's sweep does through
        // `refuse_symlinked_structural_dir`. A store root whose `txn/`
        // is a symlink (or a regular file, or a FIFO) is TAMPERED, and
        // continuing with a clean `Ok` blesses it. `open`'s earlier
        // `create_structural_dir` refuses the same shape one step
        // before this — which is why the two must not differ: the day
        // that order changes, a divergent arm here silently becomes the
        // answer.
        Ok(_) => {
            crate::observe::OperatorDiagnostic::store_established_open_txn_is_not_a_real_directory(
            )
            .emit_paths(&[crate::observe::PathSlot::Path(
                "path",
                crate::LogPath::directory(&txn_dir),
            )]);
            return Err(io_err("stat txn/")(io::Error::other(
                "txn/ is not a real directory; the store creates nothing else at that name, so \
                 sweeping through it would unlink entries outside the store root",
            )));
        }
        Err(e) => return Err(io_err("stat txn/")(e)),
    }
    let mut swept: u64 = 0;
    let mut skipped: u64 = 0;
    for entry in fs::read_dir(&txn_dir).map_err(io_err("read txn/"))? {
        let entry = entry.map_err(io_err("read txn/ entry"))?;
        // `file_type()`, never `path().is_file()`: it reports a
        // symlinked entry AS a symlink rather than following it, which
        // is what lets this decide by ENTRY TYPE. Every non-directory
        // name is swept as a NAME (`remove_file` does not follow its
        // final component, so a link's target is never touched); a
        // directory is the one entry left alone.
        // Matches cache/marker.rs's sweep_orphaned_txn_files exactly.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            let path = entry.path();
            if fs::remove_file(&path).is_ok() {
                swept = swept.saturating_add(1);
            } else {
                // Skipped, never propagated — the cache's sweep makes
                // the same call for the same reason: one entry that
                // cannot be unlinked (EPERM/EACCES, an immutable flag)
                // would otherwise fail every established open of this
                // store forever, where the entry on its own only wedges
                // the one staging name it occupies.
                skipped = skipped.saturating_add(1);
                crate::observe::OperatorDiagnostic::store_established_open_an_orphaned_txn_entry_could_not(crate::FailureClass::Io).emit_paths(&[crate::observe::PathSlot::Path("path", crate::LogPath::directory(&path))]);
            }
        }
    }
    if swept > 0 || skipped > 0 {
        crate::observe::OperatorDiagnostic::store_established_open_swept_orphaned_txn_staging_files(swept, skipped).emit();
    }
    Ok(())
}

/// Create a structural store subdirectory, refusing one that ALREADY
/// EXISTS as a symlink. Mirrors `cache/paths.rs`'s identical
/// `create_structural_dir` guard exactly: `create_dir_all`
/// FOLLOWS a symlink whose target is a directory, so a pre-planted
/// `txn -> <victim>` or `objects -> <victim>` would make every
/// subsequent structural write (or, for `txn/`, the established-open
/// sweep's `remove_file` above) land THROUGH the link, outside the
/// store root. Exhaustive on the `lstat` result and FAIL CLOSED on the
/// unexpected arm: `is_ok_and` here would treat a transient lstat error
/// (`EIO`, `EACCES`) as "not a symlink" and fall through to a
/// `create_dir_all` that follows a genuinely-planted link — the guard
/// silently degrading to no guard. A fresh subdir (no symlink) and a
/// real re-opened one are both unaffected. Narrows, but does not fully
/// close, an ACTIVE TOCTOU swapping the path between this check and a
/// later write — out of scope here: as with the cache, the store
/// directory is assumed to be in the operator's own trust domain.
#[expect(
    clippy::disallowed_methods,
    reason = "the match above just refused a pre-existing symlink at `path` (lstat, fail closed \
              on the unexpected arm); create_dir_all is safe once that check has passed — \
              cache/paths.rs's identical create_structural_dir carries the same license"
)]
fn create_structural_dir(path: &Path, context: impl Into<String>) -> Result<(), StoreError> {
    let context = context.into();
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(io_err(context)(io::Error::other(
                "a structural store directory is a symlink; refusing to create or write \
                 through it",
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(context)(e)),
    }
    fs::create_dir_all(path).map_err(io_err(context))
}

/// The verify path's own structural-directory guard: refuses a symlink
/// the same way [`create_structural_dir`] does, but never creates
/// anything — a verify open must not repair a missing directory, only
/// classify or refuse it. `read_dir` follows a symlinked INTERMEDIATE
/// path component regardless of any `O_NOFOLLOW` a later, final-
/// component file open under it might carry, so this closes what a
/// per-file `O_NOFOLLOW` cannot: a symlinked `objects/` itself.
/// Exhaustive on the lstat result and FAIL CLOSED on the unexpected
/// arm — `is_ok_and` would treat a transient lstat error (`EIO`,
/// `EACCES`) as "not a symlink" and let the caller proceed as if the
/// directory were safe.
fn refuse_symlinked_verify_dir(path: &Path, context: impl Into<String>) -> Result<(), StoreError> {
    let context = context.into();
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(io_err(context)(io::Error::other(
            "a verify-path structural store directory is a symlink; refusing to walk or write \
             through it",
        ))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(context)(e)),
    }
}

/// Non-following classification of an object's FANOUT directory
/// (`objects/<2hex>`), run BEFORE the leaf below it is classified,
/// created or written.
///
/// Every path operation follows a symlinked INTERMEDIATE component even
/// when it refuses to follow the final one, and content addressing puts
/// identical bytes at the identical relative path in every CAS. So
/// `objects/<2hex>` replaced by a link into another store makes a
/// leaf-first `symlink_metadata` describe THAT store's file: [`Store::has`]
/// answers `true` for an object this store does not hold (publish's
/// pre-flight then passes on nothing), and [`Store::put`] answers
/// "already present" having written nothing, after which every
/// [`Store::get`] of that id serves the other tree's bytes.
///
/// A real directory or a genuinely absent fanout is the only pair that
/// may continue: `put` creates the directory it needs, and `has` finds
/// nothing under a name that is not there. ANY other shape — a symlink,
/// a regular file, a FIFO — is foreign, because the store creates
/// nothing but a directory at this name. An lstat error that is not
/// `NotFound` is refused too: it says nothing about what is there, so it
/// cannot be read as "absent".
fn refuse_foreign_object_fanout(path: &Path, context: impl Into<String>) -> Result<(), StoreError> {
    let context = context.into();
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        Ok(_) => Err(io_err(context)(io::Error::other(format!(
            "{} is not a real directory; the store creates nothing but a directory at an \
             object fanout, so it is foreign and everything below it describes another tree",
            path.display()
        )))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(context)(e)),
    }
}

/// The io kinds this maps by name, as an IN-CRATE vocabulary.
///
/// `ErrorKind`'s own `Debug` is not a fixed vocabulary: `Uncategorized`
/// is std's unstable catch-all for every errno std has not yet named, it
/// was spelled `Other` before Rust 1.53, and its membership shrinks as
/// std names new kinds. Rendering it directly would make the text
/// toolchain-version-dependent and collapse `EIO`, `ENOSPC` and `EMFILE`
/// into one indistinguishable string — in an artifact that is compared
/// byte-for-byte across processes.
fn io_kind_name(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::PermissionDenied => "permission denied",
        io::ErrorKind::IsADirectory => "is a directory",
        io::ErrorKind::NotADirectory => "not a directory",
        io::ErrorKind::InvalidData => "invalid data",
        io::ErrorKind::UnexpectedEof => "unexpected eof",
        // Everything else, INCLUDING Uncategorized, renders as one
        // stable word. A caller needing the distinction has the id and
        // the store; the artifact needs stability.
        _ => "io error",
    }
}

/// Map a [`StoreError`] into the pure [`GrainSourceError`].
///
/// Two properties this exists to hold, neither of which
/// `Backend(e.to_string())` would: `Missing` stays REACHABLE (the io
/// kind is the only thing that distinguishes an absent object, since
/// `StoreError` has no `Missing` variant), and no filesystem path
/// reaches the rendering — the mapping reads `source.kind()` and the
/// id, never `context` and never `io::Error`'s own `Display`, whose text
/// is locale-sensitive on glibc.
///
/// Structural damage — a regular file where a fanout DIRECTORY belongs,
/// say — classifies as `Backend`, not `Missing`, even though no object
/// exists at the id. That is deliberate: `Missing` invites a caller to
/// treat the store as merely un-harvested, and a damaged store is not
/// that.
fn grain_source_error(id: &GrainId, e: &StoreError) -> GrainSourceError {
    match e {
        StoreError::Corrupt { id: corrupt } => GrainSourceError::Corrupt(*corrupt),
        StoreError::Io { source, .. } => match source.kind() {
            io::ErrorKind::NotFound => GrainSourceError::Missing(*id),
            kind => GrainSourceError::Backend(format!("{} reading {id}", io_kind_name(kind))),
        },
        // Neither is reachable through `get` — both come from `open` —
        // and both carry detail a fixed description replaces rather
        // than renders, so no new text can reach the artifact by way of
        // a variant growing a field.
        StoreError::Incompatible { .. } => {
            GrainSourceError::Backend("incompatible store".to_owned())
        }
        StoreError::Locked => GrainSourceError::Backend("store is locked".to_owned()),
    }
}

impl GrainSource for Store {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        Store::get(self, id).map_err(|e| grain_source_error(id, &e))
    }

    fn has(&self, id: &GrainId) -> bool {
        Store::has(self, id)
    }
}

/// txn-staged atomic write: unique `O_EXCL` tmp in `<root>/txn`, write,
/// fsync (torn-rename wedge), chmod 0444, THEN rename — the
/// chmod precedes the rename so no window ever exposes a writable
/// object at its final path.
///
/// The pid in the staging name is LOAD-BEARING FOR CORRECTNESS and not
/// an ambient input to a hashed or signed value: the counter beside it is
/// per-process, so without the pid two processes writing the same store
/// would generate the same staging name and one `create_new` would fail
/// (or, without `O_EXCL`, they would tear each other's bytes). It never
/// reaches a hashed or signed value — the file is renamed to its
/// content address and the staging name is gone.
///
/// **The same SHAPE as `cache::atomic_write`, deliberately NOT the same
/// primitives.** Two differences, both chosen rather than inherited:
///
///   - **Durability.** This calls `File::sync_all`, which is
///     `fcntl(F_FULLFSYNC)` on Apple targets — the store is the CAS OF
///     RECORD for content nothing else can refill, so it buys the
///     stronger barrier and pays for it. The cache calls its own
///     `fsync_file`, which must use plain `fsync(2)` even
///     on Apple: a cache is refetchable, and the write rate a cache
///     runs at makes `F_FULLFSYNC` the wrong trade THERE.
///   - **`O_NOFOLLOW`.** The cache's open carries it; this one does
///     not. Neither is exposed: `create_new` is `O_CREAT|O_EXCL`, which
///     refuses ANY pre-existing final component, symlink included,
///     before a follow could happen. The cache adds the flag for
///     uniformity with its other structural opens, not for a gap this
///     one leaves open.
#[expect(
    clippy::disallowed_methods,
    reason = "the pid is load-bearing for correctness here — two processes must not collide \
              on a staging name; it reaches no hashed or signed value. One audited unit: the \
              same scope covers this function's O_EXCL+create_new open, the rename into dest, \
              and the best-effort remove_file(&tmp) on failure. The safety is NOT that the \
              staging name has never been used (pids are reused across process lifetimes, and \
              a fresh process's counter restarts at 0) — it is that O_EXCL refuses ANY \
              pre-existing name, a malicious pre-plant and a stale same-pid collision alike, \
              and sweep_established_txn clears the name on the next established open for EVERY \
              non-directory entry (regular file, symlink, FIFO, socket, device node alike), so \
              neither a stale collision nor a plant is permanent. A DIRECTORY planted at a \
              staging name is the one shape that sweep leaves (F6) and it does wedge that exact \
              name. cache/write.rs's atomic_write makes the same argument for the same staging \
              discipline, but the two are NOT identical primitives: this one syncs with \
              File::sync_all (F_FULLFSYNC on Apple) because the store is the CAS of record, \
              where the cache must use plain fsync(2), and this open omits the \
              cache's O_NOFOLLOW, which O_CREAT|O_EXCL already makes redundant at the final \
              component. Staging files are created with mode 0600 before any bytes are written"
)]
fn atomic_write(root: &Path, dest: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let tmp = root.join("txn").join(unique);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true) // O_EXCL — two writers can never share a tmp
        .mode(0o600)
        .open(&tmp)
        .map_err(io_err("create txn file"))?;
    let result = (|| {
        f.write_all(bytes)?;
        f.sync_all()?; // fsync BEFORE rename: no torn-but-present objects
        f.set_permissions(fs::Permissions::from_mode(0o444))?;
        fs::rename(&tmp, dest)
    })();
    if let Err(e) = result {
        // Best-effort: if THIS remove_file also fails, the tmp name is a
        // leftover in txn/, not cleaned up here — it is swept on the
        // NEXT ESTABLISHED writer open (`sweep_established_txn`:
        // `create_new` makes it a regular file, which that sweep's
        // entry-type check matches).
        //
        // "Established" is the whole qualifier, and it is not true
        // that the marker is always written before this function is
        // reachable. It is not: the
        // MARKER's own write is a call to this function
        // (`Store::open`'s `create` branch), and at that point the
        // marker is still Absent. If that write fails after the tmp
        // exists and the cleanup fails too, the leftover survives —
        // every later open of the same root reads the marker as Absent
        // and takes the `create` branch again, which does NOT sweep.
        // The leftover therefore persists until some `create` succeeds
        // and the root becomes established; only from that open onward
        // does the sweep run. Nothing about SAFETY changes: the
        // leftover is an unreferenced, uniquely-named regular file
        // under `txn/`, `O_EXCL` refuses to reuse the name, and no
        // reader ever looks there.
        let _ = fs::remove_file(&tmp);
        return Err(io_err(format!("atomic write {}", dest.display()))(e));
    }
    Ok(())
}

#[cfg(test)]
std::thread_local! {
    static OPENS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many stores this thread has opened.
#[cfg(test)]
pub(crate) fn opens_for_test() -> u64 {
    OPENS.get()
}

#[cfg(test)]
mod tests;
