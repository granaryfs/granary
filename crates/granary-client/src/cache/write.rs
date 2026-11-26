// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Single-object durability: stage a write under a name nobody else can
//! claim, get the bytes to the platter, then rename it into place.
//!
//! **What breaks when this module is wrong:** a reader sees a partly
//! written object — a rename that published bytes the kernel had not
//! yet flushed, or a staging name two processes both picked, so one
//! writer's content lands under the other's rename. The abandonment
//! half is the same subject: a staged file whose writer dies must be
//! left where the sweep can recognise and remove it, never renamed and
//! never silently leaked.
//!
//! It owns the staging type and its `Drop` ([`StagedWrite`]), the
//! one-call composition of stage-then-rename ([`atomic_write`]), the
//! collision-free staging name ([`unique_txn_name`]), and the two
//! barriers the platform actually offers ([`fsync_file`]'s two
//! cfg-exclusive arms and [`fsync_directory`]) — the macOS arm calling
//! plain `fsync` deliberately, because std's `sync_all` issues
//! `F_FULLFSYNC` there and the cache requires plain `fsync`. It does
//! NOT own WHERE anything is written: the layout's names are
//! [`super::paths`]'s, and the decision to write at all is the cache's
//! own state machine.
//!
//! It uses one sibling, in the order `paths` records:
//! `paths` for [`super::paths::io_err`]. Nothing here reaches `marker`,
//! `anchor` or `index-load`.
//!
//! Out-of-line, and a child one flat
//! level under `cache/`, beside `paths`,
//! `marker`, `anchor` and `index-load`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::fsguard;

use super::CacheError;
use super::paths::io_err;

#[cfg(target_os = "linux")]
pub(super) fn fsync_file(file: &File) -> io::Result<()> {
    file.sync_all()
}

#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "the cache requires plain fsync(2) on macOS, never fcntl(F_FULLFSYNC) — std's \
              File::sync_all/sync_data both issue F_FULLFSYNC on Apple targets (verified at \
              source, rustc 1.97.1), so this crate calls the libc function directly; the \
              crate's own lint table (Cargo.toml addendum) narrows unsafe_code to deny \
              specifically so this FFI call can compile"
)]
pub(super) fn fsync_file(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let fd = file.as_raw_fd();
    // SAFETY: `fd` is a valid, currently-open file descriptor borrowed
    // from `file` for the duration of this call — `file` is not
    // consumed and outlives the call, and `fsync` neither retains the
    // descriptor afterward nor takes ownership of it.
    let rc = unsafe { libc::fsync(fd) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `fsguard::open_directory` (`O_DIRECTORY|O_NOFOLLOW`), never a bare
/// `File::open`. The descriptor is only fsync'd, so a symlink target
/// could not steer any CONTENT — but it could steer which directory's
/// metadata is flushed, which makes the durability claim the caller
/// relies on false without anything failing. Refusing a symlink and a
/// non-directory at the open costs nothing and needs no licence.
pub(super) fn fsync_directory(path: &Path) -> io::Result<()> {
    let directory = fsguard::open_directory(path)?;
    fsync_file(&directory)
}

/// The pid is load-bearing for correctness (two processes must not
/// collide on a staging name), not ambient input reaching a hashed
/// value — the same justification as `store::atomic_write`'s identical
/// expect.
#[expect(
    clippy::disallowed_methods,
    reason = "the pid is load-bearing for correctness here — two processes must not collide \
              on a staging name; it reaches no hashed or signed value (matches \
              store.rs's atomic_write)"
)]
fn unique_txn_name(counter: &AtomicU64) -> String {
    format!(
        "{}-{}",
        std::process::id(),
        counter.fetch_add(1, Ordering::Relaxed)
    )
}

/// A file already created, written, fsync'd and chmod'ed under `txn/`,
/// waiting for the `rename(2)` that publishes it at its destination.
///
/// **Why the write is split in two at all.** `WriterState::insert` has
/// to know whether this cache can stage BEFORE it evicts anything:
/// `txn/` unwritable is a real state (`sweep_orphaned_txn_files`' own
/// doc names the `0o555` case), and an insert that evicted first would
/// spend the cache's contents on a write that can never land, once per
/// attempt, until the cache is empty. Staging is the only honest probe
/// of "can this cache write" — an open-time check answers for the wrong
/// moment — so the staging happens first and the eviction runs between
/// it and the rename.
///
/// Dropping this WITHOUT renaming removes the staging name, best
/// effort. A drop that cannot remove it leaves exactly what a failed
/// `atomic_write` has always left: an unreferenced, uniquely-named
/// regular file under `txn/`, which the next writer open's sweep clears
/// if it can unlink it and warns about if it cannot.
pub(super) struct StagedWrite {
    tmp: PathBuf,
}

/// ONE audited unit, and one licence for it: the `O_EXCL`+`O_NOFOLLOW`
/// create of a pid+counter name under `txn/`, the rename that publishes
/// it, and the best-effort remove that clears it. Splitting the write
/// in two for `insert`'s sake must not split the AUDIT in two, so all
/// three calls live in this one block under this one `#[expect]` — and
/// `Drop` below calls [`Self::remove_staging_name`] rather than
/// carrying a licence of its own.
#[expect(
    clippy::disallowed_methods,
    reason = "one audited unit: `O_EXCL`+`O_NOFOLLOW` create of a pid+counter name under \
              `txn/`, the rename into `dest`, and the best-effort remove of the tmp when the \
              staged bytes are not published. The safety is NOT that the name has never been \
              used. A pid+counter name is unique only among LIVE processes: the OS reuses \
              numeric pids, and a fresh process's counter restarts at 0, so a later process \
              that happens to be given the SAME pid generates the SAME names — and if an \
              earlier crash left staging behind under them, the two collide. (A \
              DIFFERENTLY-pid'd leftover cannot collide at all; the hazard is pid REUSE \
              specifically.) `O_EXCL` refuses ANY pre-existing name regardless of why it is \
              there — a malicious pre-plant and a stale same-name collision are refused the \
              identical way, and `sweep_orphaned_txn_files` ATTEMPTS the name on the next \
              writer open for EVERY non-directory entry (regular file, symlink, FIFO, socket, \
              device node alike) — it clears what it can unlink and WARNS about what it \
              cannot, skipping rather than failing the open, so a stale collision or a plant \
              is normally not permanent but an entry the sweep cannot remove (EPERM/EACCES on \
              a txn/ this process cannot write, an immutable-flagged node) keeps its name \
              wedged indefinitely. A DIRECTORY planted at a staging name is the other shape \
              the sweep leaves (F6), and it too wedges that exact name — the docs here state \
              that and the other gap this does not close (a symlinked intermediate component \
              of `dest`, which this staging discipline does not protect against). \
              The remove is BY NAME, of the staging name this process itself created, never \
              through a path derived from following anything; if it fails the name is a \
              leftover in txn/ rather than an error, swept on the next writer open"
)]
impl StagedWrite {
    /// Stage `bytes` under `txn/`: `O_EXCL` create of a pid+counter
    /// name, write, fsync (the per-platform helper — never `sync_all`
    /// on macOS), chmod to `mode`. Nothing is visible at any
    /// destination until [`Self::rename_into`] publishes it.
    pub(super) fn stage(
        root: &Path,
        bytes: &[u8],
        counter: &AtomicU64,
        mode: u32,
    ) -> Result<Self, CacheError> {
        let tmp = root.join("txn").join(unique_txn_name(counter));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            // O_EXCL (from create_new) already refuses any existing name
            // at this path, symlink or not; O_NOFOLLOW is added for
            // uniformity with the other structural opens (lock, guard),
            // not because this one is otherwise exposed.
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .map_err(io_err("create txn file"))?;
        // From here on the NAME exists, so every exit path has to clear
        // it: the guard is constructed FIRST and the remaining steps
        // run with it already owning the cleanup.
        let staged = Self { tmp };
        (|| -> io::Result<()> {
            f.write_all(bytes)?;
            fsync_file(&f)?;
            f.set_permissions(fs::Permissions::from_mode(mode))
        })()
        .map_err(io_err("stage txn file"))?;
        Ok(staged)
    }

    /// Publish the staged bytes at `dest`. `self` is consumed, and its
    /// `Drop` still runs: after a SUCCESSFUL rename the staging name is
    /// already gone and the removal is a no-op `NotFound`; after a
    /// FAILED one it is the cleanup.
    ///
    /// The `rename(2)` replaces a non-directory `dest` atomically and
    /// never follows its final component. It DOES follow a symlinked
    /// INTERMEDIATE component of `dest`, the same way any path-based
    /// syscall does — a caller relying on a check made before this call
    /// is only as safe as the gap between that check and this call is
    /// short; see `load_index_read_only`'s doc for the one caller where
    /// that gap is not short.
    pub(super) fn rename_into(self, dest: &Path) -> Result<(), CacheError> {
        fs::rename(&self.tmp, dest).map_err(io_err(format!("atomic write {}", dest.display())))
    }

    /// Best-effort removal of the staging name. Called only from
    /// [`Drop`], which is what makes "every path out clears the name"
    /// structural rather than a rule each caller has to remember.
    fn remove_staging_name(&self) {
        let _ = fs::remove_file(&self.tmp);
    }
}

impl Drop for StagedWrite {
    fn drop(&mut self) {
        self.remove_staging_name();
    }
}

/// txn-staged atomic write, shared by roots (0444) and the index files
/// (0644 — they must stay reopenable for append/truncation, unlike
/// content-addressed objects): [`StagedWrite::stage`] then
/// [`StagedWrite::rename_into`], with nothing between them.
///
/// Same discipline as `store::atomic_write`, which is one function
/// rather than two because nothing in the store has to interleave a
/// decision between the staging and the rename.
///
/// `WriterState::insert` does NOT use this: it needs the two halves
/// apart, so that a cache which cannot stage declines before it evicts.
pub(super) fn atomic_write(
    root: &Path,
    dest: &Path,
    bytes: &[u8],
    counter: &AtomicU64,
    mode: u32,
) -> Result<(), CacheError> {
    StagedWrite::stage(root, bytes, counter, mode)?.rename_into(dest)
}
