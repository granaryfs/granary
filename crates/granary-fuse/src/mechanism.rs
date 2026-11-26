// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
#![cfg(test)]

//! Conformance layer 2 — FUSE-mechanism property tests.
//!
//! Everything the differential oracle cannot see, because it only ever
//! compares a DUMP of the source tree against a DUMP of the mount:
//! readdir ordering/cookies, forget accounting and inode identity,
//! kernel attribute caching, and the READDIRPLUS capability itself. This
//! module mounts a REAL granary filesystem (`fuser::spawn_mount`) and
//! drives it with ordinary syscalls to test exactly those properties.
//!
//! `#[cfg(all(test, target_os = "linux"))]` — compiles (cfg'd out) on
//! macOS, RUNS only on Linux, in the container-root lane
//! (`scripts/linux-container.sh test`). Every test starts with
//! `if !require_root(...) { return; }`, which prints `NOT EXECUTED` when
//! not root. On macOS the module only type-checks
//! (`cargo check --target x86_64-unknown-linux-gnu -p granary-fuse --tests`);
//! every row in it has been run in that lane.
//!
//!
//! Two mechanisms carry every row:
//!
//! - [`Observed`] wraps a real [`GranaryFs`] and counts callback traffic
//!   (rows 1 and 4 only) without ever touching a reply.
//! - [`ReferenceFs`] is an INDEPENDENT `fuser::Filesystem` that reuses the
//!   real reader primitives (`list_dir_plus`, `Snapshot::attr_for`/
//!   `read_at`, a real [`InodeTable`]) and injects exactly ONE armed
//!   [`Fault`] — the negative for every row but 1, 6a and 9. Every
//!   row with a `ReferenceFs` fault carries a MANDATORY same-fixture
//!   `fault: None` control checking the unarmed wiring against the
//!   same expectations as `GranaryFs`, without establishing that
//!   a mutation of the real adapter would fail the positive.
//!
//! The fault mechanism lives in this test module,
//! not as a `#[cfg(test)]` seam inside shipped `GranaryFs`.
//! This module does not mutate the real `GranaryFs`.
//! Nothing in this module establishes that each row's POSITIVE
//! would go red under a corresponding mutation of the real adapter.
//! That must be checked by mutating `GranaryFs` by hand
//! and running the row's positive against that mutation.
//!
//! ## Conformance layer 3 — the refusal taxonomy
//!
//! The refusal-taxonomy rows below drive one refusing syscall per row against a FRESH
//! mount (order-independence: no per-connection latch has formed when the
//! row's opcode is first sent) and assert both the errno and the FUSE
//! opcode traffic that proves WHICH layer answered. Five layers produce a
//! refusal on this mount: the kernel's `ro` check (zero write opcodes reach
//! the daemon); the kernel's error precedence (`EISDIR`, `ENOTDIR`,
//! `ELOOP` and `EEXIST` beat `EROFS`, decided from granary's own `LOOKUP`
//! attrs); granary's daemon handlers (`ENAMETOOLONG`, `ENOENT`, `EIO`,
//! `EACCES`, `ENODATA`); `fuser`'s trait defaults for the write ops
//! granary does not implement (`ENOSYS`, and `EPERM` for `link` and
//! `symlink`); and the kernel's per-connection latches that rewrite a
//! daemon `ENOSYS` (`setxattr`/`removexattr` to `EOPNOTSUPP`, `renameat2`
//! with flags to `EINVAL`, `fsync`/`fsyncdir` to success) — for those the
//! SECOND call on the same connection is the witness that the daemon
//! answered `ENOSYS`: had it answered the rewritten errno itself, no latch
//! forms and the opcode count is 2. `link` is the inverse case and is
//! pinned by a count of 2: fuser's direct `EPERM` never latches, while
//! the kernel's `no_link` latch (v6.15 and later) would otherwise mask a
//! daemon `ENOSYS` behind that same `EPERM`.
//!
//! A FIFO or socket entry has no row: it is a decode-time refusal, so no
//! such snapshot ever mounts — `granary-vfs`'s `snapshot/tests.rs`'s
//! `a_reserved_entry_is_refused_at_construction_naming_dir_name_and_kind`
//! and `ordinary_entries_beside_the_reserved_entry_gate_still_construct`
//! are the construction tests that cover it.
//!
//! `write`, `ftruncate` and `fallocate` on an `O_RDONLY` descriptor are
//! `EBADF`, `EINVAL` and `EBADF` from the VFS descriptor-mode check and are
//! recorded here rather than as rows for immutable diagnostic attachments.
//! Admitted writable attachments can supply ordinary writable descriptors.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use fuser::{
    AccessFlags, BackgroundSession, BsdFileFlags, CopyFileRangeFlags, FileHandle, Filesystem,
    FopenFlags, Generation, INodeNo, IoctlFlags, KernelConfig, LockOwner, MountOption, OpenAccMode,
    OpenFlags, PollEvents, PollFlags, PollNotifier, RenameFlags, ReplyAttr, ReplyBmap, ReplyCreate,
    ReplyData, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyIoctl, ReplyLock, ReplyLseek,
    ReplyOpen, ReplyPoll, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};
use rustix::fs::OFlags;
use rustix::io::Errno;

use granary_core::hash::GrainId;
use granary_core::manifest::{
    DirEntry, EntryKind, FileGrains, GrainRef, Name, SymlinkTarget, TreeStats, build_dir,
    build_grain_list,
};
use granary_core::sheaf::Timestamp;

use crate::detach_unmount;
use crate::unmount::mount_state;
use crate::{
    DirPlusSink, FUSE_SERVE_LIMITS, GranaryFs, MountBackend, SinkOutcome, check_name_length, errno,
    list_dir_plus,
};
use granary_vfs::{
    Attr, AttrPolicy, Entry, GrainFetch, GrainUnavailable, HandleKind, HandleTable, InodeTable,
    NodeKind, PathKey, READ_MAX_GRAINS, ReaderError, Snapshot, dir_and_parent,
};

mod session_guard;
mod writable;
use crate::test_connection_abort as abort;
use abort::cleanup_wait;
use session_guard::SessionGuard;

// =====================================================================
// Scaffolding: backend, mount/scratch-dir mechanics, teardown
// =====================================================================

/// A ~15-line [`MountBackend`] over an in-memory grain map. Modelled on
/// `filesystem.rs`'s own `TestBackend`, but that one is private to that
/// module's test suite — this is its own, minimal copy.
#[derive(Debug, Clone, Default)]
struct InMemBackend {
    grains: BTreeMap<GrainId, Vec<u8>>,
}

impl GrainFetch for InMemBackend {
    fn grain(&mut self, id: &GrainId, _unpacked_len: u32) -> Result<Vec<u8>, GrainUnavailable> {
        self.grains
            .get(id)
            .cloned()
            .ok_or_else(|| GrainUnavailable::new(format!("missing test grain {id}")))
    }
}

impl MountBackend for InMemBackend {
    type DirectoryCursor = ();
    fn overlay_path(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_lookup(
        &mut self,
        _parent: &[granary_core::manifest::Name],
        _name: &granary_core::manifest::Name,
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_directory(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<crate::OverlayDirectory<()>, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_children(
        &mut self,
        _cursor: &(),
    ) -> Result<crate::OverlayChildren<()>, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }

    fn overlay_nodes(&mut self) -> Result<Vec<crate::OverlayNode>, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_capacity(&mut self) -> Result<crate::OverlayCapacity, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_readlink(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<Vec<u8>, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn prepare_shrink_retry(
        &mut self,
        _request: crate::MountShrinkRequest,
    ) -> Result<Box<dyn crate::MountSyncJob>, crate::MountSyncError> {
        Err(crate::MountSyncError::InvalidRequest)
    }

    fn prepare_sync(
        &mut self,
        _request: crate::MountSyncRequest,
    ) -> Result<Box<dyn crate::MountSyncJob>, crate::MountSyncError> {
        Err(crate::MountSyncError::InvalidRequest)
    }

    fn overlay_open(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<Option<u64>, crate::WriteError> {
        Ok(None)
    }
    fn overlay_object(&mut self, _object: u64) -> Result<crate::OverlayNode, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_close(&mut self, _object: u64) -> Result<(), crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn prepare_object(&mut self, _object: u64) -> Result<(), crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn prepare_detach(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<(), crate::WriteError> {
        Ok(())
    }
    fn read_object(
        &mut self,
        _object: u64,
        _offset: u64,
        _length: usize,
    ) -> Result<Vec<u8>, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn prepare_overlay(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<(), crate::WriteError> {
        Ok(())
    }
    fn overlay_setattr(
        &mut self,
        _path: &[granary_core::manifest::Name],
        _size: Option<u64>,
        _exec: Option<bool>,
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_mutate(
        &mut self,
        _operation: crate::OverlayMutation<'_>,
    ) -> Result<(), crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn snapshot_fixture(&self) -> bool {
        true
    }

    fn mutation_readiness(&mut self) -> Result<(), crate::MountError> {
        Ok(())
    }
    fn shutdown(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn abandon(&mut self) {}
}

/// Prints a reason and returns `false` rather than asserting nothing —
/// same shape as `unmount.rs`'s own `require_root`. The marker string
/// `NOT EXECUTED` is load-bearing: it is what the container-root lane's
/// own harness greps for to prove a test that NEEDS root actually ran
/// as root rather than silently no-op'ing.
///
/// Two gates, in order: (1) effective uid 0, and (2) `/dev/fuse` present
/// as a character device. The SECOND is what keeps these tests from
/// breaking CI's ordinary `test` job: that job runs `cargo nextest` on a
/// Linux runner where this module compiles and is collected, but has no
/// `/dev/fuse` — without this check a root-but-no-fuse runner would reach
/// `spawn_mount` and PANIC. It skips with a DISTINCT marker (never
/// `NOT EXECUTED`), because the container-root lane where these are MEANT
/// to run always has `/dev/fuse`, so this branch never fires there and
/// the `NOT EXECUTED` marker gate stays meaningful.
fn require_root(test_name: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!(
            "SKIPPED {test_name}: needs to start as root (mounting a real FUSE filesystem needs \
             CAP_SYS_ADMIN / /dev/fuse access) — NOT EXECUTED on this run"
        );
        return false;
    }
    let has_dev_fuse = std::fs::metadata("/dev/fuse").is_ok_and(|m| m.file_type().is_char_device());
    if !has_dev_fuse {
        eprintln!(
            "SKIPPED-NO-DEV-FUSE {test_name}: /dev/fuse is not present as a character device — \
             this environment cannot mount a FUSE filesystem (the container-root lane, where \
             these tests are meant to run, always provides it)"
        );
        return false;
    }
    true
}

/// Which capability line of `/proc/self/status` a row's expectation is
/// decided by. `open(2)` runs `inode_permission(MAY_WRITE)` under the
/// caller's EFFECTIVE set, so an `open(O_WRONLY)` row reads `CapEff`;
/// `access(2)` from a real-uid-0 caller runs under `access_override_creds`
/// (`fs/open.c`), which sets the effective set to the PERMITTED set for
/// the duration of the check, so an `access(W_OK)` row reads `CapPrm` —
/// probing `CapEff` there would measure a register the kernel does not
/// consult for that call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CapRegister {
    Eff,
    Prm,
}

impl CapRegister {
    fn line_prefix(self) -> &'static [u8] {
        match self {
            Self::Eff => b"CapEff:",
            Self::Prm => b"CapPrm:",
        }
    }
}

/// True iff `CAP_DAC_OVERRIDE` (bit 1, `include/uapi/linux/capability.h`)
/// is set in the named line of `status` (the bytes of
/// `/proc/self/status`). Fail-closed: a missing or unparseable line is
/// `false`, never "probably fine".
fn cap_has_dac_override(status: &[u8], reg: CapRegister) -> bool {
    const CAP_DAC_OVERRIDE: u64 = 1 << 1;
    status
        .split(|&b| b == b'\n')
        .find_map(|line| line.strip_prefix(reg.line_prefix()))
        .and_then(|rest| std::str::from_utf8(rest).ok())
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .is_some_and(|mask| mask & CAP_DAC_OVERRIDE != 0)
}

/// The up-front probe for the rows whose EXPECTED answer rests on root's
/// DAC override: returns `false` and prints a `NOT EXECUTED` skip when
/// `CAP_DAC_OVERRIDE` is clear in `reg` (or the line is unreadable). The
/// marker is the one `require_root` prints, so the container-root lane's
/// marker gate counts a skip here as a lane FAILURE — a lane that cannot
/// supply the capability must not pass silently. A kernel `EACCES` on a
/// row that passed this probe is then a hard failure, never an
/// environment skip: this probe, not the row's own outcome, is what tells
/// "the kernel refused before FUSE" from "the daemon lost a count".
fn cap_line(status: &[u8], reg: CapRegister) -> String {
    status
        .split(|&b| b == b'\n')
        .find(|line| line.starts_with(reg.line_prefix()))
        .map_or_else(String::new, |line| {
            String::from_utf8_lossy(line).into_owned()
        })
}

fn require_dac_override(test_name: &str, reg: CapRegister) -> bool {
    let status = std::fs::read("/proc/self/status").unwrap_or_default();
    match reg {
        // The `open`-based rows: `inode_permission` runs in the caller's
        // EFFECTIVE credentials, so the effective set (`CapEff`) decides and
        // the real uid does not matter.
        CapRegister::Eff => {
            if cap_has_dac_override(&status, CapRegister::Eff) {
                eprintln!("CAP {test_name}: {}", cap_line(&status, CapRegister::Eff));
                return true;
            }
            eprintln!(
                "SKIPPED {test_name}: needs CAP_DAC_OVERRIDE in the CapEff set (bit 1 of the \
                 CapEff line of /proc/self/status) — NOT EXECUTED on this run"
            );
            false
        }
        // The `access(2)` row: `access_override_creds` (fs/open.c) runs the
        // check under the caller's REAL uid, and — for a real-uid-0 caller —
        // consults the PERMITTED set copied into effective under default
        // securebits (`cap_effective = cap_permitted`), or the ORIGINAL
        // effective set when `SECURE_NO_SETUID_FIXUP` is set (the copy is
        // skipped). `require_root` proves EFFECTIVE uid 0, not real, so this
        // additionally needs real uid 0; and to be correct under BOTH
        // securebits states without reading them, it requires the bit in
        // BOTH `CapPrm` and `CapEff` — whichever `access(2)` ends up
        // consulting then has it. Missing either is a clean NOT EXECUTED
        // skip, never a false `EACCES` red.
        CapRegister::Prm => {
            if !nix::unistd::Uid::current().is_root() {
                eprintln!(
                    "SKIPPED {test_name}: the access(2) probe needs REAL uid 0 (its \
                     permitted-to-effective substitution applies only to a real-uid-0 caller) \
                     — NOT EXECUTED on this run"
                );
                return false;
            }
            if cap_has_dac_override(&status, CapRegister::Prm)
                && cap_has_dac_override(&status, CapRegister::Eff)
            {
                eprintln!(
                    "CAP {test_name}: {} {}",
                    cap_line(&status, CapRegister::Prm),
                    cap_line(&status, CapRegister::Eff)
                );
                return true;
            }
            eprintln!(
                "SKIPPED {test_name}: needs CAP_DAC_OVERRIDE in BOTH CapPrm and CapEff (access(2) \
                 consults one or the other depending on SECURE_NO_SETUID_FIXUP) — NOT EXECUTED \
                 on this run"
            );
            false
        }
    }
}

#[test]
fn cap_has_dac_override_reads_the_named_register_only() {
    let full: &[u8] = b"Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\n\
                        CapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n";
    assert!(cap_has_dac_override(full, CapRegister::Eff));
    assert!(cap_has_dac_override(full, CapRegister::Prm));
    let eff_clear: &[u8] = b"CapPrm:\t000001ffffffffff\nCapEff:\t000001fffffffffd\n";
    assert!(
        !cap_has_dac_override(eff_clear, CapRegister::Eff),
        "bit 1 clear in CapEff must read as absent"
    );
    assert!(
        cap_has_dac_override(eff_clear, CapRegister::Prm),
        "the same body answers true for CapPrm -- the register matters"
    );
    assert!(cap_has_dac_override(
        b"CapEff:\t0000000000000002\n",
        CapRegister::Eff
    ));
    assert!(
        !cap_has_dac_override(b"CapEff:\t000001ffffffffff\n", CapRegister::Prm),
        "a body with no CapPrm line is fail-closed"
    );
    assert!(!cap_has_dac_override(
        b"garbage\nCapEff:\tzzzz\n",
        CapRegister::Eff
    ));
    assert!(!cap_has_dac_override(b"", CapRegister::Eff));
}

/// The actual create-and-verify mechanism behind [`scratch_dir`] — copied
/// from `unmount.rs`'s identical helper. `create_dir`, never
/// `create_dir_all`: a pre-planted symlink or directory at the target
/// path is REFUSED outright rather than silently reused or descended
/// into.
fn create_verified_scratch_dir(dir: PathBuf) -> PathBuf {
    std::fs::create_dir(&dir).expect(
        "create a fresh, exclusively-owned scratch directory (refused if the path already \
         exists, planted or stale)",
    );
    let file_type = std::fs::symlink_metadata(&dir)
        .expect("stat the directory this call just created")
        .file_type();
    assert!(
        file_type.is_dir(),
        "scratch directory {} was replaced between creation and this check — refusing to use it",
        dir.display()
    );
    dir
}

/// A scratch directory unique to the calling test and this specific
/// call, under a CANONICAL base — the same shape `unmount.rs`'s own
/// `scratch_dir` uses, including its `disallowed_methods` escape for
/// `std::process::id`: naming a throwaway test fixture is the same
/// exception the rest of the workspace's suites already take.
#[expect(
    clippy::disallowed_methods,
    reason = "test scratch-dir naming; disallowed_methods has no allow-in-tests knob"
)]
fn scratch_dir(label: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::fs::canonicalize(std::env::temp_dir())
        .expect("canonicalize the temp directory these fixtures live under");
    create_verified_scratch_dir(base.join(format!(
        "granary-fuse-mechanism-test-{label}-{}-{n}",
        std::process::id()
    )))
}

/// Lazily detaches and joins within a bound on success, panic and timeout.
/// Only removes the exclusively owned scratch directory after a kernel check.
struct MountGuard {
    session: SessionGuard,
    mp: PathBuf,
    torn: bool,
}

impl MountGuard {
    fn daemon_alive(&self) -> bool {
        self.session.daemon_alive()
    }

    fn teardown(mut self) {
        self.session
            .finish()
            .expect("mounted row must finish without a worker panic or timeout");
        cleanup_wait::assert_gone(self.session.connection, "mount", || {
            !mount_state(&self.mp).unwrap()
        });
        std::fs::remove_dir(&self.mp).expect("remove the empty, unmounted scratch directory");
        self.torn = true;
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if self.torn {
            return;
        }
        if let Err(error) = self.session.finish() {
            eprintln!("mount test cleanup: {error}");
        }
        if matches!(mount_state(&self.mp), Ok(false)) {
            // Nonrecursive rmdir refuses a mount raced onto this path.
            let _ = std::fs::remove_dir(&self.mp);
        }
    }
}

/// Spawns `fs` at a fresh scratch mountpoint under `label` and returns
/// the mountpoint plus a guard that tears it down on drop. Panics (after
/// best-effort cleanup) on a mount failure — every call site needs the
/// mount to succeed to mean anything.
#[expect(
    clippy::needless_pass_by_value,
    reason = "a test helper taking Config by value so every call site passes an owned \
              session_config(...) (or a locally-built Config, e.g. row 9's noexec variant) \
              inline without a borrow; spawn_mount borrows it internally and the value is \
              dropped at the end of the mount setup regardless"
)]
fn spawn_guarded<FS: Filesystem + Send + 'static>(
    label: &str,
    fs: FS,
    config: fuser::Config,
) -> (PathBuf, MountGuard) {
    let mountpoint = scratch_dir(label);
    match fuser::spawn_mount(fs, &mountpoint, &config) {
        Ok(session) => {
            let mp = mountpoint.clone();
            (
                mountpoint,
                MountGuard {
                    session: SessionGuard::new(session, &mp),
                    mp,
                    torn: false,
                },
            )
        }
        Err(err) => {
            let _ = std::fs::remove_dir(&mountpoint);
            panic!("could not mount {label} at {}: {err}", mountpoint.display());
        }
    }
}

// =====================================================================
// Shared observation state (rows 1 and 4's `Observed`; also used
// directly by `ReferenceFs` for row 4's negative/None-control)
// =====================================================================

/// Every FUSE callback this module can observe, one variant per opcode.
/// The refusal rows assert exact counts per opcode, so a callback that is
/// forwarded without being counted would make "the daemon never ran"
/// indistinguishable from "the daemon ran and answered". The invariant:
/// every REQUEST method either double implements counts its opcode BEFORE
/// it delegates (`Observed`) or answers (`ReferenceFs`). `init` and
/// `destroy` are session lifecycle, not opcodes here; `batch_forget` is
/// exempt on both (fuser's `ForgetOne` is unnameable from this crate, and
/// the trait default fans the batch out to `forget`, which counts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    Lookup,
    Forget,
    Getattr,
    Setattr,
    Readlink,
    Mknod,
    Mkdir,
    Unlink,
    Rmdir,
    Symlink,
    Rename,
    Link,
    Open,
    Read,
    Write,
    Flush,
    Release,
    Fsync,
    Opendir,
    Readdir,
    Readdirplus,
    Releasedir,
    Fsyncdir,
    Statfs,
    Setxattr,
    Getxattr,
    Listxattr,
    Removexattr,
    Access,
    Create,
    Fallocate,
    CopyFileRange,
    Lseek,
    Getlk,
    Setlk,
    Bmap,
    Ioctl,
    Poll,
}

/// The per-opcode map (`ops`) and the name-keyed lookup map
/// (`lookups_by_name`) carry every count a row asserts; the two filtered
/// counters beside them exist because no generic counter can express
/// their filter.
#[derive(Debug, Default, Clone)]
struct ObsState {
    /// Root-child lookups for names in the test's own expected-fixture
    /// set ONLY (row 1). A bare "count every root lookup" is flaky: a
    /// stray probe for a name the fixture does not contain (any process
    /// that sees the mount, e.g. a `.Trash`-style path) would inflate
    /// the count.
    lookup_child: u64,
    /// `GETATTR`s for any inode but the root (row 1).
    getattr_nonroot: u64,
    resident: usize,
    seq: u64,
    /// Every callback, by opcode, counted before delegation.
    ops: BTreeMap<Op, u64>,
    /// Every `LOOKUP` from ANY parent, keyed by the exact name bytes.
    /// The refusal rows assert `LOOKUP(name) == n` per name, which is
    /// what tells "the kernel stopped before asking" from "the daemon was
    /// asked and refused".
    lookups_by_name: BTreeMap<Vec<u8>, u64>,
    /// Every `READ` request as received, `(offset, size)`. The
    /// too-fragmented row needs the SIZE the kernel actually sent, not
    /// only that a read arrived: the page cache may split one user read
    /// into several requests that each stay under the grain cap.
    reads: Vec<(u64, u32)>,
}

impl ObsState {
    fn count(&mut self, op: Op) {
        *self.ops.entry(op).or_insert(0) += 1;
    }

    fn count_lookup(&mut self, name: &[u8]) {
        self.count(Op::Lookup);
        *self.lookups_by_name.entry(name.to_vec()).or_insert(0) += 1;
    }

    fn record_read(&mut self, offset: u64, size: u32) {
        self.count(Op::Read);
        self.reads.push((offset, size));
    }

    /// The count for `op`, zero when the opcode never arrived.
    fn op_count(&self, op: Op) -> u64 {
        self.ops.get(&op).copied().unwrap_or(0)
    }

    /// The number of `LOOKUP`s for exactly `name`, from any parent.
    fn lookups(&self, name: &[u8]) -> u64 {
        self.lookups_by_name.get(name).copied().unwrap_or(0)
    }
}

/// Shared observation/wait state between the test thread and the mount's
/// callback thread. One fresh instance per mount — never shared across
/// two different mounts.
#[derive(Debug)]
struct Obs {
    state: Mutex<ObsState>,
    cv: Condvar,
}

impl Obs {
    fn new() -> Self {
        Self {
            state: Mutex::new(ObsState::default()),
            cv: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, ObsState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn count(&self, op: Op) {
        self.lock().count(op);
    }
}

// =====================================================================
// Observed<B> — the observation wrapper (rows 1 and 4 only)
// =====================================================================

/// A `fuser::Filesystem` that OWNS a real [`GranaryFs`] and FORWARDS
/// every Linux-visible trait method but `batch_forget`, never rewriting
/// a reply. fuser 0.18's `Filesystem` has 41 methods on Linux (44 less
/// the three macOS-only ones): `init` and `destroy` are forwarded as
/// session lifecycle, `batch_forget` keeps its default (its `ForgetOne`
/// type is unnameable from this crate, and the default fans out to the
/// forwarded `forget`, exactly as `GranaryFs` itself relies on — see
/// `filesystem.rs`'s own `forget` doc), and the remaining 38 request
/// methods are each counted under their [`Op`] and delegated. The count is
/// a MANUAL audit against the `=0.18.0` pin in `Cargo.toml`, not a
/// compile-enforced one: nothing forces a new trait method through
/// `count()`, so a fuser that grew a request method would answer it with
/// the trait default UNCOUNTED. That cannot happen silently here only
/// because the version is pinned exactly — a bump is a deliberate act that
/// re-runs this suite, at which point this doc's count is re-audited.
#[derive(Debug)]
struct Observed<B: MountBackend> {
    inner: GranaryFs<B>,
    obs: Arc<Obs>,
    /// Row 1's own fork: `true` negotiates `FUSE_DO_READDIRPLUS`
    /// normally (delegates to `GranaryFs::init`); `false` is the
    /// negative — `init` returns `Ok(())` without ever calling
    /// `config.add_capabilities`, so the kernel never learns the mount
    /// wants READDIRPLUS and falls back to plain `READDIR` plus
    /// per-child `LOOKUP`/`GETATTR`.
    negotiate: bool,
    /// Row 1's expected fixture child names, for `lookup_child`'s
    /// filter.
    expected_children: BTreeSet<Vec<u8>>,
}

impl<B: MountBackend> Observed<B> {
    fn lock_state(&self) -> MutexGuard<'_, ObsState> {
        self.obs.lock()
    }

    /// Publishes the RUNNING daemon's inode-table size into `obs.state`
    /// and wakes anyone waiting on it. Called after every callback that
    /// can move the table (readdir/readdirplus grow it, forget shrinks
    /// it) — cheap, since it locks the SAME `inner` mutex the callback
    /// just released.
    fn publish_resident(&self) {
        let resident = self.inner.resident_count();
        let mut state = self.lock_state();
        state.resident = resident;
        state.seq = state.seq.wrapping_add(1);
        self.obs.cv.notify_all();
    }
}

impl<B: MountBackend> Filesystem for Observed<B> {
    fn init(&mut self, req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        if self.negotiate {
            self.inner.init(req, config)
        } else {
            Ok(())
        }
    }

    fn destroy(&mut self) {
        self.inner.destroy();
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name_bytes = name.as_bytes();
        let is_expected_child =
            parent == INodeNo::ROOT && self.expected_children.contains(name_bytes);
        {
            // One guard for both counters, released BEFORE delegating:
            // `publish_resident` below re-locks, and holding this across
            // the inner call would deadlock there.
            let mut state = self.lock_state();
            if is_expected_child {
                state.lookup_child += 1;
            }
            state.count_lookup(name_bytes);
        }
        self.inner.lookup(req, parent, name, reply);
        self.publish_resident();
    }

    fn forget(&self, req: &Request, ino: INodeNo, nlookup: u64) {
        self.obs.count(Op::Forget);
        self.inner.forget(req, ino, nlookup);
        self.publish_resident();
    }

    fn getattr(&self, req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        if ino != INodeNo::ROOT {
            self.lock_state().getattr_nonroot += 1;
        }
        self.obs.count(Op::Getattr);
        self.inner.getattr(req, ino, fh, reply);
    }

    // Every write-shaped operation below is counted and then DELEGATED
    // to the wrapped `GranaryFs`, which today resolves to `fuser`'s trait
    // default. Replying the default here instead would hide a future
    // `GranaryFs` override of the same method from the rows that exist
    // to observe exactly that.
    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        creation_time: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        self.obs.count(Op::Setattr);
        self.inner.setattr(
            req,
            ino,
            mode,
            uid,
            gid,
            size,
            atime,
            mtime,
            ctime,
            fh,
            creation_time,
            chgtime,
            bkuptime,
            flags,
            reply,
        );
    }

    fn readlink(&self, req: &Request, ino: INodeNo, reply: ReplyData) {
        self.obs.count(Op::Readlink);
        self.inner.readlink(req, ino, reply);
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        self.obs.count(Op::Mknod);
        self.inner
            .mknod(req, parent, name, mode, umask, rdev, reply);
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        self.obs.count(Op::Mkdir);
        self.inner.mkdir(req, parent, name, mode, umask, reply);
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.obs.count(Op::Unlink);
        self.inner.unlink(req, parent, name, reply);
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.obs.count(Op::Rmdir);
        self.inner.rmdir(req, parent, name, reply);
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        self.obs.count(Op::Symlink);
        self.inner.symlink(req, parent, link_name, target, reply);
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        self.obs.count(Op::Rename);
        self.inner
            .rename(req, parent, name, newparent, newname, flags, reply);
    }

    fn link(
        &self,
        req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        self.obs.count(Op::Link);
        self.inner.link(req, ino, newparent, newname, reply);
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        self.obs.count(Op::Open);
        self.inner.open(req, ino, flags, reply);
    }

    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        flags: OpenFlags,
        lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        self.lock_state().record_read(offset, size);
        self.inner
            .read(req, ino, fh, offset, size, flags, lock_owner, reply);
    }

    fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        write_flags: WriteFlags,
        flags: OpenFlags,
        lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        self.obs.count(Op::Write);
        self.inner.write(
            req,
            ino,
            fh,
            offset,
            data,
            write_flags,
            flags,
            lock_owner,
            reply,
        );
    }

    fn flush(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        self.obs.count(Op::Flush);
        self.inner.flush(req, ino, fh, lock_owner, reply);
    }

    fn release(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        flags: OpenFlags,
        lock_owner: Option<LockOwner>,
        flush: bool,
        reply: ReplyEmpty,
    ) {
        self.obs.count(Op::Release);
        self.inner
            .release(req, ino, fh, flags, lock_owner, flush, reply);
    }

    fn fsync(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.obs.count(Op::Fsync);
        self.inner.fsync(req, ino, fh, datasync, reply);
    }

    fn opendir(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        self.obs.count(Op::Opendir);
        self.inner.opendir(req, ino, flags, reply);
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: fuser::ReplyDirectory,
    ) {
        self.obs.count(Op::Readdir);
        self.inner.readdir(req, ino, fh, offset, reply);
        self.publish_resident();
    }

    fn readdirplus(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectoryPlus,
    ) {
        self.obs.count(Op::Readdirplus);
        self.inner.readdirplus(req, ino, fh, offset, reply);
        self.publish_resident();
    }

    fn releasedir(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.obs.count(Op::Releasedir);
        self.inner.releasedir(req, ino, fh, flags, reply);
    }

    fn fsyncdir(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.obs.count(Op::Fsyncdir);
        self.inner.fsyncdir(req, ino, fh, datasync, reply);
    }

    fn statfs(&self, req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        self.obs.count(Op::Statfs);
        self.inner.statfs(req, ino, reply);
    }

    fn setxattr(
        &self,
        req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        self.obs.count(Op::Setxattr);
        self.inner
            .setxattr(req, ino, name, value, flags, position, reply);
    }

    fn getxattr(&self, req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        self.obs.count(Op::Getxattr);
        self.inner.getxattr(req, ino, name, size, reply);
    }

    fn listxattr(&self, req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        self.obs.count(Op::Listxattr);
        self.inner.listxattr(req, ino, size, reply);
    }

    fn removexattr(&self, req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        self.obs.count(Op::Removexattr);
        self.inner.removexattr(req, ino, name, reply);
    }

    fn access(&self, req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        self.obs.count(Op::Access);
        self.inner.access(req, ino, mask, reply);
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        self.obs.count(Op::Create);
        self.inner
            .create(req, parent, name, mode, umask, flags, reply);
    }

    fn fallocate(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        self.obs.count(Op::Fallocate);
        self.inner
            .fallocate(req, ino, fh, offset, length, mode, reply);
    }

    fn lseek(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        self.obs.count(Op::Lseek);
        self.inner.lseek(req, ino, fh, offset, whence, reply);
    }

    fn copy_file_range(
        &self,
        req: &Request,
        ino_in: INodeNo,
        fh_in: FileHandle,
        offset_in: u64,
        ino_out: INodeNo,
        fh_out: FileHandle,
        offset_out: u64,
        len: u64,
        flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        self.obs.count(Op::CopyFileRange);
        self.inner.copy_file_range(
            req, ino_in, fh_in, offset_in, ino_out, fh_out, offset_out, len, flags, reply,
        );
    }

    fn getlk(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        reply: ReplyLock,
    ) {
        self.obs.count(Op::Getlk);
        self.inner
            .getlk(req, ino, fh, lock_owner, start, end, typ, pid, reply);
    }

    fn setlk(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
        reply: ReplyEmpty,
    ) {
        self.obs.count(Op::Setlk);
        self.inner
            .setlk(req, ino, fh, lock_owner, start, end, typ, pid, sleep, reply);
    }

    fn bmap(&self, req: &Request, ino: INodeNo, blocksize: u32, idx: u64, reply: ReplyBmap) {
        self.obs.count(Op::Bmap);
        self.inner.bmap(req, ino, blocksize, idx, reply);
    }

    fn ioctl(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        flags: IoctlFlags,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: ReplyIoctl,
    ) {
        self.obs.count(Op::Ioctl);
        self.inner
            .ioctl(req, ino, fh, flags, cmd, in_data, out_size, reply);
    }

    fn poll(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        ph: PollNotifier,
        events: PollEvents,
        flags: PollFlags,
        reply: ReplyPoll,
    ) {
        self.obs.count(Op::Poll);
        self.inner.poll(req, ino, fh, ph, events, flags, reply);
    }
}

// =====================================================================
// ReferenceFs<B> — the negative-control filesystem
// =====================================================================

/// The one armed fault per `ReferenceFs` mount. Every variant is the
/// negative for exactly one row (rows 1, 6a and 9 have no `ReferenceFs`
/// fault at all — see this module's row 1/6a/9 tests and the design
/// record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// Row 7: every directory's `nlink` reports 2, regardless of its
    /// real subdirectory count.
    UniformNlink2,
    /// Row 2: `st_ino` is derived from the entry's `GrainId` instead of
    /// the inode table's own identity, so two byte-identical subtrees
    /// collide.
    InoByContent,
    /// Row 6b: a directory's `readdirplus` entry is offered with the
    /// wrong `NodeKind` (as a file), lying on the wire `d_type`.
    DtypeLie,
    /// Row 3: exactly one non-dot entry is dropped, on the first
    /// CONTINUED (`offset > 0`) `readdirplus` call the mount ever
    /// serves.
    CursorSkip,
    /// Row 5: a read that covers the file's declared final byte is
    /// answered one byte short.
    ShortRead,
    /// Row 8: `statfs` reports `namelen != 255`.
    WrongNamelen,
    /// Row 4: `forget` never actually reclaims — the table is told
    /// about every FORGET but never shrinks.
    NeverReclaim,
    /// Refusal taxonomy: a `LOOKUP` whose name is over `NAME_MAX` answers
    /// `ENOENT` — the wrong errno, claiming the name is merely ABSENT —
    /// instead of `ENAMETOOLONG`. Only that one errno is rewritten; every
    /// other lookup path is untouched, and the negative asserts a valid
    /// sibling still resolves, so "answer `ENOENT` to every lookup" cannot
    /// pass as this fault.
    WrongOverlongErrno,
    /// Refusal taxonomy: a NON-ROOT directory's attr is reported as a
    /// regular file with mode `0555` on the `lookup` and `getattr`
    /// replies (`nlink` untouched), so the kernel's `may_open` skips its
    /// `S_IFDIR` arm and `open(dir, O_WRONLY)` falls through to the
    /// permission check — `EROFS` where the precedence says `EISDIR`.
    /// Deliberately NOT applied on the `readdirplus` wire path: the rows
    /// that use it drive `openat` on a fresh mount, and the reply the
    /// kernel caches for that path is the `LOOKUP` entry attr. NEVER
    /// applied to the root: the FUSE root's kind is load-bearing for the
    /// mount itself.
    DirAsFile,
}

#[derive(Debug)]
struct RefInner<B> {
    backend: B,
    inodes: InodeTable,
    handles: HandleTable,
}

/// An independent `fuser::Filesystem` that REUSES the real reader
/// primitives (`Snapshot::lookup`/`attr_for`/`read_at`, a real
/// [`InodeTable`], [`list_dir_plus`]) so its only deviation from correct
/// is the one armed [`Fault`]. See this module's own doc for the design
/// ruling on why this lives here rather than as a fault seam inside the
/// shipped `GranaryFs`.
#[derive(Debug)]
struct ReferenceFs<B: MountBackend> {
    snapshot: Snapshot,
    inner: Mutex<Option<RefInner<B>>>,
    obs: Arc<Obs>,
    fault: Option<Fault>,
    /// `Fault::CursorSkip`'s one-shot latch. The fault must drop EXACTLY
    /// one entry across the mount's whole life, on the first CONTINUED
    /// (`offset > 0`) call it sees — not one per continuation call, which
    /// is what a per-call-only arm would produce across a listing that
    /// needs several continuations (row 3's 300-entry, small-buffer
    /// fixture always needs several). Read/written only from the FUSE
    /// event-loop thread (`session_config`'s `n_threads = 1`), so a
    /// plain bool would do; `AtomicBool` costs nothing and does not rest
    /// on that single-threading fact.
    cursor_skip_fired: AtomicBool,
}

/// The `Duration` `ReferenceFs`'s own replies use as their entry/attr
/// TTL — the same value `filesystem.rs`'s `ENTRY_TTL` uses, copied here
/// because that constant is private to its module and this is a
/// completely separate adapter that happens to want the same value for
/// the same reason (an immutable snapshot has no correctness upside to
/// a shorter one).
const REF_TTL: Duration = Duration::from_mins(1);

fn ref_inert_name() -> Result<Name, ReaderError> {
    Name::new(b"self".to_vec()).map_err(|_| ReaderError::Inconsistent)
}

fn ref_node_kind_of(snapshot: &Snapshot, entry: &Entry) -> Result<NodeKind, ReaderError> {
    Ok(snapshot.attr_for(entry, 0, 0)?.kind)
}

/// This fixture's own attribute conversion, test-only and independent of
/// `filesystem`'s adapter — it does not follow the adapter's
/// once-at-mount-time discipline (there is no per-mount instant stored
/// here to reuse), it converts `attr.time` directly on every call. Every
/// fixture snapshot this module builds carries a valid, representable
/// timestamp, so `kernel_time` never returns `None` here; a real refusal
/// would be a fixture bug, and `expect` says so.
fn to_fuse_attr(attr: &Attr) -> fuser::FileAttr {
    let time = crate::filesystem::kernel_time(attr.time)
        .expect("every fixture timestamp in this module is representable");
    fuser::FileAttr {
        ino: INodeNo(attr.ino),
        size: attr.size,
        blocks: attr.blocks,
        atime: time,
        mtime: time,
        ctime: time,
        crtime: time,
        kind: match attr.kind {
            NodeKind::Dir => fuser::FileType::Directory,
            NodeKind::File => fuser::FileType::RegularFile,
            NodeKind::Symlink => fuser::FileType::Symlink,
        },
        perm: attr.perm,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: 0,
        blksize: attr.blksize,
        flags: 0,
    }
}

/// Row 2's `Fault::InoByContent`: a deterministic, nonzero `u64` derived
/// from a `GrainId`'s own bytes. Two byte-identical subtrees resolve the
/// SAME entry inside a byte-identical `DirLeaf` node, so `entry.leaf`
/// (the id of the leaf the entry was found in) is identical for both —
/// exactly the collision this fault exists to produce.
fn ino_from_content(id: GrainId) -> u64 {
    let bytes = id.to_bytes();
    let mut head = [0_u8; 8];
    // `to_bytes()` is at least 8 bytes long (1 tag + 32 digest); this
    // slice never panics.
    head.copy_from_slice(&bytes[..8]);
    let derived = u64::from_le_bytes(head);
    if derived == 0 { 1 } else { derived }
}

/// `statfs`'s reply tuple, matching `filesystem.rs`'s private
/// `statfs_reply` formula (that function cannot be reused across module
/// boundaries) with the namelen field parameterised for row 8's fault.
fn ref_statfs_tuple(stats: TreeStats, namelen: u32) -> (u64, u64, u64, u64, u64, u32, u32, u32) {
    const BSIZE: u32 = 4096;
    let blocks = stats.bytes.div_ceil(u64::from(BSIZE));
    let files = stats.entries.saturating_add(1);
    (blocks, 0, 0, files, 0, BSIZE, namelen, BSIZE)
}

/// The readdirplus sink wrapper carrying rows 3 and 6b's faults —
/// `Fault::DtypeLie` and `Fault::CursorSkip` are the only two that can
/// only be expressed on the WIRE reply (the kernel's attribute cache and
/// `d_type` are populated from what this sink actually sends), so both
/// live here rather than in `apply_attr_fault`.
struct FaultDirPlusSink<'a, S> {
    inner: &'a mut S,
    fault: Option<Fault>,
    /// The snapshot and directory node this listing is of — needed so
    /// `InoByContent` can re-look-up an offered entry by name and read
    /// its `leaf` `GrainId` (the content key), the same way
    /// `breakage.rs`'s own `BreakageDirPlusSink` re-looks-up for
    /// `FollowSymlink`.
    snapshot: &'a Snapshot,
    dir: GrainId,
    skip_armed: bool,
    /// Every honest `nlookup` credit `list_dir_plus` took (via
    /// `table.lookup`) for an entry this wrapper then made unreachable to
    /// the kernel — dropped outright (`CursorSkip`) or zero-nodeid'd
    /// (`DtypeLie`) — that `list_dir_plus` therefore never repays itself.
    /// Drained once, in `readdirplus_dispatch`.
    withheld: Vec<u64>,
}

impl<S: DirPlusSink> DirPlusSink for FaultDirPlusSink<'_, S> {
    fn offer(&mut self, mut attr: Attr, name: &[u8], next: u64) -> SinkOutcome {
        let is_dot = name == b"." || name == b"..";

        // CursorSkip: drop exactly one non-dot entry on a continued call.
        if !is_dot && self.fault == Some(Fault::CursorSkip) && self.skip_armed {
            self.skip_armed = false;
            self.withheld.push(attr.ino);
            // `list_dir_plus` already credited this entry's `nlookup` via
            // `table.lookup` before offering it; reporting `Added` here
            // (rather than `Full`, which would make `list_dir_plus` repay
            // the credit ITSELF) keeps the repayment explicit and
            // singular, in `readdirplus_dispatch` below, mirroring
            // `breakage.rs`'s own `withheld` ledger.
            return SinkOutcome::Added;
        }

        // Attr-level faults MUST be applied HERE, on the readdirplus
        // wire reply, not only in `apply_attr_fault` (getattr/lookup):
        // `ENTRY_TTL`/`REF_TTL` is a minute, so the kernel caches every
        // child's `st_ino` and `nlink` from THIS reply and never
        // re-issues a getattr for a `stat`/`find` — the oracle's
        // `ENTRY_TTL` lesson (see `breakage.rs`).
        if !is_dot {
            match self.fault {
                // A directory's honest nlink (`2 + subdir_count`): faking every
                // directory to 2 (= "no subdirectories") is the wrong
                // value a `stat` observes. (It does NOT change `find`'s
                // descent: this findutils treats a FUSE mount as
                // un-optimizable and descends regardless of nlink — see
                // row 7's tests.)
                Some(Fault::UniformNlink2) if attr.kind == NodeKind::Dir => attr.nlink = 2,
                // A GrainId-keyed allocator: key `st_ino` on the leaf
                // node the entry was found in, so two byte-identical
                // files under different paths (which content-address to
                // the SAME leaf) collide. Restricted to non-directories:
                // giving two directory entries one inode would be a
                // directory hard link the kernel rejects, a different
                // failure than the st_ino collision this fault models.
                Some(Fault::InoByContent) if attr.kind != NodeKind::Dir => {
                    if let Ok(entry) = self.snapshot.lookup(&self.dir, name) {
                        attr.ino = ino_from_content(entry.leaf);
                    }
                }
                _ => {}
            }
        }

        // DtypeLie: the oracle's ZERO-NODEID form. A plain `attr.kind =
        // File` on a nonzero nodeid does NOT deliver the d_type lie to
        // getdents (verified in the container: the kernel served the
        // honest DT_DIR). Zeroing the nodeid too makes
        // `fuse_direntplus_link` return early — no inode instantiated,
        // no attr cached — so the lied dirent `d_type` reaches
        // userspace while a later honest `lstat` issues a fresh
        // `LOOKUP`. The honest ino it supersedes was already credited
        // by `list_dir_plus`; record it for repayment, but only when
        // the inner sink actually took the entry (`Added`) — on `Full`,
        // `list_dir_plus` repays that exact credit itself, so recording
        // here too would double-forget (`breakage.rs` rule ii).
        let dtype_original_ino =
            if !is_dot && self.fault == Some(Fault::DtypeLie) && attr.kind == NodeKind::Dir {
                let original = attr.ino;
                attr.kind = NodeKind::File;
                attr.ino = 0;
                Some(original)
            } else {
                None
            };

        let outcome = self.inner.offer(attr, name, next);
        if let (Some(original), SinkOutcome::Added) = (dtype_original_ino, outcome) {
            self.withheld.push(original);
        }
        outcome
    }
}

/// The sink for `ReferenceFs`'s own `readdirplus`, over the real
/// `fuser::ReplyDirectoryPlus` — the same shape as `filesystem.rs`'s
/// private `RealDirPlusSink`, without the `bend`/`Bent` machinery (this
/// adapter has no `conformance-breakage` concept at all).
struct RefDirPlusSink<'a> {
    reply: &'a mut ReplyDirectoryPlus,
    any_added: bool,
}

impl DirPlusSink for RefDirPlusSink<'_> {
    fn offer(&mut self, attr: Attr, name: &[u8], next: u64) -> SinkOutcome {
        let file_attr = to_fuse_attr(&attr);
        let full = self.reply.add(
            INodeNo(attr.ino),
            next,
            OsStr::from_bytes(name),
            &REF_TTL,
            &file_attr,
            Generation(attr.generation),
        );
        let outcome = if full {
            SinkOutcome::Full
        } else {
            SinkOutcome::Added
        };
        if outcome == SinkOutcome::Added {
            self.any_added = true;
        }
        outcome
    }
}

impl<B: MountBackend> ReferenceFs<B> {
    fn new(
        snapshot: Snapshot,
        backend: B,
        generation: u64,
        fault: Option<Fault>,
        obs: Arc<Obs>,
    ) -> Self {
        let inodes = InodeTable::new(
            snapshot.manifest_root(),
            generation,
            u64::from(INodeNo::ROOT),
        );
        Self {
            snapshot,
            inner: Mutex::new(Some(RefInner {
                backend,
                inodes,
                handles: HandleTable::new(),
            })),
            obs,
            fault,
            cursor_skip_fired: AtomicBool::new(false),
        }
    }

    fn with_inner<T>(
        &self,
        f: impl FnOnce(&mut RefInner<B>) -> Result<T, ReaderError>,
    ) -> Result<T, ReaderError> {
        let mut guard = self.inner.lock().map_err(|_| ReaderError::Inconsistent)?;
        let inner = guard.as_mut().ok_or(ReaderError::Inconsistent)?;
        f(inner)
    }

    fn resolve_own_entry(&self, inodes: &InodeTable, ino: u64) -> Result<Entry, ReaderError> {
        let (path, dir, _kind) = inodes.resolve(ino)?;
        if ino == inodes.root_ino() {
            return Ok(Entry {
                name: ref_inert_name()?,
                kind: EntryKind::Dir { child: dir },
                leaf: dir,
            });
        }
        let last = path.last().ok_or(ReaderError::Inconsistent)?;
        self.snapshot.lookup(&dir, last)
    }

    /// Rows 2 and 7's fault application point: EXACTLY `GranaryFs`'s own
    /// `lookup`/`getattr` shape (resolve via the real primitives, then
    /// transform one field), per the design brief.
    fn apply_attr_fault(&self, mut attr: Attr, leaf: GrainId) -> Attr {
        match self.fault {
            Some(Fault::UniformNlink2) if attr.kind == NodeKind::Dir => attr.nlink = 2,
            Some(Fault::InoByContent) if attr.kind != NodeKind::Dir => {
                attr.ino = ino_from_content(leaf);
            }
            // Non-root directories only: the root's kind is load-bearing
            // for the mount itself (see the variant's doc).
            Some(Fault::DirAsFile)
                if attr.kind == NodeKind::Dir && attr.ino != u64::from(INodeNo::ROOT) =>
            {
                attr.kind = NodeKind::File;
                attr.perm = 0o555;
            }
            _ => {}
        }
        attr
    }

    /// `Fault::WrongOverlongErrno`'s single rewrite: ONLY the name-length
    /// refusal's `ENAMETOOLONG` becomes `ENOENT`; a genuine miss and every
    /// other errno pass through unchanged.
    fn overlong_errno_if_armed(&self, refusal: fuser::Errno) -> fuser::Errno {
        if refusal == fuser::Errno::ENAMETOOLONG && self.fault == Some(Fault::WrongOverlongErrno) {
            fuser::Errno::ENOENT
        } else {
            refusal
        }
    }

    fn lookup_logic(&self, parent: u64, name: &[u8]) -> Result<Attr, fuser::Errno> {
        check_name_length(name).map_err(|refusal| self.overlong_errno_if_armed(refusal))?;
        self.with_inner(|inner| {
            let (dir, _parent_of_parent) = dir_and_parent(&inner.inodes, &self.snapshot, parent)?;
            let entry = self.snapshot.lookup(&dir, name)?;
            let node_kind = ref_node_kind_of(&self.snapshot, &entry)?;
            let (parent_path, _, _) = inner.inodes.resolve(parent)?;
            let mut child_path: PathKey = parent_path.clone();
            child_path.push(name.to_vec());
            let (ino, generation) = inner.inodes.lookup(child_path, dir, node_kind)?;
            let attr = self.snapshot.attr_for(&entry, ino, generation)?;
            Ok(self.apply_attr_fault(attr, entry.leaf))
        })
        .map_err(errno)
    }

    fn getattr_logic(&self, ino: u64) -> Result<Attr, fuser::Errno> {
        self.with_inner(|inner| {
            let entry = self.resolve_own_entry(&inner.inodes, ino)?;
            let attr = self
                .snapshot
                .attr_for(&entry, ino, inner.inodes.generation())?;
            Ok(self.apply_attr_fault(attr, entry.leaf))
        })
        .map_err(errno)
    }

    fn read_logic(&self, ino: u64, offset: u64, size: u32) -> Result<Vec<u8>, fuser::Errno> {
        self.with_inner(|inner| {
            let entry = self.resolve_own_entry(&inner.inodes, ino)?;
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
            let covers_final_byte = offset.saturating_add(u64::from(size)) >= declared_size;
            Ok(self.truncate_if_armed(bytes, covers_final_byte))
        })
        .map_err(errno)
    }

    fn truncate_if_armed(&self, mut bytes: Vec<u8>, covers_final_byte: bool) -> Vec<u8> {
        if covers_final_byte && self.fault == Some(Fault::ShortRead) {
            bytes.pop();
        }
        bytes
    }

    fn readdirplus_dispatch<S: DirPlusSink>(
        &self,
        inner: &mut RefInner<B>,
        ino: u64,
        offset: u64,
        sink: &mut S,
    ) -> Result<(), ReaderError> {
        // Resolve the directory node first (immutable borrow ends before
        // the mutable one `list_dir_plus` needs); `dir` is `Copy`.
        let (dir, _parent) = dir_and_parent(&inner.inodes, &self.snapshot, ino)?;
        let armed = self.fault == Some(Fault::CursorSkip)
            && offset > 0
            && !self.cursor_skip_fired.load(Ordering::SeqCst);
        let mut wrapped = FaultDirPlusSink {
            inner: sink,
            fault: self.fault,
            snapshot: &self.snapshot,
            dir,
            skip_armed: armed,
            withheld: Vec::new(),
        };
        let result = list_dir_plus(&mut inner.inodes, &self.snapshot, ino, offset, &mut wrapped);
        let cursor_dropped = armed && !wrapped.skip_armed;
        let withheld = std::mem::take(&mut wrapped.withheld);
        for repaid in withheld {
            inner.inodes.forget(repaid, 1);
        }
        if cursor_dropped {
            self.cursor_skip_fired.store(true, Ordering::SeqCst);
        }
        result
    }

    /// Publishes the inode table's current size into `obs.state`, the
    /// same mechanism `Observed::publish_resident` uses. `ReferenceFs`
    /// is never wrapped by `Observed` (it manages `obs` directly), so
    /// row 4's negative/None-control need this call themselves, both
    /// after `readdirplus` (growth, the baseline high-water mark) and
    /// after `forget` (shrink, or its absence under `NeverReclaim`).
    fn publish_resident(&self) {
        if let Ok(resident) = self.with_inner(|inner| Ok(inner.inodes.resident_count())) {
            let mut state = self.obs.lock();
            state.resident = resident;
            state.seq = state.seq.wrapping_add(1);
            self.obs.cv.notify_all();
        }
    }
}

impl<B: MountBackend> Filesystem for ReferenceFs<B> {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        let wanted = crate::negotiate(config.capabilities()).map_err(|missing| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("kernel does not offer the requested capabilities {missing:?}"),
            )
        })?;
        config.add_capabilities(wanted).map_err(|missing| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("kernel refused a capability it advertised ({missing:?})"),
            )
        })
    }

    fn destroy(&mut self) {
        if let Ok(mut guard) = self.inner.lock()
            && let Some(mut inner) = guard.take()
        {
            let _ = inner.backend.shutdown();
        }
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        self.obs.lock().count_lookup(name.as_bytes());
        match self.lookup_logic(u64::from(parent), name.as_bytes()) {
            Ok(attr) => reply.entry(&REF_TTL, &to_fuse_attr(&attr), Generation(attr.generation)),
            Err(e) => reply.error(e),
        }
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.obs.count(Op::Forget);
        let _ = self.with_inner(|inner| {
            if self.fault != Some(Fault::NeverReclaim) {
                inner.inodes.forget(u64::from(ino), nlookup);
            }
            Ok(())
        });
        self.publish_resident();
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        self.obs.count(Op::Getattr);
        match self.getattr_logic(u64::from(ino)) {
            Ok(attr) => reply.attr(&REF_TTL, &to_fuse_attr(&attr)),
            Err(e) => reply.error(e),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        self.obs.count(Op::Open);
        if flags.acc_mode() != OpenAccMode::O_RDONLY {
            reply.error(fuser::Errno::EACCES);
            return;
        }
        match self.with_inner(|inner| {
            inner.inodes.open(u64::from(ino))?;
            inner.handles.open(u64::from(ino), HandleKind::File)
        }) {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        self.obs.lock().record_read(offset, size);
        match self.read_logic(u64::from(ino), offset, size) {
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
        self.obs.count(Op::Release);
        let _ = self.with_inner(|inner| {
            if let Some(released) = inner.handles.release(u64::from(fh), HandleKind::File) {
                inner.inodes.release(released);
            }
            Ok(())
        });
        reply.ok();
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        self.obs.count(Op::Opendir);
        match self.with_inner(|inner| {
            inner.inodes.open(u64::from(ino))?;
            inner.handles.open(u64::from(ino), HandleKind::Directory)
        }) {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        self.obs.count(Op::Readdirplus);
        let mut sink = RefDirPlusSink {
            reply: &mut reply,
            any_added: false,
        };
        let outcome = self.with_inner(|inner| {
            self.readdirplus_dispatch(inner, u64::from(ino), offset, &mut sink)
        });
        let any_added = sink.any_added;
        match outcome {
            Ok(()) => reply.ok(),
            Err(e) => {
                if any_added {
                    reply.ok();
                } else {
                    reply.error(errno(e));
                }
            }
        }
        self.publish_resident();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.obs.count(Op::Releasedir);
        let _ = self.with_inner(|inner| {
            if let Some(released) = inner.handles.release(u64::from(fh), HandleKind::Directory) {
                inner.inodes.release(released);
            }
            Ok(())
        });
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        self.obs.count(Op::Statfs);
        let namelen = if self.fault == Some(Fault::WrongNamelen) {
            254
        } else {
            255
        };
        let (blocks, bfree, bavail, files, ffree, bsize, namelen, frsize) =
            ref_statfs_tuple(self.snapshot.stats(), namelen);
        reply.statfs(blocks, bfree, bavail, files, ffree, bsize, namelen, frsize);
    }
}

// =====================================================================
// Fixture helpers
// =====================================================================

fn ts() -> Timestamp {
    Timestamp { secs: 1, nanos: 2 }
}

fn policy() -> AttrPolicy {
    AttrPolicy { uid: 0, gid: 0 }
}

fn file_entry_empty(name: &[u8]) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::File {
            exec: false,
            size: 0,
            grains: FileGrains::Inline(Vec::new()),
        },
    }
}

fn dir_entry(name: &[u8], child: GrainId) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::Dir { child },
    }
}

fn symlink_entry(name: &[u8], target: &[u8]) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::Symlink {
            target: SymlinkTarget::new(target.to_vec()).expect("fixture target is valid"),
        },
    }
}

fn build_snapshot(nodes: BTreeMap<GrainId, Vec<u8>>, root: GrainId) -> Snapshot {
    Snapshot::new(
        nodes,
        root,
        ts(),
        TreeStats::default(),
        policy(),
        FUSE_SERVE_LIMITS,
    )
    .expect("fixture snapshot indexes")
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

// =====================================================================
// Row 1 — READDIRPLUS actually arrives (the milestone's canonical
// fail-open)
// =====================================================================

fn row1_fixture() -> (Snapshot, BTreeSet<Vec<u8>>) {
    let names: Vec<Vec<u8>> = (0..6_u32)
        .map(|i| format!("child{i}").into_bytes())
        .collect();
    let entries: Vec<DirEntry> = names.iter().map(|n| file_entry_empty(n)).collect();
    let tree = build_dir(&entries).expect("row1 root builds");
    (
        build_snapshot(tree.nodes.into_iter().collect(), tree.root),
        names.into_iter().collect(),
    )
}

/// `ls -l`'s own semantic, driven directly through `std::fs` rather than
/// shelling out: `read_dir` (opendir + readdirplus) then `.metadata()`
/// (the per-child stat) on every entry. Fewer incidental syscalls than a
/// real `ls` binary (no color/xattr probing), which keeps the counters
/// this row asserts on free of a false positive from `ls`'s own extras.
fn ls_l_like(mountpoint: &Path) -> BTreeSet<Vec<u8>> {
    let mut names = BTreeSet::new();
    for entry in std::fs::read_dir(mountpoint).expect("read_dir the mount") {
        let entry = entry.expect("read one dirent");
        let _ = entry
            .metadata()
            .expect("stat each child (the ls -l semantic)");
        names.insert(entry.file_name().into_vec());
    }
    names
}

#[test]
fn row1_readdirplus_arrives_positive() {
    if !require_root("row1_readdirplus_arrives_positive") {
        return;
    }
    let (snapshot, expected_children) = row1_fixture();
    let obs = Arc::new(Obs::new());
    let fs = Observed {
        inner: GranaryFs::new(
            snapshot,
            InMemBackend::default(),
            1,
            crate::MountWritability::ReadOnly,
        )
        .expect("fixture snapshot admits the adapter bound"),
        obs: Arc::clone(&obs),
        negotiate: true,
        expected_children: expected_children.clone(),
    };
    let (mountpoint, _guard) = spawn_guarded("row1-pos", fs, crate::session_config(false));

    let seen = ls_l_like(&mountpoint);
    assert_eq!(
        seen, expected_children,
        "the mount must list exactly the fixture's children"
    );

    let state = obs.lock();
    assert!(
        state.op_count(Op::Readdirplus) > 0,
        "a READDIRPLUS must have arrived at the daemon"
    );
    assert_eq!(
        state.op_count(Op::Readdir),
        0,
        "plain READDIR must never fire under this mount's negotiation"
    );
    assert_eq!(
        state.lookup_child, 0,
        "readdirplus must fill the kernel's attr cache -- no per-child LOOKUP should follow"
    );
    assert_eq!(
        state.getattr_nonroot, 0,
        "readdirplus must fill the kernel's attr cache -- no per-child GETATTR should follow"
    );
}

/// Row 1's IN-SUITE negative. A SECOND negative requires
/// building `GranaryFs::init` (`filesystem.rs`) with its
/// `config.add_capabilities` tail replaced by `Ok(())`, whose mount would
/// come up WITHOUT readdirplus; only the positive
/// row above, run against it, would go red -- not something this committed test can
/// also assert without mutating shipped code -- NOTHING in this tree
/// runs it; see the `eprintln!` below for the same note at
/// runtime.
#[test]
fn row1_readdirplus_arrives_negative_no_negotiation() {
    if !require_root("row1_readdirplus_arrives_negative_no_negotiation") {
        return;
    }
    let (snapshot, expected_children) = row1_fixture();
    let obs = Arc::new(Obs::new());
    let fs = Observed {
        inner: GranaryFs::new(
            snapshot,
            InMemBackend::default(),
            1,
            crate::MountWritability::ReadOnly,
        )
        .expect("fixture snapshot admits the adapter bound"),
        obs: Arc::clone(&obs),
        negotiate: false,
        expected_children: expected_children.clone(),
    };
    let (mountpoint, _guard) = spawn_guarded("row1-neg", fs, crate::session_config(false));

    let seen = ls_l_like(&mountpoint);
    assert_eq!(
        seen, expected_children,
        "correctness must survive the degrade -- only its efficiency/observability changes"
    );

    let state = obs.lock();
    assert_eq!(
        state.op_count(Op::Readdirplus),
        0,
        "without negotiation, READDIRPLUS must never arrive"
    );
    // The degrade signal is qualitative — per-child daemon traffic where
    // readdirplus produced NONE (the positive asserts both are 0). A `> 0`
    // check, not an exact `== n`: the exact per-child count is a kernel
    // detail (a dcache revalidation can add a LOOKUP, coalescing can drop
    // one), and pinning it would make this row flake across kernels while
    // adding nothing — the property is "the mount fell back to per-child
    // probing", which any nonzero count shows.
    assert!(
        state.lookup_child > 0 || state.getattr_nonroot > 0,
        "the degrade signal must fire: some per-child LOOKUP or GETATTR must reach the daemon \
         when readdirplus is not negotiated, got lookup_child={} getattr_nonroot={}",
        state.lookup_child,
        state.getattr_nonroot
    );
    drop(state);
    eprintln!(
        "row1 negative note: the OTHER negative control -- a build of GranaryFs::init \
         (filesystem.rs) with its `config.add_capabilities` tail replaced by Ok(()), whose mount \
         would come up without readdirplus -- is NOT run by this suite or any script; this \
         in-suite `negotiate: false` mount is the committed form of the same fail-open."
    );
}

// =====================================================================
// Row 2 — inode distinctness across content-merged directories
// =====================================================================

fn row2_snapshot() -> Snapshot {
    let leaf = build_dir(&[file_entry_empty(b"x")]).expect("row2 leaf builds");
    // `one` and `two` reference the SAME child GrainId, so their own
    // directory content (and thus their own GrainId) is byte-identical.
    let entries = [dir_entry(b"one", leaf.root), dir_entry(b"two", leaf.root)];
    let dup = build_dir(&entries).expect("row2 dup builds");
    let root_entries = [dir_entry(b"dup", dup.root)];
    let root_tree = build_dir(&root_entries).expect("row2 root builds");
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = leaf.nodes.into_iter().collect();
    nodes.extend(dup.nodes);
    nodes.extend(root_tree.nodes);
    build_snapshot(nodes, root_tree.root)
}

fn row2_stat_both(mountpoint: &Path) -> (u64, u64) {
    let one = std::fs::metadata(mountpoint.join("dup").join("one").join("x"))
        .expect("stat dup/one/x")
        .ino();
    let two = std::fs::metadata(mountpoint.join("dup").join("two").join("x"))
        .expect("stat dup/two/x")
        .ino();
    (one, two)
}

#[test]
fn row2_inode_distinctness_positive() {
    if !require_root("row2_inode_distinctness_positive") {
        return;
    }
    let fs = GranaryFs::new(
        row2_snapshot(),
        InMemBackend::default(),
        1,
        crate::MountWritability::ReadOnly,
    )
    .expect("fixture snapshot admits the adapter bound");
    let (mountpoint, _guard) = spawn_guarded("row2-pos", fs, crate::session_config(false));
    let (one, two) = row2_stat_both(&mountpoint);
    assert_ne!(
        one, two,
        "content-identical subtrees must not collide on st_ino"
    );
}

#[test]
fn row2_inode_distinctness_negative_ino_by_content() {
    if !require_root("row2_inode_distinctness_negative_ino_by_content") {
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(
        row2_snapshot(),
        InMemBackend::default(),
        1,
        Some(Fault::InoByContent),
        obs,
    );
    let (mountpoint, _guard) = spawn_guarded("row2-neg", fs, crate::session_config(false));
    let (one, two) = row2_stat_both(&mountpoint);
    assert_eq!(
        one, two,
        "Fault::InoByContent must make content-identical subtrees collide -- the allocator bug \
         row 2 exists to kill"
    );
}

#[test]
fn row2_inode_distinctness_none_control() {
    if !require_root("row2_inode_distinctness_none_control") {
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(row2_snapshot(), InMemBackend::default(), 1, None, obs);
    let (mountpoint, _guard) = spawn_guarded("row2-none", fs, crate::session_config(false));
    let (one, two) = row2_stat_both(&mountpoint);
    assert_ne!(
        one, two,
        "ReferenceFs{{fault: None}} must behave identically to GranaryFs for this row's assertion"
    );
}

// =====================================================================
// Row 3 — multi-call readdir cookies
// =====================================================================

const ROW3_COUNT: u32 = 300;
const ROW3_CAPTURE_AT: usize = 150;

fn row3_fixture() -> Snapshot {
    let entries: Vec<DirEntry> = (0..ROW3_COUNT)
        .map(|i| file_entry_empty(format!("f{i:04}").as_bytes()))
        .collect();
    let tree = build_dir(&entries).expect("row3 300-entry root builds");
    build_snapshot(tree.nodes.into_iter().collect(), tree.root)
}

fn row3_expected_names() -> Vec<Vec<u8>> {
    let mut names = vec![b".".to_vec(), b"..".to_vec()];
    names.extend((0..ROW3_COUNT).map(|i| format!("f{i:04}").into_bytes()));
    names
}

/// Reads `dir` with a SMALL (256-byte) `getdents64` buffer, which forces
/// `rustix::fs::RawDir` to issue several refills internally. Also
/// captures the `next_entry_cookie()` right after entry index
/// `capture_at`, for the seek/replay half of row 3.
fn sweep_dir_small_buffer(dir: &Path, capture_at: usize) -> (Vec<Vec<u8>>, u64) {
    let file = std::fs::File::open(dir).expect("open directory for RawDir sweep");
    let mut buf = [MaybeUninit::uninit(); 256];
    let mut iter = rustix::fs::RawDir::new(file.as_fd(), &mut buf);
    let mut names = Vec::new();
    let mut mid_cookie = None;
    let mut index = 0_usize;
    while let Some(entry) = iter.next() {
        let entry = entry.expect("dirent decodes without error");
        names.push(entry.file_name().to_bytes().to_vec());
        if index == capture_at {
            mid_cookie = Some(entry.next_entry_cookie());
        }
        index += 1;
    }
    (
        names,
        mid_cookie.expect("fixture must have more than `capture_at` entries"),
    )
}

fn assert_full_row3_listing(names: &[Vec<u8>]) {
    let expected = row3_expected_names();
    assert_eq!(
        names.len(),
        expected.len(),
        "expected . + .. + {ROW3_COUNT} files"
    );
    let mut seen = BTreeSet::new();
    for name in names {
        assert!(seen.insert(name.clone()), "duplicate dirent {name:?}");
    }
    assert_eq!(
        names,
        expected.as_slice(),
        "entries must appear in order, exactly once"
    );
}

#[test]
fn row3_multi_call_readdir_cookies_positive() {
    if !require_root("row3_multi_call_readdir_cookies_positive") {
        return;
    }
    let fs = GranaryFs::new(
        row3_fixture(),
        InMemBackend::default(),
        1,
        crate::MountWritability::ReadOnly,
    )
    .expect("fixture snapshot admits the adapter bound");
    let (mountpoint, _guard) = spawn_guarded("row3-pos", fs, crate::session_config(false));

    let (names, cookie) = sweep_dir_small_buffer(&mountpoint, ROW3_CAPTURE_AT);
    assert_full_row3_listing(&names);

    let tail_file =
        std::fs::File::open(&mountpoint).expect("reopen root dir for the cookie replay");
    rustix::fs::seek(tail_file.as_fd(), rustix::fs::SeekFrom::Start(cookie))
        .expect("seek to the recorded cookie");
    let mut buf2 = [MaybeUninit::uninit(); 256];
    let mut iter2 = rustix::fs::RawDir::new(tail_file.as_fd(), &mut buf2);
    let mut tail = Vec::new();
    while let Some(entry) = iter2.next() {
        tail.push(
            entry
                .expect("dirent decodes")
                .file_name()
                .to_bytes()
                .to_vec(),
        );
    }
    assert_eq!(
        tail,
        names[(ROW3_CAPTURE_AT + 1)..],
        "replay from the recorded cookie must match the original tail exactly"
    );
}

#[test]
fn row3_multi_call_readdir_cookies_negative_cursor_skip() {
    if !require_root("row3_multi_call_readdir_cookies_negative_cursor_skip") {
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(
        row3_fixture(),
        InMemBackend::default(),
        1,
        Some(Fault::CursorSkip),
        obs,
    );
    let (mountpoint, _guard) = spawn_guarded("row3-neg", fs, crate::session_config(false));

    let (names, _cookie) = sweep_dir_small_buffer(&mountpoint, ROW3_CAPTURE_AT);
    let expected_len = row3_expected_names().len();
    assert_eq!(
        names.len(),
        expected_len - 1,
        "Fault::CursorSkip must drop exactly one entry from the full listing, got {} entries",
        names.len()
    );
    let mut seen = BTreeSet::new();
    for name in &names {
        assert!(
            seen.insert(name.clone()),
            "duplicate dirent {name:?} -- CursorSkip's negative must be a MISS, not a duplicate"
        );
    }
}

#[test]
fn row3_multi_call_readdir_cookies_none_control() {
    if !require_root("row3_multi_call_readdir_cookies_none_control") {
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(row3_fixture(), InMemBackend::default(), 1, None, obs);
    let (mountpoint, _guard) = spawn_guarded("row3-none", fs, crate::session_config(false));
    let (names, _cookie) = sweep_dir_small_buffer(&mountpoint, ROW3_CAPTURE_AT);
    assert_full_row3_listing(&names);
}

// =====================================================================
// Row 4 — forget accounting
// =====================================================================

const ROW4_DIRS: u32 = 4;
const ROW4_FILES_PER_DIR: u32 = 100;
const ROW4_TOTAL_FILES: usize = (ROW4_DIRS * ROW4_FILES_PER_DIR) as usize;

fn row4_fixture() -> Snapshot {
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let mut dir_entries = Vec::new();
    for d in 0..ROW4_DIRS {
        let files: Vec<DirEntry> = (0..ROW4_FILES_PER_DIR)
            .map(|f| file_entry_empty(format!("f{f:03}").as_bytes()))
            .collect();
        let sub = build_dir(&files).expect("row4 subdir builds");
        nodes.extend(sub.nodes);
        dir_entries.push(dir_entry(format!("d{d}").as_bytes(), sub.root));
    }
    let root_tree = build_dir(&dir_entries).expect("row4 root builds");
    nodes.extend(root_tree.nodes);
    build_snapshot(nodes, root_tree.root)
}

fn walk_tree_forcing_lookups(dir: &Path) {
    for entry in std::fs::read_dir(dir).expect("read_dir while walking the fixture") {
        let entry = entry.expect("read one dirent while walking");
        let path = entry.path();
        let file_type = entry.file_type().expect("dirent file_type");
        if file_type.is_dir() {
            walk_tree_forcing_lookups(&path);
        } else {
            let mut file = std::fs::File::open(&path).expect("open a fixture file");
            let mut buf = [0_u8; 1];
            let _ = std::io::Read::read(&mut file, &mut buf);
        }
    }
}

const CGROUP_MEMORY_MAX: &str = "/sys/fs/cgroup/memory.max";
const CGROUP_MEMORY_HIGH: &str = "/sys/fs/cgroup/memory.high";
const CGROUP_MEMORY_RECLAIM: &str = "/sys/fs/cgroup/memory.reclaim";

/// Reads the cgroup's own memory ceiling so the reclaim provocation
/// below writes a value LARGE enough to reach the slab shrinker rather
/// than only evicting LRU page cache — a small write can leave the
/// dentry/inode slab untouched (observed once; no test here pins it).
/// `None` when `memory.max` is unreadable or the literal `max`: with no
/// ceiling there is no BOUNDED amount to derive, and the caller refuses
/// rather than fabricating one. A fixed fallback written to
/// `memory.reclaim` up to `ROUNDS` times is not scoped to this test — it
/// lands on whatever cgroup the lane's process sits in (the bare-VM
/// lane's sudo session scope, where `memory.max` reads `max`), so an
/// unbounded environment is a skip, never a guess.
fn cgroup_reclaim_amount() -> Option<String> {
    let raw = std::fs::read_to_string(CGROUP_MEMORY_MAX).ok()?;
    let ceiling = raw.trim();
    ceiling.parse::<u64>().ok().map(|_| ceiling.to_owned())
}

/// Restores the cgroup's `memory.high` when dropped, so the transient
/// throttle `provoke_reclaim` applies cannot outlive it on ANY exit —
/// a return mid-loop or a panic mid-round included. The original value
/// is captured at construction; one that could not be read is restored
/// as `max`, cgroup v2's default. Best-effort and never panics: `Drop`
/// runs during a failed row's unwind too, and a panic there would abort
/// the process and lose the row's own message.
struct HighRestore {
    orig: Option<String>,
}

impl HighRestore {
    fn capture() -> Self {
        Self {
            orig: std::fs::read_to_string(CGROUP_MEMORY_HIGH)
                .ok()
                .map(|s| s.trim().to_owned()),
        }
    }

    fn restore(&self) {
        // Only restore what was actually captured. If the original
        // `memory.high` could not be read, leave the knob UNTOUCHED rather
        // than writing a guessed `max`: an environment that had deliberately
        // set a finite soft limit must not have it silently removed. The
        // provocation loop below refuses to LOWER the knob in that case too,
        // so nothing is left un-restored.
        if let Some(orig) = &self.orig {
            let _ = std::fs::write(CGROUP_MEMORY_HIGH, orig.as_bytes());
        }
    }
}

impl Drop for HighRestore {
    fn drop(&mut self) {
        self.restore();
    }
}

enum ReclaimOutcome {
    ForgetsArrived,
    DaemonDead,
    /// The whole bound expired with the daemon alive and no FORGET: this
    /// environment's reclaim did not evict the mount's dentries.
    EnvSkip,
    /// `memory.max` is unset or `max`, so no bounded reclaim amount can
    /// be derived; NOTHING was written to either cgroup knob.
    NoBudget,
}

/// The bounded provocation loop: write to `/sys/fs/cgroup/memory.reclaim`
/// (forcing per-cgroup reclaim, which runs the slab shrinker and can
/// evict unreferenced FUSE dentries/inodes), then wait a short slice for
/// `forget_calls` to move. Up to `ROUNDS * ROUND_WAIT` (~20s) overall,
/// well under nextest's ~60s terminate-after for this package. On EVERY
/// round's expiry, daemon liveness is checked BEFORE looping again, so a
/// crashed daemon is reported immediately rather than after the full
/// bound — a silent wait must never mask a crash. Without a bounded
/// amount (see [`cgroup_reclaim_amount`]) it returns [`ReclaimOutcome::NoBudget`]
/// before touching the cgroup at all.
fn provoke_reclaim(obs: &Obs, alive: impl Fn() -> bool) -> ReclaimOutcome {
    const ROUNDS: u32 = 10;
    const ROUND_WAIT: Duration = Duration::from_secs(2);
    // No ceiling, no write: the refusal comes BEFORE either knob is touched.
    let Some(amount) = cgroup_reclaim_amount() else {
        return ReclaimOutcome::NoBudget;
    };
    // `memory.high` THROTTLES rather than OOM-kills, so lowering it
    // transiently is safe even though the test process shares this
    // cgroup. Both this and `memory.reclaim` are attempted because a
    // low-usage cgroup can leave the dentry/inode slab untouched under
    // either alone. The guard's `Drop` restores the original soft limit
    // on every exit from this function; each round ALSO restores it
    // explicitly, so the throttle is transient within the loop and not
    // only at its end.
    let high = HighRestore::capture();
    for _ in 0..ROUNDS {
        // Lower the soft limit only when the original was captured, so a
        // knob we cannot restore is never left throttled (see `restore`).
        if high.orig.is_some() {
            let _ = std::fs::write(CGROUP_MEMORY_HIGH, b"16777216");
        }
        let _ = std::fs::write(CGROUP_MEMORY_RECLAIM, amount.as_bytes());
        let state = obs.lock();
        let (state, _timeout) = obs
            .cv
            .wait_timeout_while(state, ROUND_WAIT, |s| s.op_count(Op::Forget) == 0)
            .unwrap_or_else(PoisonError::into_inner);
        let arrived = state.op_count(Op::Forget) > 0;
        drop(state);
        high.restore();
        if arrived {
            return ReclaimOutcome::ForgetsArrived;
        }
        if !alive() {
            return ReclaimOutcome::DaemonDead;
        }
    }
    if alive() {
        ReclaimOutcome::EnvSkip
    } else {
        ReclaimOutcome::DaemonDead
    }
}

#[test]
fn row4_forget_accounting_positive() {
    if !require_root("row4_forget_accounting_positive") {
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = Observed {
        inner: GranaryFs::new(
            row4_fixture(),
            InMemBackend::default(),
            1,
            crate::MountWritability::ReadOnly,
        )
        .expect("fixture snapshot admits the adapter bound"),
        obs: Arc::clone(&obs),
        negotiate: true,
        expected_children: BTreeSet::new(),
    };
    let (mountpoint, guard) = spawn_guarded("row4-pos", fs, crate::session_config(false));

    walk_tree_forcing_lookups(&mountpoint);
    let baseline = obs.lock().resident;
    assert!(
        baseline > ROW4_TOTAL_FILES,
        "the walk must grow the inode table past the fixture's {ROW4_TOTAL_FILES} files, got \
         {baseline}"
    );

    match provoke_reclaim(&obs, || guard.daemon_alive()) {
        ReclaimOutcome::ForgetsArrived => {}
        ReclaimOutcome::DaemonDead => {
            panic!("the daemon crashed under memory pressure -- a real failure, not an env-skip")
        }
        ReclaimOutcome::EnvSkip => {
            eprintln!(
                "SKIPPED-ENV row4_forget_accounting_positive: memory.reclaim ran for the whole \
                 bound and produced no FORGET while the daemon stayed alive -- this environment's \
                 reclaim did not evict this mount's dentries"
            );
            return;
        }
        ReclaimOutcome::NoBudget => {
            eprintln!(
                "SKIPPED-ENV row4_forget_accounting_positive: memory.max is unset/max, so a \
                 bounded reclaim amount cannot be derived -- refusing to write a fabricated 8 GiB \
                 to memory.reclaim"
            );
            return;
        }
    }

    let resident_after = obs.lock().resident;
    assert!(
        resident_after < baseline,
        "the inode table must shrink after FORGETs arrive: baseline={baseline} \
         after={resident_after}"
    );
}

#[test]
fn row4_forget_accounting_negative_never_reclaim() {
    if !require_root("row4_forget_accounting_negative_never_reclaim") {
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(
        row4_fixture(),
        InMemBackend::default(),
        1,
        Some(Fault::NeverReclaim),
        Arc::clone(&obs),
    );
    let (mountpoint, guard) = spawn_guarded("row4-neg", fs, crate::session_config(false));

    walk_tree_forcing_lookups(&mountpoint);
    let baseline = obs.lock().resident;
    assert!(
        baseline > ROW4_TOTAL_FILES,
        "the walk must grow the table, got {baseline}"
    );

    match provoke_reclaim(&obs, || guard.daemon_alive()) {
        ReclaimOutcome::ForgetsArrived => {}
        ReclaimOutcome::DaemonDead => panic!("the daemon crashed under memory pressure"),
        ReclaimOutcome::EnvSkip => {
            eprintln!(
                "SKIPPED-ENV row4_forget_accounting_negative_never_reclaim: memory.reclaim never \
                 produced a FORGET while the daemon stayed alive"
            );
            return;
        }
        ReclaimOutcome::NoBudget => {
            eprintln!(
                "SKIPPED-ENV row4_forget_accounting_negative_never_reclaim: memory.max is \
                 unset/max, so a bounded reclaim amount cannot be derived -- refusing to write a \
                 fabricated 8 GiB to memory.reclaim"
            );
            return;
        }
    }

    let (forget_calls, resident_after) = {
        let state = obs.lock();
        (state.op_count(Op::Forget), state.resident)
    };
    assert!(forget_calls > 0, "forgets must have arrived at the daemon");
    assert!(
        resident_after >= baseline,
        "Fault::NeverReclaim must keep the table from shrinking: baseline={baseline} \
         after={resident_after}"
    );
}

#[test]
fn row4_forget_accounting_none_control() {
    if !require_root("row4_forget_accounting_none_control") {
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(
        row4_fixture(),
        InMemBackend::default(),
        1,
        None,
        Arc::clone(&obs),
    );
    let (mountpoint, guard) = spawn_guarded("row4-none", fs, crate::session_config(false));

    walk_tree_forcing_lookups(&mountpoint);
    let baseline = obs.lock().resident;
    assert!(
        baseline > ROW4_TOTAL_FILES,
        "the walk must grow the table, got {baseline}"
    );

    match provoke_reclaim(&obs, || guard.daemon_alive()) {
        ReclaimOutcome::ForgetsArrived => {}
        ReclaimOutcome::DaemonDead => panic!("the daemon crashed under memory pressure"),
        ReclaimOutcome::EnvSkip => {
            eprintln!(
                "SKIPPED-ENV row4_forget_accounting_none_control: memory.reclaim never produced a \
                 FORGET while the daemon stayed alive"
            );
            return;
        }
        ReclaimOutcome::NoBudget => {
            eprintln!(
                "SKIPPED-ENV row4_forget_accounting_none_control: memory.max is unset/max, so a \
                 bounded reclaim amount cannot be derived -- refusing to write a fabricated 8 GiB \
                 to memory.reclaim"
            );
            return;
        }
    }

    let resident_after = obs.lock().resident;
    assert!(
        resident_after < baseline,
        "ReferenceFs{{fault: None}} must reclaim just like GranaryFs: baseline={baseline} \
         after={resident_after}"
    );
}

// =====================================================================
// Row 5 — pread at/past EOF and across a grain boundary
// =====================================================================

/// K+1 grains (`FILE_INLINE_MAX_REFS + 1`, the smallest legal
/// `FileGrains::Spill`), each 4 real content bytes, built via
/// `build_grain_list` -- the same primitive `granary-vfs`'s `read/tests.rs`'s
/// own `read_spanning_too_many_grains_is_refused` fixture uses.
fn row5_fixture() -> (Snapshot, InMemBackend, u64) {
    let per_grain = 4_usize;
    let grain_count =
        usize::try_from(granary_core::manifest::FILE_INLINE_MAX_REFS).expect("fits") + 1;
    let total = per_grain * grain_count;
    let content: Vec<u8> = (0..total)
        .map(|i| u8::try_from(i % 256).expect("fits"))
        .collect();

    let mut backend = InMemBackend::default();
    let mut refs = Vec::with_capacity(grain_count);
    for chunk in content.chunks(per_grain) {
        let id = GrainId::of(chunk);
        refs.push(GrainRef {
            id,
            unpacked_len: u32::try_from(chunk.len()).expect("fits"),
        });
        backend.grains.insert(id, chunk.to_vec());
    }
    let built = build_grain_list(&refs).expect("K+1 grains build a spill list");

    let file_entry = DirEntry {
        name: Name::new(b"spill".to_vec()).expect("valid name"),
        kind: EntryKind::File {
            exec: false,
            size: u64::try_from(total).expect("fits"),
            grains: FileGrains::Spill {
                grain_count: u32::try_from(grain_count).expect("fits"),
                root: built.root,
            },
        },
    };
    let dir_tree = build_dir(&[file_entry]).expect("row5 root builds");
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = dir_tree.nodes.into_iter().collect();
    nodes.extend(built.nodes);
    (
        build_snapshot(nodes, dir_tree.root),
        backend,
        u64::try_from(total).expect("fits"),
    )
}

fn row5_expected(total: u64) -> Vec<u8> {
    (0..total)
        .map(|i| u8::try_from(i % 256).expect("fits"))
        .collect()
}

#[test]
fn row5_pread_boundary_and_eof_positive() {
    if !require_root("row5_pread_boundary_and_eof_positive") {
        return;
    }
    let (snapshot, backend, total) = row5_fixture();
    let fs = GranaryFs::new(snapshot, backend, 1, crate::MountWritability::ReadOnly)
        .expect("fixture snapshot admits the adapter bound");
    let (mountpoint, _guard) = spawn_guarded("row5-pos", fs, crate::session_config(false));
    let file = std::fs::File::open(mountpoint.join("spill")).expect("open the spill file");
    let expected = row5_expected(total);

    // A read spanning a grain boundary (grains are 4 bytes: offset 2,
    // length 8 spans grains 0, 1 and 2).
    let mut boundary = vec![0_u8; 8];
    file.read_exact_at(&mut boundary, 2).expect("boundary read");
    assert_eq!(boundary, expected[2..10]);

    // Exactly the remainder at EOF.
    let mut tail = vec![0_u8; 10];
    let n = file.read_at(&mut tail, total - 5).expect("read at EOF");
    assert_eq!(n, 5);
    assert_eq!(
        &tail[..5],
        &expected[usize::try_from(total - 5).expect("total fits usize")..]
    );

    // Past EOF: zero bytes, no error.
    let mut past = vec![0_u8; 4];
    let n2 = file.read_at(&mut past, total + 10).expect("read past EOF");
    assert_eq!(n2, 0);
}

#[test]
fn row5_pread_boundary_and_eof_negative_short_read() {
    if !require_root("row5_pread_boundary_and_eof_negative_short_read") {
        return;
    }
    let (snapshot, backend, total) = row5_fixture();
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(snapshot, backend, 1, Some(Fault::ShortRead), obs);
    let (mountpoint, _guard) = spawn_guarded("row5-neg", fs, crate::session_config(false));
    let file = std::fs::File::open(mountpoint.join("spill")).expect("open the spill file");
    let expected = row5_expected(total);

    // A read that does NOT cover the final byte is unaffected -- proves
    // the fault is precise (armed only when `covers_final_byte`), not a
    // blanket corruption of every read.
    let mut boundary = vec![0_u8; 8];
    file.read_exact_at(&mut boundary, 2).expect("boundary read");
    assert_eq!(boundary, expected[2..10]);

    // A read covering the final byte must come back WRONG. Deliberately
    // NOT asserting a specific byte count here: `open`'s
    // `FOPEN_KEEP_CACHE` reply means this pread() is served through the
    // kernel's ordinary page cache, not `direct_io`, and this suite
    // cannot observe (without a real mount to measure) whether the
    // kernel forwards the daemon's short reply as a short `pread()`
    // count, or folds it into a full-length read whose last byte reads
    // back as the page's zero-fill. Either shape IS the fault; asserting
    // one specific shape would risk a vacuous pass on a kernel that
    // produces the other.
    let mut tail = vec![0_u8; 10];
    let n = file
        .read_at(&mut tail, total - 5)
        .expect("read at EOF under ShortRead");
    let true_tail = &expected[usize::try_from(total - 5).expect("total fits usize")..];
    assert_ne!(
        &tail[..n],
        true_tail,
        "Fault::ShortRead must corrupt the read covering the file's final byte; got the true \
         tail back unchanged (n={n})"
    );
}

#[test]
fn row5_pread_boundary_and_eof_none_control() {
    if !require_root("row5_pread_boundary_and_eof_none_control") {
        return;
    }
    let (snapshot, backend, total) = row5_fixture();
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(snapshot, backend, 1, None, obs);
    let (mountpoint, _guard) = spawn_guarded("row5-none", fs, crate::session_config(false));
    let file = std::fs::File::open(mountpoint.join("spill")).expect("open the spill file");
    let expected = row5_expected(total);

    let mut boundary = vec![0_u8; 8];
    file.read_exact_at(&mut boundary, 2).expect("boundary read");
    assert_eq!(boundary, expected[2..10]);

    let mut tail = vec![0_u8; 10];
    let n = file.read_at(&mut tail, total - 5).expect("read at EOF");
    assert_eq!(
        n, 5,
        "ReferenceFs{{fault: None}} must return the exact remainder, not a short one"
    );
    assert_eq!(
        &tail[..5],
        &expected[usize::try_from(total - 5).expect("total fits usize")..]
    );
}

// =====================================================================
// Row 6a — `.` and `..` resolve (positive-only)
// =====================================================================

#[test]
fn row6a_dot_and_dotdot_resolve_with_no_dotdot_lookup() {
    if !require_root("row6a_dot_and_dotdot_resolve_with_no_dotdot_lookup") {
        return;
    }
    let b_tree = build_dir(&[]).expect("row6a leaf builds");
    let a_entries = [dir_entry(b"b", b_tree.root)];
    let a_tree = build_dir(&a_entries).expect("row6a middle builds");
    let root_entries = [dir_entry(b"a", a_tree.root)];
    let root_tree = build_dir(&root_entries).expect("row6a root builds");
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = b_tree.nodes.into_iter().collect();
    nodes.extend(a_tree.nodes);
    nodes.extend(root_tree.nodes);
    let snapshot = build_snapshot(nodes, root_tree.root);

    let obs = Arc::new(Obs::new());
    let fs = Observed {
        inner: GranaryFs::new(
            snapshot,
            InMemBackend::default(),
            1,
            crate::MountWritability::ReadOnly,
        )
        .expect("fixture snapshot admits the adapter bound"),
        obs: Arc::clone(&obs),
        negotiate: true,
        expected_children: BTreeSet::new(),
    };
    let (mountpoint, _guard) = spawn_guarded("row6a", fs, crate::session_config(false));

    let a_path = mountpoint.join("a");
    let b_path = a_path.join("b");

    // `stat(".")` from inside a/b resolves and is a directory.
    let dot_meta = std::fs::metadata(b_path.join(".")).expect("stat . inside a/b");
    assert!(dot_meta.is_dir());

    // `a/b/..` resolves to `a` (same device+inode, not merely "some dir").
    let a_meta = std::fs::metadata(&a_path).expect("stat a");
    let via_dotdot = std::fs::metadata(b_path.join("..")).expect("stat a/b/..");
    assert_eq!(
        (a_meta.dev(), a_meta.ino()),
        (via_dotdot.dev(), via_dotdot.ino()),
        "a/b/.. must resolve to a"
    );

    // A path with `..` in the middle: a/b/../b resolves to b itself.
    let b_meta = std::fs::metadata(&b_path).expect("stat a/b");
    let mid_dotdot =
        std::fs::metadata(a_path.join("b").join("..").join("b")).expect("a/b/../b resolves");
    assert_eq!(
        (b_meta.dev(), b_meta.ino()),
        (mid_dotdot.dev(), mid_dotdot.ino())
    );

    // A real `cd ..` from inside a/b lands in a. Safe under nextest's
    // process-per-test isolation (same reasoning `unmount.rs`'s own
    // `setuid` tests rely on) -- restored to `/` immediately after so the
    // guard's teardown never has to unmount a directory that is also the
    // process's cwd.
    std::env::set_current_dir(&b_path).expect("cd into a/b");
    std::env::set_current_dir("..").expect("cd ..");
    let cwd = std::env::current_dir().expect("current dir");
    std::env::set_current_dir("/").expect("cd back out of the mount before teardown");
    assert_eq!(cwd, a_path, "cd .. from a/b must land in a");

    let state = obs.lock();
    assert_eq!(
        state.lookups(b".."),
        0,
        "the kernel must never issue a FUSE_LOOKUP for .. -- Snapshot::readdir synthesises it, \
         Snapshot::lookup never sees that name"
    );
}

// =====================================================================
// Row 6b — `d_type` correct per entry kind
// =====================================================================

fn row6b_fixture() -> Snapshot {
    let empty = build_dir(&[]).expect("row6b empty dir builds");
    let entries = [
        dir_entry(b"adir", empty.root),
        file_entry_empty(b"afile"),
        symlink_entry(b"alink", b"target"),
    ];
    let tree = build_dir(&entries).expect("row6b root builds");
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = empty.nodes.into_iter().collect();
    nodes.extend(tree.nodes);
    build_snapshot(nodes, tree.root)
}

fn read_dtypes(dir: &Path) -> BTreeMap<Vec<u8>, rustix::fs::FileType> {
    let file = std::fs::File::open(dir).expect("open dir for d_type sweep");
    let mut buf = [MaybeUninit::uninit(); 4096];
    let mut iter = rustix::fs::RawDir::new(file.as_fd(), &mut buf);
    let mut out = BTreeMap::new();
    while let Some(entry) = iter.next() {
        let entry = entry.expect("dirent decodes");
        let name = entry.file_name().to_bytes().to_vec();
        if name == b"." || name == b".." {
            continue;
        }
        out.insert(name, entry.file_type());
    }
    out
}

#[test]
fn row6b_dtype_correct_positive() {
    if !require_root("row6b_dtype_correct_positive") {
        return;
    }
    let fs = GranaryFs::new(
        row6b_fixture(),
        InMemBackend::default(),
        1,
        crate::MountWritability::ReadOnly,
    )
    .expect("fixture snapshot admits the adapter bound");
    let (mountpoint, _guard) = spawn_guarded("row6b-pos", fs, crate::session_config(false));
    let kinds = read_dtypes(&mountpoint);
    assert_eq!(
        kinds.get(b"adir".as_slice()),
        Some(&rustix::fs::FileType::Directory)
    );
    assert_eq!(
        kinds.get(b"afile".as_slice()),
        Some(&rustix::fs::FileType::RegularFile)
    );
    assert_eq!(
        kinds.get(b"alink".as_slice()),
        Some(&rustix::fs::FileType::Symlink)
    );
}

#[test]
fn row6b_dtype_correct_negative_dtype_lie() {
    if !require_root("row6b_dtype_correct_negative_dtype_lie") {
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(
        row6b_fixture(),
        InMemBackend::default(),
        1,
        Some(Fault::DtypeLie),
        obs,
    );
    let (mountpoint, _guard) = spawn_guarded("row6b-neg", fs, crate::session_config(false));
    let kinds = read_dtypes(&mountpoint);
    assert_ne!(
        kinds.get(b"adir".as_slice()),
        Some(&rustix::fs::FileType::Directory),
        "Fault::DtypeLie must misreport the directory's wire d_type"
    );
    let real = std::fs::metadata(mountpoint.join("adir")).expect("lstat adir");
    assert!(
        real.is_dir(),
        "an honest lstat must still see the true type"
    );
}

#[test]
fn row6b_dtype_correct_none_control() {
    if !require_root("row6b_dtype_correct_none_control") {
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(row6b_fixture(), InMemBackend::default(), 1, None, obs);
    let (mountpoint, _guard) = spawn_guarded("row6b-none", fs, crate::session_config(false));
    let kinds = read_dtypes(&mountpoint);
    assert_eq!(
        kinds.get(b"adir".as_slice()),
        Some(&rustix::fs::FileType::Directory)
    );
    assert_eq!(
        kinds.get(b"afile".as_slice()),
        Some(&rustix::fs::FileType::RegularFile)
    );
    assert_eq!(
        kinds.get(b"alink".as_slice()),
        Some(&rustix::fs::FileType::Symlink)
    );
}

// =====================================================================
// Row 7 — `find` descends (the executable nlink contract)
// =====================================================================

fn row7_fixture() -> Snapshot {
    let leaf = build_dir(&[]).expect("row7 leaf builds");
    let mid = build_dir(&[dir_entry(b"leaf", leaf.root)]).expect("row7 mid builds");
    let top = build_dir(&[dir_entry(b"mid", mid.root)]).expect("row7 top builds");
    let root_tree = build_dir(&[dir_entry(b"top", top.root)]).expect("row7 root builds");
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = leaf.nodes.into_iter().collect();
    nodes.extend(mid.nodes);
    nodes.extend(top.nodes);
    nodes.extend(root_tree.nodes);
    build_snapshot(nodes, root_tree.root)
}

fn run_find(mountpoint: &Path) -> BTreeSet<PathBuf> {
    let output = Command::new("find")
        .arg(mountpoint)
        .output()
        .expect("run find");
    assert!(
        output.status.success(),
        "find exited with failure: {output:?}"
    );
    String::from_utf8(output.stdout)
        .expect("find output is utf8")
        .lines()
        .map(PathBuf::from)
        .collect()
}

#[test]
fn row7_find_descends_positive() {
    if !require_root("row7_find_descends_positive") {
        return;
    }
    if find_on_path("find").is_none() {
        eprintln!("SKIPPED-ENV row7_find_descends_positive: `find` is not on PATH");
        return;
    }
    let fs = GranaryFs::new(
        row7_fixture(),
        InMemBackend::default(),
        1,
        crate::MountWritability::ReadOnly,
    )
    .expect("fixture snapshot admits the adapter bound");
    let (mountpoint, _guard) = spawn_guarded("row7-pos", fs, crate::session_config(false));
    // The mount's nlink property, observed directly: a directory reports
    // `nlink = 2 + its subdirectory count`. `top`/`mid` each have one
    // subdirectory (3), `leaf` has none (2). This is what `find` relies
    // on to descend on filesystems that honour the Unix directory-link
    // convention — and it is the value the milestone commits to.
    let nlink_of = |rel: &str| {
        std::fs::symlink_metadata(mountpoint.join(rel))
            .expect("stat a fixture directory")
            .nlink()
    };
    assert_eq!(nlink_of("top"), 3, "top has 1 subdir (mid): nlink = 2 + 1");
    assert_eq!(
        nlink_of("top/mid"),
        3,
        "mid has 1 subdir (leaf): nlink = 2 + 1"
    );
    assert_eq!(nlink_of("top/mid/leaf"), 2, "leaf has 0 subdirs: nlink = 2");
    // Smoke check: `find` works end to end over the mount and visits
    // every directory. On a `fuse` mount this passes regardless of the
    // reported nlink (this findutils descends into FUSE directories
    // without trusting the daemon's nlink), so it is a robustness check
    // that the mount is traversable, NOT the nlink discriminator — that
    // is the `stat` assertions above and row 7's negative.
    let found = run_find(&mountpoint);
    for expected in [
        mountpoint.clone(),
        mountpoint.join("top"),
        mountpoint.join("top").join("mid"),
        mountpoint.join("top").join("mid").join("leaf"),
    ] {
        assert!(
            found.contains(&expected),
            "find must visit {}; got {found:?}",
            expected.display()
        );
    }
}

#[test]
fn row7_find_descends_negative_uniform_nlink2() {
    if !require_root("row7_find_descends_negative_uniform_nlink2") {
        return;
    }
    if find_on_path("find").is_none() {
        eprintln!("SKIPPED-ENV row7_find_descends_negative_uniform_nlink2: `find` is not on PATH");
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(
        row7_fixture(),
        InMemBackend::default(),
        1,
        Some(Fault::UniformNlink2),
        obs,
    );
    let (mountpoint, _guard) = spawn_guarded("row7-neg", fs, crate::session_config(false));
    // The observable nlink property is the nlink VALUE, read by a
    // `stat`, NOT `find`'s descent: measured in the container-root lane,
    // GNU find over a `fuse` mount descends into `top` even when `top`
    // reports `nlink = 2` (fstype `fuse`, top_nlink 2 — this findutils
    // treats a FUSE mount as un-optimizable and ignores the daemon's
    // nlink). So the negative asserts the WRONG nlink directly:
    // `top` HAS a subdirectory (`mid`), so its honest nlink is
    // `2 + 1 = 3`; `UniformNlink2` makes it report 2, the exact value
    // the synthesised-nlink rule exists to avoid.
    let top_nlink = std::fs::symlink_metadata(mountpoint.join("top"))
        .expect("stat top")
        .nlink();
    assert_eq!(
        top_nlink, 2,
        "Fault::UniformNlink2 must make a directory WITH a subdirectory report nlink=2 \
         (its honest value is 2 + 1 subdir = 3); got {top_nlink}"
    );
}

#[test]
fn row7_find_descends_none_control() {
    if !require_root("row7_find_descends_none_control") {
        return;
    }
    if find_on_path("find").is_none() {
        eprintln!("SKIPPED-ENV row7_find_descends_none_control: `find` is not on PATH");
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(row7_fixture(), InMemBackend::default(), 1, None, obs);
    let (mountpoint, _guard) = spawn_guarded("row7-none", fs, crate::session_config(false));
    // The None-control must report the SAME honest nlink as GranaryFs
    // (the positive), so `Some(UniformNlink2)` isolates exactly the
    // fault: `top` with its one subdirectory is 3, not the uniform 2.
    let nlink_of = |rel: &str| {
        std::fs::symlink_metadata(mountpoint.join(rel))
            .expect("stat a fixture directory")
            .nlink()
    };
    assert_eq!(
        nlink_of("top"),
        3,
        "ReferenceFs{{fault: None}} must report top's honest nlink (2 + 1 subdir), like GranaryFs"
    );
    assert_eq!(nlink_of("top/mid/leaf"), 2, "leaf has 0 subdirs: nlink = 2");
    let found = run_find(&mountpoint);
    for expected in [
        mountpoint.clone(),
        mountpoint.join("top"),
        mountpoint.join("top").join("mid"),
        mountpoint.join("top").join("mid").join("leaf"),
    ] {
        assert!(
            found.contains(&expected),
            "find must visit {}; got {found:?}",
            expected.display()
        );
    }
}

// =====================================================================
// Row 8 — `statfs` namelen == 255
// =====================================================================

fn row8_fixture() -> Snapshot {
    let tree = build_dir(&[file_entry_empty(b"f")]).expect("row8 root builds");
    build_snapshot(tree.nodes.into_iter().collect(), tree.root)
}

#[test]
fn row8_statfs_namelen_positive() {
    if !require_root("row8_statfs_namelen_positive") {
        return;
    }
    let fs = GranaryFs::new(
        row8_fixture(),
        InMemBackend::default(),
        1,
        crate::MountWritability::ReadOnly,
    )
    .expect("fixture snapshot admits the adapter bound");
    let (mountpoint, _guard) = spawn_guarded("row8-pos", fs, crate::session_config(false));
    let vfs = rustix::fs::statvfs(&mountpoint).expect("statvfs the mount");
    assert_eq!(vfs.f_namemax, 255);
}

#[test]
fn row8_statfs_namelen_negative_wrong_namelen() {
    if !require_root("row8_statfs_namelen_negative_wrong_namelen") {
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(
        row8_fixture(),
        InMemBackend::default(),
        1,
        Some(Fault::WrongNamelen),
        obs,
    );
    let (mountpoint, _guard) = spawn_guarded("row8-neg", fs, crate::session_config(false));
    let vfs = rustix::fs::statvfs(&mountpoint).expect("statvfs the mount");
    assert_ne!(
        vfs.f_namemax, 255,
        "Fault::WrongNamelen must make namelen != 255"
    );
    assert_eq!(vfs.f_namemax, 254);
}

#[test]
fn row8_statfs_namelen_none_control() {
    if !require_root("row8_statfs_namelen_none_control") {
        return;
    }
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(row8_fixture(), InMemBackend::default(), 1, None, obs);
    let (mountpoint, _guard) = spawn_guarded("row8-none", fs, crate::session_config(false));
    let vfs = rustix::fs::statvfs(&mountpoint).expect("statvfs the mount");
    assert_eq!(vfs.f_namemax, 255);
}

// =====================================================================
// Row 9 — execute a binary from the mount
// =====================================================================

fn row9_fixture() -> (Snapshot, InMemBackend) {
    let script = b"#!/bin/sh\necho SENTINEL-ROW9\n".to_vec();
    let id = GrainId::of(&script);
    let mut backend = InMemBackend::default();
    backend.grains.insert(id, script.clone());
    let entry = DirEntry {
        name: Name::new(b"prog".to_vec()).expect("valid name"),
        kind: EntryKind::File {
            exec: true,
            size: u64::try_from(script.len()).expect("fits"),
            grains: FileGrains::Inline(vec![GrainRef {
                id,
                unpacked_len: u32::try_from(script.len()).expect("fits"),
            }]),
        },
    };
    let tree = build_dir(&[entry]).expect("row9 root builds");
    (
        build_snapshot(tree.nodes.into_iter().collect(), tree.root),
        backend,
    )
}

#[test]
fn row9_execute_from_mount_positive() {
    if !require_root("row9_execute_from_mount_positive") {
        return;
    }
    let (snapshot, backend) = row9_fixture();
    let fs = GranaryFs::new(snapshot, backend, 1, crate::MountWritability::ReadOnly)
        .expect("fixture snapshot admits the adapter bound");
    let (mountpoint, _guard) = spawn_guarded("row9-pos", fs, crate::session_config(false));
    let output = Command::new(mountpoint.join("prog"))
        .output()
        .expect("execute the mounted script");
    assert!(
        output.status.success(),
        "expected the script to run successfully: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("SENTINEL-ROW9"),
        "unexpected output: {output:?}"
    );
}

#[test]
fn row9_execute_from_mount_negative_noexec() {
    if !require_root("row9_execute_from_mount_negative_noexec") {
        return;
    }
    let (snapshot, backend) = row9_fixture();
    let fs = GranaryFs::new(snapshot, backend, 1, crate::MountWritability::ReadOnly)
        .expect("fixture snapshot admits the adapter bound");
    let mut config = crate::session_config(false);
    config.mount_options.push(MountOption::NoExec);
    let (mountpoint, _guard) = spawn_guarded("row9-neg", fs, config);
    match Command::new(mountpoint.join("prog")).output() {
        Ok(output) => panic!("expected exec to be refused under noexec, got {output:?}"),
        Err(err) => assert_eq!(
            err.raw_os_error(),
            Some(nix::errno::Errno::EACCES as i32),
            "expected EACCES under a noexec mount, got {err:?}"
        ),
    }
}

// =====================================================================
// Row 10 — LTP `read_all -d <mount>` (best-effort)
// =====================================================================

#[test]
fn row10_ltp_read_all_best_effort() {
    if !require_root("row10_ltp_read_all_best_effort") {
        return;
    }
    let Some(ltp_bin) = find_on_path("read_all") else {
        eprintln!(
            "SKIPPED-ENV row10_ltp_read_all_best_effort: LTP's read_all binary is not on PATH \
             (not installed in this image) -- expected, and this loud skip is the point"
        );
        return;
    };
    let fs = GranaryFs::new(
        row8_fixture(),
        InMemBackend::default(),
        1,
        crate::MountWritability::ReadOnly,
    )
    .expect("fixture snapshot admits the adapter bound");
    let (mountpoint, _guard) = spawn_guarded("row10", fs, crate::session_config(false));
    let status = Command::new(ltp_bin)
        .arg("-d")
        .arg(&mountpoint)
        .status()
        .expect("run LTP read_all over the mount");
    assert!(
        status.success(),
        "LTP read_all failed over the mount: {status:?}"
    );
}

// =====================================================================
// The wedge bound's own negative
// =====================================================================

/// Proves the package's slow-timeout bound (`.config/nextest.toml`,
/// `package(granary-fuse)`, `30s` x2 terminate-after, ~60s) actually
/// TERMINATES a wedged test rather than hanging the suite forever.
/// `#[ignore]`d so it never runs in the ordinary suite. To demonstrate
/// the terminate, un-ignore it locally and run it alone:
///
/// ```text
/// cargo nextest run -p granary-fuse --run-ignored ignored-only \
///     wedge_bound_tripwire_hangs_forever
/// ```
///
/// and watch nextest print `SLOW` then `TERMINATING` at ~60s. Do NOT
/// un-ignore this in a committed change.
#[test]
#[ignore = "deliberately hangs forever -- demonstrates the nextest terminate-after bound; never \
            run in CI"]
fn wedge_bound_tripwire_hangs_forever() {
    let obs = Obs::new();
    let guard = obs.lock();
    // No thread will ever notify this condvar: this blocks forever, and
    // nextest's terminate-after is what ends it. `drop`, not a bare `let
    // _`: the latter is `deny(let_underscore_lock)` -- a lock guard
    // dropped without a binding is a real footgun in general, even though
    // this particular call never returns to reach the drop at all.
    drop(obs.cv.wait(guard));
}

// =====================================================================
// Conformance layer 3 — the refusal taxonomy: diagnostic configs
// =====================================================================

/// A DIAGNOSTIC config no product path ever builds: the shipped option
/// set (`session_config`, the only way the product mounts) with exactly
/// `MountOption::RO` removed and `DefaultPermissions` KEPT — one control
/// varied at a time. Without `ro` the kernel stops refusing writes before
/// FUSE is consulted, so the daemon-side answers (`fuser`'s defaults, the
/// `open_handle` refusal) become observable.
fn no_ro_config() -> fuser::Config {
    let mut config = crate::session_config(false);
    assert!(
        config.mount_options.contains(&MountOption::RO),
        "the shipped config must carry ro for this diagnostic to remove anything"
    );
    config
        .mount_options
        .retain(|option| *option != MountOption::RO);
    assert!(
        !config.mount_options.contains(&MountOption::RO),
        "the diagnostic config must have RO removed"
    );
    assert!(
        config
            .mount_options
            .contains(&MountOption::DefaultPermissions),
        "the diagnostic config must keep default_permissions -- only one control is varied"
    );
    config
}

/// The second DIAGNOSTIC config, again never built by any product path:
/// BOTH `MountOption::RO` and `DefaultPermissions` removed. Without
/// `default_permissions` the kernel forwards `access(2)` as `FUSE_ACCESS`
/// instead of deciding it in `generic_permission`, which is the only way
/// the daemon's own `access_check` can run at all; without `ro` a
/// permissive mutant of that check shows as SUCCESS rather than being
/// masked by the kernel's `EROFS`.
fn no_ro_no_default_permissions_config() -> fuser::Config {
    let mut config = crate::session_config(false);
    assert!(
        config.mount_options.contains(&MountOption::RO),
        "the shipped config must carry ro for this diagnostic to remove anything"
    );
    assert!(
        config
            .mount_options
            .contains(&MountOption::DefaultPermissions),
        "the shipped config must carry default_permissions for this diagnostic to remove anything"
    );
    config
        .mount_options
        .retain(|option| *option != MountOption::RO && *option != MountOption::DefaultPermissions);
    assert!(
        !config.mount_options.contains(&MountOption::RO),
        "the two-controls-removed config must have RO removed"
    );
    assert!(
        !config
            .mount_options
            .contains(&MountOption::DefaultPermissions),
        "the two-controls-removed config must have default_permissions removed"
    );
    config
}

// =====================================================================
// Conformance layer 3 — the shared refusal fixture
// =====================================================================

const N_ABSENT_GRAIN: &[u8] = b"absent-grain";
const N_DIR: &[u8] = b"dir";
const N_FILE: &[u8] = b"file";
const N_FRAG: &[u8] = b"frag";
const N_LOOP: &[u8] = b"loop";
const N_INNER: &[u8] = b"inner";
const N_MISSING: &[u8] = b"missing";
const N_NEW: &[u8] = b"new";
const N_X: &[u8] = b"x";
const N_CHILD: &[u8] = b"child";
/// The root's entries, in the strict memcmp order `build_dir` requires.
const FIXTURE_ROOT_NAMES: [&[u8]; 5] = [N_ABSENT_GRAIN, N_DIR, N_FILE, N_FRAG, N_LOOP];
const SMALL_FILE_BYTES: usize = 16;
/// The too-fragmented file's size: one-byte grains make its grain span
/// equal to its byte length, and 8192 is twice `READ_MAX_GRAINS`, so ONE
/// read of the whole file must cross the cap.
const FRAG_BYTES: usize = 8192;
const XATTR_NAME: &str = "user.x";

fn at(mountpoint: &Path, name: &[u8]) -> PathBuf {
    mountpoint.join(OsStr::from_bytes(name))
}

/// A component of `len` bytes, over `NAME_MAX` when `len > 255`.
fn probe_name(len: usize) -> Vec<u8> {
    vec![b'a'; len]
}

/// A regular file with ONE inline grain holding `content`; the grain id
/// is returned so the caller decides whether the backend carries it.
fn inline_file_entry(name: &[u8], content: &[u8]) -> (DirEntry, GrainId) {
    let id = GrainId::of(content);
    let entry = DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::File {
            exec: false,
            size: u64::try_from(content.len()).expect("fits"),
            grains: FileGrains::Inline(vec![GrainRef {
                id,
                unpacked_len: u32::try_from(content.len()).expect("fits"),
            }]),
        },
    };
    (entry, id)
}

/// The one fixture every refusal row mounts fresh: `absent-grain` (a
/// regular file whose only grain the backend does NOT hold), `dir` (holding
/// one empty file `inner`), `file` (a regular file whose grain IS held),
/// `frag` (8192 bytes as 8192 one-byte grains, all held, in the spill
/// form) and `loop` (a symlink to itself). Every row's operand state is
/// frozen by this shape; a row's setup never issues the opcode the row
/// asserts on.
fn refusal_fixture() -> (Snapshot, InMemBackend) {
    let mut backend = InMemBackend::default();

    let absent_content = [0xA5_u8; SMALL_FILE_BYTES];
    let (absent_entry, _absent_id_deliberately_not_inserted) =
        inline_file_entry(N_ABSENT_GRAIN, &absent_content);

    let file_content = [0x5A_u8; SMALL_FILE_BYTES];
    let (file_entry, file_id) = inline_file_entry(N_FILE, &file_content);
    backend.grains.insert(file_id, file_content.to_vec());

    let mut frag_refs = Vec::with_capacity(FRAG_BYTES);
    for i in 0..FRAG_BYTES {
        let byte = [u8::try_from(i % 256).expect("fits")];
        let id = GrainId::of(&byte);
        frag_refs.push(GrainRef {
            id,
            unpacked_len: 1,
        });
        backend.grains.insert(id, byte.to_vec());
    }
    let frag_list = build_grain_list(&frag_refs).expect("8192 one-byte grains build a spill list");
    let frag_entry = DirEntry {
        name: Name::new(N_FRAG.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::File {
            exec: false,
            size: u64::try_from(FRAG_BYTES).expect("fits"),
            grains: FileGrains::Spill {
                grain_count: u32::try_from(FRAG_BYTES).expect("fits"),
                root: frag_list.root,
            },
        },
    };

    let dir_tree = build_dir(&[file_entry_empty(N_INNER)]).expect("fixture dir builds");
    let root_entries = [
        absent_entry,
        dir_entry(N_DIR, dir_tree.root),
        file_entry,
        frag_entry,
        symlink_entry(N_LOOP, N_LOOP),
    ];
    let root_tree = build_dir(&root_entries).expect("fixture root builds");
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = root_tree.nodes.into_iter().collect();
    nodes.extend(dir_tree.nodes);
    nodes.extend(frag_list.nodes);
    (build_snapshot(nodes, root_tree.root), backend)
}

// =====================================================================
// Conformance layer 3 — modes, layers, expectations, the assertion
// =====================================================================

/// The mount configuration a row runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// The shipped `session_config`: `ro` and `default_permissions`.
    Ro,
    /// `no_ro_config`: `ro` removed, `default_permissions` kept.
    NoRo,
    /// `no_ro_no_default_permissions_config`: both removed.
    NoRoNoDefaultPermissions,
}

impl Mode {
    const ALL: [Self; 3] = [Self::Ro, Self::NoRo, Self::NoRoNoDefaultPermissions];

    fn label(self) -> &'static str {
        match self {
            Self::Ro => "ro",
            Self::NoRo => "noro",
            Self::NoRoNoDefaultPermissions => "noro-nodefperm",
        }
    }
}

fn config_for(mode: Mode) -> fuser::Config {
    match mode {
        Mode::Ro => crate::session_config(false),
        Mode::NoRo => no_ro_config(),
        Mode::NoRoNoDefaultPermissions => no_ro_no_default_permissions_config(),
    }
}

/// Which layer produces a row's answer. Recorded per row and printed in
/// every assertion, so a change that MOVES an answer (a kernel that starts
/// refusing earlier, a daemon handler that starts running where the kernel
/// used to stop) reads as a changed row rather than as the same errno for
/// a silently different reason.
#[derive(Clone, Copy, Debug)]
enum Layer {
    /// The kernel's `ro` check; the write opcode never reaches the daemon.
    KernelRo,
    /// VFS path and kind rules that beat `EROFS`, decided from granary's
    /// own `LOOKUP` attrs.
    KernelPrecedence,
    /// Granary's own handler answered.
    DaemonHandler,
    /// The daemon answered `ENOSYS`; the kernel rewrote it and latched the
    /// rewrite for the connection.
    KernelLatch,
}

#[derive(Clone, Copy, Debug)]
enum Count {
    Exactly(u64),
    AtLeast(u64),
}

const ZERO: Count = Count::Exactly(0);
const ONCE: Count = Count::Exactly(1);

/// What the driven syscall answered, as the raw errno or success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Errno(Errno),
    Success,
}

/// What a driver observed: the outcome the row is judged on and — for a
/// two-call driver — the FIRST call's outcome beside it, so a divergence
/// between the calls is judged by the runner AFTER the traffic line has
/// printed, never inside the driver, where a write that actually landed
/// would die unreported.
#[derive(Clone, Copy, Debug)]
struct Driven {
    outcome: Outcome,
    first: Option<Outcome>,
}

fn single(outcome: Outcome) -> Driven {
    Driven {
        outcome,
        first: None,
    }
}

fn io_outcome<T>(result: io::Result<T>) -> Driven {
    single(match result {
        Ok(_) => Outcome::Success,
        Err(err) => Outcome::Errno(Errno::from_io_error(&err).unwrap_or_else(|| {
            panic!("an error without an errno where one was expected: {err:?}")
        })),
    })
}

fn rx_outcome<T>(result: rustix::io::Result<T>) -> Driven {
    single(result.map_or_else(Outcome::Errno, |_| Outcome::Success))
}

fn nix_outcome<T>(result: nix::Result<T>) -> Driven {
    single(result.map_or_else(
        |errno| Outcome::Errno(Errno::from_raw_os_error(errno as i32)),
        |_| Outcome::Success,
    ))
}

/// One row's expectation under one mode.
#[derive(Clone, Debug)]
struct Expect {
    outcome: Outcome,
    layer: Layer,
    ops: Vec<(Op, Count)>,
    /// Exact `LOOKUP` counts by name.
    lookups: Vec<(Vec<u8>, u64)>,
    /// The expected answer rests on root's DAC override, decided in the
    /// named capability register: probed UP FRONT by `require_dac_override`
    /// (a `NOT EXECUTED` skip the lane's marker gate counts), never
    /// inferred from the row's own outcome. Only the no-`ro` rows whose
    /// expected answer is itself `EACCES`-or-success set it — the ones a
    /// lost opcode count could otherwise impersonate. The no-`ro` WRITE
    /// rows depend on the override too, but they expect their opcode with
    /// count 1, so a kernel `EACCES` there already fails the `== 1`
    /// assertion loudly.
    dac_override: Option<CapRegister>,
}

fn refused(errno: Errno, layer: Layer) -> Expect {
    Expect {
        outcome: Outcome::Errno(errno),
        layer,
        ops: Vec::new(),
        lookups: Vec::new(),
        dac_override: None,
    }
}

fn succeeds(layer: Layer) -> Expect {
    Expect {
        outcome: Outcome::Success,
        layer,
        ops: Vec::new(),
        lookups: Vec::new(),
        dac_override: None,
    }
}

impl Expect {
    fn with_ops(mut self, ops: &[(Op, Count)]) -> Self {
        self.ops.extend_from_slice(ops);
        self
    }

    fn with_lookups(mut self, lookups: &[(&[u8], u64)]) -> Self {
        self.lookups
            .extend(lookups.iter().map(|(name, count)| (name.to_vec(), *count)));
        self
    }

    fn needs_dac_override(mut self, reg: CapRegister) -> Self {
        self.dac_override = Some(reg);
        self
    }
}

/// A name as it appears in an assertion message: lossy UTF-8, with a
/// long probe abbreviated to its head and its length.
fn render_name(name: &[u8]) -> String {
    const SHOWN: usize = 24;
    if name.len() <= SHOWN {
        String::from_utf8_lossy(name).into_owned()
    } else {
        format!(
            "{}...({} bytes)",
            String::from_utf8_lossy(&name[..SHOWN]),
            name.len()
        )
    }
}

fn render_lookups(state: &ObsState) -> BTreeMap<String, u64> {
    state
        .lookups_by_name
        .iter()
        .map(|(name, count)| (render_name(name), *count))
        .collect()
}

/// The `OBS` line's body: the row, the mode, the layer, both errnos,
/// the first call's answer where there was one, and the FULL observed
/// traffic. Built once per row and carried into every assertion message.
fn describe(row: &str, mode: Mode, expect: &Expect, driven: Driven, state: &ObsState) -> String {
    format!(
        "row={row} mode={mode:?} layer={:?} expected={:?} observed={:?} first={:?} ops={:?} \
         lookups={:?} reads={:?}",
        expect.layer,
        expect.outcome,
        driven.outcome,
        driven.first,
        state.ops,
        render_lookups(state),
        state.reads
    )
}

/// The one assertion every refusal row and negative goes through: the
/// outcome, then the call cardinality (a two-call row's driver must have
/// reported a first call, a one-call row's must not), then the first
/// call's agreement with the second, then every opcode count, then every
/// lookup count — each message carrying `context`, so a failure names what
/// actually happened. Prints nothing: the runner has already printed the
/// `OBS` line before anything here can fire.
fn check_expect(context: &str, expect: &Expect, driven: Driven, calls: u8, state: &ObsState) {
    assert_eq!(
        driven.outcome, expect.outcome,
        "outcome mismatch: {context}"
    );
    assert_eq!(
        driven.first.is_some(),
        calls == 2,
        "call cardinality: the row specifies {calls} call(s) but the driver reported first={:?} \
         -- a driver reduced to one call would hollow out the two-call latch witness: {context}",
        driven.first
    );
    if let Some(first) = driven.first {
        assert_eq!(
            first, driven.outcome,
            "the second call on the same connection must answer like the first: {context}"
        );
    }
    for (op, count) in &expect.ops {
        let observed = state.op_count(*op);
        match *count {
            Count::Exactly(n) => {
                assert_eq!(
                    observed, n,
                    "{op:?} must arrive exactly {n} time(s): {context}"
                );
            }
            Count::AtLeast(n) => {
                assert!(
                    observed >= n,
                    "{op:?} must arrive at least {n} time(s), observed {observed}: {context}"
                );
            }
        }
    }
    for (name, count) in &expect.lookups {
        let observed = state.lookups(name);
        assert_eq!(
            observed,
            *count,
            "LOOKUP({}) must arrive exactly {count} time(s): {context}",
            render_name(name)
        );
    }
}

// =====================================================================
// Conformance layer 3 — the negatives and their None-controls, on
// `ReferenceFs` (its own `obs`; `Observed` wraps only `GranaryFs`)
// =====================================================================

fn drive_lstat_probe_256(mountpoint: &Path) -> Driven {
    io_outcome(std::fs::symlink_metadata(at(mountpoint, &probe_name(256))))
}

fn drive_open_dir_wronly(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::open(
        at(mountpoint, N_DIR),
        OFlags::WRONLY | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ))
}

/// The precision check behind `Fault::WrongOverlongErrno`: a valid sibling
/// must still resolve, so a double that answers `ENOENT` to EVERY lookup
/// cannot pass as the fault.
fn assert_sibling_file_resolves(mountpoint: &Path) {
    let sibling = std::fs::symlink_metadata(at(mountpoint, N_FILE));
    assert!(
        sibling.is_ok(),
        "a valid sibling must still resolve: {sibling:?}"
    );
}

/// The precision check behind `Fault::DirAsFile`'s kind guard: the fault
/// rewrites DIRECTORIES only, so the fixture's self-loop symlink must
/// still report as a symlink (`symlink_metadata`, never `metadata` — the
/// latter follows the loop and answers `ELOOP`). A double that reports
/// every non-root node as a file would pass the row's own assertions and
/// fail here; the same check on the `None` control proves the honest
/// adapter agrees.
fn assert_loop_still_symlink(mountpoint: &Path) {
    let file_type = std::fs::symlink_metadata(at(mountpoint, N_LOOP))
        .expect("lstat the fixture's self-loop symlink")
        .file_type();
    assert!(
        file_type.is_symlink(),
        "the DirAsFile fault must rewrite directories ONLY (its `attr.kind == Dir` guard): \
         `loop` reports {file_type:?}"
    );
}

/// The one runner for every `ReferenceFs` row: fresh mount under `mode`,
/// drive, snapshot the counters, print the traffic, assert through
/// `check_expect` (every reference row is a single call), run the row's
/// extra check, tear down asserting the mount is gone.
fn run_reference_row(
    test_name: &str,
    row: &str,
    fault: Option<Fault>,
    mode: Mode,
    expect: &Expect,
    drive: fn(&Path) -> Driven,
    after: Option<fn(&Path)>,
) {
    if !require_root(test_name) {
        return;
    }
    if let Some(reg) = expect.dac_override
        && !require_dac_override(test_name, reg)
    {
        return;
    }
    let (snapshot, backend) = refusal_fixture();
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(snapshot, backend, 1, fault, Arc::clone(&obs));
    let label = format!("{row}-{}", mode.label());
    let (mountpoint, guard) = spawn_guarded(&label, fs, config_for(mode));
    let driven = drive(&mountpoint);
    let state = obs.lock().clone();
    let context = describe(row, mode, expect, driven, &state);
    // Printed on EVERY run, pass or fail, and BEFORE anything that can
    // fail, so the traffic behind a row is in the log whatever happens.
    eprintln!("OBS {context}");
    check_expect(&context, expect, driven, 1, &state);
    if let Some(after) = after {
        after(&mountpoint);
    }
    guard.teardown();
}

/// The wrong answer for an over-long name is `ENOENT`; the probe is still
/// looked up exactly once, never opened, and the sibling still resolves.
fn wrong_overlong_errno_negative(mode: Mode, test_name: &str) {
    let probe = probe_name(256);
    let expect = refused(Errno::NOENT, Layer::DaemonHandler)
        .with_ops(&[(Op::Open, ZERO)])
        .with_lookups(&[(probe.as_slice(), 1)]);
    run_reference_row(
        test_name,
        "neg_wrong_overlong_errno",
        Some(Fault::WrongOverlongErrno),
        mode,
        &expect,
        drive_lstat_probe_256,
        Some(assert_sibling_file_resolves),
    );
}

fn wrong_overlong_errno_none_control(mode: Mode, test_name: &str) {
    let probe = probe_name(256);
    let expect = refused(Errno::NAMETOOLONG, Layer::DaemonHandler)
        .with_ops(&[(Op::Open, ZERO)])
        .with_lookups(&[(probe.as_slice(), 1)]);
    run_reference_row(
        test_name,
        "none_wrong_overlong_errno",
        None,
        mode,
        &expect,
        drive_lstat_probe_256,
        Some(assert_sibling_file_resolves),
    );
}

#[test]
fn neg_wrong_overlong_errno_ro() {
    wrong_overlong_errno_negative(Mode::Ro, "neg_wrong_overlong_errno_ro");
}

#[test]
fn neg_wrong_overlong_errno_noro() {
    wrong_overlong_errno_negative(Mode::NoRo, "neg_wrong_overlong_errno_noro");
}

#[test]
fn none_wrong_overlong_errno_ro() {
    wrong_overlong_errno_none_control(Mode::Ro, "none_wrong_overlong_errno_ro");
}

#[test]
fn none_wrong_overlong_errno_noro() {
    wrong_overlong_errno_none_control(Mode::NoRo, "none_wrong_overlong_errno_noro");
}

/// A directory reported as a regular file makes `may_open` skip its
/// `EISDIR` arm, and what answers next depends on the mode: under `ro`
/// the permission check's `EROFS` (`OPEN` never sent); without `ro`, root
/// passes the permission check (`CAP_DAC_OVERRIDE` in the effective set,
/// probed up front), the kernel sends `FUSE_OPEN`, and `ReferenceFs::open`
/// refuses the non-read-only mode with `EACCES` (`OPEN` = 1). Both the
/// negative and its control then check the fault left the self-loop
/// symlink alone — the kind guard's only observable.
fn dir_as_file_negative(mode: Mode, test_name: &str) {
    let expect = match mode {
        Mode::Ro => refused(Errno::ROFS, Layer::KernelRo)
            .with_ops(&[(Op::Open, ZERO)])
            .with_lookups(&[(N_DIR, 1)]),
        Mode::NoRo => refused(Errno::ACCESS, Layer::DaemonHandler)
            .with_ops(&[(Op::Open, ONCE)])
            .with_lookups(&[(N_DIR, 1)])
            .needs_dac_override(CapRegister::Eff),
        Mode::NoRoNoDefaultPermissions => {
            panic!("{test_name}: the dir-as-file negative has no two-controls-removed mode")
        }
    };
    run_reference_row(
        test_name,
        "neg_dir_as_file",
        Some(Fault::DirAsFile),
        mode,
        &expect,
        drive_open_dir_wronly,
        Some(assert_loop_still_symlink),
    );
}

fn dir_as_file_none_control(mode: Mode, test_name: &str) {
    let expect = refused(Errno::ISDIR, Layer::KernelPrecedence)
        .with_ops(&[(Op::Open, ZERO), (Op::Opendir, ZERO)])
        .with_lookups(&[(N_DIR, 1)]);
    run_reference_row(
        test_name,
        "none_dir_as_file",
        None,
        mode,
        &expect,
        drive_open_dir_wronly,
        Some(assert_loop_still_symlink),
    );
}

#[test]
fn neg_dir_as_file_ro() {
    dir_as_file_negative(Mode::Ro, "neg_dir_as_file_ro");
}

#[test]
fn neg_dir_as_file_noro() {
    dir_as_file_negative(Mode::NoRo, "neg_dir_as_file_noro");
}

#[test]
fn none_dir_as_file_ro() {
    dir_as_file_none_control(Mode::Ro, "none_dir_as_file_ro");
}

#[test]
fn none_dir_as_file_noro() {
    dir_as_file_none_control(Mode::NoRo, "none_dir_as_file_noro");
}

// =====================================================================
// Conformance layer 3 — the drivers (one syscall shape per row)
// =====================================================================

fn open_or_outcome(path: PathBuf) -> Result<std::fs::File, Driven> {
    std::fs::File::open(path).map_err(|err| io_outcome::<()>(Err(err)))
}

/// The two-call rows call their syscall TWICE on the same fresh
/// connection: the second call must answer exactly like the first, and
/// the opcode count says which side answered — exactly one when the
/// kernel latched a daemon `ENOSYS` and never asked again (the latch
/// rows), exactly two when the daemon's own reply never latches (`link`,
/// whose fuser default is a direct `EPERM`). Both answers are RETURNED,
/// never judged here: the runner asserts their agreement after the
/// traffic line has printed, so a first call that landed a write is in
/// the log rather than lost in a panic inside the driver.
fn twice(call: impl Fn() -> Driven) -> Driven {
    let first = call();
    let second = call();
    Driven {
        outcome: second.outcome,
        first: Some(first.outcome),
    }
}

fn drive_lstat_probe_1024(mountpoint: &Path) -> Driven {
    io_outcome(std::fs::symlink_metadata(at(mountpoint, &probe_name(1024))))
}

fn drive_open_missing_rdonly(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::open(
        at(mountpoint, N_MISSING),
        OFlags::RDONLY | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ))
}

fn drive_mkdir_missing_intermediate(mountpoint: &Path) -> Driven {
    io_outcome(std::fs::create_dir(
        at(mountpoint, N_MISSING).join(OsStr::from_bytes(N_X)),
    ))
}

fn drive_mkdir_existing_dir(mountpoint: &Path) -> Driven {
    io_outcome(std::fs::create_dir(at(mountpoint, N_DIR)))
}

fn drive_open_excl_existing_file(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::open(
        at(mountpoint, N_FILE),
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o644),
    ))
}

fn drive_open_dir_then_read(mountpoint: &Path) -> Driven {
    let mut file = match open_or_outcome(at(mountpoint, N_DIR)) {
        Ok(file) => file,
        Err(outcome) => return outcome,
    };
    let mut buf = [0_u8; 16];
    io_outcome(io::Read::read(&mut file, &mut buf))
}

fn drive_open_file_as_component(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::open(
        at(mountpoint, N_FILE).join(OsStr::from_bytes(N_CHILD)),
        OFlags::WRONLY | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ))
}

fn drive_open_self_loop(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::open(
        at(mountpoint, N_LOOP),
        OFlags::RDONLY | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ))
}

fn drive_open_self_loop_nofollow(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::open(
        at(mountpoint, N_LOOP),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ))
}

fn drive_open_file_wronly(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::open(
        at(mountpoint, N_FILE),
        OFlags::WRONLY | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ))
}

/// ONE `O_DIRECT` read of the absent-grain file. A buffered `read` here is
/// LAUNDERED by the page cache: a readahead fetch failure surfaces to
/// userspace as `EIO` whatever errno the daemon actually replied, so the
/// row would stay green even if the daemon answered `ENOENT` for the
/// missing grain — the errno it claims to pin (`DaemonHandler` EIO) would
/// not be what it measured. The direct-I/O path sends the `READ` straight
/// to the daemon, so the errno the row asserts is the daemon's own
/// (`GrainUnavailable` -> EIO), and a handler answering `ENOENT` reddens it.
/// Same page-aligned shape as `drive_direct_read_frag`.
fn drive_read_absent_grain(mountpoint: &Path) -> Driven {
    const ALIGN: usize = 4096;
    let fd = match rustix::fs::open(
        at(mountpoint, N_ABSENT_GRAIN),
        OFlags::RDONLY | OFlags::DIRECT | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(errno) => return single(Outcome::Errno(errno)),
    };
    let file = std::fs::File::from(fd);
    let mut backing = vec![0_u8; ALIGN * 2];
    let base = backing.as_ptr().addr();
    let start = base.next_multiple_of(ALIGN) - base;
    let aligned = &mut backing[start..start + ALIGN];
    io_outcome(file.read_at(aligned, 0))
}

/// ONE `O_DIRECT` read of the whole 8192-byte file from a page-aligned
/// buffer. Through the page cache the kernel may split a user read into
/// page-sized `READ`s that each stay at or under the grain cap, so `cat`
/// could return data instead of `EIO`; FUSE's direct-I/O path sends one
/// `READ` of `min(count, max_read)`, and 8192 one-byte grains is twice
/// the cap. Whether that single READ actually arrived is asserted from
/// the recorded sizes (`assert_a_read_crossed_the_grain_cap`), never
/// assumed.
fn drive_direct_read_frag(mountpoint: &Path) -> Driven {
    const ALIGN: usize = 4096;
    let fd = match rustix::fs::open(
        at(mountpoint, N_FRAG),
        OFlags::RDONLY | OFlags::DIRECT | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(errno) => return single(Outcome::Errno(errno)),
    };
    let file = std::fs::File::from(fd);
    let mut backing = vec![0_u8; FRAG_BYTES + ALIGN];
    let base = backing.as_ptr().addr();
    let start = base.next_multiple_of(ALIGN) - base;
    let aligned = &mut backing[start..start + FRAG_BYTES];
    io_outcome(file.read_at(aligned, 0))
}

/// Whether some recorded `READ` `(offset, size)` spanned more than
/// `READ_MAX_GRAINS` of the too-fragmented file's one-byte grains. The
/// span is the request's size CLIPPED to the file: a request at offset
/// `o` of size `s` touches `min(s, FRAG_BYTES - o)` grains, so an
/// 8192-byte request at offset 4096 spans only 4096 and must NOT count.
fn read_crossed_grain_cap(reads: &[(u64, u32)]) -> bool {
    let cap = u64::try_from(READ_MAX_GRAINS).expect("READ_MAX_GRAINS fits u64");
    let file_len = u64::try_from(FRAG_BYTES).expect("FRAG_BYTES fits u64");
    reads.iter().any(|&(offset, size)| {
        let span = u64::from(size).min(file_len.saturating_sub(offset));
        span > cap
    })
}

#[test]
fn read_crossed_grain_cap_uses_the_grain_span_not_the_request_size() {
    assert!(read_crossed_grain_cap(&[(0, 8192)]));
    assert!(
        !read_crossed_grain_cap(&[(4096, 8192)]),
        "8192 bytes requested at offset 4096 span only the file's last 4096 grains"
    );
    assert!(!read_crossed_grain_cap(&[(0, 4096)]));
    assert!(read_crossed_grain_cap(&[(0, 4097)]));
    assert!(!read_crossed_grain_cap(&[]));
}

/// The too-fragmented row is evidence only if SOME recorded `READ` spanned
/// more than `READ_MAX_GRAINS` grains. If none did, the cap was never
/// exercised and the outcome, whatever it was, proves nothing — loud and
/// inconclusive, never green.
fn assert_a_read_crossed_the_grain_cap(state: &ObsState) {
    assert!(
        read_crossed_grain_cap(&state.reads),
        "INCONCLUSIVE-FRAG: no single READ spanned more than {READ_MAX_GRAINS} one-byte \
         grains, so the fragmentation cap was never exercised and the outcome is not evidence \
         either way; every recorded READ as (offset, size): {:?}",
        state.reads
    );
}

fn drive_getxattr_file(mountpoint: &Path) -> Driven {
    let mut value = [0_u8; 64];
    rx_outcome(rustix::fs::getxattr(
        at(mountpoint, N_FILE),
        XATTR_NAME,
        value.as_mut_slice(),
    ))
}

fn drive_access_file_w_ok(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::access(
        at(mountpoint, N_FILE),
        rustix::fs::Access::WRITE_OK,
    ))
}

fn drive_mkdir_new(mountpoint: &Path) -> Driven {
    io_outcome(std::fs::create_dir(at(mountpoint, N_NEW)))
}

fn drive_unlink_file(mountpoint: &Path) -> Driven {
    io_outcome(std::fs::remove_file(at(mountpoint, N_FILE)))
}

fn drive_rmdir_dir(mountpoint: &Path) -> Driven {
    io_outcome(std::fs::remove_dir(at(mountpoint, N_DIR)))
}

fn drive_rename_file_to_new(mountpoint: &Path) -> Driven {
    io_outcome(std::fs::rename(
        at(mountpoint, N_FILE),
        at(mountpoint, N_NEW),
    ))
}

fn drive_renameat2_noreplace_twice(mountpoint: &Path) -> Driven {
    twice(|| {
        rx_outcome(rustix::fs::renameat_with(
            rustix::fs::CWD,
            at(mountpoint, N_FILE),
            rustix::fs::CWD,
            at(mountpoint, N_NEW),
            rustix::fs::RenameFlags::NOREPLACE,
        ))
    })
}

fn drive_mknod_fifo_new(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::mknodat(
        rustix::fs::CWD,
        at(mountpoint, N_NEW),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o644),
        0,
    ))
}

fn drive_chmod_file(mountpoint: &Path) -> Driven {
    io_outcome(std::fs::set_permissions(
        at(mountpoint, N_FILE),
        std::fs::Permissions::from_mode(0o600),
    ))
}

fn drive_chown_file(mountpoint: &Path) -> Driven {
    io_outcome(std::os::unix::fs::chown(
        at(mountpoint, N_FILE),
        Some(1),
        Some(1),
    ))
}

/// EXPLICIT timestamps, never `UTIME_NOW`/`UTIME_OMIT`: the VFS short-cuts
/// an all-omit call to success before any write check, and explicit times
/// need owner-or-capable, which root is.
fn drive_utimensat_file(mountpoint: &Path) -> Driven {
    let times = rustix::fs::Timestamps {
        last_access: rustix::fs::Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
        last_modification: rustix::fs::Timespec {
            tv_sec: 2,
            tv_nsec: 0,
        },
    };
    rx_outcome(rustix::fs::utimensat(
        rustix::fs::CWD,
        at(mountpoint, N_FILE),
        &times,
        rustix::fs::AtFlags::empty(),
    ))
}

fn drive_truncate_file(mountpoint: &Path) -> Driven {
    nix_outcome(nix::unistd::truncate(at(mountpoint, N_FILE).as_path(), 0))
}

fn drive_creat_new(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::open(
        at(mountpoint, N_NEW),
        OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC,
        rustix::fs::Mode::from_raw_mode(0o644),
    ))
}

fn drive_symlink_new(mountpoint: &Path) -> Driven {
    io_outcome(std::os::unix::fs::symlink("file", at(mountpoint, N_NEW)))
}

fn drive_link_new_twice(mountpoint: &Path) -> Driven {
    twice(|| {
        io_outcome(std::fs::hard_link(
            at(mountpoint, N_FILE),
            at(mountpoint, N_NEW),
        ))
    })
}

fn drive_setxattr_file_twice(mountpoint: &Path) -> Driven {
    twice(|| {
        rx_outcome(rustix::fs::setxattr(
            at(mountpoint, N_FILE),
            XATTR_NAME,
            b"v",
            rustix::fs::XattrFlags::CREATE,
        ))
    })
}

fn drive_removexattr_file_twice(mountpoint: &Path) -> Driven {
    twice(|| rx_outcome(rustix::fs::removexattr(at(mountpoint, N_FILE), XATTR_NAME)))
}

fn drive_fsync_file_rdonly_twice(mountpoint: &Path) -> Driven {
    let file = match open_or_outcome(at(mountpoint, N_FILE)) {
        Ok(file) => file,
        Err(outcome) => return outcome,
    };
    twice(|| rx_outcome(rustix::fs::fsync(&file)))
}

fn drive_fsync_dir_twice(mountpoint: &Path) -> Driven {
    let dir = match open_or_outcome(at(mountpoint, N_DIR)) {
        Ok(dir) => dir,
        Err(outcome) => return outcome,
    };
    twice(|| rx_outcome(rustix::fs::fsync(&dir)))
}

// =====================================================================
// Conformance layer 3 — the row table
// =====================================================================

/// A row's expectation per mode; `None` means the mode is not a row for
/// this id, and no test is generated for it (`matrix_is_complete`
/// holds the two in step).
#[derive(Clone, Debug)]
struct ModeTable {
    ro: Option<Expect>,
    noro: Option<Expect>,
    noro_nodefperm: Option<Expect>,
}

impl ModeTable {
    fn get(&self, mode: Mode) -> Option<&Expect> {
        match mode {
            Mode::Ro => self.ro.as_ref(),
            Mode::NoRo => self.noro.as_ref(),
            Mode::NoRoNoDefaultPermissions => self.noro_nodefperm.as_ref(),
        }
    }

    /// The daemon-handler and kernel-precedence rows: the same answer with
    /// and without `ro`.
    fn same(both: Expect) -> Self {
        Self {
            ro: Some(both.clone()),
            noro: Some(both),
            noro_nodefperm: None,
        }
    }

    fn split(ro: Expect, noro: Expect) -> Self {
        Self {
            ro: Some(ro),
            noro: Some(noro),
            noro_nodefperm: None,
        }
    }

    fn triple(ro: Expect, noro: Expect, noro_nodefperm: Expect) -> Self {
        Self {
            ro: Some(ro),
            noro: Some(noro),
            noro_nodefperm: Some(noro_nodefperm),
        }
    }
}

#[derive(Debug)]
struct Row {
    name: &'static str,
    /// Drives the syscall(s) against the mount; returns the raw errno or
    /// success, with the first call's answer beside it for a two-call row.
    drive: fn(&Path) -> Driven,
    /// How many times the driver calls its syscall: 1, or 2 for the rows
    /// whose witness is the SECOND call on the same connection. The runner
    /// asserts the driver reported exactly that many (`Driven::first` is
    /// `Some` iff 2), so a driver quietly reduced to one call — which would
    /// still match the errno — fails the row instead of hollowing out its
    /// latch witness.
    calls: u8,
    /// The write rows: after the counters are snapshotted, re-list the
    /// root's NAME SET and assert it still equals the fixture's five names.
    /// This is a live daemon observation — the drive issued a `LOOKUP`,
    /// never a listing of the root, so this `read_dir` is the mount's first
    /// `READDIRPLUS` of the root and reaches the daemon — and it is a
    /// regression tripwire for a FUTURE write-capable adapter whose landed
    /// create/unlink/rename/mkdir would change the listing. It is NOT the
    /// witness that the write was refused: that is the asserted opcode
    /// count (`Mkdir == 1` and so on) together with the `ENOSYS`/`EROFS`
    /// outcome, and for the current granary the immutable snapshot means
    /// no write can land at all. A landed ATTRIBUTE change (a `setattr`
    /// that truncated `file` and then replied `ENOSYS`, a stored xattr) is
    /// NOT detectable here: the drive's own `LOOKUP` populated the kernel's
    /// entry/attr cache (`ENTRY_TTL`, a minute) and `open` replies
    /// `FOPEN_KEEP_CACHE`, so a post-drive re-stat or `getxattr` of `file`
    /// is served from that cache with no daemon round trip — a re-stat
    /// that looks like coverage and is not. Catching that would need a
    /// `Notifier::inval_entry`/`inval_inode` before the re-stat; deferred,
    /// out of scope while the snapshot is immutable.
    tree_unchanged: bool,
    /// A check on the recorded traffic that must hold BEFORE the outcome
    /// is judged, because without it the outcome is not evidence.
    precheck: Option<fn(&ObsState)>,
    expect: ModeTable,
}

fn row(name: &'static str, drive: fn(&Path) -> Driven, expect: ModeTable) -> Row {
    Row {
        name,
        drive,
        calls: 1,
        tree_unchanged: false,
        precheck: None,
        expect,
    }
}

impl Row {
    fn with_tree_unchanged(mut self) -> Self {
        self.tree_unchanged = true;
        self
    }

    fn with_two_calls(mut self) -> Self {
        self.calls = 2;
        self
    }

    fn with_precheck(mut self, precheck: fn(&ObsState)) -> Self {
        self.precheck = Some(precheck);
        self
    }
}

/// A write row: under `ro` the kernel answers `EROFS` and the opcode is
/// never sent; without `ro` the opcode reaches the daemon exactly once
/// and `noro_errno` is what userspace sees (fuser's default directly, or
/// the kernel's latched rewrite of it). The tree is re-listed afterwards.
///
/// The whole no-`ro` write table is load-bearing on the caller's DAC
/// override (`may_create`/`may_delete`/`inode_permission`, `fs/namei.c`,
/// against the fixture's 0555 directories and 0444 files), which the
/// container-root lane guarantees. No per-row capability probe is added:
/// these rows EXPECT their opcode with count 1, so a kernel `EACCES` shows
/// as `(EACCES, opcode 0)` and fails the `== 1` assertion loudly — an
/// honest failure on a capability-poor root, never a silent skip.
fn write_row(
    name: &'static str,
    drive: fn(&Path) -> Driven,
    op: Op,
    noro_errno: Errno,
    noro_layer: Layer,
    ro_lookups: &[(&[u8], u64)],
    noro_lookups: &[(&[u8], u64)],
) -> Row {
    let count = if matches!(op, Op::Setxattr | Op::Removexattr) || name == "renameat2_noreplace" {
        Count::Exactly(2)
    } else {
        ONCE
    };
    row(
        name,
        drive,
        ModeTable::split(
            refused(Errno::ROFS, Layer::KernelRo)
                .with_ops(&[(op, ZERO)])
                .with_lookups(ro_lookups),
            refused(noro_errno, noro_layer)
                .with_ops(&[(op, count)])
                .with_lookups(noro_lookups),
        ),
    )
    .with_tree_unchanged()
}

macro_rules! refusal_rows {
    ( $( $variant:ident : $( $mode:ident => $test:ident ),+ ; )+ ) => {
        /// Every refusal row; `spec` is an exhaustive match over it, so a
        /// variant without a spec does not compile.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum RowId {
            $( $variant, )+
        }

        const ALL_ROWS: &[RowId] = &[ $( RowId::$variant, )+ ];

        /// Exactly the `(row, mode)` pairs a `#[test]` was generated for.
        const EMITTED: &[(RowId, Mode)] = &[ $( $( (RowId::$variant, Mode::$mode), )+ )+ ];

        $( $(
            #[test]
            fn $test() {
                run_row(RowId::$variant, Mode::$mode, stringify!($test));
            }
        )+ )+
    };
}

refusal_rows! {
    Enametoolong256: Ro => enametoolong_256_ro, NoRo => enametoolong_256_noro;
    Enametoolong1024: Ro => enametoolong_1024_ro, NoRo => enametoolong_1024_noro;
    EnoentOpenMissing: Ro => enoent_open_missing_ro, NoRo => enoent_open_missing_noro;
    EnoentMkdirMissingIntermediate: Ro => enoent_mkdir_missing_intermediate_ro,
        NoRo => enoent_mkdir_missing_intermediate_noro;
    EexistMkdirExisting: Ro => eexist_mkdir_existing_ro, NoRo => eexist_mkdir_existing_noro;
    EexistOpenExclExisting: Ro => eexist_open_excl_existing_ro,
        NoRo => eexist_open_excl_existing_noro;
    EisdirOpenDirWronly: Ro => eisdir_open_dir_wronly_ro, NoRo => eisdir_open_dir_wronly_noro;
    EisdirOpenDirThenRead: Ro => eisdir_open_dir_then_read_ro,
        NoRo => eisdir_open_dir_then_read_noro;
    EnotdirFileAsComponent: Ro => enotdir_file_as_component_ro,
        NoRo => enotdir_file_as_component_noro;
    EloopSelfLoopOpen: Ro => eloop_self_loop_open_ro, NoRo => eloop_self_loop_open_noro;
    EloopOpenNofollow: Ro => eloop_open_nofollow_ro, NoRo => eloop_open_nofollow_noro;
    OpenFileWronly: Ro => open_file_wronly_ro, NoRo => open_file_wronly_noro;
    EioGrainAbsent: Ro => eio_grain_absent_ro, NoRo => eio_grain_absent_noro;
    EioTooFragmented: Ro => eio_too_fragmented_ro, NoRo => eio_too_fragmented_noro;
    EnodataGetxattr: Ro => enodata_getxattr_ro, NoRo => enodata_getxattr_noro;
    AccessWOk: Ro => access_w_ok_ro, NoRo => access_w_ok_noro,
        NoRoNoDefaultPermissions => access_w_ok_noro_nodefperm;
    MkdirNew: Ro => mkdir_new_ro, NoRo => mkdir_new_noro;
    UnlinkFile: Ro => unlink_file_ro, NoRo => unlink_file_noro;
    RmdirDir: Ro => rmdir_dir_ro, NoRo => rmdir_dir_noro;
    RenameFileToNew: Ro => rename_file_to_new_ro, NoRo => rename_file_to_new_noro;
    Renameat2Noreplace: Ro => renameat2_noreplace_ro, NoRo => renameat2_noreplace_noro;
    MknodFifoNew: Ro => mknod_fifo_new_ro, NoRo => mknod_fifo_new_noro;
    ChmodFile: Ro => chmod_file_ro, NoRo => chmod_file_noro;
    ChownFile: Ro => chown_file_ro, NoRo => chown_file_noro;
    UtimensatFile: Ro => utimensat_file_ro, NoRo => utimensat_file_noro;
    TruncateFile: Ro => truncate_file_ro, NoRo => truncate_file_noro;
    CreatNew: Ro => creat_new_ro, NoRo => creat_new_noro;
    SymlinkNew: Ro => symlink_new_ro, NoRo => symlink_new_noro;
    LinkNew: Ro => link_new_ro, NoRo => link_new_noro;
    SetxattrFile: Ro => setxattr_file_ro, NoRo => setxattr_file_noro;
    RemovexattrFile: Ro => removexattr_file_ro, NoRo => removexattr_file_noro;
    FsyncFileRdonly: Ro => fsync_file_rdonly_ro, NoRo => fsync_file_rdonly_noro;
    FsyncDir: Ro => fsync_dir_ro, NoRo => fsync_dir_noro;
}

/// The refusal table. Every row freezes its operand state (existence,
/// kind, destination state, explicit times, descriptor access mode) —
/// those decide which layer wins — and names its expected producer per
/// mode, with the opcode and lookup witnesses that prove it.
#[expect(
    clippy::too_many_lines,
    reason = "the refusal table, one arm per row; splitting it would hide the table's shape"
)]
fn spec(id: RowId) -> Row {
    match id {
        RowId::Enametoolong256 => row(
            "enametoolong_256",
            drive_lstat_probe_256,
            ModeTable::same(
                refused(Errno::NAMETOOLONG, Layer::DaemonHandler)
                    .with_ops(&[(Op::Open, ZERO)])
                    .with_lookups(&[(probe_name(256).as_slice(), 1)]),
            ),
        ),
        RowId::Enametoolong1024 => row(
            "enametoolong_1024",
            drive_lstat_probe_1024,
            ModeTable::same(
                refused(Errno::NAMETOOLONG, Layer::DaemonHandler)
                    .with_ops(&[(Op::Open, ZERO)])
                    .with_lookups(&[(probe_name(1024).as_slice(), 1)]),
            ),
        ),
        RowId::EnoentOpenMissing => row(
            "enoent_open_missing",
            drive_open_missing_rdonly,
            ModeTable::same(
                refused(Errno::NOENT, Layer::DaemonHandler)
                    .with_ops(&[(Op::Open, ZERO)])
                    .with_lookups(&[(N_MISSING, 1)]),
            ),
        ),
        // The write-precedence form of a miss: the daemon's LOOKUP reply
        // for the intermediate decides and the kernel stops there — no
        // MKDIR, no lookup of the final component, `ro` never consulted.
        RowId::EnoentMkdirMissingIntermediate => row(
            "enoent_mkdir_missing_intermediate",
            drive_mkdir_missing_intermediate,
            ModeTable::same(
                refused(Errno::NOENT, Layer::DaemonHandler)
                    .with_ops(&[(Op::Mkdir, ZERO)])
                    .with_lookups(&[(N_MISSING, 1), (N_X, 0)]),
            ),
        ),
        RowId::EexistMkdirExisting => row(
            "eexist_mkdir_existing",
            drive_mkdir_existing_dir,
            ModeTable::same(
                refused(Errno::EXIST, Layer::KernelPrecedence)
                    .with_ops(&[(Op::Mkdir, ZERO)])
                    .with_lookups(&[(N_DIR, 1)]),
            ),
        ),
        RowId::EexistOpenExclExisting => row(
            "eexist_open_excl_existing",
            drive_open_excl_existing_file,
            ModeTable::same(
                refused(Errno::EXIST, Layer::KernelPrecedence)
                    .with_ops(&[(Op::Create, ZERO), (Op::Mknod, ZERO), (Op::Open, ZERO)])
                    .with_lookups(&[(N_FILE, 1)]),
            ),
        ),
        RowId::EisdirOpenDirWronly => row(
            "eisdir_open_dir_wronly",
            drive_open_dir_wronly,
            ModeTable::same(
                refused(Errno::ISDIR, Layer::KernelPrecedence)
                    .with_ops(&[(Op::Open, ZERO), (Op::Opendir, ZERO)])
                    .with_lookups(&[(N_DIR, 1)]),
            ),
        ),
        // The two-syscall form DOES open the directory (OPENDIR = 1); the
        // read is refused by the VFS before any READ is sent.
        RowId::EisdirOpenDirThenRead => row(
            "eisdir_open_dir_then_read",
            drive_open_dir_then_read,
            ModeTable::same(
                refused(Errno::ISDIR, Layer::KernelPrecedence)
                    .with_ops(&[(Op::Opendir, ONCE), (Op::Read, ZERO)])
                    .with_lookups(&[(N_DIR, 1)]),
            ),
        ),
        // The intermediate IS looked up (the walk needs its dentry to see
        // it cannot be descended); the final component never is.
        RowId::EnotdirFileAsComponent => row(
            "enotdir_file_as_component",
            drive_open_file_as_component,
            ModeTable::same(
                refused(Errno::NOTDIR, Layer::KernelPrecedence)
                    .with_ops(&[(Op::Open, ZERO)])
                    .with_lookups(&[(N_FILE, 1), (N_CHILD, 0)]),
            ),
        ),
        // `MAXSYMLINKS` is 40 and the mount advertises no symlink caching,
        // so every hop of the self-loop is a READLINK; later hops of the
        // same name hit the dentry cache, so the LOOKUP count stays 1.
        RowId::EloopSelfLoopOpen => row(
            "eloop_self_loop_open",
            drive_open_self_loop,
            ModeTable::same(
                refused(Errno::LOOP, Layer::KernelPrecedence)
                    .with_ops(&[(Op::Readlink, Count::Exactly(40)), (Op::Open, ZERO)])
                    .with_lookups(&[(N_LOOP, 1)]),
            ),
        ),
        RowId::EloopOpenNofollow => row(
            "eloop_open_nofollow",
            drive_open_self_loop_nofollow,
            ModeTable::same(
                refused(Errno::LOOP, Layer::KernelPrecedence)
                    .with_ops(&[(Op::Readlink, ZERO), (Op::Open, ZERO)])
                    .with_lookups(&[(N_LOOP, 1)]),
            ),
        ),
        // `open_handle`'s non-shipped regression guard: reachable only
        // without `ro`, as root (the kernel's own permission check refuses
        // a non-root caller on the 0444 mode before FUSE is asked — root
        // passes it on `CAP_DAC_OVERRIDE` in the EFFECTIVE set, probed up
        // front).
        RowId::OpenFileWronly => row(
            "open_file_wronly",
            drive_open_file_wronly,
            ModeTable::split(
                refused(Errno::ROFS, Layer::KernelRo)
                    .with_ops(&[(Op::Open, ZERO)])
                    .with_lookups(&[(N_FILE, 1)]),
                refused(Errno::ACCESS, Layer::DaemonHandler)
                    .with_ops(&[(Op::Open, ONCE)])
                    .with_lookups(&[(N_FILE, 1)])
                    .needs_dac_override(CapRegister::Eff),
            ),
        ),
        RowId::EioGrainAbsent => row(
            "eio_grain_absent",
            drive_read_absent_grain,
            ModeTable::same(
                refused(Errno::IO, Layer::DaemonHandler)
                    .with_ops(&[(Op::Open, ONCE), (Op::Read, Count::AtLeast(1))])
                    .with_lookups(&[(N_ABSENT_GRAIN, 1)]),
            ),
        ),
        RowId::EioTooFragmented => row(
            "eio_too_fragmented",
            drive_direct_read_frag,
            ModeTable::same(
                refused(Errno::IO, Layer::DaemonHandler)
                    .with_ops(&[(Op::Open, ONCE)])
                    .with_lookups(&[(N_FRAG, 1)]),
            ),
        )
        .with_precheck(assert_a_read_crossed_the_grain_cap),
        RowId::EnodataGetxattr => row(
            "enodata_getxattr",
            drive_getxattr_file,
            ModeTable::same(
                refused(Errno::NODATA, Layer::DaemonHandler)
                    .with_ops(&[(Op::Getxattr, ONCE)])
                    .with_lookups(&[(N_FILE, 1)]),
            ),
        ),
        // The `access` triple. Under `default_permissions` the kernel
        // decides `access(2)` itself and never sends ACCESS: `EROFS` with
        // `ro`, and SUCCESS without it as root (`CAP_DAC_OVERRIDE` — the
        // mount then CLAIMS writability). That success is decided in the
        // PERMITTED set, not the effective one: `access(2)` from a
        // real-uid-0 caller runs under `access_override_creds`, which
        // copies `CapPrm` into the effective set for the check — so the
        // up-front probe reads `CapPrm`. Only with both controls removed
        // does the daemon's own `access_check` run, its non-shipped
        // regression guard: ACCESS = 1, `EACCES`, and DAC is never
        // consulted (no probe).
        RowId::AccessWOk => row(
            "access_w_ok",
            drive_access_file_w_ok,
            ModeTable::triple(
                refused(Errno::ROFS, Layer::KernelRo)
                    .with_ops(&[(Op::Access, ZERO)])
                    .with_lookups(&[(N_FILE, 1)]),
                succeeds(Layer::KernelPrecedence)
                    .with_ops(&[(Op::Access, ZERO)])
                    .with_lookups(&[(N_FILE, 1)])
                    .needs_dac_override(CapRegister::Prm),
                refused(Errno::ACCESS, Layer::DaemonHandler)
                    .with_ops(&[(Op::Access, ONCE)])
                    .with_lookups(&[(N_FILE, 1)]),
            ),
        ),
        RowId::MkdirNew => write_row(
            "mkdir_new",
            drive_mkdir_new,
            Op::Mkdir,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_NEW, 1)],
            &[(N_NEW, 1)],
        ),
        RowId::UnlinkFile => write_row(
            "unlink_file",
            drive_unlink_file,
            Op::Unlink,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_FILE, 0)],
            &[(N_FILE, 1)],
        ),
        RowId::RmdirDir => write_row(
            "rmdir_dir",
            drive_rmdir_dir,
            Op::Rmdir,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_DIR, 0)],
            &[(N_DIR, 1)],
        ),
        RowId::RenameFileToNew => write_row(
            "rename_file_to_new",
            drive_rename_file_to_new,
            Op::Rename,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_FILE, 0), (N_NEW, 0)],
            &[(N_FILE, 1), (N_NEW, 1)],
        ),
        RowId::Renameat2Noreplace => write_row(
            "renameat2_noreplace",
            drive_renameat2_noreplace_twice,
            Op::Rename,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_FILE, 0), (N_NEW, 0)],
            &[],
        )
        .with_two_calls(),
        RowId::MknodFifoNew => write_row(
            "mknod_fifo_new",
            drive_mknod_fifo_new,
            Op::Mknod,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_NEW, 1)],
            &[(N_NEW, 1)],
        ),
        RowId::ChmodFile => write_row(
            "chmod_file",
            drive_chmod_file,
            Op::Setattr,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_FILE, 1)],
            &[(N_FILE, 1)],
        ),
        RowId::ChownFile => write_row(
            "chown_file",
            drive_chown_file,
            Op::Setattr,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_FILE, 1)],
            &[(N_FILE, 1)],
        ),
        RowId::UtimensatFile => write_row(
            "utimensat_file",
            drive_utimensat_file,
            Op::Setattr,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_FILE, 1)],
            &[(N_FILE, 1)],
        ),
        RowId::TruncateFile => write_row(
            "truncate_file",
            drive_truncate_file,
            Op::Setattr,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_FILE, 1)],
            &[(N_FILE, 1)],
        ),
        RowId::CreatNew => row(
            "creat_new",
            drive_creat_new,
            ModeTable::split(
                refused(Errno::ROFS, Layer::KernelRo)
                    .with_ops(&[(Op::Create, ZERO), (Op::Mknod, ZERO), (Op::Open, ZERO)])
                    .with_lookups(&[(N_NEW, 1)]),
                refused(Errno::ROFS, Layer::DaemonHandler)
                    .with_ops(&[(Op::Create, ONCE), (Op::Mknod, ZERO), (Op::Open, ZERO)])
                    .with_lookups(&[(N_NEW, 1)]),
            ),
        )
        .with_tree_unchanged(),
        RowId::SymlinkNew => write_row(
            "symlink_new",
            drive_symlink_new,
            Op::Symlink,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_NEW, 1)],
            &[(N_NEW, 1)],
        ),
        RowId::LinkNew => row(
            "link_new",
            drive_link_new_twice,
            ModeTable::split(
                refused(Errno::ROFS, Layer::KernelRo)
                    .with_ops(&[(Op::Link, ZERO)])
                    .with_lookups(&[(N_NEW, 2), (N_FILE, 1)]),
                refused(Errno::ROFS, Layer::DaemonHandler)
                    .with_ops(&[(Op::Link, Count::Exactly(2))])
                    .with_lookups(&[(N_NEW, 2), (N_FILE, 1)]),
            ),
        )
        .with_tree_unchanged()
        .with_two_calls(),
        RowId::SetxattrFile => write_row(
            "setxattr_file",
            drive_setxattr_file_twice,
            Op::Setxattr,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_FILE, 1)],
            &[(N_FILE, 1)],
        )
        .with_two_calls(),
        RowId::RemovexattrFile => write_row(
            "removexattr_file",
            drive_removexattr_file_twice,
            Op::Removexattr,
            Errno::ROFS,
            Layer::DaemonHandler,
            &[(N_FILE, 1)],
            &[(N_FILE, 1)],
        )
        .with_two_calls(),
        // `fsync`/`fsyncdir`: the daemon's ENOSYS becomes SUCCESS and the
        // kernel latches `no_fsync`/`no_fsyncdir`; the second call never
        // reaches the daemon. Same in both modes — `ro` does not gate a
        // sync on a read-only descriptor.
        RowId::FsyncFileRdonly => row(
            "fsync_file_rdonly",
            drive_fsync_file_rdonly_twice,
            ModeTable::same(
                succeeds(Layer::KernelLatch)
                    .with_ops(&[(Op::Fsync, ONCE)])
                    .with_lookups(&[(N_FILE, 1)]),
            ),
        )
        .with_two_calls(),
        RowId::FsyncDir => row(
            "fsync_dir",
            drive_fsync_dir_twice,
            ModeTable::same(
                succeeds(Layer::KernelLatch)
                    .with_ops(&[(Op::Fsyncdir, ONCE)])
                    .with_lookups(&[(N_DIR, 1)]),
            ),
        )
        .with_two_calls(),
    }
}

/// The root's current name set as the daemon lists it — a live
/// `READDIRPLUS`, since nothing before this call has listed the root (see
/// `Row::tree_unchanged`). Called only AFTER the counters are snapshotted,
/// so its own opcodes never enter a row's asserted traffic.
fn observe_root_names(mountpoint: &Path) -> BTreeSet<Vec<u8>> {
    std::fs::read_dir(mountpoint)
        .expect("re-list the root after the refused write")
        .map(|entry| entry.expect("read one dirent").file_name().into_vec())
        .collect()
}

fn render_names(names: &BTreeSet<Vec<u8>>) -> Vec<String> {
    names.iter().map(|name| render_name(name)).collect()
}

/// `names` must be exactly the fixture's five root entries.
fn assert_root_names(names: &BTreeSet<Vec<u8>>, context: &str) {
    let expected: BTreeSet<Vec<u8>> = FIXTURE_ROOT_NAMES
        .iter()
        .copied()
        .map(<[u8]>::to_vec)
        .collect();
    assert_eq!(
        *names, expected,
        "the tree must be unchanged after the refused write: {context}"
    );
}

#[test]
fn assert_root_names_accepts_the_fixture_root() {
    let names: BTreeSet<Vec<u8>> = FIXTURE_ROOT_NAMES
        .iter()
        .copied()
        .map(<[u8]>::to_vec)
        .collect();
    assert_root_names(&names, "unit");
}

#[test]
#[should_panic(expected = "the tree must be unchanged after the refused write")]
fn assert_root_names_rejects_a_missing_name() {
    let mut names: BTreeSet<Vec<u8>> = FIXTURE_ROOT_NAMES
        .iter()
        .copied()
        .map(<[u8]>::to_vec)
        .collect();
    assert!(names.remove(N_FILE), "the fixture root lists `file`");
    assert_root_names(&names, "unit");
}

/// The ONE runner for every generated row test: fresh mount of the real
/// adapter under `mode`, drive, snapshot the counters, PRINT the traffic,
/// observe and print the root's names for a write row, the row's
/// precheck, `check_expect`, the name-set assertion, teardown asserting
/// the mount is gone. The two prints come first so nothing that can fail
/// — the tree observation included — suppresses the record of what the
/// daemon saw. A `(row, mode)` without a spec panics rather than
/// returning: `matrix_is_complete` keeps the generated set and the
/// table in step, and a silent return here would be a green that verified
/// nothing.
fn run_row(id: RowId, mode: Mode, test_name: &str) {
    if !require_root(test_name) {
        return;
    }
    let row = spec(id);
    let expect = row
        .expect
        .get(mode)
        .expect("mode emitted without a spec -- matrix_is_complete should have caught this");
    if let Some(reg) = expect.dac_override
        && !require_dac_override(test_name, reg)
    {
        return;
    }
    let (snapshot, backend) = refusal_fixture();
    let obs = Arc::new(Obs::new());
    let fs = Observed {
        inner: GranaryFs::new(snapshot, backend, 1, crate::MountWritability::ReadOnly)
            .expect("fixture snapshot admits the adapter bound"),
        obs: Arc::clone(&obs),
        negotiate: true,
        expected_children: BTreeSet::new(),
    };
    let label = format!("{}-{}", row.name, mode.label());
    let (mountpoint, guard) = spawn_guarded(&label, fs, config_for(mode));
    let driven = (row.drive)(&mountpoint);
    let state = obs.lock().clone();
    let context = describe(row.name, mode, expect, driven, &state);
    // Printed on EVERY run, pass or fail, and BEFORE anything that can
    // fail, so the traffic behind a row is in the log whatever happens.
    eprintln!("OBS {context}");
    let names = row.tree_unchanged.then(|| {
        let names = observe_root_names(&mountpoint);
        eprintln!(
            "TREE row={} mode={mode:?} names={:?}",
            row.name,
            render_names(&names)
        );
        names
    });
    if let Some(precheck) = row.precheck {
        precheck(&state);
    }
    check_expect(&context, expect, driven, row.calls, &state);
    if let Some(names) = names {
        assert_root_names(&names, &context);
    }
    guard.teardown();
}

/// The generated test set and the table must agree exactly: a mode the
/// spec answers that no test was generated for is silent coverage loss,
/// and a generated test whose spec answers `None` would be a vacuous run.
/// Pure table arithmetic — no root, no mount.
#[test]
fn matrix_is_complete() {
    assert!(!ALL_ROWS.is_empty(), "the row set must not be empty");
    assert!(
        !EMITTED.is_empty(),
        "the generated test set must not be empty"
    );
    for id in ALL_ROWS.iter().copied() {
        let table = spec(id).expect;
        for mode in Mode::ALL {
            let specified = table.get(mode).is_some();
            let emitted = EMITTED.contains(&(id, mode));
            assert_eq!(
                specified, emitted,
                "({id:?}, {mode:?}): the spec answers this mode: {specified}; a test was \
                 generated for it: {emitted}"
            );
        }
    }
}

/// The component cap ABOVE 1024 bytes is kernel-dependent (up to v6.14
/// the kernel caps a FUSE name at 1024 bytes; from v6.15 it is
/// `PATH_MAX - 1` once `FUSE_MAX_PAGES` is negotiated with `max_pages > 1`,
/// which fuser always requests), so whether a 1025-byte name reaches the
/// daemon or is refused by the kernel is never asserted — only the errno
/// is, and the producer is printed for the record.
#[test]
fn diag_name_1025() {
    if !require_root("diag_name_1025") {
        return;
    }
    let (snapshot, backend) = refusal_fixture();
    let obs = Arc::new(Obs::new());
    let fs = Observed {
        inner: GranaryFs::new(snapshot, backend, 1, crate::MountWritability::ReadOnly)
            .expect("fixture snapshot admits the adapter bound"),
        obs: Arc::clone(&obs),
        negotiate: true,
        expected_children: BTreeSet::new(),
    };
    let (mountpoint, guard) = spawn_guarded("diag-name-1025", fs, crate::session_config(false));
    let probe = probe_name(1025);
    let outcome = io_outcome(std::fs::symlink_metadata(at(&mountpoint, &probe))).outcome;
    let lookup_arrived = obs.lock().lookups(&probe) > 0;
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").map_or_else(
        |_| "unknown".to_owned(),
        |release| release.trim().to_owned(),
    );
    eprintln!(
        "DIAG name_max: 1025-byte component errno={outcome:?} lookup_arrived={lookup_arrived} \
         kernel={kernel}"
    );
    assert_eq!(
        outcome,
        Outcome::Errno(Errno::NAMETOOLONG),
        "a 1025-byte component must be ENAMETOOLONG from whichever layer answers"
    );
    guard.teardown();
}

/// `/proc/self/mountinfo` octal-escapes a space in the mount-point field
/// (`\040`), so a parser that compared the raw field would report this
/// LIVE mount as absent — and `teardown`/`Drop` remove the scratch
/// directory on exactly that answer. The leaf name here carries a space;
/// the check must still see the mount while it is up, and the directory
/// must be gone once the kernel reports it down.
#[test]
fn mount_state_sees_a_mountpoint_whose_path_holds_a_space() {
    if !require_root("mount_state_sees_a_mountpoint_whose_path_holds_a_space") {
        return;
    }
    let (snapshot, backend) = refusal_fixture();
    let obs = Arc::new(Obs::new());
    let fs = ReferenceFs::new(snapshot, backend, 1, None, obs);
    let (mountpoint, guard) = spawn_guarded("mountinfo space", fs, crate::session_config(false));
    assert!(
        mountpoint.as_os_str().as_bytes().contains(&b' '),
        "the fixture must put a space in the mountpoint's own name: {}",
        mountpoint.display()
    );
    let while_mounted = mount_state(&mountpoint);
    assert!(
        matches!(while_mounted, Ok(true)),
        "a live mount whose path holds a space must be reported mounted, got {while_mounted:?} \
         for {}",
        mountpoint.display()
    );
    let connection = guard.session.connection;
    guard.teardown();
    cleanup_wait::assert_gone(connection, "unmounted scratch directory", || {
        !mountpoint.try_exists().unwrap()
    });
}

#[derive(Debug, Default)]
struct TerminalReplies(Mutex<Vec<(crate::Callback, crate::CallbackOutcome)>>);
impl crate::CallbackObserver for TerminalReplies {
    fn begin(&self, _callback: crate::Callback) -> Option<Box<dyn crate::CallbackScope>> {
        None
    }
    fn completed(&self, callback: crate::Callback, outcome: crate::CallbackOutcome) {
        self.0.lock().unwrap().push((callback, outcome));
    }
}

fn run_writable_refusal(
    id: RowId,
    callback: crate::Callback,
    op: Op,
    calls: u64,
    sync: bool,
    test_name: &str,
) {
    if !require_root(test_name) {
        return;
    }
    let row = spec(id);
    let (snapshot, backend) = refusal_fixture();
    let replies = Arc::new(TerminalReplies::default());
    let observer = Arc::new(Obs::new());
    let writability = if sync {
        crate::MountWritability::ReadOnly
    } else {
        crate::MountWritability::Writable
    };
    let mut inner = GranaryFs::new(snapshot, backend, 1, writability).unwrap();
    inner.observer_for_test(replies.clone());
    let fs = Observed {
        inner,
        obs: observer.clone(),
        negotiate: true,
        expected_children: BTreeSet::new(),
    };
    let (mountpoint, guard) = spawn_guarded(test_name, fs, crate::writable_session_config());
    let driven = (row.drive)(&mountpoint);
    let state = observer.lock().clone();
    let expected = if sync {
        succeeds(Layer::KernelLatch).with_ops(&[(op, ONCE)])
    } else {
        refused(Errno::OPNOTSUPP, Layer::DaemonHandler).with_ops(&[(op, Count::Exactly(calls))])
    };
    let context = describe(row.name, Mode::NoRo, &expected, driven, &state);
    eprintln!("OBS {context}");
    check_expect(&context, &expected, driven, row.calls, &state);
    let dispatched = replies
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|(name, outcome)| *name == callback && *outcome == crate::CallbackOutcome::Refused)
        .count();
    assert_eq!(
        (dispatched, state.ops.get(&op).copied().unwrap_or(0)),
        (usize::try_from(calls).unwrap(), calls),
        "direct refusal and one terminal count per dispatch: {context}"
    );
    assert_root_names(&observe_root_names(&mountpoint), &context);
    guard.teardown();
}

#[test]
fn writable_linux_link_refusal() {
    run_writable_refusal(
        RowId::LinkNew,
        crate::Callback::Link,
        Op::Link,
        2,
        false,
        "writable_linux_link_refusal",
    );
}
#[test]
fn writable_linux_special_node_refusal() {
    run_writable_refusal(
        RowId::MknodFifoNew,
        crate::Callback::Mknod,
        Op::Mknod,
        1,
        false,
        "writable_linux_special_node_refusal",
    );
}
#[test]
fn writable_linux_noncanonical_chmod_refusal() {
    run_writable_refusal(
        RowId::ChmodFile,
        crate::Callback::Setattr,
        Op::Setattr,
        1,
        false,
        "writable_linux_noncanonical_chmod_refusal",
    );
}
#[test]
fn writable_linux_chown_refusal() {
    run_writable_refusal(
        RowId::ChownFile,
        crate::Callback::Setattr,
        Op::Setattr,
        1,
        false,
        "writable_linux_chown_refusal",
    );
}
#[test]
fn writable_linux_utimens_refusal() {
    run_writable_refusal(
        RowId::UtimensatFile,
        crate::Callback::Setattr,
        Op::Setattr,
        1,
        false,
        "writable_linux_utimens_refusal",
    );
}
#[test]
fn writable_linux_setxattr_refusal_has_no_latch() {
    run_writable_refusal(
        RowId::SetxattrFile,
        crate::Callback::Setxattr,
        Op::Setxattr,
        2,
        false,
        "writable_linux_setxattr_refusal_has_no_latch",
    );
}
#[test]
fn writable_linux_removexattr_refusal_has_no_latch() {
    run_writable_refusal(
        RowId::RemovexattrFile,
        crate::Callback::Removexattr,
        Op::Removexattr,
        2,
        false,
        "writable_linux_removexattr_refusal_has_no_latch",
    );
}
#[test]
fn writable_linux_ro_fsync_counts_daemon_refusal_before_kernel_latch() {
    run_writable_refusal(
        RowId::FsyncFileRdonly,
        crate::Callback::Fsync,
        Op::Fsync,
        1,
        true,
        "writable_linux_ro_fsync_counts_daemon_refusal_before_kernel_latch",
    );
}
#[test]
fn writable_linux_ro_fsyncdir_counts_daemon_refusal_before_kernel_latch() {
    run_writable_refusal(
        RowId::FsyncDir,
        crate::Callback::Fsyncdir,
        Op::Fsyncdir,
        1,
        true,
        "writable_linux_ro_fsyncdir_counts_daemon_refusal_before_kernel_latch",
    );
}

#[test]
fn writable_linux_xattr_queries_refuse_including_size_probes() {
    if !require_root("writable_linux_xattr_queries_refuse_including_size_probes") {
        return;
    }
    let (snapshot, backend) = refusal_fixture();
    let replies = Arc::new(TerminalReplies::default());
    let observer = Arc::new(Obs::new());
    let mut inner =
        GranaryFs::new(snapshot, backend, 1, crate::MountWritability::Writable).unwrap();
    inner.observer_for_test(replies.clone());
    let fs = Observed {
        inner,
        obs: observer.clone(),
        negotiate: true,
        expected_children: BTreeSet::new(),
    };
    let (mountpoint, guard) =
        spawn_guarded("rw-xattr-queries", fs, crate::writable_session_config());
    let mut cases = 0;
    for size in [0, 64] {
        let mut bytes = vec![0; size];
        assert_eq!(
            rustix::fs::getxattr(at(&mountpoint, N_FILE), XATTR_NAME, bytes.as_mut_slice()),
            Err(Errno::OPNOTSUPP)
        );
        assert_eq!(
            rustix::fs::listxattr(at(&mountpoint, N_FILE), bytes.as_mut_slice()),
            Err(Errno::OPNOTSUPP)
        );
        cases += 2;
    }
    let state = observer.lock().clone();
    // Snapshot the log: mounted directory callbacks also complete through this observer.
    let replies = replies.0.lock().unwrap().clone();
    for (op, callback) in [
        (Op::Getxattr, crate::Callback::Getxattr),
        (Op::Listxattr, crate::Callback::Listxattr),
    ] {
        assert_eq!(
            (
                state.ops.get(&op).copied().unwrap_or(0),
                replies
                    .iter()
                    .filter(|(name, result)| *name == callback
                        && *result == crate::CallbackOutcome::Refused)
                    .count()
            ),
            (2, 2)
        );
    }
    assert_eq!(cases, 4);
    assert_root_names(&observe_root_names(&mountpoint), "xattr query refusal");
    guard.teardown();
}

#[test]
fn writable_linux_panic_unmounts_and_releases_own_connection() {
    if !require_root("writable_linux_panic_unmounts_and_releases_own_connection") {
        return;
    }
    let case = "writable_linux_panic_unmounts_and_releases_own_connection";
    if !session_guard::require_control_fs(case) {
        return;
    }
    let (snapshot, backend) = refusal_fixture();
    let fs = GranaryFs::new(snapshot, backend, 1, crate::MountWritability::ReadOnly).unwrap();
    let (other_path, other) = spawn_guarded("panic-control", fs, crate::session_config(false));
    let (snapshot, backend) = refusal_fixture();
    let fs = GranaryFs::new(snapshot, backend, 1, crate::MountWritability::ReadOnly).unwrap();
    let (mountpoint, guard) = spawn_guarded("panic-cleanup", fs, crate::session_config(false));
    if !abort::require_available(
        guard.session.abort_available && other.session.abort_available,
        case,
    ) {
        return;
    }
    let connection = guard.session.connection.unwrap();
    // Keep this mount busy across the unwind to exercise the bounded abort path.
    let held = std::fs::File::open(at(&mountpoint, N_FILE)).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = guard;
        panic!("exercise mounted cleanup during unwind");
    }));
    assert!(result.is_err());
    drop(held);
    cleanup_wait::assert_gone(Some(connection), "mount", || {
        !mount_state(&mountpoint).unwrap()
    });
    cleanup_wait::assert_gone(Some(connection), "unmounted scratch directory", || {
        !mountpoint.try_exists().unwrap()
    });
    cleanup_wait::assert_gone(Some(connection), "connection directory", || {
        !session_guard::connection_path(connection)
            .try_exists()
            .unwrap()
    });
    assert!(mount_state(&other_path).unwrap());
    assert!(session_guard::connection_path(other.session.connection.unwrap()).exists());
    assert_eq!(std::fs::read(at(&other_path, N_FILE)).unwrap().len(), 16);
    other.teardown();
}

struct PendingXattr {
    inner: GranaryFs<InMemBackend>,
    pending: Arc<Mutex<Option<ReplyXattr>>>,
}

impl Filesystem for PendingXattr {
    fn getattr(&self, req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        self.inner.getattr(req, ino, fh, reply);
    }

    fn getxattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, size: u32, reply: ReplyXattr) {
        assert_eq!(size, 0, "exercise a pending size probe");
        *self.pending.lock().unwrap() = Some(reply);
    }
}

#[test]
fn writable_linux_pending_size_probe_times_out_and_releases_connection() {
    if !require_root("writable_linux_pending_size_probe_times_out_and_releases_connection") {
        return;
    }
    let case = "writable_linux_pending_size_probe_times_out_and_releases_connection";
    if !session_guard::require_control_fs(case) {
        return;
    }
    let (snapshot, backend) = refusal_fixture();
    let pending = Arc::new(Mutex::new(None));
    let fs = PendingXattr {
        inner: GranaryFs::new(snapshot, backend, 1, crate::MountWritability::ReadOnly).unwrap(),
        pending: pending.clone(),
    };
    let mountpoint = scratch_dir("pending-size-probe");
    let session = fuser::spawn_mount(fs, &mountpoint, &crate::session_config(false)).unwrap();
    let session = SessionGuard::with_deadline(session, &mountpoint, Duration::from_secs(1));
    let guard = MountGuard {
        session,
        mp: mountpoint.clone(),
        torn: false,
    };
    if !abort::require_available(guard.session.abort_available, case) {
        return;
    }
    let connection = guard.session.connection.unwrap();
    let result = rustix::fs::getxattr(&mountpoint, XATTR_NAME, &mut [0_u8; 0]);
    assert!(result.is_err(), "deadline must release the blocked syscall");
    assert!(
        pending.lock().unwrap().take().is_some(),
        "the kernel sent the size probe"
    );
    let mut guard = guard;
    assert_eq!(
        guard.session.finish().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    drop(guard);
    cleanup_wait::assert_gone(Some(connection), "mount", || {
        !mount_state(&mountpoint).unwrap()
    });
    cleanup_wait::assert_gone(Some(connection), "unmounted scratch directory", || {
        !mountpoint.try_exists().unwrap()
    });
    cleanup_wait::assert_gone(Some(connection), "connection directory", || {
        !session_guard::connection_path(connection)
            .try_exists()
            .unwrap()
    });
}
