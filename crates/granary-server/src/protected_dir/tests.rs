// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The descriptor walk and its rules over the real filesystem, the
//! filesystem-type table, and the recording double the enrollment tests
//! share ([`Recorder`]).
//!
//! The scratch root is the system temporary directory, canonicalised (on
//! macOS `/var` is a symbolic link to `/private/var`, which the walk
//! refuses by design). Walks pass the filesystem acknowledgement except
//! where the type rule is the subject, since macOS has no type table.
//! Arms that need another owner run only as root, and return early
//! otherwise; their names end in `_as_root`.

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use nix::sys::stat::Mode;

use super::{
    DirOps, FsRole, HeldLock, NixOps, ProtectedDir, ProtectionError, RuleBroken, Stat,
    filesystem_type_verdict, magic_bits,
};

// ------------------------------------------------------------ shared helpers

/// A fresh scratch directory, canonical, mode 0o700.
pub(crate) fn scratch(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    #[expect(
        clippy::disallowed_methods,
        reason = "`std::process::id` names a scratch directory so two test binaries do not share \
                  one; nothing under test reads it"
    )]
    let pid = std::process::id();
    let base = std::env::temp_dir().canonicalize().unwrap();
    let dir = base.join(format!(
        "granary-{tag}-{pid}-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

pub(crate) fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub(crate) fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// One call through the seam. Names are recorded; descriptors are named by
/// their inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Call {
    OpenRoot,
    OpenDirAt(String),
    Fstat,
    FsMagic,
    StatAt(String),
    StatPath,
    OpenReadAt(String),
    ReadAt,
    CreateExclAt(String),
    /// The exclusive lock, on the descriptor of this inode.
    Lock {
        ino: u64,
    },
    /// The exclusive lock without waiting, on the descriptor of this
    /// inode.
    TryLock {
        ino: u64,
    },
    Fchown {
        uid: u32,
        gid: u32,
    },
    Fchmod {
        mode: Mode,
    },
    WriteAt,
    SyncFile {
        ino: u64,
    },
    SyncDir {
        ino: u64,
    },
    RenameAt(String, String),
    UnlinkAt(String),
}

/// When a hook runs: before the real call (it can fail it) or after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Before,
    After,
}

pub(crate) type Hook = Arc<dyn Fn(&Call, Phase) -> io::Result<()> + Send + Sync>;

/// The real calls ([`NixOps`]), recorded in order, with an optional hook
/// that can fail a call before it runs or stall it before or after, and an
/// optional effective uid to report instead of the real one.
#[derive(Clone)]
pub(crate) struct Recorder {
    log: Arc<Mutex<Vec<Call>>>,
    hook: Arc<Mutex<Option<Hook>>>,
    euid: Option<u32>,
    /// Model a different trusted owner without changing kernel ownership.
    ownership: Option<(u32, u32)>,
    /// Emulate umask by changing an exclusively created file's actual mode.
    create_mode: Option<Mode>,
    /// Report a different inode for the operator's directory path.
    replaced_path: bool,
    descriptor_kind: Option<u32>,
    fifo_creation: bool,
    /// Report every stat's times as zero: a filesystem whose clock is
    /// coarser than the changes made to it, so two changes share a ctime.
    frozen_times: bool,
    /// Seconds added to the change time `fstat` and `stat_at` report (not
    /// `stat_path`), after any freezing, frozen or not; shared by every
    /// clone, so a test's handle steers the copy the reader holds.
    ctime_skew: Arc<AtomicI64>,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder").finish_non_exhaustive()
    }
}

impl Recorder {
    pub(crate) fn new() -> Self {
        Self {
            log: Arc::default(),
            hook: Arc::default(),
            euid: None,
            ownership: None,
            create_mode: None,
            replaced_path: false,
            descriptor_kind: None,
            fifo_creation: false,
            frozen_times: false,
            ctime_skew: Arc::default(),
        }
    }

    pub(crate) fn with_descriptor_kind(kind: u32) -> Self {
        Self {
            descriptor_kind: Some(kind),
            ..Self::new()
        }
    }
    pub(crate) fn with_fifo_creation() -> Self {
        Self {
            fifo_creation: true,
            ..Self::new()
        }
    }
    pub(crate) fn root_publication(owner: u32, group: u32) -> Self {
        Self {
            euid: Some(0),
            ownership: Some((owner, group)),
            ..Self::new()
        }
    }

    pub(crate) fn with_create_mode(mode: Mode) -> Self {
        Self {
            create_mode: Some(mode),
            ..Self::new()
        }
    }

    pub(crate) fn with_replaced_path() -> Self {
        Self {
            replaced_path: true,
            ..Self::new()
        }
    }

    /// A recorder whose stats all report the same times (`frozen_times`).
    pub(crate) fn with_frozen_times() -> Self {
        Self {
            frozen_times: true,
            ..Self::new()
        }
    }

    /// Offset the change time `fstat` and `stat_at` report by `seconds`.
    pub(crate) fn set_ctime_skew(&self, seconds: i64) {
        self.ctime_skew.store(seconds, Ordering::Relaxed);
    }

    fn times(&self, stat: io::Result<Stat>) -> io::Result<Stat> {
        stat.map(|mut stat| {
            if let Some((owner, group)) = self.ownership {
                stat.uid = owner;
                stat.gid = group;
            }
            if self.frozen_times {
                stat.mtime = (0, 0);
                stat.ctime = (0, 0);
            }
            stat.ctime.0 = stat
                .ctime
                .0
                .saturating_add(self.ctime_skew.load(Ordering::Relaxed));
            stat
        })
    }

    pub(crate) fn with_euid(euid: u32) -> Self {
        Self {
            euid: Some(euid),
            ..Self::new()
        }
    }

    pub(crate) fn set_hook(
        &self,
        hook: impl Fn(&Call, Phase) -> io::Result<()> + Send + Sync + 'static,
    ) {
        *self.hook.lock().unwrap() = Some(Arc::new(hook));
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        self.log.lock().unwrap().clone()
    }

    pub(crate) fn clear_calls(&self) {
        self.log.lock().unwrap().clear();
    }

    fn run<T>(&self, call: Call, real: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        let shown = call.clone();
        self.log.lock().unwrap().push(call);
        let hook = self.hook.lock().unwrap().clone();
        if let Some(hook) = &hook {
            hook(&shown, Phase::Before)?;
        }
        let out = real();
        if let Some(hook) = &hook {
            hook(&shown, Phase::After)?;
        }
        out
    }
}

fn ino(file: &File) -> u64 {
    NixOps.fstat(file).map_or(0, |s| s.ino)
}

impl DirOps for Recorder {
    fn open_root(&self) -> io::Result<File> {
        self.run(Call::OpenRoot, || NixOps.open_root())
    }
    fn open_dir_at(&self, parent: &File, name: &std::ffi::OsStr) -> io::Result<File> {
        self.run(Call::OpenDirAt(name.to_string_lossy().into_owned()), || {
            NixOps.open_dir_at(parent, name)
        })
    }
    fn fstat(&self, file: &File) -> io::Result<Stat> {
        self.times(self.run(Call::Fstat, || NixOps.fstat(file)))
            .map(|mut stat| {
                if stat.is_file()
                    && let Some(kind) = self.descriptor_kind
                {
                    stat.mode = kind | 0o600;
                }
                stat
            })
    }
    fn fs_magic(&self, file: &File) -> io::Result<Option<u64>> {
        self.run(Call::FsMagic, || NixOps.fs_magic(file))
    }
    fn stat_at(&self, dir: &File, name: &str) -> io::Result<Stat> {
        self.times(self.run(Call::StatAt(name.to_owned()), || NixOps.stat_at(dir, name)))
    }
    fn stat_path(&self, path: &Path) -> io::Result<Stat> {
        self.run(Call::StatPath, || NixOps.stat_path(path))
            .map(|mut stat| {
                if self.replaced_path {
                    stat.ino = stat.ino.wrapping_add(1);
                }
                stat
            })
    }
    fn open_read_at(&self, dir: &File, name: &str) -> io::Result<File> {
        self.run(Call::OpenReadAt(name.to_owned()), || {
            NixOps.open_read_at(dir, name)
        })
    }
    fn read_at(&self, file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        self.run(Call::ReadAt, || NixOps.read_at(file, buf, offset))
    }
    fn create_excl_at(&self, dir: &File, name: &str) -> io::Result<File> {
        self.run(Call::CreateExclAt(name.to_owned()), || {
            let file = if self.fifo_creation {
                #[cfg(target_os = "linux")]
                {
                    nix::unistd::mkfifoat(dir, name, Mode::S_IRUSR | Mode::S_IWUSR)
                        .map_err(io::Error::from)?;
                    NixOps.open_read_at(dir, name)?
                }
                #[cfg(not(target_os = "linux"))]
                {
                    return Err(io::Error::other("FIFO substitution requires Linux"));
                }
            } else {
                NixOps.create_excl_at(dir, name)?
            };
            if let Some(mode) = self.create_mode {
                NixOps.fchmod(&file, mode)?;
            }
            Ok(file)
        })
    }
    fn lock(&self, dir: &File) -> io::Result<HeldLock> {
        self.run(Call::Lock { ino: ino(dir) }, || NixOps.lock(dir))
    }
    fn try_lock(&self, dir: &File) -> io::Result<HeldLock> {
        self.run(Call::TryLock { ino: ino(dir) }, || NixOps.try_lock(dir))
    }
    fn fchown(&self, file: &File, uid: u32, gid: u32) -> io::Result<()> {
        self.run(Call::Fchown { uid, gid }, || {
            if self.ownership.is_some() {
                Ok(())
            } else {
                NixOps.fchown(file, uid, gid)
            }
        })
    }
    fn fchmod(&self, file: &File, mode: Mode) -> io::Result<()> {
        self.run(Call::Fchmod { mode }, || NixOps.fchmod(file, mode))
    }
    fn write_at(&self, file: &File, bytes: &[u8], offset: u64) -> io::Result<usize> {
        self.run(Call::WriteAt, || NixOps.write_at(file, bytes, offset))
    }
    fn sync_file(&self, file: &File) -> io::Result<()> {
        self.run(Call::SyncFile { ino: ino(file) }, || NixOps.sync_file(file))
    }
    fn sync_dir(&self, dir: &File) -> io::Result<()> {
        self.run(Call::SyncDir { ino: ino(dir) }, || NixOps.sync_dir(dir))
    }
    fn rename_at(&self, dir: &File, from: &str, to: &str) -> io::Result<()> {
        self.run(Call::RenameAt(from.to_owned(), to.to_owned()), || {
            NixOps.rename_at(dir, from, to)
        })
    }
    fn unlink_at(&self, dir: &File, name: &str) -> io::Result<()> {
        self.run(Call::UnlinkAt(name.to_owned()), || {
            NixOps.unlink_at(dir, name)
        })
    }
    fn euid(&self) -> u32 {
        self.euid.unwrap_or_else(|| NixOps.euid())
    }
}

/// A one-shot pause: the paused side signals it arrived and waits for a
/// release; the controlling side waits for the arrival (bounded) and
/// releases.
#[derive(Debug, Default)]
pub(crate) struct Pause {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Pause {
    /// Called by the paused side: mark arrival, wait for release.
    pub(crate) fn arrive_and_wait(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).unwrap();
        }
    }

    /// Wait until the paused side arrived; `false` if it did not within
    /// `bound`.
    pub(crate) fn wait_arrived(&self, bound: std::time::Duration) -> bool {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, bound, |s| !s.0)
            .unwrap();
        state.0
    }

    pub(crate) fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.1 = true;
        self.changed.notify_all();
    }
}

// ------------------------------------------------------------ the walk

/// Every field of a [`Stat`] is the kernel's: the change time above all,
/// which the enrollment reader's identity relies on and no seam test
/// exercises from a real `stat`.
#[test]
fn a_stat_carries_the_kernels_fields_change_time_included() {
    use std::os::unix::fs::MetadataExt as _;
    let dir = scratch("stat-fields");
    let path = dir.join("f");
    std::fs::write(&path, b"bytes").unwrap();
    // An old modification time: the change time is now, so the two differ
    // and a mapping that confused them is seen.
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000))
        .unwrap();
    let file = File::open(&path).unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    let parent = File::open(&dir).unwrap();
    for stat in [
        NixOps.fstat(&file).unwrap(),
        NixOps.stat_at(&parent, "f").unwrap(),
    ] {
        assert_eq!(stat.ino, meta.ino());
        assert_eq!(stat.mode, meta.mode());
        assert_eq!(stat.dev, i128::from(meta.dev()));
        assert_eq!(stat.uid, meta.uid());
        assert_eq!(stat.gid, meta.gid());
        assert_eq!(stat.size, i64::try_from(meta.size()).unwrap());
        assert_eq!(stat.mtime, (meta.mtime(), meta.mtime_nsec()));
        assert_eq!(stat.ctime, (meta.ctime(), meta.ctime_nsec()));
        assert_ne!(stat.ctime, stat.mtime, "the fixture's two times differ");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_private_scratch_directory_passes_for_the_server_and_a_verb() {
    let dir = scratch("pd-ok").join("enroll");
    std::fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o700);
    let server = ProtectedDir::for_server(&NixOps, &dir, true).unwrap();
    let verb = ProtectedDir::for_verb(&NixOps, &dir, true).unwrap();
    let meta = std::fs::metadata(&dir).unwrap();
    assert_eq!(server.stat.ino, meta.ino());
    assert_eq!(verb.owner(), meta.uid());
    let parent = std::fs::metadata(dir.parent().unwrap()).unwrap();
    assert_eq!(NixOps.fstat(&server.parent).unwrap().ino, parent.ino());
}

#[test]
fn a_relative_path_a_dot_component_and_the_root_are_refused_before_the_walk() {
    let recorder = Recorder::new();
    for (path, want) in [
        ("relative/dir", "NotAbsolute"),
        ("/tmp/./x", "DotComponent"),
        ("/tmp/../x", "DotComponent"),
        ("/", "NoComponent"),
        ("//", "NoComponent"),
    ] {
        let err = ProtectedDir::for_server(&recorder, Path::new(path), true).unwrap_err();
        let got = match err {
            ProtectionError::NotAbsolute { .. } => "NotAbsolute",
            ProtectionError::DotComponent { .. } => "DotComponent",
            ProtectionError::NoComponent => "NoComponent",
            other => panic!("{path}: {other}"),
        };
        assert_eq!(got, want, "{path}");
    }
    assert!(
        recorder.calls().is_empty(),
        "nothing is opened before the path is checked"
    );
}

/// The directory takes no group or other access of any kind, read or
/// search included, for the server and a verb alike: whoever can open it
/// can hold the verbs' lock on it.
#[test]
fn a_directory_open_to_group_or_other_is_refused_by_both_constructors_naming_it() {
    let dir = scratch("pd-gw").join("enroll");
    std::fs::create_dir(&dir).unwrap();
    for mode in [0o770, 0o750, 0o705, 0o701, 0o710] {
        chmod(&dir, mode);
        for (who, got) in [
            (
                "server",
                ProtectedDir::for_server(&NixOps, &dir, true).map(|_| ()),
            ),
            (
                "verb",
                ProtectedDir::for_verb(&NixOps, &dir, true).map(|_| ()),
            ),
        ] {
            match got {
                Err(ProtectionError::Rule {
                    component,
                    rule: RuleBroken::DirectoryAccessible { mode: got },
                }) => {
                    assert_eq!((component, got), (dir.clone(), mode), "{who} {mode:o}");
                    let shown = RuleBroken::DirectoryAccessible { mode }.to_string();
                    assert!(shown.contains("group or other access"), "{shown}");
                }
                other => panic!("{who} {mode:o}: {other:?}"),
            }
        }
    }
    chmod(&dir, 0o700);
    ProtectedDir::for_server(&NixOps, &dir, true).unwrap();
    ProtectedDir::for_verb(&NixOps, &dir, true).unwrap();
}

/// `flock` on a directory descriptor excludes a second open of the same
/// directory, and dropping the held lock releases it (Linux and macOS).
#[test]
fn the_lock_is_a_flock_on_the_directory_descriptor_and_drop_releases_it() {
    let dir = scratch("pd-lock").join("enroll");
    std::fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o700);
    let held = ProtectedDir::for_verb(&NixOps, &dir, true).unwrap();
    let lock = NixOps.lock(&held.dir).unwrap();
    let probe = || {
        nix::fcntl::Flock::lock(
            File::open(&dir).unwrap(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .map(drop)
        .map_err(|(_, e)| e)
    };
    assert_eq!(probe(), Err(nix::errno::Errno::EWOULDBLOCK));
    assert!(
        std::fs::read_dir(&dir).unwrap().next().is_none(),
        "no lock file was created"
    );
    drop(lock);
    assert_eq!(probe(), Ok(()));
}

#[test]
fn a_symbolic_link_at_any_component_is_refused() {
    let base = scratch("pd-link");
    let real = base.join("real");
    std::fs::create_dir(&real).unwrap();
    chmod(&real, 0o700);
    std::fs::create_dir(real.join("enroll")).unwrap();
    chmod(&real.join("enroll"), 0o700);
    std::os::unix::fs::symlink(&real, base.join("link")).unwrap();
    std::os::unix::fs::symlink(real.join("enroll"), base.join("final-link")).unwrap();
    for (path, at) in [
        (base.join("link/enroll"), base.join("link")),
        (base.join("final-link"), base.join("final-link")),
    ] {
        match ProtectedDir::for_verb(&NixOps, &path, true).unwrap_err() {
            ProtectionError::LinkOrNotDirectory { component } => assert_eq!(component, at),
            other => panic!("{}: {other}", path.display()),
        }
    }
}

#[test]
fn a_missing_component_and_a_file_component_are_named() {
    let base = scratch("pd-missing");
    match ProtectedDir::for_server(&NixOps, &base.join("nope/enroll"), true).unwrap_err() {
        ProtectionError::Missing { component } => assert_eq!(component, base.join("nope")),
        other => panic!("{other}"),
    }
    std::fs::write(base.join("file"), b"x").unwrap();
    match ProtectedDir::for_server(&NixOps, &base.join("file/enroll"), true).unwrap_err() {
        ProtectionError::LinkOrNotDirectory { component } => {
            assert_eq!(component, base.join("file"));
        }
        other => panic!("{other}"),
    }
}

#[test]
fn a_writable_ancestor_is_refused_unless_it_is_sticky() {
    let base = scratch("pd-anc");
    let open = base.join("open");
    std::fs::create_dir(&open).unwrap();
    let dir = open.join("enroll");
    std::fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o700);
    chmod(&open, 0o777);
    match ProtectedDir::for_server(&NixOps, &dir, true).unwrap_err() {
        ProtectionError::Rule {
            component,
            rule: RuleBroken::AncestorWritable { mode: 0o777 },
        } => assert_eq!(component, open),
        other => panic!("{other}"),
    }
    chmod(&open, 0o1777);
    ProtectedDir::for_server(&NixOps, &dir, true).unwrap();
}

#[test]
fn the_server_must_own_the_directory_and_a_verb_must_be_its_owner_or_root() {
    let dir = scratch("pd-owner").join("enroll");
    std::fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o700);
    let me = nix::unistd::geteuid().as_raw();
    let other = me.wrapping_add(4242);
    match ProtectedDir::for_server(&Recorder::with_euid(other), &dir, true).unwrap_err() {
        ProtectionError::Rule {
            rule: RuleBroken::ServerNotOwner { euid, owner },
            ..
        } => assert_eq!((euid, owner), (other, me)),
        e => panic!("{e}"),
    }
    match ProtectedDir::for_verb(&Recorder::with_euid(other), &dir, true).unwrap_err() {
        ProtectionError::Rule {
            rule: RuleBroken::VerbNotOwner { euid, owner },
            ..
        } => assert_eq!((euid, owner), (other, me)),
        e => panic!("{e}"),
    }
    // A verb run as root walks with the directory's owner as `O`.
    let as_root = ProtectedDir::for_verb(&Recorder::with_euid(0), &dir, true).unwrap();
    assert_eq!((as_root.owner(), as_root.euid), (me, 0));
}

#[test]
fn an_ancestor_of_another_owner_is_refused_as_root() {
    if !is_root() {
        return;
    }
    let base = scratch("pd-anc-owner");
    let theirs = base.join("theirs");
    std::fs::create_dir(&theirs).unwrap();
    chmod(&theirs, 0o755);
    let dir = theirs.join("enroll");
    std::fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o700);
    // The directory belongs to uid 4242; its parent to uid 4343.
    nix::unistd::chown(&dir, Some(nix::unistd::Uid::from_raw(4242)), None).unwrap();
    nix::unistd::chown(&theirs, Some(nix::unistd::Uid::from_raw(4343)), None).unwrap();
    match ProtectedDir::for_verb(&NixOps, &dir, true).unwrap_err() {
        ProtectionError::Rule {
            component,
            rule:
                RuleBroken::AncestorOwner {
                    uid: 4343,
                    trusted: 4242,
                },
        } => assert_eq!(component, theirs),
        other => panic!("{other}"),
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn without_a_type_table_the_walk_refuses_unless_acknowledged() {
    let dir = scratch("pd-type").join("enroll");
    std::fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o700);
    match ProtectedDir::for_server(&NixOps, &dir, false).unwrap_err() {
        ProtectionError::Rule {
            component,
            rule:
                RuleBroken::FilesystemType {
                    magic: None,
                    role: FsRole::Ancestor,
                },
        } => assert_eq!(component, PathBuf::from("/")),
        other => panic!("{other}"),
    }
    ProtectedDir::for_server(&NixOps, &dir, true).unwrap();
}

/// On Linux the walk without the acknowledgement agrees with the table on
/// every component, whatever filesystems this host has.
#[cfg(target_os = "linux")]
#[test]
fn on_linux_the_unacknowledged_walk_follows_the_table() {
    let dir = scratch("pd-type").join("enroll");
    std::fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o700);
    let mut expected = Ok(());
    let mut at = PathBuf::from("/");
    let mut paths = vec![at.clone()];
    for c in dir.components().skip(1) {
        at.push(c);
        paths.push(at.clone());
    }
    let last = paths.len() - 1;
    for (i, p) in paths.iter().enumerate() {
        let f = File::open(p).unwrap();
        let magic = NixOps.fs_magic(&f).unwrap().unwrap();
        let role = if i == last {
            FsRole::Directory
        } else {
            FsRole::Ancestor
        };
        if expected.is_ok() && !filesystem_type_verdict(magic, role) {
            expected = Err(p.clone());
        }
    }
    match (ProtectedDir::for_server(&NixOps, &dir, false), expected) {
        (Ok(_), Ok(())) => {}
        (
            Err(ProtectionError::Rule {
                component,
                rule: RuleBroken::FilesystemType { .. },
            }),
            Err(p),
        ) => {
            assert_eq!(component, p);
        }
        (got, want) => panic!("walk {got:?}, table {want:?}"),
    }
}

#[test]
fn the_type_table_takes_ext_xfs_btrfs_everywhere_and_overlay_tmpfs_only_above() {
    for magic in [0xEF53, 0x5846_5342, 0x9123_683E] {
        assert!(
            filesystem_type_verdict(magic, FsRole::Directory),
            "{magic:#x}"
        );
        assert!(
            filesystem_type_verdict(magic, FsRole::Ancestor),
            "{magic:#x}"
        );
    }
    for magic in [0x794C_7630, 0x0102_1994] {
        assert!(
            !filesystem_type_verdict(magic, FsRole::Directory),
            "{magic:#x}"
        );
        assert!(
            filesystem_type_verdict(magic, FsRole::Ancestor),
            "{magic:#x}"
        );
    }
    // nfs, smb, cifs, smb2, 9p, virtiofs, fuse, ceph, and unknowns.
    for magic in [
        0x6969,
        0x517B,
        0xFF53_4D42,
        0xFE53_4D42,
        0x0102_1997,
        0x6A65_6A63,
        0x6573_5546,
        0x00C3_6400,
        0,
        1,
        u64::MAX,
    ] {
        assert!(
            !filesystem_type_verdict(magic, FsRole::Directory),
            "{magic:#x}"
        );
        assert!(
            !filesystem_type_verdict(magic, FsRole::Ancestor),
            "{magic:#x}"
        );
    }
}

#[test]
fn a_signed_32_bit_f_type_is_read_as_its_unsigned_magic() {
    let btrfs = 0x9123_683E_u32;
    let signed = i32::from_ne_bytes(btrfs.to_ne_bytes());
    assert!(signed < 0, "the fixture is the negative case");
    let magic = magic_bits(i128::from(signed));
    assert_eq!(magic, 0x9123_683E);
    assert!(filesystem_type_verdict(magic, FsRole::Directory));
    // A 64-bit `f_type` holds the same magic unchanged.
    assert_eq!(magic_bits(i128::from(i64::from(btrfs))), 0x9123_683E);
    assert_eq!(magic_bits(0xEF53), 0xEF53);
}

#[test]
fn the_walk_opens_each_component_from_its_parent_and_judges_each_descriptor() {
    let dir = scratch("pd-calls").join("enroll");
    std::fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o700);
    let recorder = Recorder::new();
    ProtectedDir::for_server(&recorder, &dir, true).unwrap();
    let calls = recorder.calls();
    let opens: Vec<_> = calls
        .iter()
        .filter_map(|c| match c {
            Call::OpenDirAt(name) => Some(name.clone()),
            _ => None,
        })
        .collect();
    let names: Vec<String> = dir
        .components()
        .skip(1)
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    assert_eq!(opens, names);
    assert_eq!(calls.first(), Some(&Call::OpenRoot));
    let fstats = calls.iter().filter(|c| **c == Call::Fstat).count();
    let magics = calls.iter().filter(|c| **c == Call::FsMagic).count();
    assert_eq!((fstats, magics), (names.len() + 1, names.len() + 1));
}

#[test]
fn directory_identity_requires_device_and_inode() {
    let dir = scratch("directory-identity");
    let held = ProtectedDir::for_server(&NixOps, &dir, true).unwrap();
    let a = held.stat;
    assert!(a.same_directory(&a));
    assert!(!a.same_directory(&Stat {
        dev: a.dev + 1,
        ..a
    }));
    assert!(!a.same_directory(&Stat {
        ino: a.ino + 1,
        ..a
    }));
    std::fs::remove_dir_all(dir).unwrap();
}
