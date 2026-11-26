// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A directory only one trusted owner can change, resolved by descriptors.
//!
//! **The protection rule** (the shape of OpenSSH's `StrictModes`, with the
//! sticky-directory allowance). One uid is trusted: the directory's owner,
//! `O`.
//! - **The directory**: a real directory (no symbolic link at its name),
//!   owned by `O`, with no group or other access at all (`mode & 0o077 ==
//!   0`). Stricter than the ancestors' rule because the local verbs lock
//!   the directory itself (`flock` on its descriptor): no one but `O` and
//!   root can open it, so no one else can hold that lock. The authority's
//!   state directory takes the same rule for the same reason: the server
//!   locks it too, and a uid that could open it could hold that lock and
//!   refuse the authority's start.
//! - **Every ancestor**, from `/` down: a real directory, owned by root or
//!   by `O`, and either without group or other write or carrying the
//!   sticky bit. In a sticky directory only an entry's owner or root can
//!   rename or remove the entry, and the next component's owner is already
//!   required to be root or `O`, so `/tmp`-like parents are allowed.
//! - **A file in it**: a regular file owned by `O` with no group or other
//!   write. Group or other read is allowed.
//! - **The filesystem** of each component is one whose owner and mode bits
//!   the local kernel enforces ([`filesystem_type_verdict`]): for the
//!   directory, ext2/3/4, xfs and btrfs qualify. An ancestor may also use
//!   overlay or tmpfs. A network or user-space filesystem's bits are not what the
//!   server's kernel enforces, so they protect nothing. An explicit
//!   acknowledgement lifts the type refusals and nothing else. A platform
//!   with no table (anything but Linux) refuses every walk without the
//!   acknowledgement.
//!
//! Who `O` must be depends on the caller: the server requires `O` to be its
//! effective uid ([`ProtectedDir::for_server`]: the enrollment reader and
//! the authority's state directory); a local verb requires its effective
//! uid to be `O` or root ([`ProtectedDir::for_verb`]).
//!
//! **No time-of-check gap.** The walk opens `/` and then each component of
//! the absolute path with `openat(parent, component, O_DIRECTORY |
//! O_NOFOLLOW | O_CLOEXEC)`, and judges each opened descriptor with `fstat`
//! and `fstatfs`, never a name a racer could swap: a link at any component
//! fails the open. Every walked directory descriptor is kept,
//! and every later operation on a file in the directory is an `*at` call on
//! the held descriptor. Each file open is `O_NOFOLLOW | O_NONBLOCK` and is
//! judged by `fstat` on the opened descriptor, so a FIFO cannot block the
//! open and a non-regular file is refused after it.
//!
//! **The trust boundary is the rule itself.** Once the walk passes, only
//! root or `O` can change any component, so a later change is the
//! operator's act. A rename of the directory itself after the walk is not
//! seen through the held descriptor; a caller that must notice one (the
//! server's enrollment reader) compares the path's identity with the held
//! descriptor's on each use.
//!
//! **What the rule does not see.** POSIX ACLs on Linux are covered: an ACL
//! granting any named user or group write forces the mask, which `st_mode`
//! reports in the group bits, to include write, so the rule refuses it.
//! macOS extended ACLs are not checked; macOS is a development venue, never
//! a deployment this rule protects.
//!
//! **Durability.** Every sync, of a file or a directory, is
//! [`File::sync_all`] on the descriptor: `F_FULLFSYNC` on macOS, `fsync` on
//! Linux.
//!
//! **The lock.** [`DirOps::lock`] takes an exclusive `flock` on the held
//! directory descriptor, waiting for it; [`DirOps::try_lock`] takes it or
//! fails at once. No lock file is created. It works on a directory
//! descriptor on Linux and macOS alike.
//!
//! Every file operation goes through one narrow seam ([`DirOps`]), so a
//! test can record the order of the calls, fail any one, or stall it.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use nix::fcntl::{AT_FDCWD, AtFlags, Flock, FlockArg, OFlag};
use nix::sys::stat::{FileStat, Mode};

/// The bits of `st_mode` that name the file type.
const TYPE_MASK: u32 = 0o170_000;
/// A directory's type bits.
const TYPE_DIR: u32 = 0o040_000;
/// A regular file's type bits.
const TYPE_FILE: u32 = 0o100_000;
/// Group or other write.
const GROUP_OTHER_WRITE: u32 = 0o022;
/// Any group or other access: read, write or search.
const GROUP_OTHER_ANY: u32 = 0o077;
/// The sticky bit.
const STICKY: u32 = 0o1000;

/// What `fstat` or `fstatat` reports, in the widths every platform fits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stat {
    pub(crate) dev: i128,
    pub(crate) ino: u64,
    /// The whole `st_mode`: type and permission bits.
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) size: i64,
    pub(crate) mtime: (i64, i64),
    pub(crate) ctime: (i64, i64),
}

impl Stat {
    /// Identity of the opened object, independent of its path spelling.
    pub(crate) fn same_directory(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    fn from_nix(st: &FileStat) -> Self {
        Self {
            dev: i128::from(st.st_dev),
            ino: st.st_ino,
            mode: mode_bits(st.st_mode),
            uid: st.st_uid,
            gid: st.st_gid,
            size: st.st_size,
            mtime: (st.st_mtime, st.st_mtime_nsec),
            ctime: (st.st_ctime, st.st_ctime_nsec),
        }
    }

    pub(crate) const fn is_dir(&self) -> bool {
        self.mode & TYPE_MASK == TYPE_DIR
    }

    pub(crate) const fn is_file(&self) -> bool {
        self.mode & TYPE_MASK == TYPE_FILE
    }

    /// The permission bits, sticky included.
    pub(crate) const fn perms(&self) -> u32 {
        self.mode & 0o7777
    }
}

/// The lock a [`DirOps::lock`] call took on a duplicate of the directory's
/// descriptor: released when dropped (unlocked, and the duplicate closed).
#[derive(Debug)]
pub(crate) struct HeldLock {
    _held: Flock<File>,
}

/// The file operations a protected directory's users make (module docs).
/// Each is one syscall; none follows a symbolic link at the name it is
/// given. A missing name is an error of kind [`io::ErrorKind::NotFound`].
pub(crate) trait DirOps: std::fmt::Debug + Send + Sync + 'static {
    /// Open `/` as a directory.
    fn open_root(&self) -> io::Result<File>;
    /// `openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
    /// O_CLOEXEC)`.
    fn open_dir_at(&self, parent: &File, name: &OsStr) -> io::Result<File>;
    /// `fstat` on an open descriptor.
    fn fstat(&self, file: &File) -> io::Result<Stat>;
    /// `fstatfs`'s filesystem type, or `None` on a platform this module
    /// has no type table for.
    fn fs_magic(&self, file: &File) -> io::Result<Option<u64>>;
    /// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`.
    fn stat_at(&self, dir: &File, name: &str) -> io::Result<Stat>;
    /// `fstatat(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW)`.
    fn stat_path(&self, path: &Path) -> io::Result<Stat>;
    /// `openat(dir, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)`.
    fn open_read_at(&self, dir: &File, name: &str) -> io::Result<File>;
    /// One positional read, which may be short.
    fn read_at(&self, file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize>;
    /// `openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
    /// O_NONBLOCK | O_CLOEXEC, 0o600)`.
    fn create_excl_at(&self, dir: &File, name: &str) -> io::Result<File>;
    /// `flock(LOCK_EX)` on a duplicate of the directory's descriptor,
    /// waiting for it. The duplicate shares the open file description, so
    /// the lock is the directory's own.
    fn lock(&self, dir: &File) -> io::Result<HeldLock>;
    /// `flock(LOCK_EX | LOCK_NB)` on a duplicate of the directory's
    /// descriptor: the lock, or an error of kind
    /// [`io::ErrorKind::WouldBlock`] at once when another description
    /// holds it.
    fn try_lock(&self, dir: &File) -> io::Result<HeldLock>;
    /// `fchown(file, uid, gid)`.
    fn fchown(&self, file: &File, uid: u32, gid: u32) -> io::Result<()>;
    /// Set permission bits on the opened temporary, independently of umask.
    fn fchmod(&self, file: &File, mode: Mode) -> io::Result<()>;
    /// One positional write, which may be short.
    fn write_at(&self, file: &File, bytes: &[u8], offset: u64) -> io::Result<usize>;
    /// Make a file durable ([`File::sync_all`]).
    fn sync_file(&self, file: &File) -> io::Result<()>;
    /// Make a directory's entries durable ([`File::sync_all`] on its
    /// descriptor).
    fn sync_dir(&self, dir: &File) -> io::Result<()>;
    /// `renameat(dir, from, dir, to)`.
    fn rename_at(&self, dir: &File, from: &str, to: &str) -> io::Result<()>;
    /// `unlinkat(dir, name, 0)`.
    fn unlink_at(&self, dir: &File, name: &str) -> io::Result<()>;
    /// The process's effective uid.
    fn euid(&self) -> u32;
}

/// The production [`DirOps`], over `nix` and std.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NixOps;

pub(crate) const fn exclusive_temp_flags() -> OFlag {
    OFlag::O_WRONLY
        .union(OFlag::O_CREAT)
        .union(OFlag::O_EXCL)
        .union(OFlag::O_NOFOLLOW)
        .union(OFlag::O_NONBLOCK)
        .union(OFlag::O_CLOEXEC)
}

fn errno(e: nix::errno::Errno) -> io::Error {
    io::Error::from(e)
}

impl DirOps for NixOps {
    fn open_root(&self) -> io::Result<File> {
        nix::fcntl::open(
            "/",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(errno)
    }

    fn open_dir_at(&self, parent: &File, name: &OsStr) -> io::Result<File> {
        nix::fcntl::openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(errno)
    }

    fn fstat(&self, file: &File) -> io::Result<Stat> {
        nix::sys::stat::fstat(file)
            .map(|st| Stat::from_nix(&st))
            .map_err(errno)
    }

    #[cfg(target_os = "linux")]
    fn fs_magic(&self, file: &File) -> io::Result<Option<u64>> {
        let fs = nix::sys::statfs::fstatfs(file).map_err(errno)?;
        Ok(Some(magic_bits(i128::from(fs.filesystem_type().0))))
    }

    #[cfg(not(target_os = "linux"))]
    fn fs_magic(&self, file: &File) -> io::Result<Option<u64>> {
        // Still a real call, so an unreadable descriptor fails here as it
        // would on Linux; only the type has no table to be judged by.
        nix::sys::statfs::fstatfs(file).map_err(errno)?;
        Ok(None)
    }

    fn stat_at(&self, dir: &File, name: &str) -> io::Result<Stat> {
        nix::sys::stat::fstatat(dir, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map(|st| Stat::from_nix(&st))
            .map_err(errno)
    }

    fn stat_path(&self, path: &Path) -> io::Result<Stat> {
        nix::sys::stat::fstatat(AT_FDCWD, path, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map(|st| Stat::from_nix(&st))
            .map_err(errno)
    }

    fn open_read_at(&self, dir: &File, name: &str) -> io::Result<File> {
        nix::fcntl::openat(
            dir,
            name,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(errno)
    }

    fn read_at(&self, file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        file.read_at(buf, offset)
    }

    fn create_excl_at(&self, dir: &File, name: &str) -> io::Result<File> {
        nix::fcntl::openat(
            dir,
            name,
            exclusive_temp_flags(),
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .map(File::from)
        .map_err(errno)
    }

    fn lock(&self, dir: &File) -> io::Result<HeldLock> {
        Flock::lock(dir.try_clone()?, FlockArg::LockExclusive)
            .map(|held| HeldLock { _held: held })
            .map_err(|(_, e)| errno(e))
    }

    fn try_lock(&self, dir: &File) -> io::Result<HeldLock> {
        Flock::lock(dir.try_clone()?, FlockArg::LockExclusiveNonblock)
            .map(|held| HeldLock { _held: held })
            .map_err(|(_, e)| errno(e))
    }

    fn fchown(&self, file: &File, uid: u32, gid: u32) -> io::Result<()> {
        nix::unistd::fchown(
            file,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
        )
        .map_err(errno)
    }

    fn fchmod(&self, file: &File, mode: Mode) -> io::Result<()> {
        nix::sys::stat::fchmod(file, mode).map_err(errno)
    }

    fn write_at(&self, file: &File, bytes: &[u8], offset: u64) -> io::Result<usize> {
        file.write_at(bytes, offset)
    }

    fn sync_file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn sync_dir(&self, dir: &File) -> io::Result<()> {
        dir.sync_all()
    }

    fn rename_at(&self, dir: &File, from: &str, to: &str) -> io::Result<()> {
        nix::fcntl::renameat(dir, from, dir, to).map_err(errno)
    }

    fn unlink_at(&self, dir: &File, name: &str) -> io::Result<()> {
        nix::unistd::unlinkat(dir, name, nix::unistd::UnlinkatFlags::NoRemoveDir).map_err(errno)
    }

    fn euid(&self) -> u32 {
        nix::unistd::geteuid().as_raw()
    }
}

/// `st_mode` widened to `u32`: `mode_t` is `u16` on macOS and `u32` on
/// Linux.
#[cfg_attr(
    target_os = "linux",
    expect(
        clippy::useless_conversion,
        reason = "`mode_t` is already `u32` on Linux and narrower elsewhere"
    )
)]
fn mode_bits(mode: nix::libc::mode_t) -> u32 {
    u32::from(mode)
}

/// `statfs`'s `f_type` as the table's magic: its low 32 bits. Every magic
/// is a 32-bit value, and a target whose `f_type` is a signed 32-bit word
/// reports one with the top bit set (btrfs's `0x9123683E`) as negative.
#[cfg(any(target_os = "linux", test))]
fn magic_bits(f_type: i128) -> u64 {
    u64::try_from(f_type & 0xFFFF_FFFF).unwrap_or(u64::MAX)
}

// ------------------------------------------------------------ filesystem types

/// ext2, ext3 and ext4 share one magic.
const EXT_MAGIC: u64 = 0xEF53;
const XFS_MAGIC: u64 = 0x5846_5342;
const BTRFS_MAGIC: u64 = 0x9123_683E;
const OVERLAY_MAGIC: u64 = 0x794C_7630;
const TMPFS_MAGIC: u64 = 0x0102_1994;

/// Where in a walk a filesystem type is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsRole {
    /// The protected directory itself, where the state lives.
    Directory,
    /// A directory above it on the path.
    Ancestor,
}

/// Whether a filesystem type is one whose owner and mode bits the local
/// kernel enforces, for a component in `role` (module docs). `magic` is
/// `statfs`'s `f_type` on Linux. The protected directory takes
/// ext2/3/4, xfs and btrfs; an ancestor also takes overlay and tmpfs, common as a
/// container's root or as `/run`. Everything else is refused: CIFS/SMB,
/// NFS, 9p, virtiofs, fuse, ceph and any type this table does not know.
///
/// This is the one place the table lives; every protected walk asks it.
#[must_use]
pub const fn filesystem_type_verdict(magic: u64, role: FsRole) -> bool {
    match magic {
        EXT_MAGIC | XFS_MAGIC | BTRFS_MAGIC => true,
        OVERLAY_MAGIC | TMPFS_MAGIC => matches!(role, FsRole::Ancestor),
        _ => false,
    }
}

// ------------------------------------------------------------ errors

/// Which ownership and mode rule a component broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleBroken {
    /// Not a directory.
    NotDirectory,
    /// An ancestor owned by neither root nor the trusted owner.
    AncestorOwner {
        /// The ancestor's owner.
        uid: u32,
        /// The trusted owner.
        trusted: u32,
    },
    /// An ancestor writable by group or other, without the sticky bit.
    AncestorWritable {
        /// The ancestor's permission bits.
        mode: u32,
    },
    /// The directory open to group or other in any way (read, write or
    /// search).
    DirectoryAccessible {
        /// The directory's permission bits.
        mode: u32,
    },
    /// The directory is not owned by the server's effective uid.
    ServerNotOwner {
        /// The server's effective uid.
        euid: u32,
        /// The directory's owner.
        owner: u32,
    },
    /// A verb runs as neither the directory's owner nor root.
    VerbNotOwner {
        /// The verb's effective uid.
        euid: u32,
        /// The directory's owner.
        owner: u32,
    },
    /// A filesystem type the rule refuses here; `None` on a platform with
    /// no type table.
    FilesystemType {
        /// `statfs`'s type, when the platform reports one.
        magic: Option<u64>,
        /// Where in the walk.
        role: FsRole,
    },
}

impl std::fmt::Display for RuleBroken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDirectory => write!(f, "not a directory"),
            Self::AncestorOwner { uid, trusted } => write!(
                f,
                "owned by uid {uid}, which is neither root nor the directory's owner {trusted}"
            ),
            Self::AncestorWritable { mode } => write!(
                f,
                "mode {mode:04o} lets group or other write, and it is not sticky"
            ),
            Self::DirectoryAccessible { mode } => write!(
                f,
                "mode {mode:04o} gives group or other access; the directory must be 0700 or stricter"
            ),
            Self::ServerNotOwner { euid, owner } => write!(
                f,
                "owned by uid {owner}, not by the server's effective uid {euid}"
            ),
            Self::VerbNotOwner { euid, owner } => write!(
                f,
                "owned by uid {owner}; run the verb as that uid or as root, not as uid {euid}"
            ),
            Self::FilesystemType {
                magic: Some(magic),
                role,
            } => write!(
                f,
                "filesystem type {magic:#x} does not enforce owner and mode bits for {} \
                 (supported: ext2/3/4, xfs, btrfs{}); an explicit acknowledgement lifts this",
                match role {
                    FsRole::Directory => "the protected directory",
                    FsRole::Ancestor => "an ancestor",
                },
                match role {
                    FsRole::Directory => "",
                    FsRole::Ancestor => ", overlay, tmpfs",
                }
            ),
            Self::FilesystemType { magic: None, .. } => write!(
                f,
                "this platform has no filesystem type table, so the protection rule cannot be \
                 claimed; an explicit acknowledgement lifts this (development only)"
            ),
        }
    }
}

/// Why a directory is not protected. Each variant names the component.
#[derive(Debug)]
pub enum ProtectionError {
    /// The path is not absolute.
    NotAbsolute {
        /// The configured path.
        path: PathBuf,
    },
    /// The path names `/` itself, which has no parent to hold.
    NoComponent,
    /// A `.` or `..` component, refused before the walk.
    DotComponent {
        /// The configured path.
        path: PathBuf,
    },
    /// A component is missing.
    Missing {
        /// The path up to and including the component.
        component: PathBuf,
    },
    /// A component is a symbolic link or not a directory.
    LinkOrNotDirectory {
        /// The path up to and including the component.
        component: PathBuf,
    },
    /// A component could not be opened or examined.
    Io {
        /// The path up to and including the component.
        component: PathBuf,
        /// The failure.
        source: io::Error,
    },
    /// A component broke the protection rule.
    Rule {
        /// The path up to and including the component.
        component: PathBuf,
        /// The rule broken.
        rule: RuleBroken,
    },
}

impl std::fmt::Display for ProtectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAbsolute { path } => {
                write!(f, "{} is not an absolute path", path.display())
            }
            Self::NoComponent => write!(f, "the directory cannot be `/` itself"),
            Self::DotComponent { path } => write!(
                f,
                "{} has a `.` or `..` component; name the directory directly",
                path.display()
            ),
            Self::Missing { component } => write!(f, "{} does not exist", component.display()),
            Self::LinkOrNotDirectory { component } => write!(
                f,
                "{} is a symbolic link or not a directory",
                component.display()
            ),
            Self::Io { component, source } => write!(f, "{}: {source}", component.display()),
            Self::Rule { component, rule } => write!(f, "{}: {rule}", component.display()),
        }
    }
}

impl std::error::Error for ProtectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Why a file in a protected directory fails the file rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRuleBroken {
    /// A symbolic link at the name.
    Link,
    /// Not a regular file (a FIFO, a directory, a device).
    NotRegular {
        /// The file's type bits.
        kind: u32,
    },
    /// Owned by someone other than the directory's owner.
    Owner {
        /// The file's owner.
        uid: u32,
        /// The directory's owner.
        expected: u32,
    },
    /// Writable by group or other.
    Writable {
        /// The file's permission bits.
        mode: u32,
    },
}

impl std::fmt::Display for FileRuleBroken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Link => write!(f, "a symbolic link"),
            Self::NotRegular { kind } => write!(f, "not a regular file (type {kind:#o})"),
            Self::Owner { uid, expected } => write!(
                f,
                "owned by uid {uid}, not by the directory's owner {expected}"
            ),
            Self::Writable { mode } => write!(f, "mode {mode:04o} lets group or other write"),
        }
    }
}

/// Judge an opened file's `fstat` against the file rule.
///
/// # Errors
/// The [`FileRuleBroken`] it fails.
pub(crate) const fn judge_file(stat: &Stat, owner: u32) -> Result<(), FileRuleBroken> {
    if !stat.is_file() {
        return Err(FileRuleBroken::NotRegular {
            kind: stat.mode & TYPE_MASK,
        });
    }
    if stat.uid != owner {
        return Err(FileRuleBroken::Owner {
            uid: stat.uid,
            expected: owner,
        });
    }
    if stat.mode & GROUP_OTHER_WRITE != 0 {
        return Err(FileRuleBroken::Writable { mode: stat.perms() });
    }
    Ok(())
}

/// Whether an open failed because a symbolic link sat at the name
/// (`O_NOFOLLOW`'s `ELOOP`).
pub(crate) fn is_link_refusal(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ELOOP)
}

// ------------------------------------------------------------ the walk

/// Who the trusted owner must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Caller {
    /// The owner is the effective uid.
    Server,
    /// The effective uid is the owner or root.
    Verb,
}

/// A protected directory, held open (module docs).
#[derive(Debug)]
pub(crate) struct ProtectedDir {
    /// The directory's descriptor.
    pub(crate) dir: File,
    /// Its parent's descriptor.
    pub(crate) parent: File,
    /// Earlier components, held to preserve the identities of the whole walk.
    ancestors: Vec<File>,
    /// The directory's `fstat` at the walk.
    pub(crate) stat: Stat,
    /// The caller's effective uid.
    pub(crate) euid: u32,
}

impl ProtectedDir {
    /// Held components in walk order, from `/` through the directory itself.
    pub(crate) fn walked_directories(&self) -> impl Iterator<Item = &File> {
        self.ancestors.iter().chain([&self.parent, &self.dir])
    }

    /// The trusted owner `O`.
    pub(crate) const fn owner(&self) -> u32 {
        self.stat.uid
    }

    /// The directory's group, which a root-run verb gives each file it
    /// creates.
    pub(crate) const fn gid(&self) -> u32 {
        self.stat.gid
    }

    /// Walk `path` for the server: the owner must be the effective uid.
    ///
    /// # Errors
    /// The [`ProtectionError`] naming the component at fault.
    pub(crate) fn for_server(
        ops: &impl DirOps,
        path: &Path,
        accept_unsupported_filesystem: bool,
    ) -> Result<Self, ProtectionError> {
        walk(ops, path, accept_unsupported_filesystem, Caller::Server)
    }

    /// Walk `path` for a local verb: the effective uid must be the owner
    /// or root, and the ownership rule uses the owner.
    ///
    /// # Errors
    /// The [`ProtectionError`] naming the component at fault.
    pub(crate) fn for_verb(
        ops: &impl DirOps,
        path: &Path,
        accept_unsupported_filesystem: bool,
    ) -> Result<Self, ProtectionError> {
        walk(ops, path, accept_unsupported_filesystem, Caller::Verb)
    }
}

/// The components of an absolute path, refusing `.` and `..`. Empty
/// components (`//`, a trailing `/`) are skipped.
fn components(path: &Path) -> Result<Vec<&OsStr>, ProtectionError> {
    let bytes = path.as_os_str().as_bytes();
    let Some(rest) = bytes.strip_prefix(b"/") else {
        return Err(ProtectionError::NotAbsolute {
            path: path.to_path_buf(),
        });
    };
    let mut out = Vec::new();
    for part in rest.split(|b| *b == b'/') {
        match part {
            b"" => {}
            b"." | b".." => {
                return Err(ProtectionError::DotComponent {
                    path: path.to_path_buf(),
                });
            }
            name => out.push(OsStr::from_bytes(name)),
        }
    }
    if out.is_empty() {
        return Err(ProtectionError::NoComponent);
    }
    Ok(out)
}

/// One opened component, kept until the owner is known.
struct Seen {
    path: PathBuf,
    stat: Stat,
    magic: Option<u64>,
}

fn walk(
    ops: &impl DirOps,
    path: &Path,
    accept_unsupported_filesystem: bool,
    caller: Caller,
) -> Result<ProtectedDir, ProtectionError> {
    let names = components(path)?;
    let root_path = PathBuf::from("/");
    let io_at = |component: &Path, source: io::Error| ProtectionError::Io {
        component: component.to_path_buf(),
        source,
    };
    let root = ops.open_root().map_err(|e| io_at(&root_path, e))?;
    let examine = |file: &File, at: &Path| -> Result<Seen, ProtectionError> {
        let stat = ops.fstat(file).map_err(|e| io_at(at, e))?;
        let magic = ops.fs_magic(file).map_err(|e| io_at(at, e))?;
        Ok(Seen {
            path: at.to_path_buf(),
            stat,
            magic,
        })
    };
    let mut seen = vec![examine(&root, &root_path)?];
    let mut parents = Vec::new();
    let mut current = root;
    let mut at = root_path;
    for name in names {
        at.push(name);
        let next = ops
            .open_dir_at(&current, name)
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => ProtectionError::Missing {
                    component: at.clone(),
                },
                _ if is_link_refusal(&e) || e.raw_os_error() == Some(libc::ENOTDIR) => {
                    ProtectionError::LinkOrNotDirectory {
                        component: at.clone(),
                    }
                }
                _ => io_at(&at, e),
            })?;
        seen.push(examine(&next, &at)?);
        parents.push(std::mem::replace(&mut current, next));
    }
    // `components` refused a path with no component, so the loop ran.
    let Some(parent) = parents.pop() else {
        return Err(ProtectionError::NoComponent);
    };
    let Some((last, ancestors)) = seen.split_last() else {
        return Err(ProtectionError::NoComponent);
    };
    let euid = ops.euid();
    let owner = last.stat.uid;
    let rule = |s: &Seen, rule: RuleBroken| ProtectionError::Rule {
        component: s.path.clone(),
        rule,
    };
    for ancestor in ancestors {
        judge_ancestor(&ancestor.stat, owner).map_err(|r| rule(ancestor, r))?;
        judge_type(
            ancestor.magic,
            FsRole::Ancestor,
            accept_unsupported_filesystem,
        )
        .map_err(|r| rule(ancestor, r))?;
    }
    judge_directory(&last.stat, owner, euid, caller).map_err(|r| rule(last, r))?;
    judge_type(last.magic, FsRole::Directory, accept_unsupported_filesystem)
        .map_err(|r| rule(last, r))?;
    Ok(ProtectedDir {
        dir: current,
        parent,
        ancestors: parents,
        stat: last.stat,
        euid,
    })
}

const fn judge_ancestor(stat: &Stat, owner: u32) -> Result<(), RuleBroken> {
    if !stat.is_dir() {
        return Err(RuleBroken::NotDirectory);
    }
    if stat.uid != 0 && stat.uid != owner {
        return Err(RuleBroken::AncestorOwner {
            uid: stat.uid,
            trusted: owner,
        });
    }
    if stat.mode & GROUP_OTHER_WRITE != 0 && stat.mode & STICKY == 0 {
        return Err(RuleBroken::AncestorWritable { mode: stat.perms() });
    }
    Ok(())
}

const fn judge_directory(
    stat: &Stat,
    owner: u32,
    euid: u32,
    caller: Caller,
) -> Result<(), RuleBroken> {
    if !stat.is_dir() {
        return Err(RuleBroken::NotDirectory);
    }
    match caller {
        Caller::Server if euid != owner => {
            return Err(RuleBroken::ServerNotOwner { euid, owner });
        }
        Caller::Verb if euid != owner && euid != 0 => {
            return Err(RuleBroken::VerbNotOwner { euid, owner });
        }
        Caller::Server | Caller::Verb => {}
    }
    if stat.mode & GROUP_OTHER_ANY != 0 {
        return Err(RuleBroken::DirectoryAccessible { mode: stat.perms() });
    }
    Ok(())
}

const fn judge_type(
    magic: Option<u64>,
    role: FsRole,
    acknowledged: bool,
) -> Result<(), RuleBroken> {
    if acknowledged {
        return Ok(());
    }
    match magic {
        Some(m) if filesystem_type_verdict(m, role) => Ok(()),
        _ => Err(RuleBroken::FilesystemType { magic, role }),
    }
}

#[cfg(test)]
pub(crate) mod tests;
