// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The file operations the log adapter makes, as one narrow seam
//! ([`FileOps`]), and their production implementation ([`StdFileOps`]).
//! Every syscall the adapter issues goes through here, so a test can
//! record them in order and fail any one of them.
//!
//! The production implementation holds the state directory, resolved by
//! the protection walk (`crate::protected_dir`, the server's rule: the
//! directory owned by the server's uid with no group or other access),
//! its parent's descriptor, and an exclusive `flock` on the directory's
//! own descriptor, all for its whole life. Every call names a file by its
//! name in the held directory and is an `*at` call on its descriptor;
//! every directory sync is on a held descriptor. No call follows a
//! symbolic link at the name it is given.
//!
//! - **The state name.** [`FileOps::check_state`] re-reads the configured
//!   name relative to the held parent (`fstatat(parent, name,
//!   AT_SYMLINK_NOFOLLOW)`) and refuses unless it is the held directory,
//!   by `(st_dev, st_ino)`: a link there, another directory, or nothing.
//! - **Every open** is `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and is judged
//!   by `fstat` on the opened descriptor: a regular file, owned by the
//!   directory's owner, with no group or other write (the protection
//!   rule's file rule). Log and marker opens cannot block on a FIFO and
//!   refuse it afterward. The unfence timestamp walk checks entry types
//!   with `fstatat` before opening, then checks the opened identity.
//! - **Modes.** A file is created `0o600` by its create mode, never by
//!   changing the umask. An existing file that grants group or other read
//!   is accepted without a word: behind a directory no other uid can
//!   enter, its read bits reach no one.
//! - **The marker's read** takes at most the format's largest marker plus
//!   one byte, so a longer file reads as a wrong-length marker the decoder
//!   refuses.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use granary_core::runmarker::{CLEAN_LEN, RUNNING_LEN};
use nix::fcntl::{AtFlags, OFlag};
use nix::sys::stat::Mode;

use super::FileLogConfigError;
use crate::protected_dir::{DirOps, HeldLock, NixOps, ProtectedDir, judge_file};

/// The most bytes a marker read takes: the largest marker, plus one so a
/// longer file is seen to be longer.
pub(crate) const MARKER_READ_LIMIT: usize = RUNNING_LEN + 1;
const _: () = assert!(RUNNING_LEN >= CLEAN_LEN);

/// What is at a name, without following a symbolic link there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

/// What the held state directory holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirState {
    Empty,
    Occupied,
}

/// One of the two held directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Held {
    /// The state directory.
    State,
    /// The directory that holds it (spec §6.2's anchor).
    Anchor,
}

/// The file operations the adapter makes (module docs). Each is one
/// syscall, or the smallest sequence for it, on a name in the held state
/// directory.
pub(crate) trait FileOps: Send + Sync {
    /// An open file description.
    type File: Send + Sync;

    /// Whether the configured state directory's name is still the held
    /// directory: `Ok` when it is, an error when anything else (or
    /// nothing) is there.
    fn check_state(&self) -> io::Result<()>;
    /// What is at `name`, not following a link there; `None` when nothing
    /// is.
    fn stat_at(&self, name: &str) -> io::Result<Option<Kind>>;
    /// Whether the held directory is empty or holds anything.
    fn dir_state(&self) -> io::Result<DirState>;
    /// Create `name` exclusively, read-write, mode `0o600`, refusing a
    /// link at the name.
    fn create_new(&self, name: &str) -> io::Result<Self::File>;
    /// Open the regular file at `name` read-write, refusing a link there
    /// and a file the protection rule refuses.
    fn open_rw(&self, name: &str) -> io::Result<Self::File>;
    /// Read at most [`MARKER_READ_LIMIT`] bytes of the regular file at
    /// `name`, refusing a link there and a file the protection rule
    /// refuses.
    fn read_marker(&self, name: &str) -> io::Result<Vec<u8>>;
    /// Read the whole of `file` through its own description.
    fn read_all(&self, file: &Self::File) -> io::Result<Vec<u8>>;
    /// One positional write of `bytes` at `offset`, which may be short.
    fn pwrite(&self, file: &Self::File, offset: u64, bytes: &[u8]) -> io::Result<usize>;
    /// Make `file` durable: `F_FULLFSYNC` on macOS, `fsync` elsewhere.
    fn sync_file(&self, file: &Self::File) -> io::Result<()>;
    /// Make a held directory's entries durable, through its descriptor.
    fn sync_dir(&self, dir: Held) -> io::Result<()>;
    /// Cut `file` to `len` bytes.
    fn truncate(&self, file: &Self::File, len: u64) -> io::Result<()>;
    /// Link `from` to the new name `to`, never replacing a name there.
    fn link(&self, from: &str, to: &str) -> io::Result<()>;
    /// Remove the name `name`.
    fn unlink(&self, name: &str) -> io::Result<()>;
    /// Rename `from` over `to`.
    fn rename(&self, from: &str, to: &str) -> io::Result<()>;
}

/// The production file operations (module docs). `File::sync_all` is
/// `F_FULLFSYNC` on macOS, on a directory's descriptor too, and `fsync`
/// on Linux.
#[derive(Debug)]
pub(crate) struct StdFileOps {
    /// The state directory, its parent, and its `fstat` at the walk.
    held: ProtectedDir,
    /// The state directory's name in its parent.
    name: OsString,
    /// The exclusive lock on the state directory, for the adapter's life.
    _lock: HeldLock,
}

fn errno(e: nix::errno::Errno) -> io::Error {
    io::Error::from(e)
}

/// A refusal the adapter answers as an I/O error of its own kind.
fn refused(what: String) -> io::Error {
    io::Error::other(what)
}

impl StdFileOps {
    pub(super) fn directory_stat(&self) -> &crate::protected_dir::Stat {
        &self.held.stat
    }

    /// Resolve the state directory at `state` by the protection walk,
    /// and lock it (module docs).
    ///
    /// # Errors
    /// [`FileLogConfigError::Directory`] when the walk refuses it (absent,
    /// a link, the owner, a mode, a filesystem type);
    /// [`FileLogConfigError::Locked`] when another description holds its
    /// lock; [`FileLogConfigError::Lock`] when the lock call fails
    /// otherwise.
    pub(crate) fn open(
        state: &Path,
        accept_unsupported_filesystem: bool,
    ) -> Result<Self, FileLogConfigError> {
        let held = ProtectedDir::for_server(&NixOps, state, accept_unsupported_filesystem)
            .map_err(FileLogConfigError::Directory)?;
        Self::from_held(state, held)
    }

    pub(crate) fn for_verb(state: &Path, accept: bool) -> Result<Self, FileLogConfigError> {
        let held = ProtectedDir::for_verb(&NixOps, state, accept)
            .map_err(FileLogConfigError::Directory)?;
        Self::from_held(state, held)
    }

    fn from_held(state: &Path, held: ProtectedDir) -> Result<Self, FileLogConfigError> {
        // The walk refused a path with no last component, so this is the
        // name it opened last.
        let name = state
            .file_name()
            .ok_or(FileLogConfigError::Directory(
                crate::protected_dir::ProtectionError::NoComponent,
            ))?
            .to_os_string();
        let lock = NixOps.try_lock(&held.dir).map_err(|e| {
            if e.kind() == io::ErrorKind::WouldBlock {
                FileLogConfigError::Locked {
                    path: state.to_path_buf(),
                }
            } else {
                FileLogConfigError::Lock {
                    path: state.to_path_buf(),
                    source: e,
                }
            }
        })?;
        Ok(Self {
            held,
            name,
            _lock: lock,
        })
    }

    pub(crate) fn state_times(&self) -> io::Result<crate::lifecycle::StateTimes> {
        self.check_state()?;
        let mut times = crate::lifecycle::StateTimes::default();
        let mut pending = vec![self.held.dir.try_clone()?];
        while let Some(dir) = pending.pop() {
            let stat = NixOps.fstat(&dir)?;
            times.directories.push(stat.ctime);
            let mut entries = nix::dir::Dir::openat(
                &dir,
                ".",
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(errno)?;
            for entry in entries.iter() {
                let entry = entry.map_err(errno)?;
                let name = entry.file_name();
                if name.to_bytes() == b"." || name.to_bytes() == b".." {
                    continue;
                }
                let (file, stat) = inspect_time_entry(
                    name,
                    || {
                        nix::sys::stat::fstatat(&dir, name, AtFlags::AT_SYMLINK_NOFOLLOW)
                            .map_err(errno)
                    },
                    || {
                        nix::fcntl::openat(
                            &dir,
                            name,
                            OFlag::O_RDONLY
                                | OFlag::O_NOFOLLOW
                                | OFlag::O_NONBLOCK
                                | OFlag::O_CLOEXEC,
                            Mode::empty(),
                        )
                        .map(File::from)
                        .map_err(errno)
                    },
                    |file| NixOps.fstat(file),
                )?;
                if stat.is_dir() {
                    pending.push(file);
                } else {
                    judge_file(&stat, self.held.owner())
                        .map_err(|rule| refused(rule.to_string()))?;
                    times.files.push(stat.mtime.max(stat.ctime));
                }
            }
        }
        self.check_state()?;
        Ok(times)
    }

    /// `openat(dir, name, flags | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
    /// mode)`, then the file rule on the opened descriptor's `fstat`.
    fn open_at(&self, name: &str, flags: OFlag, mode: Mode) -> io::Result<File> {
        let file = nix::fcntl::openat(
            &self.held.dir,
            name,
            flags | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            mode,
        )
        .map(File::from)
        .map_err(errno)?;
        // A root-run local verb creates the temporary for the trusted owner,
        // so its eventual log or marker remains usable by the server uid.
        if flags.contains(OFlag::O_CREAT) && NixOps.euid() == 0 {
            NixOps.fchown(&file, self.held.stat.uid, self.held.stat.gid)?;
        }
        let stat = NixOps.fstat(&file)?;
        judge_file(&stat, self.held.owner()).map_err(|rule| refused(format!("{name}: {rule}")))?;
        Ok(file)
    }
}

impl FileOps for StdFileOps {
    type File = File;

    fn check_state(&self) -> io::Result<()> {
        let at = nix::sys::stat::fstatat(
            &self.held.parent,
            self.name.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(errno)?;
        if (i128::from(at.st_dev), at.st_ino) == (self.held.stat.dev, self.held.stat.ino) {
            Ok(())
        } else {
            Err(refused(format!(
                "{} is no longer the state directory this authority holds",
                Path::new(&self.name).display()
            )))
        }
    }

    fn stat_at(&self, name: &str) -> io::Result<Option<Kind>> {
        match NixOps.stat_at(&self.held.dir, name) {
            Ok(stat) => Ok(Some(match stat.mode & 0o170_000 {
                0o120_000 => Kind::Symlink,
                _ if stat.is_dir() => Kind::Dir,
                _ if stat.is_file() => Kind::File,
                _ => Kind::Other,
            })),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn dir_state(&self) -> io::Result<DirState> {
        // A description of its own, so the read starts at the first entry.
        let mut dir = nix::dir::Dir::openat(
            &self.held.dir,
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?;
        for entry in dir.iter() {
            let entry = entry.map_err(errno)?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                return Ok(DirState::Occupied);
            }
        }
        Ok(DirState::Empty)
    }

    fn create_new(&self, name: &str) -> io::Result<File> {
        self.open_at(
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
    }

    fn open_rw(&self, name: &str) -> io::Result<File> {
        self.open_at(name, OFlag::O_RDWR, Mode::empty())
    }

    fn read_marker(&self, name: &str) -> io::Result<Vec<u8>> {
        let file = self.open_at(name, OFlag::O_RDONLY, Mode::empty())?;
        let mut bytes = vec![0_u8; MARKER_READ_LIMIT];
        let mut len = 0;
        while let Some(rest) = bytes.get_mut(len..).filter(|rest| !rest.is_empty()) {
            let offset = u64::try_from(len).unwrap_or(u64::MAX);
            match file.read_at(rest, offset) {
                Ok(0) => break,
                Ok(n) => len += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        bytes.truncate(len);
        Ok(bytes)
    }

    fn read_all(&self, file: &File) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            let offset = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            match file.read_at(&mut chunk, offset) {
                Ok(0) => return Ok(bytes),
                Ok(n) => bytes.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn pwrite(&self, file: &File, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        file.write_at(bytes, offset)
    }

    fn sync_file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn sync_dir(&self, dir: Held) -> io::Result<()> {
        match dir {
            Held::State => self.held.dir.sync_all(),
            Held::Anchor => self.held.parent.sync_all(),
        }
    }

    fn truncate(&self, file: &File, len: u64) -> io::Result<()> {
        file.set_len(len)
    }

    fn link(&self, from: &str, to: &str) -> io::Result<()> {
        nix::unistd::linkat(&self.held.dir, from, &self.held.dir, to, AtFlags::empty())
            .map_err(errno)
    }

    fn unlink(&self, name: &str) -> io::Result<()> {
        NixOps.unlink_at(&self.held.dir, name)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        NixOps.rename_at(&self.held.dir, from, to)
    }
}

/// Refuse unsupported types before opening, then verify the opened identity.
fn inspect_time_entry(
    name: &std::ffi::CStr,
    before: impl FnOnce() -> io::Result<nix::sys::stat::FileStat>,
    open: impl FnOnce() -> io::Result<File>,
    after: impl FnOnce(&File) -> io::Result<crate::protected_dir::Stat>,
) -> io::Result<(File, crate::protected_dir::Stat)> {
    let before = before()?;
    let kind =
        nix::sys::stat::SFlag::from_bits_truncate(before.st_mode) & nix::sys::stat::SFlag::S_IFMT;
    if kind != nix::sys::stat::SFlag::S_IFREG && kind != nix::sys::stat::SFlag::S_IFDIR {
        return Err(refused(format!(
            "unfence entry `{}` is not a regular file or directory",
            name.to_string_lossy()
        )));
    }
    let file = open()?;
    let stat = after(&file)?;
    if (stat.dev, stat.ino) != (i128::from(before.st_dev), before.st_ino) {
        return Err(refused(format!(
            "unfence entry `{}` changed identity between stat and open",
            name.to_string_lossy()
        )));
    }
    Ok((file, stat))
}

#[cfg(test)]
mod tests;
