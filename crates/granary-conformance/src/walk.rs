// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `granconf dump`'s walker: the one place this crate touches a real
//! filesystem to BUILD rows (as opposed to reading them back from a
//! dump's text — see [`crate::row::parse_dump`]).
//!
//! Iterative, not recursive — the same reasoning
//! `crates/granary-client/src/harvest.rs`'s `harvest_tree` states for
//! its own worklist: how deep a tree can nest is bounded by `PATH_MAX`
//! divided by the shortest legal name, and a native-stack recursive
//! walk answers the deep end of that range with a stack overflow
//! (SIGABRT), never a [`WalkError`].
//!
//! **Readdir goes through `nix::dir::Dir`, never
//! `std::fs::DirEntry::file_type`.** The latter silently falls back to
//! a `metadata()` stat on `DT_UNKNOWN` (measured on this pinned 1.97.1
//! toolchain), which is exactly the shortcut that would hide the field
//! the dump contract mandates be recorded RAW. **After the root is opened once,
//! traversal is fd-relative:** raw readdir uses the pinned directory and entry
//! classification uses `fstatat(..., AT_SYMLINK_NOFOLLOW)`, never `d_type`. A
//! reader lying about `d_type` must have its lie recorded in the row, not obeyed
//! by the walker that decides whether to descend.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use nix::dir::{Dir, Type as NixType};
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, openat, readlinkat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};

use granary_core::hash::GrainId;

use crate::escape;
use crate::row::{DType, Kind, Payload, Row, RowError, new_row};

/// The largest regular file whose content the dump will digest.
///
/// The payload column is a whole-file digest, so the walker must hold the
/// file in memory to compute it. 64 MiB is far above anything `gendir`
/// emits (its largest case is about 4 MiB) and far below a size that
/// threatens the process; a tree carrying something bigger gets
/// [`WalkError::FileTooLarge`] naming the path, which is a result an
/// operator can act on, unlike an OOM kill.
pub const PAYLOAD_MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum WalkError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Nix {
        path: PathBuf,
        source: nix::Error,
    },
    NotADirectory {
        path: PathBuf,
    },
    /// `DT_UNKNOWN` in the raw readdir stream — a loud precondition
    /// refusal, never a per-entry skip: this field is exactly
    /// what the dump exists to observe.
    UnknownDType {
        path: PathBuf,
    },
    /// A raw directory-entry name containing `/`. Each raw name must be one
    /// path component; accepting a separator would make relative-path
    /// construction non-injective.
    EntryNameContainsSlash {
        directory: PathBuf,
        name: Vec<u8>,
    },
    /// A directory whose raw readdir stream never produced `.` or
    /// `..` — both must be observed before either is
    /// dropped from the row set.
    MissingDotEntries {
        path: PathBuf,
    },
    /// Any lstat type other than directory, regular file, or symlink —
    /// outside what a v1 manifest, and so this oracle, can represent.
    SpecialFile {
        path: PathBuf,
    },
    /// An entry observed as a regular file by `fstatat` did not yield a
    /// regular-file fd when opened. Repeated lookups are attacker-controlled,
    /// so a type change is a refusal, not an assertion.
    OpenedFileIsNotRegular {
        path: PathBuf,
    },
    /// A regular-file fd reported a negative length.
    InvalidFileSize {
        path: PathBuf,
        len: i64,
    },
    /// A regular file larger than [`PAYLOAD_MAX_BYTES`]. The payload
    /// column is a digest of the file's WHOLE content, so hashing it
    /// means holding it: an unbounded read turns a large file — or a
    /// source that keeps delivering bytes — into an allocation failure
    /// that kills the walk instead of reporting a divergence. A named
    /// refusal is the observable an oracle needs.
    FileTooLarge {
        path: PathBuf,
        len: u64,
    },
    /// Two distinct raw paths rendered the same escaped text — an
    /// injective escaper makes this unreachable from distinct inputs,
    /// so its only real trigger is the walker visiting one path twice;
    /// kept as a defensive emit-time check either way.
    DuplicateEscapedPath {
        escaped: String,
    },
    Row(RowError),
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Nix { path, source } => write!(f, "{}: {source}", path.display()),
            Self::NotADirectory { path } => write!(f, "{}: not a directory", path.display()),
            Self::FileTooLarge { path, len } => {
                write!(
                    f,
                    "{}: {len} bytes exceeds the {PAYLOAD_MAX_BYTES}-byte payload bound",
                    path.display()
                )
            }
            Self::UnknownDType { path } => {
                write!(
                    f,
                    "{}: readdir reported DT_UNKNOWN — refusing rather than stat-falling-back",
                    path.display()
                )
            }
            Self::EntryNameContainsSlash { directory, name } => {
                write!(
                    f,
                    "{}: raw directory-entry name contains '/': {}",
                    directory.display(),
                    escape::escape(name)
                )
            }
            Self::MissingDotEntries { path } => {
                write!(
                    f,
                    "{}: raw readdir stream never produced '.' and '..'",
                    path.display()
                )
            }
            Self::SpecialFile { path } => {
                write!(
                    f,
                    "{}: unsupported file type — not representable in v1",
                    path.display()
                )
            }
            Self::OpenedFileIsNotRegular { path } => {
                write!(f, "{}: open did not yield a regular file", path.display())
            }
            Self::InvalidFileSize { path, len } => {
                write!(
                    f,
                    "{}: regular-file fd reported negative size {len}",
                    path.display()
                )
            }
            Self::DuplicateEscapedPath { escaped } => {
                write!(f, "two rows rendered the same escaped path: {escaped}")
            }
            Self::Row(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WalkError {}

impl From<RowError> for WalkError {
    fn from(e: RowError) -> Self {
        Self::Row(e)
    }
}

const fn dtype_of(t: NixType) -> DType {
    match t {
        NixType::Fifo => DType::Fifo,
        NixType::CharacterDevice => DType::Chr,
        NixType::Directory => DType::Dir,
        NixType::BlockDevice => DType::Blk,
        NixType::File => DType::File,
        NixType::Symlink => DType::Symlink,
        NixType::Socket => DType::Sock,
    }
}

fn child_rel_path(prefix: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len().saturating_add(name.len()).saturating_add(1));
    out.extend_from_slice(prefix);
    if !out.is_empty() {
        out.push(b'/');
    }
    out.extend_from_slice(name);
    out
}

/// One directory entry's raw readdir answer: its name bytes and the
/// RAW `dtype` `nix::dir::Entry::file_type()` reported.
struct RawChild {
    name: Vec<u8>,
    dtype: DType,
}

/// One directory's raw readdir stream: every non-`.`/`..` entry, plus
/// whether `.` and `..` were seen.
struct RawEntries {
    children: Vec<RawChild>,
    saw_dot: bool,
    saw_dotdot: bool,
}

fn refuse_entry_name_with_slash(directory: &Path, name: &[u8]) -> Result<(), WalkError> {
    if name.contains(&b'/') {
        Err(WalkError::EntryNameContainsSlash {
            directory: directory.to_path_buf(),
            name: name.to_vec(),
        })
    } else {
        Ok(())
    }
}

/// Read one directory's raw readdir stream.
///
/// # Errors
/// [`WalkError::Nix`] if the pinned directory cannot be iterated,
/// [`WalkError::EntryNameContainsSlash`] if a raw name is not one component,
/// or [`WalkError::UnknownDType`] on the first `DT_UNKNOWN` entry.
fn read_raw_entries(dir: &mut Dir, display_dir: &Path) -> Result<RawEntries, WalkError> {
    let mut saw_dot = false;
    let mut saw_dotdot = false;
    let mut children = Vec::new();
    for entry in dir.iter() {
        let entry = entry.map_err(|source| WalkError::Nix {
            path: display_dir.to_path_buf(),
            source,
        })?;
        let name = entry.file_name().to_bytes().to_vec();
        if name == b"." {
            saw_dot = true;
            continue;
        }
        if name == b".." {
            saw_dotdot = true;
            continue;
        }
        refuse_entry_name_with_slash(display_dir, &name)?;
        let raw = entry.file_type().ok_or_else(|| WalkError::UnknownDType {
            path: display_dir.join(OsStr::from_bytes(&name)),
        })?;
        children.push(RawChild {
            name,
            dtype: dtype_of(raw),
        });
    }
    Ok(RawEntries {
        children,
        saw_dot,
        saw_dotdot,
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StatKind {
    Directory,
    File,
    Symlink,
    Other,
}

fn stat_kind(stat: &FileStat) -> StatKind {
    let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
    if kind == SFlag::S_IFDIR {
        StatKind::Directory
    } else if kind == SFlag::S_IFREG {
        StatKind::File
    } else if kind == SFlag::S_IFLNK {
        StatKind::Symlink
    } else {
        StatKind::Other
    }
}

fn is_executable(stat: &FileStat) -> bool {
    let executable = Mode::S_IXUSR | Mode::S_IXGRP | Mode::S_IXOTH;
    Mode::from_bits_truncate(stat.st_mode).intersects(executable)
}

fn read_bounded_payload<R: Read>(
    reader: R,
    display_path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, WalkError> {
    // `take` is the allocation boundary, not `st_size`: a FUSE server may
    // report any size and then deliver a different number of bytes.
    let mut limited = reader.take(max_bytes.saturating_add(1));
    let mut content = Vec::new();
    limited
        .read_to_end(&mut content)
        .map_err(|source| WalkError::Io {
            path: display_path.to_path_buf(),
            source,
        })?;
    let delivered = u64::try_from(content.len()).unwrap_or(u64::MAX);
    if delivered > max_bytes {
        return Err(WalkError::FileTooLarge {
            path: display_path.to_path_buf(),
            len: delivered,
        });
    }
    Ok(content)
}

fn check_dot_entries(saw_dot: bool, saw_dotdot: bool, path: &Path) -> Result<(), WalkError> {
    if saw_dot && saw_dotdot {
        Ok(())
    } else {
        Err(WalkError::MissingDotEntries {
            path: path.to_path_buf(),
        })
    }
}

/// Classify and read one child entry into a [`Row`] — the traversal's
/// only place that trusts the LSTAT kind (never `dtype`) to decide what
/// the entry actually is.
fn classify_child(
    parent: &Dir,
    name: &OsStr,
    rel_path: Vec<u8>,
    display_path: &Path,
    dtype: DType,
) -> Result<(Row, Option<Dir>), WalkError> {
    let lstat =
        fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|source| WalkError::Nix {
            path: display_path.to_path_buf(),
            source,
        })?;
    if stat_kind(&lstat) == StatKind::Directory {
        let child_dir = Dir::openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| WalkError::Nix {
            path: display_path.to_path_buf(),
            source,
        })?;
        let row = new_row(
            rel_path,
            Kind::Dir,
            dtype,
            None,
            is_executable(&lstat),
            Payload::None,
        )?;
        return Ok((row, Some(child_dir)));
    }
    if stat_kind(&lstat) == StatKind::File {
        let fd = openat(
            parent,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|source| WalkError::Nix {
            path: display_path.to_path_buf(),
            source,
        })?;
        let opened = fstat(&fd).map_err(|source| WalkError::Nix {
            path: display_path.to_path_buf(),
            source,
        })?;
        if stat_kind(&opened) != StatKind::File {
            return Err(WalkError::OpenedFileIsNotRegular {
                path: display_path.to_path_buf(),
            });
        }
        let len = u64::try_from(opened.st_size).map_err(|_| WalkError::InvalidFileSize {
            path: display_path.to_path_buf(),
            len: opened.st_size,
        })?;
        let content = read_bounded_payload(File::from(fd), display_path, PAYLOAD_MAX_BYTES)?;
        let hex = GrainId::of(&content).digest_hex();
        let row = new_row(
            rel_path,
            Kind::File,
            dtype,
            Some(len),
            is_executable(&opened),
            Payload::Content(hex),
        )?;
        return Ok((row, None));
    }
    if stat_kind(&lstat) == StatKind::Symlink {
        let target = readlinkat(parent, name).map_err(|source| WalkError::Nix {
            path: display_path.to_path_buf(),
            source,
        })?;
        let row = new_row(
            rel_path,
            Kind::Symlink,
            dtype,
            None,
            is_executable(&lstat),
            Payload::Target(target.as_os_str().as_bytes().to_vec()),
        )?;
        return Ok((row, None));
    }
    Err(WalkError::SpecialFile {
        path: display_path.to_path_buf(),
    })
}

fn open_root(root: &Path) -> Result<Dir, WalkError> {
    Dir::open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| {
        if source == Errno::ENOTDIR || source == Errno::ELOOP {
            WalkError::NotADirectory {
                path: root.to_path_buf(),
            }
        } else {
            WalkError::Nix {
                path: root.to_path_buf(),
                source,
            }
        }
    })
}

fn walk_opened_root(root: &Path, root_dir: Dir) -> Result<Vec<Row>, WalkError> {
    let mut rows: Vec<Row> = Vec::new();
    let mut stack: Vec<(Vec<u8>, PathBuf, Dir)> = vec![(Vec::new(), root.to_path_buf(), root_dir)];
    while let Some((rel_prefix, display_dir, mut dir)) = stack.pop() {
        let raw = read_raw_entries(&mut dir, &display_dir)?;
        check_dot_entries(raw.saw_dot, raw.saw_dotdot, &display_dir)?;
        for child in raw.children {
            let rel_path = child_rel_path(&rel_prefix, &child.name);
            let display_path = display_dir.join(OsStr::from_bytes(&child.name));
            let (row, child_dir) = classify_child(
                &dir,
                OsStr::from_bytes(&child.name),
                rel_path.clone(),
                &display_path,
                child.dtype,
            )?;
            if let Some(child_dir) = child_dir {
                stack.push((rel_path, display_path, child_dir));
            }
            rows.push(row);
        }
    }
    // Sort FIRST so the duplicate reported is a property of the row set
    // and not of the order the kernel happened to hand back.
    rows.sort_by(|a, b| a.path.cmp(&b.path));
    refuse_duplicate_escaped_paths(&rows)?;
    Ok(rows)
}

/// Walk `root`, returning every descendant entry as a [`Row`], sorted
/// by the RAW BYTES of its relative path (never the escaped rendering
/// — see [`crate::escape`]'s module doc for why those orders can
/// disagree).
///
/// # Errors
/// See [`WalkError`]'s variants; each names the path and the exact
/// precondition that failed.
pub fn walk(root: &Path) -> Result<Vec<Row>, WalkError> {
    let root_dir = open_root(root)?;
    walk_opened_root(root, root_dir)
}

/// The emit-time refusal: two rows rendering to the same escaped path.
/// Given an INJECTIVE escaper (`crate::escape`'s own round-trip tests),
/// distinct raw paths can never collide here — the only way two rows
/// share an escaped rendering is sharing the same raw path outright,
/// which no single real `readdir` stream can produce twice for one
/// directory. This check exists anyway, as the defensive belt on that
/// reasoning rather than a replacement for it: it is what would catch
/// a walker bug that visited (or otherwise fabricated) the same path
/// twice, a failure mode this function can be driven into directly —
/// see this module's tests — even though [`walk`] itself cannot
/// reach it through any real directory tree.
///
/// # Errors
/// [`WalkError::DuplicateEscapedPath`] naming the first collision.
pub fn refuse_duplicate_escaped_paths(rows: &[Row]) -> Result<(), WalkError> {
    let mut seen: HashSet<String> = HashSet::new();
    for row in rows {
        let escaped = escape::escape(&row.path);
        if !seen.insert(escaped.clone()) {
            return Err(WalkError::DuplicateEscapedPath { escaped });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
