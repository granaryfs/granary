// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Deterministic corpus loading: one unpacked version tree in, a
//! memcmp-sorted depth-first node list out.
//!
//! Two rules the walker enforces rather than assumes. It **refuses**
//! anything it cannot account for (device nodes, fifos, sockets,
//! unreadable directories, out-of-format names and symlink targets)
//! instead of skipping it — a silently skipped file is a silently
//! wrong dedup ratio. And it records **empty directories**, because
//! they are manifest nodes with real bytes.
//!
//! The emitted order IS the traversal order the range-GET coalescing
//! model assumes, and it is exactly `Vec<Name>` lexicographic order
//! (`Name` compares memcmp, never locale collation) — asserted, not asserted-by-comment.
//!
//! **`BadName` and `BadTarget` are reachable without root and covered by
//! tests.** APFS's own limits (`NAME_MAX` 255 bytes, exactly the format's
//! `NAME_MAX`; `PATH_MAX` 1024 bytes, under the format's
//! `SYMLINK_TARGET_MAX` of 4096) make an over-long name or target
//! unconstructible there. Length is not the format's only rejection
//! rule: a name starting with the `.gran` byte prefix the format reserves
//! is an ordinary file (`dot_gran_prefix_is_refused_as_bad_name`), and
//! `symlink("", path)` is accepted by APFS and reads back as a
//! zero-byte target, which the format also rejects
//! (`empty_symlink_target_is_refused_as_bad_target`, macOS-only: Linux
//! refuses `symlink("", path)` itself, so the input cannot be built there).
//!
//! The totality property — refuse, never silently skip — is covered
//! per refusal arm: `BadName`, `BadTarget`, `Io` (an unreadable
//! directory) and `Unsupported`. `Unsupported` is demonstrated with a
//! fifo AND, separately, a unix-domain socket: both are ordinary
//! filesystem objects a non-root process can create, so "the one
//! unrepresentable thing APFS will actually create" undersold it —
//! only device nodes need root, and are correctly not exercised here.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use granary_core::manifest::{Name, NameError, SymlinkTarget, SymlinkTargetError};

/// What a corpus node is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    /// A regular file.
    File {
        /// Any exec bit set (`0o111`) — git's any-exec-bit rule.
        exec: bool,
        /// Size in bytes at walk time.
        len: u64,
    },
    /// A symlink, never followed.
    Symlink {
        /// Validated target bytes.
        target: SymlinkTarget,
    },
    /// A directory with no entries — a manifest node with no file.
    EmptyDir,
}

/// One node, addressed by its validated path components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Path components from the corpus root, never empty.
    pub components: Vec<Name>,
    /// What it is.
    pub kind: NodeKind,
}

/// One unpacked version tree.
#[derive(Debug)]
pub struct Corpus {
    /// Filesystem root the components are relative to.
    pub root: PathBuf,
    /// Depth-first, memcmp-sorted.
    pub nodes: Vec<Node>,
    /// Regular files only.
    pub file_count: u64,
    /// Sum of regular-file sizes.
    pub file_bytes: u64,
}

/// Why a corpus could not be loaded.
#[derive(Debug)]
pub enum CorpusError {
    /// An I/O error at a specific path.
    Io {
        /// Where.
        path: PathBuf,
        /// What.
        source: io::Error,
    },
    /// A directory-entry name the frozen manifest format rejects.
    BadName {
        /// Where.
        path: PathBuf,
        /// What.
        source: NameError,
    },
    /// A symlink target the frozen manifest format rejects.
    BadTarget {
        /// Where.
        path: PathBuf,
        /// What.
        source: SymlinkTargetError,
    },
    /// A file type v1 never emits — fifo, socket (`node.rs`'s
    /// `ENTRY_TAG_FIFO`/`ENTRY_TAG_SOCKET` are reserved tags, not live
    /// ones) or a device node. Refused, never skipped.
    Unsupported {
        /// Where.
        path: PathBuf,
        /// What kind of thing it was.
        what: &'static str,
    },
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::BadName { path, source } => write!(f, "{}: bad name: {source}", path.display()),
            Self::BadTarget { path, source } => {
                write!(f, "{}: bad symlink target: {source}", path.display())
            }
            Self::Unsupported { path, what } => {
                write!(f, "{}: unsupported file type ({what})", path.display())
            }
        }
    }
}

impl core::error::Error for CorpusError {}

/// Walk `root` into a deterministic node list.
///
/// # Errors
/// [`CorpusError`] on I/O failure, on a name or symlink target the
/// frozen format rejects, or on any file type v1 cannot represent.
pub fn load(root: &Path) -> Result<Corpus, CorpusError> {
    let mut c = Corpus {
        root: root.to_path_buf(),
        nodes: Vec::new(),
        file_count: 0,
        file_bytes: 0,
    };
    let mut prefix: Vec<Name> = Vec::new();
    walk(root, &mut prefix, &mut c)?;
    Ok(c)
}

impl Corpus {
    /// Absolute path of a node.
    #[must_use]
    pub fn path_of(&self, node: &Node) -> PathBuf {
        let mut p = self.root.clone();
        for c in &node.components {
            p.push(OsStr::from_bytes(c.as_bytes()));
        }
        p
    }

    /// Read one regular file's contents.
    ///
    /// # Errors
    /// Propagates the read failure.
    pub fn read(&self, node: &Node) -> io::Result<Vec<u8>> {
        fs::read(self.path_of(node))
    }
}

/// Returns whether the directory had any entries.
fn walk(dir: &Path, prefix: &mut Vec<Name>, out: &mut Corpus) -> Result<bool, CorpusError> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    let reader = fs::read_dir(dir).map_err(|source| CorpusError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in reader {
        let entry = entry.map_err(|source| CorpusError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        names.push(entry.file_name().as_bytes().to_vec());
    }
    // memcmp order, the format's order — not the OS's.
    names.sort_unstable();
    let had_entries = !names.is_empty();

    for raw in names {
        let path = dir.join(OsStr::from_bytes(&raw));
        let name = Name::new(raw).map_err(|source| CorpusError::BadName {
            path: path.clone(),
            source,
        })?;
        let meta = fs::symlink_metadata(&path).map_err(|source| CorpusError::Io {
            path: path.clone(),
            source,
        })?;
        prefix.push(name);
        if meta.is_dir() {
            if !walk(&path, prefix, out)? {
                out.nodes.push(Node {
                    components: prefix.clone(),
                    kind: NodeKind::EmptyDir,
                });
            }
        } else if meta.is_file() {
            out.file_count += 1;
            out.file_bytes += meta.len();
            out.nodes.push(Node {
                components: prefix.clone(),
                kind: NodeKind::File {
                    exec: meta.permissions().mode() & 0o111 != 0,
                    len: meta.len(),
                },
            });
        } else if meta.is_symlink() {
            let target = fs::read_link(&path).map_err(|source| CorpusError::Io {
                path: path.clone(),
                source,
            })?;
            let target =
                SymlinkTarget::new(target.as_os_str().as_bytes().to_vec()).map_err(|source| {
                    CorpusError::BadTarget {
                        path: path.clone(),
                        source,
                    }
                })?;
            out.nodes.push(Node {
                components: prefix.clone(),
                kind: NodeKind::Symlink { target },
            });
        } else {
            return Err(CorpusError::Unsupported {
                path,
                what: "not a file, directory or symlink",
            });
        }
        prefix.pop();
    }
    Ok(had_entries)
}

#[expect(
    clippy::disallowed_methods,
    reason = "test scratch-dir naming; disallowed_methods has no allow-in-tests knob"
)]
#[cfg(test)]
mod tests;
