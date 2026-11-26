// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Deterministic attributes for manifest entries.

use granary_core::manifest::EntryKind;
use granary_core::sheaf::Timestamp;

use crate::{Entry, ReaderError, Snapshot};

const DIRECTORY_SIZE: u64 = 4096;
const ATTR_BLOCK_SIZE: u32 = 4096;
const STAT_BLOCK_UNIT: u64 = 512;

/// Everything a mount reports about one object. Deterministic
/// presentation, never reconstructed source metadata: manifest v1
/// carries no mode, uid, gid, timestamps, nlink or xattrs (`EntryKind`
/// has a type tag, `exec: bool`, `size: u64` and a symlink target, and
/// `metadata_root`'s only v1-legal value is absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr {
    pub ino: u64,
    pub generation: u64,
    pub kind: NodeKind,
    /// Permission bits only, no type bits.
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// 512-byte units, as `stat(2)` defines it.
    pub blocks: u64,
    pub blksize: u32,
    /// All FOUR of the kernel's `FileAttr` timestamps — atime, mtime,
    /// ctime and crtime — are this value. The format's own
    /// value, UNCONVERTED: the checked conversion to the kernel's
    /// timestamp type, and the refusal of a root the kernel's type cannot
    /// represent, both still happen once — only WHERE moved, from this
    /// engine to the adapter that presents this `Attr`.
    pub time: Timestamp,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind { Dir, File, Symlink }

/// Permission presentation depends only on mount policy, kind and execute intent.
#[must_use]
pub const fn permission_mode(writable: bool, kind: NodeKind, exec: bool) -> u16 {
    match (writable, kind, exec) {
        (_, NodeKind::Symlink, _) => 0o777,
        (true, NodeKind::Dir, _) | (true, NodeKind::File, true) => 0o755,
        (true, NodeKind::File, false) => 0o644,
        (false, NodeKind::Dir, _) | (false, NodeKind::File, true) => 0o555,
        (false, NodeKind::File, false) => 0o444,
    }
}

impl Snapshot {
    /// Synthesises deterministic presentation attributes for one entry.
    ///
    /// `ino` and `generation` come from the per-path inode table; this policy
    /// does not derive identity from content.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Inconsistent`] when a directory is absent from
    /// the snapshot's directory index, or [`ReaderError::UnsupportedEntry`]
    /// for a reserved FIFO or socket entry.
    pub fn attr_for(&self, entry: &Entry, ino: u64, generation: u64) -> Result<Attr, ReaderError> {
        let (kind, perm, nlink, size) = match &entry.kind {
            EntryKind::Dir { child } => (
                NodeKind::Dir,
                0o555,
                2_u32.saturating_add(self.dir_subdirs(child)?),
                DIRECTORY_SIZE,
            ),
            EntryKind::File { exec, size, .. } => {
                (NodeKind::File, if *exec { 0o555 } else { 0o444 }, 1, *size)
            }
            EntryKind::Symlink { target } => {
                (NodeKind::Symlink, 0o777, 1, u64::from(target.wire_len()))
            }
            EntryKind::Fifo | EntryKind::Socket => {
                return Err(ReaderError::UnsupportedEntry);
            }
        };
        let policy = self.policy();
        Ok(Attr {
            ino,
            generation,
            kind,
            perm,
            nlink,
            uid: policy.uid,
            gid: policy.gid,
            size,
            blocks: size.div_ceil(STAT_BLOCK_UNIT),
            blksize: ATTR_BLOCK_SIZE,
            time: self.timestamp(),
        })
    }

    /// Returns a symlink target as opaque bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::Inconsistent`] when the entry is not a symlink.
    pub fn readlink<'entry>(&self, entry: &'entry Entry) -> Result<&'entry [u8], ReaderError> {
        match &entry.kind {
            EntryKind::Symlink { target } => {
                // Absolute or escaping targets are NOT privilege escalation —
                // they resolve under the caller's own permissions.
                Ok(target.as_bytes())
            }
            _ => Err(ReaderError::Inconsistent),
        }
    }
}

#[cfg(test)]
mod tests;
