// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Monotonic FUSE file handles, and the exactly-one-release-per-open
//! guarantee `InodeTable` cannot provide by itself.

use alloc::collections::{BTreeMap, BTreeSet};

use crate::ReaderError;

/// Which kind of open a handle stands for. `open`/`opendir` and
/// `release`/`releasedir` must not cross: releasing a directory handle
/// through the file path (or vice versa) must be a no-op, not a release of
/// something the caller did not actually name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleKind {
    File,
    Directory,
}

/// A monotonic, never-reused file-handle allocator plus an
/// `fh -> (ino, kind)` map — the same non-reuse policy `InodeTable` already
/// applies to inode numbers, and for the same reason: a kernel that has not
/// yet been told an old handle is gone must never be handed a fresh object
/// under the same number.
///
/// This is where the "exactly one release per open" guarantee lives.
/// `InodeTable::release(ino)` takes no file handle, so the inode table
/// ALONE cannot tell a duplicate or unknown RELEASE from a genuine one: its
/// `saturating_sub` would drive `handles` to 0 on a second RELEASE for the
/// same open and, at `nlookup == 0`, reclaim an inode a live fd still uses
/// — the no-fd-invalidation property defeated by one stray kernel message.
/// Removing the handle from THIS table FIRST, and decrementing the inode
/// table only if that removal actually found something, is what makes a
/// duplicate, unknown, or wrong-kind RELEASE a no-op instead.
#[derive(Debug)]
pub struct HandleTable {
    by_fh: BTreeMap<u64, (u64, HandleKind)>,
    next: u64,
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

impl HandleTable {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            by_fh: BTreeMap::new(),
            next: 1,
        }
    }

    /// Allocates a fresh handle for `ino` and registers it, as one
    /// operation — an `open` that allocated but never registered (or vice
    /// versa) is exactly the kind of half-done sequence a caller could
    /// observe.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError::HandleCountOverflow`] if the monotonic
    /// counter is exhausted. Never wraps and never reuses a number.
    pub fn open(&mut self, ino: u64, kind: HandleKind) -> Result<u64, ReaderError> {
        let fh = self.next;
        let successor = fh.checked_add(1).ok_or(ReaderError::HandleCountOverflow)?;
        self.next = successor;
        self.by_fh.insert(fh, (ino, kind));
        Ok(fh)
    }

    /// Check capacity before a journalled create acquires a handle.
    /// # Errors
    /// Handle-number exhaustion.
    pub fn preflight_open(&self) -> Result<(), ReaderError> {
        self.next
            .checked_add(1)
            .ok_or(ReaderError::HandleCountOverflow)?;
        Ok(())
    }

    /// Validate the exact inode and kind before using a handle.
    #[must_use]
    pub fn matches(&self, fh: u64, ino: u64, kind: HandleKind) -> bool {
        self.by_fh.get(&fh) == Some(&(ino, kind))
    }

    /// The inodes with at least one open handle of either kind, each once.
    pub fn open_inodes(&self) -> impl Iterator<Item = u64> + use<> {
        self.by_fh
            .values()
            .map(|(ino, _)| *ino)
            .collect::<BTreeSet<_>>()
            .into_iter()
    }

    /// Releases `fh` if it names a live handle of exactly `kind`.
    ///
    /// Returns the inode it named, so the caller can decrement the
    /// `InodeTable`'s own per-inode handle count — and returns `None`,
    /// changing nothing, for a duplicate RELEASE, an unknown handle, or a
    /// handle of the WRONG kind (a RELEASEDIR naming a file handle, or a
    /// RELEASE naming a directory handle). The caller must call
    /// `InodeTable::release` ONLY when this returns `Some` — that gate is
    /// what makes a duplicate RELEASE harmless.
    pub fn release(&mut self, fh: u64, kind: HandleKind) -> Option<u64> {
        match self.by_fh.get(&fh) {
            Some(&(ino, existing_kind)) if existing_kind == kind => {
                self.by_fh.remove(&fh);
                Some(ino)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
