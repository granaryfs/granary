// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The directory-descent primitive `readdir`/`readdirplus`/`opendir` all
//! need: resolving an inode's own node and its parent's. The sink-shaped
//! listing algorithms that call this (`list_dir`, `list_dir_plus`) stay
//! with the adapter's own listing module — they are written against its
//! platform reply types and are not portable.

use granary_core::hash::GrainId;
use granary_core::manifest::EntryKind;

use crate::{InodeTable, ReaderError, Snapshot};

/// Resolves the two B-tree nodes a `readdir`/`readdirplus`/`opendir` needs
/// for `ino`: the directory's OWN node (what its entries live in) and its
/// PARENT's (what `..` is synthesised from).
///
/// `InodeTable::resolve(ino)` returns the PARENT's node, not `ino`'s own —
/// see `InodeEntry::dir`'s field doc. For the root the two coincide (the
/// root is its own parent); for any other directory, naively calling
/// `snapshot.readdir(&table.resolve(ino).1, ...)` lists the PARENT's
/// entries instead of `ino`'s own. Descending correctly means looking
/// `ino`'s own path up BY NAME inside its parent and taking the
/// `EntryKind::Dir` out of the result.
///
/// # Errors
///
/// Returns [`ReaderError::Inconsistent`] if `ino` is unknown, if its
/// recorded path is empty but it is not the root, or if the resolved
/// entry is not a directory.
pub fn dir_and_parent(
    table: &InodeTable,
    snapshot: &Snapshot,
    ino: u64,
) -> Result<(GrainId, GrainId), ReaderError> {
    let (path, parent, _kind) = table.resolve(ino)?;
    if ino == table.root_ino() {
        // The root is its own parent, and `resolve`'s `dir` field for it
        // IS the root's own node (`InodeTable::new`).
        return Ok((parent, parent));
    }
    let last = path.last().ok_or(ReaderError::Inconsistent)?;
    let entry = snapshot.lookup(&parent, last)?;
    match entry.kind {
        EntryKind::Dir { child } => Ok((child, parent)),
        _ => Err(ReaderError::Inconsistent),
    }
}

#[cfg(test)]
mod tests;
