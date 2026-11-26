// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Owned queries retain no namespace or mediator borrow between pages.

use super::{Name, Namespace, OverlayEntry, OverlayError, OverlayIo, OverlayKind, OverlayStore};
use crate::{OwnershipStatus, Store};

/// Maximum owned child rows transferred by one query.
pub const OVERLAY_PAGE_ROWS: usize = 256;

/// Namespace refusals are distinct from service and consistency failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayQuery<T> {
    Found(T),
    Missing,
    NotDirectory,
    Changed,
}

/// The root has no persisted entry or overlay inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayQueryEntry {
    pub entry: Option<OverlayEntry>,
    pub nlink: u32,
}

/// An exclusive name bound to the directory's identity and admitted revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayCursor {
    path: Vec<Name>,
    inode: Option<u64>,
    incarnation: u64,
    revision: u64,
    after: Option<Name>,
}

#[cfg(test)]
impl OverlayCursor {
    pub(in crate::overlay_store) fn revision_for_test(&self) -> u64 {
        self.revision
    }

    pub(in crate::overlay_store) fn change_incarnation(&mut self) {
        self.incarnation += 1;
    }
    pub(in crate::overlay_store) fn change_identity(&mut self) {
        self.inode = Some(u64::MAX);
    }
}

/// Directory and parent attributes belong to the same observation as the cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayDirectoryQuery {
    pub directory: OverlayQueryEntry,
    pub parent: OverlayQueryEntry,
    pub cursor: OverlayCursor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPage {
    pub entries: Vec<OverlayQueryEntry>,
    pub next: Option<OverlayCursor>,
}

fn owned(ns: &Namespace, path: &[Name]) -> Result<OverlayQueryEntry, OverlayError> {
    Ok(OverlayQueryEntry {
        entry: ns.query_entry(path)?.cloned(),
        nlink: ns.query_nlink(path)?,
    })
}

fn directory(ns: &Namespace, path: &[Name]) -> Result<OverlayQuery<()>, OverlayError> {
    if path.is_empty() {
        ns.query_entry(path)?;
        return Ok(OverlayQuery::Found(()));
    }
    Ok(match ns.query_entry(path)? {
        None => OverlayQuery::Missing,
        Some(entry) if matches!(entry.kind, OverlayKind::Directory) => OverlayQuery::Found(()),
        Some(_) => OverlayQuery::NotDirectory,
    })
}

impl<P: OverlayIo> OverlayStore<P> {
    fn query_ready<T>(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        action: impl FnOnce(&Self) -> Result<OverlayQuery<T>, OverlayError>,
    ) -> Result<OverlayQuery<T>, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        let result = action(self);
        if matches!(result, Err(OverlayError::Poisoned)) {
            self.poison();
        }
        result
    }

    /// Copy one attached entry, or explicit root metadata.
    /// # Errors
    /// Readiness, custody or sticky index-consistency failure.
    pub fn query_path(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        path: &[Name],
    ) -> Result<OverlayQuery<OverlayQueryEntry>, OverlayError> {
        self.query_ready(store, ownership, |s| {
            if !path.is_empty() && s.namespace.query_entry(path)?.is_none() {
                return Ok(OverlayQuery::Missing);
            }
            Ok(OverlayQuery::Found(owned(&s.namespace, path)?))
        })
    }

    /// Resolve a held-object binding without copying its entry value.
    pub(crate) fn query_path_inode(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        path: &[Name],
    ) -> Result<OverlayQuery<Option<u64>>, OverlayError> {
        self.query_ready(store, ownership, |s| {
            let entry = s.namespace.query_entry(path)?;
            if !path.is_empty() && entry.is_none() {
                return Ok(OverlayQuery::Missing);
            }
            s.namespace.query_nlink(path)?;
            Ok(OverlayQuery::Found(entry.map(|entry| entry.inode)))
        })
    }

    /// Refresh only the addressed attached identity; absence represents detachment.
    /// # Errors
    /// Readiness, custody or sticky index-consistency failure.
    pub fn query_inode(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        inode: u64,
    ) -> Result<OverlayQuery<OverlayQueryEntry>, OverlayError> {
        self.query_ready(store, ownership, |s| {
            let Some(entry) = s.namespace.query_inode(inode)? else {
                return Ok(OverlayQuery::Missing);
            };
            Ok(OverlayQuery::Found(owned(&s.namespace, &entry.path)?))
        })
    }

    /// Compare one attached identity, copying its entry only when it changed.
    pub(crate) fn query_inode_change(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        expected: &OverlayEntry,
    ) -> Result<OverlayQuery<Option<OverlayEntry>>, OverlayError> {
        self.query_ready(store, ownership, |s| {
            let Some(entry) = s.namespace.query_inode(expected.inode)? else {
                return Ok(OverlayQuery::Missing);
            };
            s.namespace.query_nlink(&entry.path)?;
            Ok(OverlayQuery::Found(
                (entry != expected).then(|| entry.clone()),
            ))
        })
    }

    /// Validate the parent and copy only the requested child.
    /// # Errors
    /// Readiness, custody or sticky index-consistency failure.
    pub fn query_lookup(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        parent: &[Name],
        name: &Name,
    ) -> Result<OverlayQuery<OverlayQueryEntry>, OverlayError> {
        self.query_ready(store, ownership, |s| {
            match directory(&s.namespace, parent)? {
                OverlayQuery::Missing => return Ok(OverlayQuery::Missing),
                OverlayQuery::NotDirectory => return Ok(OverlayQuery::NotDirectory),
                OverlayQuery::Found(()) => (),
                OverlayQuery::Changed => return Err(OverlayError::poisoned()),
            }
            let mut path = parent.to_vec();
            path.push(name.clone());
            if s.namespace.query_entry(&path)?.is_none() {
                return Ok(OverlayQuery::Missing);
            }
            Ok(OverlayQuery::Found(owned(&s.namespace, &path)?))
        })
    }

    /// Inspect one child reference without copying a directory's rows.
    pub(crate) fn query_has_children(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        path: &[Name],
    ) -> Result<OverlayQuery<bool>, OverlayError> {
        self.query_ready(store, ownership, |s| {
            match directory(&s.namespace, path)? {
                OverlayQuery::Missing => return Ok(OverlayQuery::Missing),
                OverlayQuery::NotDirectory => return Ok(OverlayQuery::NotDirectory),
                OverlayQuery::Found(()) => (),
                OverlayQuery::Changed => return Err(OverlayError::poisoned()),
            }
            Ok(OverlayQuery::Found(
                !s.namespace.query_children(path, None, 1)?.is_empty(),
            ))
        })
    }

    /// Begin a directory observation; a continuation is never a FUSE cookie.
    /// # Errors
    /// Readiness, custody or sticky index-consistency failure.
    pub fn query_directory(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        path: &[Name],
    ) -> Result<OverlayQuery<OverlayDirectoryQuery>, OverlayError> {
        self.query_ready(store, ownership, |s| {
            match directory(&s.namespace, path)? {
                OverlayQuery::Missing => return Ok(OverlayQuery::Missing),
                OverlayQuery::NotDirectory => return Ok(OverlayQuery::NotDirectory),
                OverlayQuery::Found(()) => (),
                OverlayQuery::Changed => return Err(OverlayError::poisoned()),
            }
            let mut parent = path.to_vec();
            parent.pop();
            let journal = s.journal.lock().map_err(Self::lock_error)?;
            let context = (s.query_incarnation, journal.state.next_seq());
            drop(journal);
            Ok(OverlayQuery::Found(OverlayDirectoryQuery {
                directory: owned(&s.namespace, path)?,
                parent: owned(&s.namespace, &parent)?,
                cursor: OverlayCursor {
                    path: path.to_vec(),
                    inode: s.namespace.query_entry(path)?.map(|e| e.inode),
                    incarnation: context.0,
                    revision: context.1,
                    after: None,
                },
            }))
        })
    }

    /// Copy at most 256 children; changed context is a retry, never false EOF.
    /// # Errors
    /// Readiness, custody or sticky index-consistency failure.
    pub fn query_children(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        cursor: &OverlayCursor,
    ) -> Result<OverlayQuery<OverlayPage>, OverlayError> {
        self.query_ready(store, ownership, |s| {
            let journal = s.journal.lock().map_err(Self::lock_error)?;
            let context = (s.query_incarnation, journal.state.next_seq());
            drop(journal);
            if context != (cursor.incarnation, cursor.revision) {
                return Ok(OverlayQuery::Changed);
            }
            match directory(&s.namespace, &cursor.path)? {
                OverlayQuery::Found(()) => (),
                _ => return Ok(OverlayQuery::Changed),
            }
            if s.namespace.query_entry(&cursor.path)?.map(|e| e.inode) != cursor.inode {
                return Ok(OverlayQuery::Changed);
            }
            let children = s.namespace.query_children(
                &cursor.path,
                cursor.after.as_ref(),
                OVERLAY_PAGE_ROWS + 1,
            )?;
            let mut entries = Vec::new();
            for entry in children.iter().take(OVERLAY_PAGE_ROWS) {
                entries.push(owned(&s.namespace, &entry.path)?);
            }
            let next = if children.len() > OVERLAY_PAGE_ROWS {
                let last = entries
                    .last()
                    .and_then(|e| e.entry.as_ref())
                    .and_then(|e| e.path.last())
                    .ok_or_else(OverlayError::poisoned)?;
                let mut next = cursor.clone();
                next.after = Some(last.clone());
                Some(next)
            } else {
                None
            };
            Ok(OverlayQuery::Found(OverlayPage { entries, next }))
        })
    }
}
