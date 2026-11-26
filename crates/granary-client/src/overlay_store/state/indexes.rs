// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Derived associations contain references only; entry values remain in the primary map.

use super::{BTreeMap, Name, Namespace, OverlayError, OverlayKind, Record, path};
use std::collections::BTreeSet;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct DirectoryIndex {
    children: BTreeMap<Name, Vec<Name>>,
    subdirectories: u32,
}

type DerivedIndexes = (
    BTreeMap<u64, Vec<Name>>,
    BTreeMap<Vec<Name>, DirectoryIndex>,
);

fn mismatch() -> OverlayError {
    OverlayError::poisoned()
}

impl Namespace {
    #[cfg(test)]
    pub(in crate::overlay_store) fn inject_subdirectory_count(
        &mut self,
        parent: &[Name],
        count: u32,
    ) -> Result<(), OverlayError> {
        self.parents
            .get_mut(parent)
            .ok_or_else(mismatch)?
            .subdirectories = count;
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::overlay_store) fn remove_child_reference(
        &mut self,
        parent: &[Name],
        name: &Name,
    ) -> Result<(), OverlayError> {
        self.parents
            .get_mut(parent)
            .ok_or_else(mismatch)?
            .children
            .remove(name);
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::overlay_store) fn inject_inverse_reference(&mut self, inode: u64, p: Vec<Name>) {
        self.inverse.insert(inode, p);
    }

    #[cfg(test)]
    pub(in crate::overlay_store) fn inject_child_reference(
        &mut self,
        parent: &[Name],
        name: Name,
        p: Vec<Name>,
    ) -> Result<(), OverlayError> {
        self.parents
            .get_mut(parent)
            .ok_or_else(mismatch)?
            .children
            .insert(name, p);
        Ok(())
    }

    pub(in crate::overlay_store) fn query_entry(
        &self,
        p: &[Name],
    ) -> Result<Option<&super::OverlayEntry>, OverlayError> {
        if p.is_empty() {
            if !self.parents.contains_key(p) {
                return Err(mismatch());
            }
            return Ok(None);
        }
        self.check_entry_associations(p)?;
        Ok(self.entries.get(p))
    }

    pub(in crate::overlay_store) fn query_inode(
        &self,
        inode: u64,
    ) -> Result<Option<&super::OverlayEntry>, OverlayError> {
        let Some(p) = self.inverse.get(&inode) else {
            return Ok(None);
        };
        let entry = self.query_entry(p)?.ok_or_else(mismatch)?;
        if entry.inode != inode {
            return Err(mismatch());
        }
        Ok(Some(entry))
    }

    pub(in crate::overlay_store) fn query_nlink(&self, p: &[Name]) -> Result<u32, OverlayError> {
        let entry = self.query_entry(p)?;
        if !p.is_empty() && !entry.is_some_and(|e| matches!(e.kind, OverlayKind::Directory)) {
            return Ok(1);
        }
        self.parents
            .get(p)
            .ok_or_else(mismatch)?
            .subdirectories
            .checked_add(2)
            .ok_or_else(mismatch)
    }

    pub(in crate::overlay_store) fn query_children(
        &self,
        p: &[Name],
        after: Option<&Name>,
        limit: usize,
    ) -> Result<Vec<&super::OverlayEntry>, OverlayError> {
        use std::ops::Bound::{Excluded, Unbounded};
        let bucket = self.parents.get(p).ok_or_else(mismatch)?;
        let mut rows = Vec::new();
        for (name, child) in bucket
            .children
            .range((after.map_or(Unbounded, Excluded), Unbounded))
            .take(limit)
        {
            let (actual_name, parent) = child.split_last().ok_or_else(mismatch)?;
            if actual_name != name || parent != p {
                return Err(mismatch());
            }
            rows.push(self.query_entry(child)?.ok_or_else(mismatch)?);
        }
        Ok(rows)
    }

    pub(super) fn rebuild_indexes(&mut self) -> Result<(), OverlayError> {
        let (inverse, parents) = self.derived_indexes().map_err(|_| mismatch())?;
        self.inverse = inverse;
        self.parents = parents;
        self.check_indexes().map_err(|_| mismatch())
    }

    fn derived_indexes(&self) -> Result<DerivedIndexes, &'static str> {
        let mut inverse = BTreeMap::new();
        let mut parents = BTreeMap::from([(Vec::new(), DirectoryIndex::default())]);
        for (key, entry) in &self.entries {
            if key != &entry.path || key.is_empty() || entry.inode == 0 {
                return Err("primary identity mismatch");
            }
            if inverse.insert(entry.inode, key.clone()).is_some() {
                return Err("duplicate inverse identity");
            }
            if matches!(entry.kind, OverlayKind::Directory) {
                parents.insert(key.clone(), DirectoryIndex::default());
            }
        }
        for (key, entry) in &self.entries {
            let (name, parent) = key.split_last().ok_or("empty primary path")?;
            let bucket = parents.get_mut(parent).ok_or("missing parent directory")?;
            if bucket.children.insert(name.clone(), key.clone()).is_some() {
                return Err("duplicate child name");
            }
            if matches!(entry.kind, OverlayKind::Directory) {
                bucket.subdirectories = bucket
                    .subdirectories
                    .checked_add(1)
                    .ok_or("subdirectory count overflow")?;
                bucket
                    .subdirectories
                    .checked_add(2)
                    .ok_or("directory link count overflow")?;
            }
        }
        Ok((inverse, parents))
    }

    /// The oracle starts with the primary map, including children absent from an index.
    pub(in crate::overlay_store) fn check_indexes(&self) -> Result<(), &'static str> {
        if self.inverse.len() != self.entries.len() {
            return Err("inverse association mismatch");
        }
        let mut counts: BTreeMap<Vec<Name>, u32> = BTreeMap::from([(Vec::new(), 0)]);
        for (key, entry) in &self.entries {
            if key != &entry.path || entry.inode == 0 {
                return Err("primary identity mismatch");
            }
            if self.inverse.get(&entry.inode) != Some(key) {
                return Err("inverse association mismatch");
            }
            let (name, parent) = key.split_last().ok_or("empty primary path")?;
            if !parent.is_empty()
                && !self
                    .entries
                    .get(parent)
                    .is_some_and(|e| matches!(e.kind, OverlayKind::Directory))
            {
                return Err("missing parent directory");
            }
            let bucket = self.parents.get(parent).ok_or("missing directory bucket")?;
            if bucket.children.get(name) != Some(key) {
                return Err("missing-child mismatch");
            }
            if matches!(entry.kind, OverlayKind::Directory) {
                counts.entry(key.clone()).or_default();
                let count = counts.entry(parent.to_vec()).or_default();
                *count = count.checked_add(1).ok_or("subdirectory count overflow")?;
                count
                    .checked_add(2)
                    .ok_or("directory link count overflow")?;
            }
        }
        for (parent, bucket) in &self.parents {
            let expected = counts.get(parent).ok_or("stale directory bucket")?;
            for (name, child) in &bucket.children {
                let (actual_name, actual_parent) =
                    child.split_last().ok_or("stale-child mismatch")?;
                if actual_name != name
                    || actual_parent != parent
                    || !self.entries.contains_key(child)
                {
                    return Err("stale-child mismatch");
                }
            }
            if bucket.subdirectories != *expected {
                return Err("subdirectory-count mismatch");
            }
        }
        if counts.len() != self.parents.len() {
            return Err("missing directory bucket");
        }
        Ok(())
    }

    pub(super) fn insert_index_entry(&mut self, p: &[Name]) -> Result<(), OverlayError> {
        let entry = self.entries.get(p).ok_or_else(mismatch)?;
        let (name, parent) = p.split_last().ok_or_else(mismatch)?;
        if self.inverse.insert(entry.inode, p.to_vec()).is_some() {
            return Err(mismatch());
        }
        let bucket = self.parents.get_mut(parent).ok_or_else(mismatch)?;
        if bucket.children.insert(name.clone(), p.to_vec()).is_some() {
            return Err(mismatch());
        }
        if matches!(entry.kind, OverlayKind::Directory) {
            bucket.subdirectories = bucket.subdirectories.checked_add(1).ok_or_else(mismatch)?;
            bucket.subdirectories.checked_add(2).ok_or_else(mismatch)?;
            if self
                .parents
                .insert(p.to_vec(), DirectoryIndex::default())
                .is_some()
            {
                return Err(mismatch());
            }
        }
        Ok(())
    }

    pub(super) fn remove_index_entry(&mut self, p: &[Name]) -> Result<(), OverlayError> {
        let entry = self.entries.get(p).ok_or_else(mismatch)?;
        let (name, parent) = p.split_last().ok_or_else(mismatch)?;
        if self.inverse.remove(&entry.inode).as_deref() != Some(p) {
            return Err(mismatch());
        }
        let bucket = self.parents.get_mut(parent).ok_or_else(mismatch)?;
        if bucket.children.remove(name).as_deref() != Some(p) {
            return Err(mismatch());
        }
        if matches!(entry.kind, OverlayKind::Directory) {
            bucket.subdirectories = bucket.subdirectories.checked_sub(1).ok_or_else(mismatch)?;
            let removed = self.parents.remove(p).ok_or_else(mismatch)?;
            if !removed.children.is_empty() || removed.subdirectories != 0 {
                return Err(mismatch());
            }
        }
        Ok(())
    }

    fn check_entry_associations(&self, p: &[Name]) -> Result<(), OverlayError> {
        let (name, parent) = p.split_last().ok_or_else(mismatch)?;
        let child = self
            .parents
            .get(parent)
            .and_then(|bucket| bucket.children.get(name));
        if let Some(entry) = self.entries.get(p) {
            if entry.path != p
                || self.inverse.get(&entry.inode).map(Vec::as_slice) != Some(p)
                || child.map(Vec::as_slice) != Some(p)
                || matches!(entry.kind, OverlayKind::Directory) != self.parents.contains_key(p)
            {
                return Err(mismatch());
            }
        } else if child.is_some() || self.parents.contains_key(p) {
            return Err(mismatch());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn count_index_clone(&self) {
        let inverse = self.inverse.len();
        let buckets = self.parents.len();
        let members = self
            .parents
            .values()
            .map(|b| b.children.len())
            .sum::<usize>();
        let bytes = |p: &[Name]| p.iter().map(|n| n.as_bytes().len()).sum::<usize>();
        let path_bytes = self
            .entries
            .unmeasured()
            .keys()
            .map(|p| bytes(p))
            .sum::<usize>()
            + self
                .entries
                .unmeasured()
                .values()
                .map(|e| bytes(&e.path))
                .sum::<usize>()
            + self
                .stages
                .values()
                .filter_map(|s| s.path.as_ref())
                .map(|p| bytes(p))
                .sum::<usize>()
            + self.inverse.values().map(|p| bytes(p)).sum::<usize>()
            + self
                .parents
                .iter()
                .map(|(p, b)| {
                    bytes(p)
                        + b.children
                            .iter()
                            .map(|(n, p)| n.as_bytes().len() + bytes(p))
                            .sum::<usize>()
                })
                .sum::<usize>();
        super::super::work::namespace_clone(
            self.entries.len(),
            inverse,
            buckets,
            members,
            path_bytes,
        );
        super::CLONED_INDEX_ROWS.set({
            let old = super::CLONED_INDEX_ROWS.get();
            (
                old.0 + inverse,
                old.1 + buckets,
                old.2 + members,
                old.3 + path_bytes,
            )
        });
    }
}

/// Expected associations are selected from the primary transition, before changing indexes.
pub(super) struct Transition {
    paths: BTreeSet<Vec<Name>>,
    old: BTreeMap<Vec<Name>, (u64, bool)>,
    counts: BTreeMap<Vec<Name>, u32>,
}

impl Transition {
    pub(super) fn capture(ns: &Namespace, record: &Record) -> Result<Self, OverlayError> {
        let mut paths = BTreeSet::new();
        match record {
            Record::Create { at, .. }
            | Record::RecreateFile { at: Some(at), .. }
            | Record::StageBind { at, .. }
            | Record::SetattrExec { at, .. }
            | Record::Delete { at, .. } => {
                paths.insert(path(at));
            }
            Record::Move { from, to } | Record::Replace { from, to } => {
                let src = path(from);
                let dst = path(to);
                paths.insert(src.clone());
                paths.insert(dst.clone());
                for p in ns.entries.keys().filter(|p| p.starts_with(&src)) {
                    paths.insert(p.clone());
                    let mut moved = dst.clone();
                    moved.extend_from_slice(p.get(src.len()..).ok_or_else(mismatch)?);
                    paths.insert(moved);
                }
            }
            Record::WriteExtent { stage_id, .. }
            | Record::Truncate { stage_id, .. }
            | Record::StageRollback { stage_id, .. }
            | Record::FileSynced { stage_id, .. } => {
                if let Some(p) = ns.stages.get(stage_id).and_then(|s| s.path.as_ref()) {
                    paths.insert(p.clone());
                }
            }
            Record::RecreateFile { at: None, .. }
            | Record::IntentRegistered { .. }
            | Record::CommitBoundary { .. }
            | Record::ProjectedBoundary { .. }
            | Record::LandedCommit { .. }
            | Record::CommitAttempt { .. }
            | Record::ResidualDisposition(_)
            | Record::CommitFence { .. } => {}
        }
        let mut old = BTreeMap::new();
        let mut counts = BTreeMap::new();
        for p in &paths {
            ns.check_entry_associations(p)?;
            if let Some(entry) = ns.entries.get(p) {
                old.insert(
                    p.clone(),
                    (entry.inode, matches!(entry.kind, OverlayKind::Directory)),
                );
            }
            for parent in [p.as_slice(), p.split_last().ok_or_else(mismatch)?.1] {
                counts.insert(
                    parent.to_vec(),
                    ns.parents.get(parent).map_or(0, |b| b.subdirectories),
                );
            }
        }
        Ok(Self { paths, old, counts })
    }

    pub(super) fn validate(mut self, ns: &Namespace) -> Result<(), OverlayError> {
        let mut current = BTreeMap::new();
        for p in &self.paths {
            ns.check_entry_associations(p)?;
            if let Some(entry) = ns.entries.get(p) {
                current.insert(entry.inode, p.as_slice());
            }
            let parent = p.split_last().ok_or_else(mismatch)?.1;
            let count = self.counts.get_mut(parent).ok_or_else(mismatch)?;
            if self.old.get(p).is_some_and(|(_, dir)| *dir) {
                *count = count.checked_sub(1).ok_or_else(mismatch)?;
            }
            if ns
                .entries
                .get(p)
                .is_some_and(|e| matches!(e.kind, OverlayKind::Directory))
            {
                *count = count.checked_add(1).ok_or_else(mismatch)?;
            }
        }
        for (inode, _) in self.old.values() {
            if ns.inverse.get(inode).map(Vec::as_slice) != current.get(inode).copied() {
                return Err(mismatch());
            }
        }
        for (p, count) in self.counts {
            if let Some(bucket) = ns.parents.get(&p) {
                if bucket.subdirectories != count {
                    return Err(mismatch());
                }
            } else if count != 0 {
                return Err(mismatch());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
