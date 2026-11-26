// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Private namespace fold; no disk mutation occurs during provisional replay.

use super::{OverlayEntry, OverlayError, OverlayKind, PathChange, ViewChange};
use granary_core::hash::GrainId;
use granary_core::manifest::Name;
use granary_core::overlay_journal::{CreateKind, DeleteKind, Record, SyncedMark};
use std::collections::{BTreeMap, BTreeSet};

mod indexes;
use indexes::{DirectoryIndex, Transition};

#[derive(Debug, Clone)]
pub(super) struct Stage {
    pub inode: u64,
    pub path: Option<Vec<Name>>,
    pub size: u64,
    pub base: Option<GrainId>,
    pub base_size: u64,
    pub mark: Option<SyncedMark>,
    // Restored bytes supply the checkpoint when no synced mark is present.
    pub rollback: Option<(Option<GrainId>, u64)>,
    // Only a receipt-bound completion supplies the captured journal boundary.
    // Replayed v1 marks do not encode it; retain conservative dirty state there.
    pub checkpoint_boundary: Option<u64>,
    pub extents: BTreeMap<u64, Record>,
    pub zeros: Vec<(u64, u64)>,
    pub handles: u64,
    pub captures: BTreeMap<u64, u64>,
}

impl Stage {
    pub(super) fn inherited(&self) -> (Option<GrainId>, u64) {
        self.rollback.unwrap_or((self.base, self.base_size))
    }

    pub(super) fn checkpoint(&self) -> (Option<GrainId>, u64) {
        self.mark.map_or_else(
            || self.inherited(),
            |mark| (Some(mark.content), mark.synced_size),
        )
    }

    pub(super) fn agrees_with(&self, mark: SyncedMark) -> bool {
        self.checkpoint() == (Some(mark.content), mark.synced_size)
    }
}

#[derive(Debug, Default)]
#[cfg_attr(not(test), derive(Clone))]
pub(super) struct Namespace {
    #[cfg(not(test))]
    pub entries: BTreeMap<Vec<Name>, OverlayEntry>,
    #[cfg(test)]
    pub entries: super::work::PrimaryEntries,
    pub stages: BTreeMap<u64, Stage>,
    inverse: BTreeMap<u64, Vec<Name>>,
    parents: BTreeMap<Vec<Name>, DirectoryIndex>,
    next_inode: u64,
}

#[cfg(test)]
std::thread_local! {
    pub(super) static EXHAUSTIVE_QUERY_CHECKS: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
    pub(super) static QUERY_COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static QUERY_PRIMARY_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static CLONED_ENTRIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static CLONED_ENTRY_VALUES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static CLONED_INDEX_ROWS: std::cell::Cell<(usize, usize, usize, usize)> = const { std::cell::Cell::new((0, 0, 0, 0)) };
}

#[cfg(test)]
pub(super) fn exhaustive_query_checks() -> bool {
    EXHAUSTIVE_QUERY_CHECKS.get()
}
#[cfg(test)]
impl Clone for Namespace {
    fn clone(&self) -> Self {
        let _storage = super::work::StorageScope::enter();
        CLONED_ENTRIES.set(CLONED_ENTRIES.get() + self.entries.len());
        self.count_index_clone();
        Self {
            entries: self.entries.clone(),
            stages: self.stages.clone(),
            inverse: self.inverse.clone(),
            parents: self.parents.clone(),
            next_inode: self.next_inode,
        }
    }
}

pub(super) fn path(at: &granary_core::overlay_journal::Location) -> Vec<Name> {
    let mut path = at.parent.names().to_vec();
    path.push(at.name.clone());
    path
}

impl Namespace {
    pub(super) fn remaining_inodes(&self) -> u64 {
        u64::MAX.saturating_sub(self.next_inode)
    }

    pub(super) fn assign_inode(&mut self, p: &[Name], inode: u64) -> Result<(), OverlayError> {
        let next = inode.checked_add(1).ok_or_else(OverlayError::poisoned)?;
        if inode == 0 || self.inverse.get(&inode).is_some_and(|old| old != p) {
            return Err(OverlayError::poisoned());
        }
        let entry = self.entries.get_mut(p).ok_or_else(OverlayError::poisoned)?;
        if self.inverse.get(&entry.inode).map(Vec::as_slice) != Some(p) {
            return Err(OverlayError::poisoned());
        }
        self.inverse.remove(&entry.inode);
        entry.inode = inode;
        self.inverse.insert(inode, p.to_vec());
        self.next_inode = self.next_inode.max(next);
        Ok(())
    }

    /// Carry each old inode whose identity is unchanged at its path, and give
    /// every other entry a fresh one. `captured` indexes the landed commit's
    /// captured entries by capture-time overlay inode; it is empty where there
    /// is no landing.
    pub(super) fn preserve_inodes(
        &mut self,
        old: &Self,
        captured: &BTreeMap<u64, &OverlayEntry>,
    ) -> Result<ViewChange, OverlayError> {
        self.next_inode = old.next_inode;
        let mut change = ViewChange::default();
        for node in self.entries.values_mut() {
            let previous = old.entries.get(&node.path);
            if let Some(previous) =
                previous.filter(|previous| same_identity(previous, node, captured))
            {
                node.inode = previous.inode;
            } else {
                node.inode = self.next_inode;
                self.next_inode = self
                    .next_inode
                    .checked_add(1)
                    .ok_or_else(|| OverlayError::refused("inode exhaustion"))?;
                change.paths.push(PathChange {
                    path: node.path.clone(),
                    old: previous.map(|previous| previous.inode),
                    new: Some(node.inode),
                });
            }
        }
        let mut listed: BTreeSet<&[Name]> =
            change.paths.iter().map(|c| c.path.as_slice()).collect();
        let mut absent = Vec::new();
        for previous in old.entries.values() {
            match self.entries.get(&previous.path) {
                Some(node) if node.inode == previous.inode => continue,
                Some(_) => {}
                // Ancestors sort first, so a listed ancestor is already in
                // `listed`; the removal of its subtree is implied by it.
                None if (1..previous.path.len())
                    .any(|n| previous.path.get(..n).is_some_and(|a| listed.contains(a))) => {}
                None => {
                    listed.insert(&previous.path);
                    absent.push(PathChange {
                        path: previous.path.clone(),
                        old: Some(previous.inode),
                        new: None,
                    });
                }
            }
            change.retired.insert(previous.inode, previous.clone());
        }
        change.paths.extend(absent);
        change.paths.sort_by(|a, b| a.path.cmp(&b.path));
        for (&id, stage) in &mut self.stages {
            stage.inode = if let Some(entry) = stage.path.as_ref().and_then(|p| self.entries.get(p))
            {
                entry.inode
            } else if let Some(previous) = old.stages.get(&id) {
                previous.inode
            } else {
                let inode = self.next_inode;
                self.next_inode = self
                    .next_inode
                    .checked_add(1)
                    .ok_or_else(|| OverlayError::refused("inode exhaustion"))?;
                inode
            };
        }
        self.rebuild_indexes()?;
        Ok(change)
    }
    pub(super) fn base(entries: &[OverlayEntry]) -> Result<Self, OverlayError> {
        let mut state = Self {
            next_inode: 1,
            ..Self::default()
        };
        for entry in entries {
            if entry.path.is_empty()
                || entry.stage_id.is_some()
                || entry.size > granary_core::overlay_journal::SIZE_MAX
                || matches!(entry.kind, OverlayKind::File { content: None })
            {
                return Err(OverlayError::refused("invalid base entry"));
            }
            validate_path(&entry.path)?;
            let mut node = entry.clone();
            node.inode = state.inode()?;
            if state.entries.insert(node.path.clone(), node).is_some() {
                return Err(OverlayError::refused("duplicate base entry"));
            }
        }
        for p in state.entries.keys() {
            state.parent(p)?;
        }
        state.rebuild_indexes()?;
        Ok(state)
    }

    pub(super) fn base_with_inodes(entries: &[OverlayEntry]) -> Result<Self, OverlayError> {
        let mut state = Self::base(entries)?;
        for entry in entries {
            state
                .entries
                .get_mut(&entry.path)
                .ok_or_else(|| OverlayError::refused("projection base missing"))?
                .inode = entry.inode;
            state.next_inode = state.next_inode.max(
                entry
                    .inode
                    .checked_add(1)
                    .ok_or_else(OverlayError::poisoned)?,
            );
        }
        state.rebuild_indexes()?;
        Ok(state)
    }
    pub(super) fn inode(&mut self) -> Result<u64, OverlayError> {
        let inode = self.next_inode;
        self.next_inode = inode
            .checked_add(1)
            .ok_or_else(|| OverlayError::refused("inode exhausted"))?;
        Ok(inode)
    }
    fn parent(&self, p: &[Name]) -> Result<(), OverlayError> {
        let Some((_, parent)) = p.split_last() else {
            return Err(OverlayError::refused("empty path"));
        };
        if !parent.is_empty()
            && !self
                .entries
                .get(parent)
                .is_some_and(|e| matches!(e.kind, OverlayKind::Directory))
        {
            return Err(OverlayError::refused("parent is not a directory"));
        }
        Ok(())
    }
    fn bind(
        &mut self,
        id: u64,
        p: Vec<Name>,
        size: u64,
        base: Option<GrainId>,
    ) -> Result<(), OverlayError> {
        let entry = self
            .entries
            .get_mut(&p)
            .ok_or_else(|| OverlayError::refused("bind name missing"))?;
        if !matches!(entry.kind, OverlayKind::File { .. })
            || entry.stage_id.is_some()
            || self.stages.contains_key(&id)
        {
            return Err(OverlayError::refused("bind type or stage conflict"));
        }
        entry.stage_id = Some(id);
        entry.size = size;
        let inode = entry.inode;
        self.insert_stage(id, inode, Some(p), size, base)
    }
    /// A stage with no extents yet, named at `path` or detached.
    fn insert_stage(
        &mut self,
        id: u64,
        inode: u64,
        path: Option<Vec<Name>>,
        size: u64,
        base: Option<GrainId>,
    ) -> Result<(), OverlayError> {
        if self.stages.contains_key(&id) {
            return Err(OverlayError::refused("bind type or stage conflict"));
        }
        self.stages.insert(
            id,
            Stage {
                inode,
                path,
                size,
                base,
                base_size: size,
                mark: None,
                rollback: None,
                checkpoint_boundary: None,
                extents: BTreeMap::new(),
                zeros: Vec::new(),
                handles: 0,
                captures: BTreeMap::new(),
            },
        );
        Ok(())
    }
    /// A new entry at `p`, whose parent must be a directory and whose name
    /// must be absent.
    fn insert_entry(
        &mut self,
        p: &[Name],
        kind: OverlayKind,
        exec: bool,
    ) -> Result<(), OverlayError> {
        self.parent(p)?;
        if self.entries.contains_key(p) {
            return Err(OverlayError::refused("create destination exists"));
        }
        let inode = self.inode()?;
        self.entries.insert(
            p.to_vec(),
            OverlayEntry {
                inode,
                path: p.to_vec(),
                kind,
                stage_id: None,
                size: 0,
                exec,
            },
        );
        self.insert_index_entry(p)
    }
    fn detach(&mut self, p: &[Name]) -> Result<(), OverlayError> {
        self.remove_index_entry(p)?;
        let entry = self
            .entries
            .remove(p)
            .ok_or_else(|| OverlayError::refused("name missing"))?;
        if let Some(id) = entry.stage_id {
            self.stages
                .get_mut(&id)
                .ok_or_else(|| OverlayError::refused("stage missing"))?
                .path = None;
        }
        Ok(())
    }
    pub(super) fn fold(&mut self, record: &Record) -> Result<(), OverlayError> {
        let before = Transition::capture(self, record)?;
        self.fold_record(record)?;
        before.validate(self)?;
        #[cfg(test)]
        self.check_indexes().map_err(|_| OverlayError::poisoned())?;
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the exhaustive record fold keeps namespace transitions together"
    )]
    fn fold_record(&mut self, record: &Record) -> Result<(), OverlayError> {
        match record {
            Record::Create { at, kind } => {
                let p = path(at);
                let (node_kind, exec) = match kind {
                    CreateKind::File { exec, .. } => (OverlayKind::File { content: None }, *exec),
                    CreateKind::Dir => (OverlayKind::Directory, false),
                    CreateKind::Symlink { target } => (
                        OverlayKind::Symlink {
                            target: target.clone(),
                        },
                        false,
                    ),
                };
                self.insert_entry(&p, node_kind, exec)?;
                if let CreateKind::File { stage_id, .. } = kind {
                    self.bind(*stage_id, p, 0, None)?;
                }
            }
            // An issued stage carried under its own id: the anchor is its base
            // bytes, not a synced mark. Without a location it has no entry, so
            // an old name now taken by another entry is no conflict.
            Record::RecreateFile {
                at,
                exec,
                stage_id,
                anchor,
            } => {
                let (base, size) = anchor.map_or((None, 0), |a| (Some(a.content), a.size));
                if let Some(at) = at {
                    let p = path(at);
                    self.insert_entry(&p, OverlayKind::File { content: None }, *exec)?;
                    self.bind(*stage_id, p, size, base)?;
                } else {
                    let inode = self.inode()?;
                    self.insert_stage(*stage_id, inode, None, size, base)?;
                }
            }
            Record::StageBind {
                at,
                stage_id,
                staged_size,
                base_content,
                ..
            } => {
                if self.entries.get(&path(at)).map(|e| &e.kind)
                    != Some(&OverlayKind::File {
                        content: Some(*base_content),
                    })
                {
                    return Err(OverlayError::refused("bind base content"));
                }
                self.bind(*stage_id, path(at), *staged_size, Some(*base_content))?;
            }
            Record::WriteExtent { stage_id, .. }
            | Record::Truncate { stage_id, .. }
            | Record::StageRollback { stage_id, .. } => {
                let stage = self
                    .stages
                    .get_mut(stage_id)
                    .ok_or_else(|| OverlayError::refused("stage missing"))?;
                stage
                    .extents
                    .retain(|_, previous| !previous.extent_superseded_by(record));
                match record {
                    Record::WriteExtent { offset, length, .. } => {
                        let end = offset
                            .checked_add(*length)
                            .ok_or_else(|| OverlayError::refused("extent overflow"))?;
                        if *offset > stage.size {
                            stage.zeros.push((stage.size, *offset));
                        }
                        stage.zeros = subtract(&stage.zeros, *offset, end);
                        stage.size = stage.size.max(end);
                        stage.extents.insert(*offset, record.clone());
                    }
                    Record::Truncate { new_size: size, .. } => {
                        let size = *size;
                        if size < stage.size {
                            stage.zeros.push((size, stage.size));
                        }
                        if size > stage.size {
                            stage.zeros.push((stage.size, size));
                        }
                        stage.size = size;
                    }
                    Record::StageRollback { anchor, .. } => {
                        let (content, size) =
                            anchor.map_or((None, 0), |a| (Some(a.content), a.size));
                        stage.zeros.clear();
                        stage.size = size;
                        stage.rollback = Some((content, size));
                    }
                    _ => return Err(OverlayError::refused("truncate fold")),
                }
                if let Some(p) = &stage.path {
                    self.entries
                        .get_mut(p)
                        .ok_or_else(|| OverlayError::refused("stage name missing"))?
                        .size = stage.size;
                }
            }
            Record::Move { from, to } | Record::Replace { from, to } => {
                let src = path(from);
                let dst = path(to);
                self.parent(&dst)?;
                if src == dst || dst.starts_with(&src) {
                    return Err(OverlayError::refused("move cycle or identity"));
                }
                let source = self
                    .entries
                    .get(&src)
                    .ok_or_else(|| OverlayError::refused("move source missing"))?;
                if let Some(target) = self.entries.get(&dst) {
                    if matches!(record, Record::Move { .. })
                        || matches!(target.kind, OverlayKind::Directory)
                            != matches!(source.kind, OverlayKind::Directory)
                        || self
                            .entries
                            .keys()
                            .any(|p| p.len() > dst.len() && p.starts_with(&dst))
                    {
                        return Err(OverlayError::refused("replace destination refused"));
                    }
                    self.detach(&dst)?;
                } else if matches!(record, Record::Replace { .. }) {
                    return Err(OverlayError::refused("replace destination missing"));
                }
                let moved: Vec<_> = self
                    .entries
                    .keys()
                    .filter(|p| p.starts_with(&src))
                    .cloned()
                    .collect();
                for old in moved.iter().rev() {
                    self.remove_index_entry(old)?;
                }
                for old in moved {
                    let mut entry = self
                        .entries
                        .remove(&old)
                        .ok_or_else(|| OverlayError::refused("move entry missing"))?;
                    let mut new = dst.clone();
                    new.extend_from_slice(
                        old.get(src.len()..)
                            .ok_or_else(|| OverlayError::refused("move prefix"))?,
                    );
                    validate_path(&new)?;
                    entry.path.clone_from(&new);
                    if let Some(id) = entry.stage_id {
                        self.stages
                            .get_mut(&id)
                            .ok_or_else(|| OverlayError::refused("stage missing"))?
                            .path = Some(new.clone());
                    }
                    self.entries.insert(new.clone(), entry);
                    self.insert_index_entry(&new)?;
                }
            }
            Record::Delete { at, kind } => {
                let p = path(at);
                let node = self
                    .entries
                    .get(&p)
                    .ok_or_else(|| OverlayError::refused("delete name missing"))?;
                let valid = match (kind, &node.kind) {
                    (DeleteKind::File { stage_id }, OverlayKind::File { .. }) => {
                        *stage_id == node.stage_id
                    }
                    (DeleteKind::Dir, OverlayKind::Directory)
                    | (DeleteKind::Symlink, OverlayKind::Symlink { .. }) => true,
                    _ => false,
                };
                if !valid
                    || self
                        .entries
                        .keys()
                        .any(|v| v.len() > p.len() && v.starts_with(&p))
                {
                    return Err(OverlayError::refused("delete type/stage/nonempty refused"));
                }
                self.detach(&p)?;
            }
            Record::SetattrExec { at, exec } => {
                let node = self
                    .entries
                    .get_mut(&path(at))
                    .ok_or_else(|| OverlayError::refused("setattr name missing"))?;
                if !matches!(node.kind, OverlayKind::File { .. }) {
                    return Err(OverlayError::refused("setattr type refused"));
                }
                node.exec = *exec;
            }
            Record::FileSynced {
                stage_id,
                synced_size,
                content,
                generation,
                ..
            } => {
                let stage = self
                    .stages
                    .get_mut(stage_id)
                    .ok_or_else(|| OverlayError::refused("sync stage missing"))?;
                stage.mark = Some(SyncedMark {
                    synced_size: *synced_size,
                    content: *content,
                    generation: *generation,
                });
            }
            Record::IntentRegistered { .. }
            | Record::ResidualDisposition(_)
            | Record::CommitBoundary { .. }
            | Record::ProjectedBoundary { .. }
            | Record::LandedCommit { .. }
            | Record::CommitAttempt { .. }
            | Record::CommitFence { .. } => {}
        }
        Ok(())
    }
}

/// Whether `new` keeps the identity of `old`, the entry at the same path in
/// the view being replaced. Stage presence alone is no evidence: a retired
/// stage keeps the identity only when its captured version is what landed.
fn same_identity(
    old: &OverlayEntry,
    new: &OverlayEntry,
    captured: &BTreeMap<u64, &OverlayEntry>,
) -> bool {
    if std::mem::discriminant(&old.kind) != std::mem::discriminant(&new.kind) {
        return false;
    }
    let carried = old.stage_id.is_some() && old.stage_id == new.stage_id;
    // By inode, not path: a local rename after the capture keeps the inode.
    let landed = old.stage_id.is_some()
        && new.stage_id.is_none()
        && new.exec == old.exec
        && captured
            .get(&old.inode)
            .is_some_and(|entry| entry.kind == new.kind);
    let unchanged = old.kind == new.kind && old.exec == new.exec;
    carried || landed || unchanged
}

pub(super) fn subtract(intervals: &[(u64, u64)], start: u64, end: u64) -> Vec<(u64, u64)> {
    let mut result = Vec::new();
    for &(a, b) in intervals {
        if a < start {
            result.push((a, b.min(start)));
        }
        if b > end {
            result.push((a.max(end), b));
        }
    }
    result.retain(|(a, b)| a < b);
    result
}

fn validate_path(path: &[Name]) -> Result<(), OverlayError> {
    let (_, parent) = path
        .split_last()
        .ok_or_else(|| OverlayError::refused("empty path"))?;
    granary_core::overlay_journal::Parent::new(parent.to_vec())
        .map_err(|_| OverlayError::refused("path bounds"))?;
    Ok(())
}
