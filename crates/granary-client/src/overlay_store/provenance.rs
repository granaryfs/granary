// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Immutable namespace effects are annotated against the complete live prefix.
//! A filtered projection consumes these identities and dependencies, never a
//! fresh pathname lookup against a different namespace incarnation.

use super::{Namespace, OverlayEntry, OverlayError, OverlayKind, Record, codec, state};
use granary_core::manifest::Name;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The entries a record can read or rewrite, captured before it is folded so
/// that replay never copies the whole namespace per record.
pub(super) type Touched = BTreeMap<Vec<Name>, OverlayEntry>;

pub(super) fn record_paths(record: &Record) -> (Option<Vec<Name>>, Option<Vec<Name>>) {
    match record {
        Record::Create { at, .. } | Record::RecreateFile { at: Some(at), .. } => {
            (None, Some(state::path(at)))
        }
        Record::Move { from, to } | Record::Replace { from, to } => {
            (Some(state::path(from)), Some(state::path(to)))
        }
        Record::Delete { at, .. }
        | Record::SetattrExec { at, .. }
        | Record::StageBind { at, .. } => (Some(state::path(at)), None),
        // Payload effects such as rollback name their stage by id.
        _ => (None, None),
    }
}

/// How many locations a record names whose parent a residual replacement may
/// lift.
fn locations(record: &Record) -> u64 {
    match record {
        Record::Move { .. } | Record::Replace { .. } => 2,
        Record::Create { .. }
        | Record::StageBind { .. }
        | Record::Delete { .. }
        | Record::SetattrExec { .. }
        | Record::RecreateFile { at: Some(_), .. } => 1,
        _ => 0,
    }
}

fn subtree<'a>(
    entries: &'a BTreeMap<Vec<Name>, OverlayEntry>,
    prefix: &[Name],
) -> impl Iterator<Item = (&'a Vec<Name>, &'a OverlayEntry)> {
    entries
        .range(prefix.to_vec()..)
        .take_while(move |(path, _)| path.starts_with(prefix))
}

/// Capture the source and destination subtrees and their parents.
pub(super) fn touched(namespace: &Namespace, record: &Record) -> Touched {
    let (source, destination) = record_paths(record);
    let mut seen = Touched::new();
    for path in source.iter().chain(destination.iter()) {
        for (key, entry) in subtree(&namespace.entries, path) {
            seen.insert(key.clone(), entry.clone());
        }
        if let Some((_, parent)) = path.split_last()
            && let Some(entry) = namespace.entries.get(parent)
        {
            seen.insert(parent.to_vec(), entry.clone());
        }
    }
    seen
}

/// Identity and effect dependencies resolved when a record was admitted.
#[derive(Debug, Clone)]
pub struct NamespaceEffect {
    pub(crate) seq: u64,
    pub(crate) record: Record,
    pub(crate) source: Option<u64>,
    pub(crate) result: Option<u64>,
    pub(crate) parents: Vec<u64>,
    pub(crate) dependencies: BTreeSet<u64>,
    pub(crate) regular_source: bool,
    pub(crate) content_change: bool,
}
impl NamespaceEffect {
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.seq
    }
    #[must_use]
    pub fn record(&self) -> &Record {
        &self.record
    }
    #[must_use]
    pub fn source_identity(&self) -> Option<u64> {
        self.source
    }
    #[must_use]
    pub fn result_identity(&self) -> Option<u64> {
        self.result
    }
    #[must_use]
    pub fn parent_identities(&self) -> &[u64] {
        &self.parents
    }
    #[must_use]
    pub fn dependencies(&self) -> &BTreeSet<u64> {
        &self.dependencies
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct History {
    pub base: Vec<OverlayEntry>,
    pub records: Vec<Arc<NamespaceEffect>>,
    // `reach[i]` is the sum of `locations` over `records[..=i]`, kept beside
    // the records so a projected reserve reads a prefix instead of scanning.
    reach: Vec<u64>,
    // Retain eligibility by identity even after a replacement detaches or
    // collects its staging file. Dependency exclusion may restore that target.
    pub checkpoints: BTreeMap<u64, super::DurableFile>,
    identities: BTreeMap<u64, u64>,
    names: BTreeMap<Vec<Name>, u64>,
}
impl History {
    pub(super) fn base(namespace: &Namespace) -> Self {
        Self {
            base: namespace.entries.values().cloned().collect(),
            ..Self::default()
        }
    }
    pub(super) fn annotate(
        &self,
        seq: u64,
        record: &Record,
        before: &Touched,
        after: &Namespace,
    ) -> Result<NamespaceEffect, OverlayError> {
        let mut effect = NamespaceEffect {
            seq,
            record: record.clone(),
            source: None,
            result: None,
            parents: Vec::new(),
            dependencies: BTreeSet::new(),
            regular_source: false,
            content_change: true,
        };
        let (source, destination, vacancy) = match record {
            // A named recreate is a file creation; a detached one has no name.
            Record::Create { at, .. } | Record::RecreateFile { at: Some(at), .. } => {
                (None, Some(state::path(at)), true)
            }
            Record::Move { from, to } => (Some(state::path(from)), Some(state::path(to)), true),
            Record::Replace { from, to } => (Some(state::path(from)), Some(state::path(to)), false),
            Record::Delete { at, .. }
            | Record::SetattrExec { at, .. }
            | Record::StageBind { at, .. } => (Some(state::path(at)), None, false),
            _ => (None, None, false),
        };
        if let Some(path) = &source {
            let entry = before
                .get(path)
                .ok_or_else(|| OverlayError::refused("provenance source missing"))?;
            effect.source = Some(entry.inode);
            effect.regular_source = matches!(entry.kind, OverlayKind::File { .. });
            self.consume_name(path, &mut effect);
            self.consume_identity(entry.inode, &mut effect);
            if matches!(
                record,
                Record::Delete {
                    kind: codec::DeleteKind::Dir,
                    ..
                }
            ) {
                for (name, producer) in &self.names {
                    if name.len() > path.len() && name.starts_with(path) {
                        effect.dependencies.insert(*producer);
                    }
                }
            }
        }
        for path in source.iter().chain(destination.iter()) {
            let (_, parent) = path
                .split_last()
                .ok_or_else(|| OverlayError::refused("provenance empty path"))?;
            let inode = if parent.is_empty() {
                0
            } else {
                before
                    .get(parent)
                    .filter(|entry| matches!(entry.kind, OverlayKind::Directory))
                    .ok_or_else(|| OverlayError::refused("provenance parent missing"))?
                    .inode
            };
            effect.parents.push(inode);
            self.consume_identity(inode, &mut effect);
            self.consume_name(parent, &mut effect);
        }
        if let Some(path) = &destination {
            if vacancy {
                self.consume_name(path, &mut effect);
            }
            effect.result = after.entries.get(path).map(|entry| entry.inode);
        }
        Ok(effect)
    }
    fn consume_name(&self, path: &[Name], effect: &mut NamespaceEffect) {
        if let Some(producer) = self.names.get(path) {
            effect.dependencies.insert(*producer);
        }
    }
    fn consume_identity(&self, inode: u64, effect: &mut NamespaceEffect) {
        if let Some(producer) = self.identities.get(&inode) {
            effect.dependencies.insert(*producer);
        }
    }
    pub(super) fn accept(&mut self, effect: NamespaceEffect, before: &Touched, after: &Namespace) {
        if let Record::FileSynced {
            stage_id,
            synced_size,
            content,
            ..
        } = effect.record
            && let Some(stage) = after.stages.get(&stage_id)
        {
            self.checkpoints.insert(
                stage.inode,
                super::DurableFile {
                    inode: stage.inode,
                    size: synced_size,
                    content,
                    content_boundary: 0,
                },
            );
        }
        if matches!(
            effect.record,
            Record::Create { .. }
                | Record::RecreateFile { at: Some(_), .. }
                | Record::Move { .. }
                | Record::Replace { .. }
                | Record::Delete { .. }
                | Record::SetattrExec { .. }
        ) {
            if let Some(inode) = effect.source {
                self.identities.insert(inode, effect.seq);
            }
            if let Some(inode) = effect.result {
                self.identities.insert(inode, effect.seq);
            }
            let (source, destination) = record_paths(&effect.record);
            let mut paths = BTreeSet::new();
            for prefix in source.iter().chain(destination.iter()) {
                paths.extend(subtree(&after.entries, prefix).map(|(path, _)| path.clone()));
                paths.extend(
                    before
                        .keys()
                        .filter(|path| path.starts_with(prefix))
                        .cloned(),
                );
            }
            for path in paths {
                let old = before.get(&path).map(|entry| entry.inode);
                let new = after.entries.get(&path).map(|entry| entry.inode);
                if old != new {
                    self.names.insert(path, effect.seq);
                }
            }
        }
        let reach = self
            .reach
            .last()
            .copied()
            .unwrap_or(0)
            .saturating_add(locations(&effect.record));
        self.reach.push(reach);
        self.records.push(Arc::new(effect));
    }

    /// The namespace locations the records through `through` can lift a
    /// parent at. Records are accepted in journal order, so their seqs rise
    /// and the prefix ends at a partition point.
    pub(super) fn locations_through(&self, through: u64) -> u64 {
        let count = self.records.partition_point(|effect| effect.seq <= through);
        count
            .checked_sub(1)
            .and_then(|last| self.reach.get(last))
            .copied()
            .unwrap_or(0)
    }

    /// `locations_through` by the scan it replaces.
    #[cfg(test)]
    pub(super) fn locations_through_by_scan(&self, through: u64) -> u64 {
        self.records
            .iter()
            .filter(|effect| effect.seq <= through)
            .map(|effect| locations(&effect.record))
            .sum()
    }

    /// Fold the base and every record through `through`, annotating each as it
    /// was admitted. Identities are the replay's own, not the live namespace's.
    pub(super) fn prefix(
        base: &[OverlayEntry],
        bytes: &[u8],
        through: u64,
    ) -> Result<(Namespace, Self), OverlayError> {
        let mut namespace = Namespace::base(base)?;
        let mut history = Self::base(&namespace);
        let mut result: Result<(), OverlayError> = Ok(());
        codec::scan_journal_with(bytes, |seq, record| {
            if seq <= through && result.is_ok() {
                result = (|| {
                    let before = touched(&namespace, record);
                    namespace.fold(record)?;
                    let effect = history.annotate(seq, record, &before, &namespace)?;
                    history.accept(effect, &before, &namespace);
                    Ok(())
                })();
            }
        })
        .map_err(|_| OverlayError::refused("provenance journal scan"))?;
        result?;
        Ok((namespace, history))
    }

    /// Rebuild volatile provenance from the unchanged journal encoding, then
    /// translate replay identities to the live namespace's preserved inodes.
    pub(super) fn replay(
        base: &[OverlayEntry],
        bytes: &[u8],
        live: &mut Namespace,
    ) -> Result<Self, OverlayError> {
        let (namespace, mut history) = Self::prefix(base, bytes, u64::MAX)?;
        let mut mapping = BTreeMap::from([(0, 0)]);
        for (path, entry) in &namespace.entries {
            let current = live
                .entries
                .get(path)
                .ok_or_else(|| OverlayError::refused("provenance replay namespace"))?;
            mapping.insert(entry.inode, current.inode);
        }
        for (id, stage) in &namespace.stages {
            if let Some(current) = live.stages.get(id) {
                mapping.insert(stage.inode, current.inode);
            }
        }
        let ids: BTreeSet<_> = history
            .base
            .iter()
            .map(|entry| entry.inode)
            .chain(history.records.iter().flat_map(|effect| {
                effect
                    .source
                    .into_iter()
                    .chain(effect.result)
                    .chain(effect.parents.iter().copied())
            }))
            .collect();
        for inode in ids {
            if let std::collections::btree_map::Entry::Vacant(slot) = mapping.entry(inode) {
                slot.insert(live.inode()?);
            }
        }
        let map = |inode: u64| {
            mapping
                .get(&inode)
                .copied()
                .ok_or_else(|| OverlayError::refused("provenance identity mapping"))
        };
        for entry in &mut history.base {
            entry.inode = map(entry.inode)?;
        }
        for effect in &mut history.records {
            let effect = Arc::make_mut(effect);
            effect.source = effect.source.map(map).transpose()?;
            effect.result = effect.result.map(map).transpose()?;
            effect.parents = effect
                .parents
                .iter()
                .copied()
                .map(map)
                .collect::<Result<_, _>>()?;
        }
        history.identities = history
            .identities
            .into_iter()
            .map(|(inode, seq)| Ok((map(inode)?, seq)))
            .collect::<Result<_, OverlayError>>()?;
        history.checkpoints = history
            .checkpoints
            .into_values()
            .map(|mut file| {
                file.inode = map(file.inode)?;
                Ok((file.inode, file))
            })
            .collect::<Result<_, OverlayError>>()?;
        Ok(history)
    }
}
