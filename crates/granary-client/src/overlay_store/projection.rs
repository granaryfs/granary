// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Dependency-closed durable namespace projection over sealed provenance.

use super::{
    Namespace, NamespaceEffect, OverlayEntry, OverlayError, OverlayKind, Record, SyncBoundary,
    codec, state,
};
use crate::writable_store::{CaptureCoverageInput, StageMutation, StageProjection};
use granary_core::hash::GrainId;
use granary_core::manifest::Name;
use std::collections::{BTreeMap, BTreeSet};

/// Durable file payload selected by the caller after authenticating its objects
/// and completing their acceptance barriers. Identity is independent of path.
#[derive(Debug, Clone)]
pub struct DurableFile {
    pub inode: u64,
    pub size: u64,
    pub content: GrainId,
    pub content_boundary: u64,
}

/// Namespace and identity annotations for a prepared root. This does not grant
/// cache authority or attest object acceptance; registration validates the exact
/// root and its authenticated leaves separately.
#[derive(Debug)]
pub struct PreparedProjection {
    entries: Vec<OverlayEntry>,
    boundary: u64,
    stages: Vec<StageProjection>,
    mutations: Vec<StageMutation>,
    rebuild: BTreeSet<u64>,
    changed: Vec<(GrainId, u64)>,
    excluded: BTreeSet<u64>,
}
/// Which directories to re-encode and which payloads are new since the base.
struct RebuildPlan {
    rebuild: BTreeSet<u64>,
    changed: Vec<(GrainId, u64)>,
}
impl PreparedProjection {
    #[must_use]
    pub fn entries(&self) -> &[OverlayEntry] {
        &self.entries
    }
    /// Identities of the projected directories whose entry list may differ from
    /// the base's: those a surviving effect names as a parent (all effects for a
    /// complete tree), those holding a file whose durable payload is not its base
    /// payload, and those that are not base directories at all, closed upward to
    /// the root (identity 0).
    /// Every other projected directory is a base directory with an unchanged
    /// subtree. Over-approximating this set is safe; under-approximating it
    /// would change the root.
    #[must_use]
    pub fn rebuild_set(&self) -> &BTreeSet<u64> {
        &self.rebuild
    }
    /// Durable payloads, as (content, size), of the projected files that are not
    /// their base payload: changed since the base, or without a base entry.
    #[must_use]
    pub fn changed_payloads(&self) -> &[(GrainId, u64)] {
        &self.changed
    }
    /// The seqs of the effects the projection left out: never-synced creations
    /// and moves, and everything depending on them.
    pub(super) fn excluded(&self) -> &BTreeSet<u64> {
        &self.excluded
    }
    /// The stage annotation of each projected file, with the journal cursor
    /// its durable payload covers.
    pub(super) fn stage_projections(&self) -> &[StageProjection] {
        &self.stages
    }
    /// Bind the complete sealed journal provenance to exact prepared root bytes.
    /// This is validation input, not a receipt or acknowledgement capability.
    #[must_use]
    pub fn coverage_input(&self, prepared_root: GrainId) -> CaptureCoverageInput {
        CaptureCoverageInput {
            prepared_root,
            boundary: self.boundary,
            projections: self.stages.clone(),
            mutations: self.mutations.clone(),
            identities: self.entries.clone(),
        }
    }
}

impl SyncBoundary {
    /// Build a complete commit seal from its frozen namespace, or replay a scoped
    /// seal's surviving effects at their eligible durable payloads. An excluded
    /// replacement never removes its destination. Symlink targets and directories
    /// require no regular-file selection.
    /// # Errors
    /// Refuses unknown/duplicate identities, invalid payload bounds, inconsistent
    /// source/parent provenance or an unsupported projection transition.
    #[expect(
        clippy::too_many_lines,
        reason = "complete and scoped trees share payload validation and rebuild annotations"
    )]
    pub fn project(&self, selected: &[DurableFile]) -> Result<PreparedProjection, OverlayError> {
        if self.complete_tree()
            && (selected.len() != self.files().len()
                || selected.iter().any(|file| {
                    file.content_boundary != self.through_seq()
                        || !self.files().iter().any(|capture| {
                            capture
                                .entry()
                                .is_some_and(|entry| entry.inode == file.inode)
                                && capture.size() == file.size
                        })
                }))
        {
            return Err(OverlayError::refused("complete tree selection"));
        }
        let mut durable = self.base_durable();
        let mut admitted = BTreeSet::new();
        for file in self.checkpoints() {
            durable.insert(file.inode, file.clone());
        }
        for file in selected {
            let known = self
                .entries()
                .iter()
                .chain(self.base_entries())
                .any(|entry| {
                    entry.inode == file.inode && matches!(entry.kind, OverlayKind::File { .. })
                })
                || self.effects().iter().any(|effect| {
                    matches!(
                        effect.record,
                        Record::Create {
                            kind: codec::CreateKind::File { .. },
                            ..
                        } | Record::RecreateFile { at: Some(_), .. }
                    ) && effect.result == Some(file.inode)
                });
            if !known
                || !admitted.insert(file.inode)
                || file.size > codec::SIZE_MAX
                || file.content_boundary > self.through_seq()
            {
                return Err(OverlayError::refused(
                    "durable projection identity/boundary",
                ));
            }
            durable.insert(file.inode, file.clone());
        }
        let mut namespace = Namespace::base_with_inodes(self.base_entries())?;
        let mut complete = namespace.clone();
        for effect in self.effects() {
            apply(&mut complete, effect, false)?;
        }
        let mut excluded = BTreeSet::new();
        let mut effect_parents = BTreeSet::new();
        for effect in self.effects() {
            if self.complete_tree() {
                effect_parents.extend(effect.parents.iter().copied());
                continue;
            }
            let blocked = match effect.record {
                Record::Create {
                    kind: codec::CreateKind::File { .. },
                    ..
                }
                | Record::RecreateFile { at: Some(_), .. } => !effect
                    .result
                    .is_some_and(|inode| durable.contains_key(&inode)),
                Record::Move { .. } | Record::Replace { .. } => {
                    effect.regular_source
                        && !effect
                            .source
                            .is_some_and(|inode| durable.contains_key(&inode))
                }
                _ => false,
            };
            if blocked
                || effect
                    .dependencies
                    .iter()
                    .any(|producer| excluded.contains(producer))
            {
                excluded.insert(effect.seq);
                continue;
            }
            effect_parents.extend(effect.parents.iter().copied());
            apply(&mut namespace, effect, true)?;
        }
        if self.complete_tree() {
            complete.entries.clear();
            for entry in self.entries() {
                complete.entries.insert(entry.path.clone(), entry.clone());
            }
            for entry in complete.entries.values() {
                if let OverlayKind::File { content } = entry.kind {
                    let payload = durable
                        .get(&entry.inode)
                        .ok_or_else(|| OverlayError::refused("complete tree payload"))?;
                    if payload.size != entry.size
                        || (entry.stage_id.is_none()
                            && content.is_some_and(|id| id != payload.content))
                    {
                        return Err(OverlayError::refused("complete tree payload"));
                    }
                }
            }
            namespace = complete;
        }
        let (entries, stages) = self.projected_entries(namespace, &durable)?;
        let mutations = self.journal_mutations();
        let RebuildPlan { rebuild, changed } = self.rebuild_plan(&entries, effect_parents)?;
        Ok(PreparedProjection {
            entries,
            boundary: self.through_seq(),
            stages,
            mutations,
            rebuild,
            changed,
            excluded,
        })
    }
    /// The directories to re-encode and the changed payloads, by identity.
    fn rebuild_plan(
        &self,
        entries: &[OverlayEntry],
        effect_parents: BTreeSet<u64>,
    ) -> Result<RebuildPlan, OverlayError> {
        let base_dirs: BTreeSet<u64> = self
            .base_entries()
            .iter()
            .filter(|entry| matches!(entry.kind, OverlayKind::Directory))
            .map(|entry| entry.inode)
            .collect();
        let base_files: BTreeMap<u64, (GrainId, u64)> = self
            .base_entries()
            .iter()
            .filter_map(|entry| match entry.kind {
                OverlayKind::File {
                    content: Some(content),
                } => Some((entry.inode, (content, entry.size))),
                _ => None,
            })
            .collect();
        let dir_at: BTreeMap<&[Name], u64> = entries
            .iter()
            .filter(|entry| matches!(entry.kind, OverlayKind::Directory))
            .map(|entry| (entry.path.as_slice(), entry.inode))
            .collect();
        let parent_of = |path: &[Name]| -> Result<u64, OverlayError> {
            let (_, parent) = path
                .split_last()
                .ok_or_else(|| OverlayError::refused("projection empty path"))?;
            if parent.is_empty() {
                return Ok(0);
            }
            dir_at
                .get(parent)
                .copied()
                .ok_or_else(|| OverlayError::refused("projection parent missing"))
        };
        let mut seeds = effect_parents;
        let mut changed = Vec::new();
        for entry in entries {
            match entry.kind {
                OverlayKind::Directory if !base_dirs.contains(&entry.inode) => {
                    seeds.insert(entry.inode);
                }
                OverlayKind::File {
                    content: Some(content),
                } if base_files.get(&entry.inode) != Some(&(content, entry.size)) => {
                    changed.push((content, entry.size));
                    seeds.insert(parent_of(&entry.path)?);
                }
                _ => {}
            }
        }
        let mut rebuild = BTreeSet::new();
        for entry in entries {
            if matches!(entry.kind, OverlayKind::Directory) && seeds.contains(&entry.inode) {
                rebuild.insert(entry.inode);
                for end in 1..entry.path.len() {
                    if let Some(ancestor) = entry.path.get(..end).and_then(|p| dir_at.get(p)) {
                        rebuild.insert(*ancestor);
                    }
                }
                rebuild.insert(0);
            }
        }
        if seeds.contains(&0) {
            rebuild.insert(0);
        }
        Ok(RebuildPlan { rebuild, changed })
    }
    /// Every base file at its base payload: the durable content of a clean file.
    fn base_durable(&self) -> BTreeMap<u64, DurableFile> {
        self.base_entries()
            .iter()
            .filter_map(|entry| match entry.kind {
                OverlayKind::File {
                    content: Some(content),
                } => Some((
                    entry.inode,
                    DurableFile {
                        inode: entry.inode,
                        size: entry.size,
                        content,
                        content_boundary: 0,
                    },
                )),
                _ => None,
            })
            .collect()
    }
    fn projected_entries(
        &self,
        namespace: Namespace,
        durable: &BTreeMap<u64, DurableFile>,
    ) -> Result<(Vec<OverlayEntry>, Vec<StageProjection>), OverlayError> {
        let stages_by_inode: BTreeMap<_, _> = self
            .entries()
            .iter()
            .filter_map(|entry| entry.stage_id.map(|stage| (entry.inode, stage)))
            .collect();
        let mut entries = Vec::new();
        let mut stages = Vec::new();
        for mut entry in namespace.entries.into_values() {
            if matches!(entry.kind, OverlayKind::File { .. }) {
                let payload = durable.get(&entry.inode).ok_or_else(|| {
                    OverlayError::refused("projection file lacks durable payload")
                })?;
                entry.size = payload.size;
                entry.kind = OverlayKind::File {
                    content: Some(payload.content),
                };
                // A detached durable target preserved by exclusion still has its
                // original stage binding; live named files keep their stage too.
                entry.stage_id = stages_by_inode
                    .get(&entry.inode)
                    .copied()
                    .or(entry.stage_id);
                if let Some(stage_id) = entry.stage_id {
                    stages.push(StageProjection {
                        stage_id,
                        incarnation: self.incarnation(),
                        path: entry.path.clone(),
                        content_boundary: payload.content_boundary,
                    });
                }
            }
            entries.push(entry);
        }
        Ok((entries, stages))
    }
    fn journal_mutations(&self) -> Vec<StageMutation> {
        self.effects()
            .iter()
            .filter_map(|effect| match effect.record {
                Record::WriteExtent {
                    stage_id,
                    offset,
                    length,
                    ..
                } => Some(StageMutation::Write {
                    seq: effect.seq,
                    stage_id,
                    incarnation: self.incarnation(),
                    offset,
                    length,
                }),
                Record::Truncate { stage_id, new_size } => Some(StageMutation::Truncate {
                    seq: effect.seq,
                    stage_id,
                    incarnation: self.incarnation(),
                    size: new_size,
                }),
                Record::StageRollback { stage_id, .. } => Some(StageMutation::Rollback {
                    seq: effect.seq,
                    stage_id,
                    incarnation: self.incarnation(),
                }),
                _ => None,
            })
            .collect()
    }
}

fn apply(
    namespace: &mut Namespace,
    effect: &NamespaceEffect,
    allow_omitted: bool,
) -> Result<(), OverlayError> {
    let paths = match &effect.record {
        Record::Move { from, to } | Record::Replace { from, to } => {
            vec![state::path(from), state::path(to)]
        }
        Record::Create { at, .. }
        | Record::RecreateFile { at: Some(at), .. }
        | Record::Delete { at, .. }
        | Record::SetattrExec { at, .. }
        | Record::StageBind { at, .. } => vec![state::path(at)],
        _ => return Ok(()),
    };
    if let Some(source) = effect.source
        && paths
            .first()
            .and_then(|path| namespace.entries.get(path))
            .map(|entry| entry.inode)
            != Some(source)
    {
        return Err(OverlayError::refused("projection source identity"));
    }
    if paths.len() != effect.parents.len() {
        return Err(OverlayError::refused("projection parent count"));
    }
    for (path, parent) in paths.iter().zip(&effect.parents) {
        let (_, names) = path
            .split_last()
            .ok_or_else(|| OverlayError::refused("projection empty path"))?;
        let actual = if names.is_empty() {
            Some(0)
        } else {
            namespace.entries.get(names).map(|entry| entry.inode)
        };
        if actual != Some(*parent) {
            return Err(OverlayError::refused("projection parent identity"));
        }
    }
    let record = match &effect.record {
        Record::Replace { from, to }
            if allow_omitted && !namespace.entries.contains_key(&state::path(to)) =>
        {
            Record::Move {
                from: from.clone(),
                to: to.clone(),
            }
        }
        record => record.clone(),
    };
    namespace.fold(&record)?;
    if let Some(inode) = effect.result
        && let Some(path) = paths.last()
    {
        namespace.assign_inode(path, inode)?;
    }
    Ok(())
}
