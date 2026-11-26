// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Prepared-root recovery and name-granular merging against an authenticated head.

use super::VerifiedBase;
use crate::{OverlayEntry, OverlayKind, OwnedCandidate};
use granary_core::{
    grainsource::{GrainSource, GrainSourceError},
    hash::GrainId,
    manifest::{self, EntryKind, Name},
    root,
};
use granary_store::crypto::{self, TrustedKeys};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};

/// The recovery action permitted by the verified head chain.
#[derive(Debug, PartialEq, Eq)]
pub enum HeadRelation {
    /// The head equals the prepared root, or the verified chain contains its
    /// exact id or an equal manifest. Reports the newest witness, including
    /// the prepared parent when its manifest is equal.
    Subsumed { by_seq: u64, by_root: GrainId },
    /// The verified chain reaches the prepared parent without proving the
    /// selection published. The chain excludes the parent and is newest first.
    /// An empty chain means the head is the prepared parent: publish the
    /// prepared root unchanged, without a manifest merge.
    NeedsRebase { chain: Vec<(u64, GrainId)> },
    /// Every examined link verified, but the chain holds another root at the
    /// prepared parent's sequence (the prepared root's own if parentless), or
    /// ends before it: the volume's history diverged from the prepared root.
    Stale,
    /// A root failed validation, or ancestry was unavailable or broken.
    Corrupt,
}

/// Classify a registered prepared root before attempting recovery publication.
/// `head` supplies signature trust; `content` supplies ancestor root bytes by id.
/// Exact root ancestry or equal manifests prove publication, never writer
/// identity alone. Except for exact prepared/head equality, the full chain to
/// the prepared parent must verify, including links below a content witness.
/// Parentless prepared roots remain exact-id-verified at their own sequence.
#[must_use]
pub fn classify_head(
    prepared: &OwnedCandidate,
    head: &VerifiedBase,
    content: &dyn GrainSource,
    trusted: &TrustedKeys,
) -> HeadRelation {
    let Ok(mut doc) = root::decode_root(head.bytes()) else {
        return HeadRelation::Corrupt;
    };
    let Ok(initial) = crypto::check_head(
        prepared.bytes(),
        doc.volume.as_str(),
        prepared.seq(),
        trusted,
    ) else {
        return HeadRelation::Corrupt;
    };
    // Equality is an explicit exception to requiring the parent on the chain.
    if head.id() == prepared.id() {
        return HeadRelation::Subsumed {
            by_seq: head.seq(),
            by_root: head.id(),
        };
    }
    let (ancestor_id, ancestor_seq) = match (initial.parent, initial.seq.checked_sub(1)) {
        (Some(parent), Some(seq)) => (parent, seq),
        (None, _) => (prepared.id(), initial.seq),
        _ => return HeadRelation::Corrupt,
    };
    if head.seq() < ancestor_seq {
        return HeadRelation::Stale;
    }
    let mut id = head.id();
    let mut chain = Vec::new();
    let mut subsumed = None;
    while doc.seq > ancestor_seq {
        chain.push((doc.seq, id));
        if subsumed.is_none() && (id == prepared.id() || doc.manifest_root == initial.manifest_root)
        {
            subsumed = Some((doc.seq, id));
        }
        let (Some(parent), Some(prev)) = (doc.parent, doc.seq.checked_sub(1)) else {
            return HeadRelation::Corrupt;
        };
        let Ok(bytes) = content.get(&parent) else {
            return HeadRelation::Corrupt;
        };
        let Ok(ancestor) = root::check_link(doc.parent, &bytes, doc.volume.as_str(), prev) else {
            return HeadRelation::Corrupt;
        };
        doc = ancestor;
        id = parent;
    }
    if id != ancestor_id {
        return HeadRelation::Stale;
    }
    if subsumed.is_none()
        && (initial.parent.is_none() || doc.manifest_root == initial.manifest_root)
    {
        subsumed = Some((doc.seq, id));
    }
    if let Some((by_seq, by_root)) = subsumed {
        HeadRelation::Subsumed { by_seq, by_root }
    } else {
        HeadRelation::NeedsRebase { chain }
    }
}

/// Differing concurrent changes at one name or beneath an incompatible ancestor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebaseConflict {
    pub path: Vec<Name>,
}

impl std::fmt::Display for RebaseConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rebase conflict at {:?}", self.path)
    }
}
impl std::error::Error for RebaseConflict {}

/// A conflicting name or an unavailable, malformed or unresolved input manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebaseError {
    Conflict(RebaseConflict),
    InvalidManifest,
}

impl std::fmt::Display for RebaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict(conflict) => conflict.fmt(f),
            Self::InvalidManifest => f.write_str("invalid rebase manifest"),
        }
    }
}
impl std::error::Error for RebaseError {}

fn conflict(path: &[Name]) -> RebaseError {
    RebaseError::Conflict(RebaseConflict {
        path: path.to_vec(),
    })
}

type Entries = BTreeMap<Vec<Name>, OverlayEntry>;

/// Immutable copies make the validator's monotone fetch contract structural.
#[derive(Default)]
struct ManifestNodes(BTreeMap<GrainId, Vec<u8>>);

impl GrainSource for ManifestNodes {
    fn has(&self, id: &GrainId) -> bool {
        self.0.contains_key(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(GrainSourceError::Missing(*id))
    }
}

impl ManifestNodes {
    fn entries(&mut self, root: GrainId, source: &dyn GrainSource) -> Result<Entries, RebaseError> {
        let mut cursor = manifest::TreeCursor::new(root);
        loop {
            match cursor
                .resume(&|id| self.0.get(id).cloned())
                .map_err(|_| RebaseError::InvalidManifest)?
            {
                manifest::Step::Done(_) => break,
                manifest::Step::Need(id) => {
                    let bytes = source.get(&id).map_err(|_| RebaseError::InvalidManifest)?;
                    if GrainId::of(&bytes) != id {
                        return Err(RebaseError::InvalidManifest);
                    }
                    self.0.insert(id, bytes);
                }
            }
        }
        let mut result = BTreeMap::new();
        let mut work = vec![(root, Vec::new())];
        while let Some((id, prefix)) = work.pop() {
            for leaf in crate::writable_store::capture::entries(self, id, 1)
                .map_err(|_| RebaseError::InvalidManifest)?
            {
                let mut path = prefix.clone();
                path.push(leaf.name);
                if let EntryKind::Dir { child } = &leaf.kind {
                    work.push((*child, path.clone()));
                }
                let (kind, size, exec) =
                    OverlayKind::from_manifest(leaf.kind).ok_or(RebaseError::InvalidManifest)?;
                result.insert(
                    path.clone(),
                    OverlayEntry {
                        path,
                        inode: 0,
                        kind,
                        stage_id: None,
                        size,
                        exec,
                    },
                );
            }
        }
        Ok(result)
    }
}

fn local_entries(local: &[OverlayEntry]) -> Result<Entries, RebaseError> {
    let mut entries = BTreeMap::new();
    for entry in local {
        if entry.path.is_empty()
            || matches!(entry.kind, OverlayKind::File { content: None })
            || entries.insert(entry.path.clone(), entry.clone()).is_some()
        {
            return Err(RebaseError::InvalidManifest);
        }
    }
    for path in entries.keys() {
        let (_, parent) = path.split_last().ok_or(RebaseError::InvalidManifest)?;
        if !parent.is_empty()
            && !entries
                .get(parent)
                .is_some_and(|entry| matches!(entry.kind, OverlayKind::Directory))
        {
            return Err(RebaseError::InvalidManifest);
        }
    }
    Ok(entries)
}

fn same(a: Option<&OverlayEntry>, b: Option<&OverlayEntry>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.kind == b.kind
                && (!matches!(a.kind, OverlayKind::File { .. })
                    || (a.size, a.exec) == (b.size, b.exec))
        }
        _ => false,
    }
}

fn changes(base: &Entries, side: &Entries) -> BTreeSet<Vec<Name>> {
    base.keys()
        .chain(side.keys())
        .filter(|path| !same(base.get(*path), side.get(*path)))
        .cloned()
        .collect()
}

fn descendants<'a>(
    changes: &'a BTreeSet<Vec<Name>>,
    path: &'a [Name],
) -> impl Iterator<Item = &'a Vec<Name>> {
    changes
        .range((Excluded(path.to_vec()), Unbounded))
        .take_while(move |changed| changed.starts_with(path))
}

fn merge_name<'a>(
    path: &[Name],
    base: Option<&'a OverlayEntry>,
    local: Option<&'a OverlayEntry>,
    head: Option<&'a OverlayEntry>,
) -> Result<Option<&'a OverlayEntry>, RebaseError> {
    if same(local, head) || same(base, head) {
        Ok(local)
    } else if same(base, local) {
        Ok(head)
    } else {
        Err(conflict(path))
    }
}

/// Preserve deletions evidenced after a selected root's preparation. A path
/// absent from head whose entire selected subtree matches a newer ancestor
/// was carried before it was deleted. Other selected changes still rebase
/// against their own parent; writer identity supplies no evidence.
pub(crate) fn preserve_recovered_deletions(
    local: &[OverlayEntry],
    head: GrainId,
    ancestors: &[GrainId],
    content: &dyn GrainSource,
) -> Result<Vec<OverlayEntry>, RebaseError> {
    let mut local = local_entries(local)?;
    let mut nodes = ManifestNodes::default();
    let head = nodes.entries(head, content)?;
    for ancestor in ancestors {
        let ancestor = nodes.entries(*ancestor, content)?;
        let changed = changes(&ancestor, &local);
        local.retain(|path, entry| {
            head.contains_key(path)
                || !same(Some(entry), ancestor.get(path))
                || descendants(&changed, path).next().is_some()
        });
    }
    Ok(local.into_values().collect())
}

/// Merge a materialized local namespace against its own base and the verified head.
/// Results are in path order and unstaged. An entry keeps the local inode at its
/// path only if it has the same kind as that local entry. Otherwise it carries
/// zero for live inode allocation at installation.
/// File equality uses content, size and exec; directories compare only by kind,
/// symlinks only by target. Equal concurrent changes coalesce. Renames are
/// deletion plus creation.
///
/// # Errors
/// A typed path conflict for overlapping changes, including changed descendants
/// of a replaced ancestor. Invalid or unavailable manifests, duplicate paths,
/// non-directory parents and unresolved local file content refuse the merge.
pub fn merge_manifests(
    base: GrainId,
    local: &[OverlayEntry],
    head: &VerifiedBase,
    content: &dyn GrainSource,
) -> Result<Vec<OverlayEntry>, RebaseError> {
    merge_reporting_conflicts(base, local, head, content, |path| Err(conflict(path)))
}

/// Report every colliding path when the observer permits the walk to continue.
/// The result remains a conflict; a partial merge never becomes publishable.
pub(crate) fn merge_reporting_conflicts(
    base: GrainId,
    local: &[OverlayEntry],
    head: &VerifiedBase,
    content: &dyn GrainSource,
    mut report: impl FnMut(&[Name]) -> Result<(), RebaseError>,
) -> Result<Vec<OverlayEntry>, RebaseError> {
    let local = local_entries(local)?;
    let mut nodes = ManifestNodes::default();
    let base = nodes.entries(base, content)?;
    let head = nodes.entries(head.manifest_root(), content)?;
    let local_changes = changes(&base, &local);
    let head_changes = changes(&base, &head);
    let paths: BTreeSet<_> = base.keys().chain(local.keys()).chain(head.keys()).collect();
    let mut merged = Vec::new();
    let mut first_conflict = None;
    'paths: for path in paths {
        for (side, changed, other, other_changed) in [
            (&local, &local_changes, &head, &head_changes),
            (&head, &head_changes, &local, &local_changes),
        ] {
            let replaced = changed.contains(path)
                && side
                    .get(path)
                    .is_some_and(|entry| !matches!(entry.kind, OverlayKind::Directory));
            let removed_directory = side.get(path).is_none()
                && base
                    .get(path)
                    .is_some_and(|entry| matches!(entry.kind, OverlayKind::Directory));
            // Removals count for replacement collisions; directory deletion
            // versus another deletion is judged at the deleted descendant.
            if (replaced
                && !same(side.get(path), other.get(path))
                && descendants(other_changed, path).next().is_some())
                || (removed_directory
                    && descendants(other_changed, path).any(|p| other.contains_key(p)))
            {
                report(path)?;
                first_conflict.get_or_insert_with(|| conflict(path));
                continue 'paths;
            }
        }
        let chosen = match merge_name(path, base.get(path), local.get(path), head.get(path)) {
            Ok(chosen) => chosen,
            Err(error) => {
                report(path)?;
                first_conflict.get_or_insert(error);
                None
            }
        };
        if let Some(chosen) = chosen {
            let mut entry = chosen.clone();
            entry.inode = local
                .get(path)
                .filter(|local| {
                    std::mem::discriminant(&local.kind) == std::mem::discriminant(&entry.kind)
                })
                .map_or(0, |local| local.inode);
            entry.stage_id = None;
            merged.push(entry);
        }
    }
    first_conflict.map_or(Ok(merged), Err)
}

#[cfg(test)]
mod tests;
