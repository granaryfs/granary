// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Accepted object projections for capture-ordered registration.

use super::VerifiedBase;
use crate::{
    CoordinationError, DurableFile, OverlayError, OverlayKind, Policy, PreparedProjection,
    PublishError, PublishSummary, SyncBoundary,
};
use granary_core::binstore::BinStore;
use granary_core::grainsource::{GrainSource, GrainSourceError};
use granary_core::hash::GrainId;
use granary_core::manifest::{self, DirEntry, EntryKind, FileGrains, Name};
use granary_core::root::Timestamp;
use granary_store::crypto::TrustedKeys;
use std::collections::{BTreeMap, BTreeSet};

/// Capture-order admission. Accepted earlier projections remain eligible before
/// their receipts arrive; explicitly failed uploads contribute no new payload.
/// The engine retains this state under its declared graph charge until refresh.
#[derive(Debug, Default, Clone)]
pub struct SyncProjectionQueue {
    lane: Option<GrainId>,
    last: u64,
    entries: BTreeMap<u64, Option<Vec<DurableFile>>>,
}

/// Named payloads enter the projected tree. Detached open-file payloads upload
/// their grains without a root leaf; their keys are exact captured-file indices.
#[derive(Debug, Default)]
pub struct SyncObjectSelection {
    pub selected: Vec<DurableFile>,
    pub orphaned: BTreeMap<usize, FileGrains>,
}
impl From<Vec<DurableFile>> for SyncObjectSelection {
    fn from(selected: Vec<DurableFile>) -> Self {
        Self {
            selected,
            orphaned: BTreeMap::new(),
        }
    }
}

/// Opaque projection whose manifest, spill lists, bins, binmap and sheaf have
/// accepted remote custody. It is unsigned and cannot enter the publish/cache
/// APIs. The mediator signs it with its persisted writer during registration.
#[derive(Debug)]
pub struct AcceptedSyncProjection {
    boundary: SyncBoundary,
    selected: Vec<DurableFile>,
    projection: PreparedProjection,
    pub(crate) accepted: crate::publish::AcceptedObjects,
    pub(crate) nodes: BTreeMap<GrainId, Vec<u8>>,
}
impl AcceptedSyncProjection {
    #[must_use]
    pub fn projection(&self) -> &PreparedProjection {
        &self.projection
    }
    #[must_use]
    pub fn binmap_work(&self) -> &crate::BinmapWork {
        &self.accepted.work
    }
    #[must_use]
    pub fn summary(&self) -> &PublishSummary {
        &self.accepted.summary
    }
    #[must_use]
    pub fn boundary(&self) -> &SyncBoundary {
        &self.boundary
    }
    /// The named file this projection selected, as a projected boundary
    /// records it: its stage and captured payload. A directory, a seal that
    /// captured nothing, a clean unchanged file and a detached file select
    /// none.
    /// # Errors
    /// More than one selected file, or one with no captured entry.
    pub(crate) fn selection(
        &self,
    ) -> Result<Option<granary_core::overlay_journal::ProjectedSelection>, OverlayError> {
        let file = match self.selected.as_slice() {
            [] => return Ok(None),
            [file] => file,
            _ => return Err(refused()),
        };
        let entry = self
            .boundary
            .files()
            .iter()
            .filter_map(crate::CapturedFile::entry)
            .find(|entry| entry.inode == file.inode)
            .ok_or_else(refused)?;
        Ok(entry.stage_id.map(
            |stage_id| granary_core::overlay_journal::ProjectedSelection {
                stage_id,
                content: file.content,
                size: file.size,
            },
        ))
    }
}

fn refused() -> OverlayError {
    OverlayError::refused("sync projection admission")
}
impl SyncProjectionQueue {
    fn check(&self, boundary: &SyncBoundary) -> Result<(), OverlayError> {
        if self.lane != Some(boundary.context_id()) || !self.entries.contains_key(&boundary.id()) {
            return Err(refused());
        }
        Ok(())
    }
    /// Reserve an admission position immediately after a seal, in seal order.
    /// # Errors
    /// Duplicate/reversed seal, changed base or journal incarnation.
    pub fn reserve(&mut self, boundary: &SyncBoundary) -> Result<(), OverlayError> {
        let lane = boundary.context_id();
        if boundary.id() <= self.last || self.lane.is_some_and(|current| current != lane) {
            return Err(refused());
        }
        self.lane = Some(lane);
        self.last = boundary.id();
        self.entries.insert(boundary.id(), None);
        Ok(())
    }
    pub(crate) fn project(
        &self,
        boundary: &SyncBoundary,
        selected: &[DurableFile],
    ) -> Result<PreparedProjection, OverlayError> {
        self.check(boundary)?;
        if self
            .entries
            .get(&boundary.id())
            .is_some_and(Option::is_some)
        {
            return Err(refused());
        }
        if boundary.complete_tree() {
            return boundary.project(selected);
        }
        let mut eligible = BTreeMap::new();
        for (&id, files) in &self.entries {
            if id >= boundary.id() {
                break;
            }
            for file in files.as_ref().ok_or_else(refused)? {
                eligible.insert(file.inode, file.clone());
            }
        }
        for file in selected {
            eligible.insert(file.inode, file.clone());
        }
        boundary.project(&eligible.into_values().collect::<Vec<_>>())
    }
    /// Publish eligibility only with the opaque completed acceptance capability.
    /// The engine admits it after retaining the exact registration request;
    /// object acceptance alone never authorizes a sync reply.
    /// # Errors
    /// Foreign/stale admission or repeated completion.
    pub fn admit(&mut self, accepted: &AcceptedSyncProjection) -> Result<(), OverlayError> {
        self.check(&accepted.boundary)?;
        if self
            .entries
            .range(..accepted.boundary.id())
            .any(|(_, files)| files.is_none())
        {
            return Err(refused());
        }
        let entry = self
            .entries
            .get_mut(&accepted.boundary.id())
            .ok_or_else(refused)?;
        if entry.is_some() {
            return Err(refused());
        }
        *entry = Some(accepted.selected.clone());
        Ok(())
    }
    /// Explicitly settle failed object work. Later captures fall back to their
    /// previous durable projections; accepted entries cannot be discarded here.
    /// # Errors
    /// Foreign/settled admission, including a completed acceptance barrier.
    pub fn fail(&mut self, boundary: &SyncBoundary) -> Result<(), OverlayError> {
        self.check(boundary)?;
        if self
            .entries
            .get(&boundary.id())
            .is_some_and(Option::is_some)
        {
            return Err(refused());
        }
        self.entries.remove(&boundary.id());
        Ok(())
    }
}

struct Objects<'a> {
    nodes: BTreeMap<GrainId, Vec<u8>>,
    source: &'a dyn GrainSource,
}
impl GrainSource for Objects<'_> {
    fn has(&self, id: &GrainId) -> bool {
        self.nodes.contains_key(id) || self.source.has(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        let bytes = match self.nodes.get(id) {
            Some(bytes) => bytes.clone(),
            None => self.source.get(id)?,
        };
        if GrainId::of(&bytes) != *id {
            return Err(GrainSourceError::Corrupt(*id));
        }
        Ok(bytes)
    }
}

/// Every entry of one directory, in order, from its hash-verified B-tree. The
/// caller reads only directories under an already validated base, so this
/// decodes and does not re-validate.
fn dir_entries(
    source: &dyn GrainSource,
    id: GrainId,
    depth: u32,
    out: &mut Vec<DirEntry>,
) -> Result<(), PublishError> {
    if depth > manifest::DEPTH_MAX {
        return Err(PublishError::BadPlan);
    }
    let bytes = source.get(&id)?;
    if GrainId::of(&bytes) != id {
        return Err(PublishError::CorruptMeta { id });
    }
    let (kind, cursor) = granary_core::encoding::open_envelope(&bytes)
        .map_err(|_| PublishError::CorruptMeta { id })?;
    match kind {
        granary_core::encoding::ObjectType::DirLeaf => {
            out.extend(
                manifest::decode_dir_leaf(cursor).map_err(|_| PublishError::CorruptMeta { id })?,
            );
        }
        granary_core::encoding::ObjectType::DirInterior => {
            for child in manifest::decode_dir_interior(cursor)
                .map_err(|_| PublishError::CorruptMeta { id })?
            {
                dir_entries(source, child.child, depth + 1, out)?;
            }
        }
        _ => return Err(PublishError::CorruptMeta { id }),
    }
    Ok(())
}

/// The base manifest's directories, read on demand by base path from the
/// verified manifest root. Each directory is decoded at most once.
struct BaseDirs {
    root: GrainId,
    ids: BTreeMap<Vec<Name>, GrainId>,
    entries: BTreeMap<Vec<Name>, Vec<DirEntry>>,
}
impl BaseDirs {
    fn new(root: GrainId) -> Self {
        Self {
            root,
            ids: BTreeMap::new(),
            entries: BTreeMap::new(),
        }
    }
    fn id(&mut self, source: &dyn GrainSource, path: &[Name]) -> Result<GrainId, PublishError> {
        let Some((name, parent)) = path.split_last() else {
            return Ok(self.root);
        };
        if let Some(id) = self.ids.get(path) {
            return Ok(*id);
        }
        let EntryKind::Dir { child } = self.entry(source, parent, name)?.kind else {
            return Err(PublishError::BadPlan);
        };
        self.ids.insert(path.to_vec(), child);
        Ok(child)
    }
    fn entry(
        &mut self,
        source: &dyn GrainSource,
        dir: &[Name],
        name: &Name,
    ) -> Result<DirEntry, PublishError> {
        if !self.entries.contains_key(dir) {
            let id = self.id(source, dir)?;
            let mut out = Vec::new();
            dir_entries(source, id, 1, &mut out)?;
            self.entries.insert(dir.to_vec(), out);
        }
        let list = self.entries.get(dir).ok_or(PublishError::BadPlan)?;
        let at = list
            .binary_search_by(|entry| entry.name.cmp(name))
            .map_err(|_| PublishError::BadPlan)?;
        list.get(at).cloned().ok_or(PublishError::BadPlan)
    }
}

/// The ids of the base manifest the build reused, and the root it produced.
struct Built {
    root: GrainId,
    reuse: BTreeSet<GrainId>,
}

/// What resolving a directory's children needs, carried through the bottom-up build.
struct Resolver<'a, F> {
    rebuild: &'a BTreeSet<u64>,
    base_by_inode: BTreeMap<u64, &'a crate::OverlayEntry>,
    walker: BaseDirs,
    built: BTreeMap<Vec<Name>, GrainId>,
    reuse: BTreeSet<GrainId>,
    payload: &'a mut F,
}
impl<F: FnMut(GrainId) -> Result<FileGrains, PublishError>> Resolver<'_, F> {
    /// The manifest entry for one projected child of a directory being rebuilt.
    /// `parent_at` is where that directory sat in the base, when it was there.
    fn entry(
        &mut self,
        source: &dyn GrainSource,
        parent_at: Option<&[Name]>,
        child: &crate::OverlayEntry,
        verified_spills: &mut BTreeSet<(GrainId, u64, u32)>,
    ) -> Result<DirEntry, PublishError> {
        let name = child.path.last().ok_or(PublishError::BadPlan)?;
        let kind = match &child.kind {
            OverlayKind::Directory if self.rebuild.contains(&child.inode) => EntryKind::Dir {
                child: *self.built.get(&child.path).ok_or(PublishError::BadPlan)?,
            },
            OverlayKind::Directory => {
                let at = self
                    .base_by_inode
                    .get(&child.inode)
                    .filter(|entry| matches!(entry.kind, OverlayKind::Directory))
                    .ok_or(PublishError::BadPlan)?;
                let id = self.walker.id(source, &at.path)?;
                self.reuse.insert(id);
                EntryKind::Dir { child: id }
            }
            OverlayKind::Symlink { target } => EntryKind::Symlink {
                target: target.clone(),
            },
            OverlayKind::File {
                content: Some(content),
            } => {
                if let Some((size, grains)) = self.base_payload(source, parent_at, child, name)? {
                    if let FileGrains::Spill { grain_count, root } = &grains {
                        self.reuse.insert(*root);
                        verified_spills.insert((*root, size, *grain_count));
                    }
                    EntryKind::File {
                        exec: child.exec,
                        size,
                        grains,
                    }
                } else {
                    let grains = (self.payload)(*content)?;
                    let bytes = manifest::node::file_payload(child.size, &grains)
                        .map_err(|_| PublishError::BadPlan)?;
                    if GrainId::of(&bytes) != *content {
                        return Err(PublishError::CorruptMeta { id: *content });
                    }
                    EntryKind::File {
                        exec: child.exec,
                        size: child.size,
                        grains,
                    }
                }
            }
            OverlayKind::File { content: None } => return Err(PublishError::BadPlan),
        };
        Ok(DirEntry {
            name: name.clone(),
            kind,
        })
    }
    /// The base entry's size and grains when this file is still its base
    /// payload, at its base parent under its base name; nothing otherwise.
    fn base_payload(
        &mut self,
        source: &dyn GrainSource,
        parent_at: Option<&[Name]>,
        child: &crate::OverlayEntry,
        name: &Name,
    ) -> Result<Option<(u64, FileGrains)>, PublishError> {
        let (Some(parent), Some(old)) = (parent_at, self.base_by_inode.get(&child.inode)) else {
            return Ok(None);
        };
        if old.path.split_last() != Some((name, parent))
            || old.kind != child.kind
            || old.size != child.size
        {
            return Ok(None);
        }
        let OverlayKind::File {
            content: Some(content),
        } = &child.kind
        else {
            return Ok(None);
        };
        let EntryKind::File { size, grains, .. } = self.walker.entry(source, parent, name)?.kind
        else {
            return Ok(None);
        };
        let matches_content = size == child.size
            && manifest::node::file_payload(size, &grains)
                .is_ok_and(|bytes| GrainId::of(&bytes) == *content);
        Ok(matches_content.then_some((size, grains)))
    }
}

/// Build the projected root by re-encoding only the directories in the
/// projection's rebuild set, bottom up. Every other directory keeps its base
/// node id, and a file that is still its base payload keeps its base entry.
fn manifest_tree(
    projection: &PreparedProjection,
    boundary: &SyncBoundary,
    base: &VerifiedBase,
    objects: &mut Objects<'_>,
    payload: &mut impl FnMut(GrainId) -> Result<FileGrains, PublishError>,
) -> Result<Built, PublishError> {
    let rebuild = projection.rebuild_set();
    if rebuild.is_empty() {
        return Ok(Built {
            root: base.manifest_root(),
            reuse: BTreeSet::from([base.manifest_root()]),
        });
    }
    let mut dirs: BTreeMap<Vec<Name>, (u64, Vec<&crate::OverlayEntry>)> =
        BTreeMap::from([(Vec::new(), (0, Vec::new()))]);
    for entry in projection.entries() {
        if matches!(entry.kind, OverlayKind::Directory) && rebuild.contains(&entry.inode) {
            dirs.insert(entry.path.clone(), (entry.inode, Vec::new()));
        }
    }
    for entry in projection.entries() {
        let (_, parent) = entry.path.split_last().ok_or(PublishError::BadPlan)?;
        if let Some((_, children)) = dirs.get_mut(parent) {
            children.push(entry);
        }
    }
    let mut paths: Vec<_> = dirs.keys().cloned().collect();
    paths.sort_by_key(|path| std::cmp::Reverse(path.len()));
    let mut resolver = Resolver {
        rebuild,
        base_by_inode: boundary
            .base_entries()
            .iter()
            .map(|entry| (entry.inode, entry))
            .collect(),
        walker: BaseDirs::new(base.manifest_root()),
        built: BTreeMap::new(),
        reuse: BTreeSet::new(),
        payload,
    };
    let mut root = None;
    for path in paths {
        let (identity, children) = dirs.remove(&path).ok_or(PublishError::BadPlan)?;
        // Where this directory sat in the base, when it is a base directory.
        let base_path = if identity == 0 {
            Some(Vec::new())
        } else {
            resolver
                .base_by_inode
                .get(&identity)
                .filter(|entry| matches!(entry.kind, OverlayKind::Directory))
                .map(|entry| entry.path.clone())
        };
        let mut entries = Vec::with_capacity(children.len());
        let mut verified_spills = BTreeSet::new();
        for child in children {
            entries.push(resolver.entry(
                &*objects,
                base_path.as_deref(),
                child,
                &mut verified_spills,
            )?);
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let tree = manifest::build_dir(&entries).map_err(|_| PublishError::BadPlan)?;
        let workspace_refusal = std::cell::Cell::new(None);
        manifest::tree::validate_dir_btree_seeded(
            &tree.root,
            &|id| {
                tree.nodes
                    .iter()
                    .find(|(key, _)| key == id)
                    .map(|(_, bytes)| bytes.clone())
                    .or_else(|| {
                        objects
                            .get(id)
                            .map_err(|error| {
                                if matches!(&error, GrainSourceError::Backend(reason) if reason == "sync object workspace") {
                                    workspace_refusal.set(Some(error));
                                }
                            })
                            .ok()
                    })
            },
            &verified_spills,
        )
        .map_err(|_| {
            workspace_refusal
                .into_inner()
                .map_or(PublishError::BadPlan, PublishError::Source)
        })?;
        objects.nodes.extend(tree.nodes);
        if path.is_empty() {
            root = Some(tree.root);
        } else {
            resolver.built.insert(path, tree.root);
        }
    }
    Ok(Built {
        root: root.ok_or(PublishError::BadPlan)?,
        reuse: resolver.reuse,
    })
}

/// Canonical reconstruction shared by commit rebases and projection equivalence checks.
pub(crate) fn entries_tree(
    entries: &[crate::OverlayEntry],
    source: &dyn GrainSource,
    mut payload: impl FnMut(GrainId) -> Result<FileGrains, PublishError>,
) -> Result<(GrainId, BTreeMap<GrainId, Vec<u8>>), PublishError> {
    let mut objects = Objects {
        nodes: BTreeMap::new(),
        source,
    };
    let root = manifest_tree_full(entries, &mut objects, &mut payload)?;
    Ok((root, objects.nodes))
}

fn manifest_tree_full(
    entries: &[crate::OverlayEntry],
    objects: &mut Objects<'_>,
    payload: &mut impl FnMut(GrainId) -> Result<FileGrains, PublishError>,
) -> Result<GrainId, PublishError> {
    let mut dirs: BTreeMap<Vec<Name>, Vec<DirEntry>> = BTreeMap::from([(Vec::new(), Vec::new())]);
    for entry in entries {
        if matches!(entry.kind, OverlayKind::Directory) {
            dirs.insert(entry.path.clone(), Vec::new());
        }
    }
    for entry in entries {
        let (name, parent) = entry.path.split_last().ok_or(PublishError::BadPlan)?;
        let kind = match &entry.kind {
            OverlayKind::Directory => continue,
            OverlayKind::Symlink { target } => EntryKind::Symlink {
                target: target.clone(),
            },
            OverlayKind::File {
                content: Some(content),
            } => {
                let grains = payload(*content)?;
                let bytes = manifest::node::file_payload(entry.size, &grains)
                    .map_err(|_| PublishError::BadPlan)?;
                if GrainId::of(&bytes) != *content {
                    return Err(PublishError::CorruptMeta { id: *content });
                }
                EntryKind::File {
                    exec: entry.exec,
                    size: entry.size,
                    grains,
                }
            }
            OverlayKind::File { content: None } => return Err(PublishError::BadPlan),
        };
        dirs.get_mut(parent)
            .ok_or(PublishError::BadPlan)?
            .push(DirEntry {
                name: name.clone(),
                kind,
            });
    }
    let mut paths: Vec<_> = dirs.keys().cloned().collect();
    paths.sort_by_key(|path| std::cmp::Reverse(path.len()));
    let mut root = None;
    for path in paths {
        let mut entries = dirs.remove(&path).ok_or(PublishError::BadPlan)?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let built = manifest::build_dir(&entries).map_err(|_| PublishError::BadPlan)?;
        objects.nodes.extend(built.nodes);
        if let Some((name, parent)) = path.split_last() {
            dirs.get_mut(parent)
                .ok_or(PublishError::BadPlan)?
                .push(DirEntry {
                    name: name.clone(),
                    kind: EntryKind::Dir { child: built.root },
                });
        } else {
            root = Some(built.root);
        }
    }
    let root = root.ok_or(PublishError::BadPlan)?;
    manifest::validate_dir_tree(&root, &|id| objects.get(id).ok())
        .map_err(|_| PublishError::BadPlan)?;
    Ok(root)
}

/// The selection must name exactly the files this seal captured: named files by
/// identity and size, detached ones by index.
fn check_selection(
    boundary: &SyncBoundary,
    selected: &[DurableFile],
    orphaned: &BTreeMap<usize, FileGrains>,
) -> Result<(), PublishError> {
    let expected: BTreeMap<_, _> = boundary
        .files()
        .iter()
        .filter_map(|file| file.entry().map(|entry| (entry.inode, file.size())))
        .collect();
    let actual: BTreeMap<_, _> = selected
        .iter()
        .map(|file| (file.inode, file.size))
        .collect();
    if actual != expected
        || actual.len() != selected.len()
        || selected
            .iter()
            .any(|file| file.content_boundary != boundary.through_seq())
    {
        return Err(PublishError::BadPlan);
    }
    let expected_orphans: Vec<_> = boundary
        .files()
        .iter()
        .enumerate()
        .filter_map(|(index, file)| file.entry().is_none().then_some(index))
        .collect();
    if orphaned.keys().copied().collect::<Vec<_>>() != expected_orphans {
        return Err(PublishError::BadPlan);
    }
    Ok(())
}

/// The grains and lists of detached open files: they upload without a root leaf.
fn orphan_objects(
    boundary: &SyncBoundary,
    objects: &Objects<'_>,
    orphaned: BTreeMap<usize, FileGrains>,
    capture_error: &impl Fn(CoordinationError) -> PublishError,
) -> Result<Vec<GrainId>, PublishError> {
    let mut extra = Vec::new();
    for (index, grains) in orphaned {
        let size = boundary
            .files()
            .get(index)
            .ok_or(PublishError::BadPlan)?
            .size();
        let refs = crate::writable_store::capture::captured_refs(objects, size, &grains)
            .map_err(capture_error)?;
        match grains {
            FileGrains::Inline(_) => extra.extend(refs.into_iter().map(|grain| grain.id)),
            FileGrains::Spill { root, .. } => {
                extra.extend(crate::publish::collect_objects(objects, &root)?);
            }
        }
    }
    Ok(extra)
}

/// How the accepted projection's manifest is built.
#[derive(Clone, Copy)]
enum Build {
    Incremental,
    #[cfg(test)]
    Full,
}

fn projected_tree<'a>(
    build: Build,
    projection: &PreparedProjection,
    boundary: &SyncBoundary,
    base: &VerifiedBase,
    source: &'a dyn GrainSource,
    mut payload: impl FnMut(GrainId) -> Result<FileGrains, PublishError>,
) -> Result<(Built, Objects<'a>), PublishError> {
    let mut objects = Objects {
        nodes: BTreeMap::new(),
        source,
    };
    let tree = match build {
        Build::Incremental => {
            manifest_tree(projection, boundary, base, &mut objects, &mut payload)?
        }
        #[cfg(test)]
        Build::Full => Built {
            root: manifest_tree_full(projection.entries(), &mut objects, &mut payload)?,
            reuse: BTreeSet::new(),
        },
    };
    Ok((tree, objects))
}

/// Build the same manifest as commit preparation, stopping before remote
/// custody and submission preparation.
pub(super) fn commit_manifest(
    queue: &SyncProjectionQueue,
    boundary: &SyncBoundary,
    selection: &SyncObjectSelection,
    base: &VerifiedBase,
    source: &dyn GrainSource,
    payload: impl FnMut(GrainId) -> Result<FileGrains, PublishError>,
) -> Result<(GrainId, BTreeMap<GrainId, Vec<u8>>), PublishError> {
    check_selection(boundary, &selection.selected, &selection.orphaned)?;
    let projection = queue
        .project(boundary, &selection.selected)
        .map_err(|_| PublishError::BadPlan)?;
    if boundary.base() != (base.id(), base.seq()) {
        return Err(PublishError::BadPlan);
    }
    let (tree, objects) = projected_tree(
        Build::Incremental,
        &projection,
        boundary,
        base,
        source,
        payload,
    )?;
    Ok((tree.root, objects.nodes))
}

/// Build and accept the projected object closure using the exact verified
/// captured base, with no head discovery, root PUT, pin or hint capability.
/// Only the directories the projection changed are re-encoded; the rest of the
/// base manifest is reused by node id. Selected payloads must identify
/// precisely the named files of this seal.
/// Await this operation outside the mediator; admit its result before projecting
/// the next capture. The source may fetch absent immutable spill lists/grains.
/// `capture_error` preserves the caller's local-budget classification when
/// detached-file verification returns a capture coverage error.
///
/// # Errors
/// Pending earlier admission, missing/foreign payload, stale base, invalid
/// signature/manifest, corrupt object or any failed/unknown acceptance barrier.
///
/// # Cancellation safety
/// Dropping this future may leave accepted, unreferenced objects. It does not
/// admit a queue entry or complete a capture. The supervisor must explicitly
/// settle that admission and the retained boundary/floors.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit captured base and closure seam inputs"
)]
pub async fn accept_sync_projection<R: BinStore>(
    queue: &SyncProjectionQueue,
    boundary: &SyncBoundary,
    selected: impl Into<SyncObjectSelection>,
    base: &VerifiedBase,
    trusted: &TrustedKeys,
    source: &dyn GrainSource,
    payload: impl FnMut(GrainId) -> Result<FileGrains, PublishError>,
    remote: &R,
    now: Timestamp,
    policy: Policy,
    capture_error: impl Fn(CoordinationError) -> PublishError,
) -> Result<AcceptedSyncProjection, PublishError> {
    accept_with(
        Build::Incremental,
        false,
        queue,
        boundary,
        selected,
        base,
        trusted,
        source,
        payload,
        remote,
        now,
        policy,
        capture_error,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit full commit construction seam"
)]
pub(crate) async fn accept_commit_projection<R: BinStore>(
    queue: &SyncProjectionQueue,
    boundary: &SyncBoundary,
    selected: impl Into<SyncObjectSelection>,
    base: &VerifiedBase,
    trusted: &TrustedKeys,
    source: &dyn GrainSource,
    payload: impl FnMut(GrainId) -> Result<FileGrains, PublishError>,
    remote: &R,
    now: Timestamp,
    policy: Policy,
    capture_error: impl Fn(CoordinationError) -> PublishError,
) -> Result<AcceptedSyncProjection, PublishError> {
    accept_with(
        Build::Incremental,
        true,
        queue,
        boundary,
        selected,
        base,
        trusted,
        source,
        payload,
        remote,
        now,
        policy,
        capture_error,
    )
    .await
}

/// The same acceptance over the whole-tree builder, as the equivalence oracle.
#[cfg(test)]
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the production entry point"
)]
pub(crate) async fn accept_sync_projection_full<R: BinStore>(
    queue: &SyncProjectionQueue,
    boundary: &SyncBoundary,
    selected: impl Into<SyncObjectSelection>,
    base: &VerifiedBase,
    trusted: &TrustedKeys,
    source: &dyn GrainSource,
    payload: impl FnMut(GrainId) -> Result<FileGrains, PublishError>,
    remote: &R,
    now: Timestamp,
    policy: Policy,
    capture_error: impl Fn(CoordinationError) -> PublishError,
) -> Result<AcceptedSyncProjection, PublishError> {
    accept_with(
        Build::Full,
        true,
        queue,
        boundary,
        selected,
        base,
        trusted,
        source,
        payload,
        remote,
        now,
        policy,
        capture_error,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit captured base and closure seam inputs"
)]
async fn accept_with<R: BinStore>(
    build: Build,
    full: bool,
    queue: &SyncProjectionQueue,
    boundary: &SyncBoundary,
    selected: impl Into<SyncObjectSelection>,
    base: &VerifiedBase,
    trusted: &TrustedKeys,
    source: &dyn GrainSource,
    payload: impl FnMut(GrainId) -> Result<FileGrains, PublishError>,
    remote: &R,
    now: Timestamp,
    policy: Policy,
    capture_error: impl Fn(CoordinationError) -> PublishError,
) -> Result<AcceptedSyncProjection, PublishError> {
    let SyncObjectSelection { selected, orphaned } = selected.into();
    check_selection(boundary, &selected, &orphaned)?;
    let projection = queue
        .project(boundary, &selected)
        .map_err(|_| PublishError::BadPlan)?;
    let (base_id, seq) = boundary.base();
    if base.id() != base_id {
        return Err(PublishError::CorruptMeta { id: base_id });
    }
    if base.seq() != seq {
        return Err(PublishError::BadPlan);
    }
    let state = crate::publish::shards::State::load(
        remote,
        boundary.volume(),
        base.bytes(),
        trusted,
        policy,
        full,
        base.exhaustion(),
    )
    .await?;
    // The parent sheaf is closure too; a signed missing reference is not custody.
    let doc =
        granary_store::crypto::check_head(base.bytes(), boundary.volume().as_str(), seq, trusted)
            .map_err(|_| PublishError::BadPlan)?;
    let sheaf = remote
        .get_meta(boundary.volume().as_str(), &doc.sheaf_head)
        .await?;
    if GrainId::of(&sheaf) != doc.sheaf_head {
        return Err(PublishError::CorruptMeta { id: doc.sheaf_head });
    }
    granary_core::sheaf::decode_sheaf(&sheaf).map_err(|_| PublishError::BadPlan)?;
    let (tree, objects) = projected_tree(build, &projection, boundary, base, source, payload)?;
    let extra = orphan_objects(boundary, &objects, orphaned, &capture_error)?;
    let accepted = crate::publish::accept_loaded_objects(
        remote,
        &objects,
        tree.root,
        crate::HarvestStats::default(),
        boundary.volume(),
        now,
        policy,
        state,
        &extra,
        &tree.reuse,
    )
    .await?;
    Ok(AcceptedSyncProjection {
        boundary: boundary.clone(),
        selected,
        projection,
        accepted,
        nodes: objects.nodes,
    })
}
