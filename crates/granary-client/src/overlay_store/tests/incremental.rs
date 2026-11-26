// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The incremental projection against the whole-tree build it replaces.
//!
//! Every row builds a real base manifest, applies a script of overlay
//! operations, seals, and accepts the projection twice: through the production
//! path and through the whole-tree builder kept as the reference. The two must
//! agree on the root, the summary and the exact upload sequence, and a reader
//! walking the accepted root must find what the projection says is durable.

use super::sync_objects::{Objects, Remote, now, verified};
use super::*;
use crate::sync::accept_sync_projection_full;
use crate::{
    DurableFile, Policy, PublishError, SyncProjectionQueue, VerifiedBase, accept_sync_projection,
};
use granary_core::grainsource::{GrainSource, GrainSourceError};
use granary_core::manifest::{self, DirEntry, EntryKind, FileGrains, GrainRef};
use granary_store::crypto::TrustedKeys;
use std::cell::RefCell;

/// Real file payloads and the objects behind them.
#[derive(Default)]
pub(super) struct World {
    pub(super) objects: Objects,
    payloads: BTreeMap<GrainId, (u64, FileGrains)>,
}
impl World {
    fn register(&mut self, size: u64, grains: FileGrains) -> (GrainId, u64) {
        let content = GrainId::of(&manifest::node::file_payload(size, &grains).unwrap());
        self.payloads.insert(content, (size, grains));
        (content, size)
    }
    pub(super) fn inline(&mut self, bytes: &[u8]) -> (GrainId, u64) {
        let grains = if bytes.is_empty() {
            FileGrains::Inline(vec![])
        } else {
            let id = GrainId::of(bytes);
            self.objects.0.insert(id, bytes.to_vec());
            FileGrains::Inline(vec![GrainRef {
                id,
                unpacked_len: u32::try_from(bytes.len()).unwrap(),
            }])
        };
        self.register(bytes.len() as u64, grains)
    }
    /// A spilled payload whose claimed grain count is `claimed`, whatever its tree holds.
    pub(super) fn register_spill_claim(
        &mut self,
        size: u64,
        claimed: u32,
        root: GrainId,
    ) -> (GrainId, u64) {
        self.register(
            size,
            FileGrains::Spill {
                grain_count: claimed,
                root,
            },
        )
    }
    /// A file whose 129 grains force a spilled grain list. `tag` makes it unique.
    pub(super) fn spilled(&mut self, tag: u16) -> (GrainId, u64) {
        let refs: Vec<GrainRef> = (0..129_u8)
            .map(|i| {
                let bytes = [tag.to_le_bytes()[0], tag.to_le_bytes()[1], i];
                self.objects.0.insert(GrainId::of(&bytes), bytes.to_vec());
                GrainRef {
                    id: GrainId::of(&bytes),
                    unpacked_len: 3,
                }
            })
            .collect();
        let built = manifest::build_grain_list(&refs).unwrap();
        self.objects.0.extend(built.nodes);
        self.register(
            129 * 3,
            FileGrains::Spill {
                grain_count: 129,
                root: built.root,
            },
        )
    }
}

fn ns(f: &mut Fixture, record: Record) {
    f.overlay
        .namespace_record(&mut f.store, &f.owner, record)
        .unwrap();
}
fn path_of(p: &str) -> Vec<Name> {
    p.split('/').map(name).collect()
}
pub(super) fn loc(p: &str) -> codec::Location {
    let mut names = path_of(p);
    let last = names.pop().unwrap();
    codec::Location {
        parent: codec::Parent::new(names).unwrap(),
        name: last,
    }
}
pub(super) fn dir(p: &str) -> OverlayEntry {
    OverlayEntry {
        path: path_of(p),
        inode: 0,
        kind: OverlayKind::Directory,
        stage_id: None,
        size: 0,
        exec: false,
    }
}
pub(super) fn file(p: &str, content: (GrainId, u64), exec: bool) -> OverlayEntry {
    OverlayEntry {
        path: path_of(p),
        inode: 0,
        kind: OverlayKind::File {
            content: Some(content.0),
        },
        stage_id: None,
        size: content.1,
        exec,
    }
}

/// The base manifest for `entries`, built from the leaves up.
pub(super) fn manifest_of(world: &mut World, entries: &[OverlayEntry]) -> GrainId {
    let mut dirs: BTreeMap<Vec<Name>, Vec<DirEntry>> = BTreeMap::from([(Vec::new(), Vec::new())]);
    for entry in entries {
        if matches!(entry.kind, OverlayKind::Directory) {
            dirs.insert(entry.path.clone(), Vec::new());
        }
    }
    for entry in entries {
        let (last, parent) = entry.path.split_last().unwrap();
        let kind = match &entry.kind {
            OverlayKind::Directory => continue,
            OverlayKind::File {
                content: Some(content),
            } => EntryKind::File {
                exec: entry.exec,
                size: entry.size,
                grains: world.payloads[content].1.clone(),
            },
            OverlayKind::Symlink { target } => EntryKind::Symlink {
                target: target.clone(),
            },
            OverlayKind::File { content: None } => unreachable!(),
        };
        dirs.get_mut(parent).unwrap().push(DirEntry {
            name: last.clone(),
            kind,
        });
    }
    let mut paths: Vec<_> = dirs.keys().cloned().collect();
    paths.sort_by_key(|path| std::cmp::Reverse(path.len()));
    let mut root = None;
    for path in paths {
        let mut list = dirs.remove(&path).unwrap();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        let built = manifest::build_dir(&list).unwrap();
        world.objects.0.extend(built.nodes);
        if let Some((last, parent)) = path.split_last() {
            dirs.get_mut(parent).unwrap().push(DirEntry {
                name: last.clone(),
                kind: EntryKind::Dir { child: built.root },
            });
        } else {
            root = Some(built.root);
        }
    }
    root.unwrap()
}

/// Reads and records which objects the accept path asked for.
struct Counting<'a> {
    objects: &'a Objects,
    gets: std::sync::Mutex<Vec<GrainId>>,
}
impl GrainSource for Counting<'_> {
    fn has(&self, id: &GrainId) -> bool {
        self.objects.has(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.gets.lock().unwrap().push(*id);
        self.objects.get(id)
    }
}

/// The scripted side of a row: overlay operations over the base.
pub(super) struct Ctx {
    pub(super) f: Fixture,
    pub(super) world: World,
    target: SyncTarget,
    /// Bytes of the one file a stage-target seal captures.
    selected: Option<Vec<u8>>,
    generation: u64,
}
impl Ctx {
    fn entry(&self, p: &str) -> OverlayEntry {
        self.f.overlay.namespace.entries[&path_of(p)].clone()
    }
    pub(super) fn mkdir(&mut self, p: &str) {
        ns(
            &mut self.f,
            Record::Create {
                at: loc(p),
                kind: codec::CreateKind::Dir,
            },
        );
    }
    pub(super) fn symlink(&mut self, p: &str, target: &str) {
        ns(
            &mut self.f,
            Record::Create {
                at: loc(p),
                kind: codec::CreateKind::Symlink {
                    target: manifest::SymlinkTarget::new(target.as_bytes().to_vec()).unwrap(),
                },
            },
        );
    }
    pub(super) fn create(&mut self, p: &str) -> u64 {
        self.f
            .overlay
            .create_file(&mut self.f.store, &self.f.owner, loc(p), false)
            .unwrap()
    }
    pub(super) fn write(&mut self, stage: u64, bytes: &[u8]) {
        self.f
            .overlay
            .write(&mut self.f.store, &self.f.owner, stage, 0, bytes)
            .unwrap();
    }
    /// Write `bytes` and record them as durable under their real payload.
    pub(super) fn sync(&mut self, stage: u64, bytes: &[u8]) {
        let content = self.world.inline(bytes).0;
        self.write(stage, bytes);
        self.sync_as(stage, content);
    }
    pub(super) fn sync_as(&mut self, stage: u64, content: GrainId) {
        let token = self
            .f
            .overlay
            .capture(&mut self.f.store, &self.f.owner, stage)
            .unwrap();
        self.f
            .overlay
            .flush_boundary(&mut self.f.store, &self.f.owner, &token)
            .unwrap();
        self.generation += 1;
        self.f
            .overlay
            .record_file_synced(
                &mut self.f.store,
                &self.f.owner,
                &RegisteredCapture {
                    capture: token,
                    writer: [17; 16],
                    generation: self.generation,
                    prepared_root: grain(2),
                    content,
                },
            )
            .unwrap();
    }
    pub(super) fn copy_up(&mut self, p: &str) -> u64 {
        self.f
            .overlay
            .copy_up(&mut self.f.store, &self.f.owner, loc(p), &mut self.f.source)
            .unwrap()
    }
    pub(super) fn rename(&mut self, from: &str, to: &str) {
        let record = if self.f.overlay.namespace.entries.contains_key(&path_of(to)) {
            Record::Replace {
                from: loc(from),
                to: loc(to),
            }
        } else {
            Record::Move {
                from: loc(from),
                to: loc(to),
            }
        };
        ns(&mut self.f, record);
    }
    pub(super) fn remove(&mut self, p: &str) {
        let entry = self.entry(p);
        let kind = match entry.kind {
            OverlayKind::Directory => codec::DeleteKind::Dir,
            OverlayKind::Symlink { .. } => codec::DeleteKind::Symlink,
            OverlayKind::File { .. } => codec::DeleteKind::File {
                stage_id: entry.stage_id,
            },
        };
        ns(&mut self.f, Record::Delete { at: loc(p), kind });
    }
    pub(super) fn chmod(&mut self, p: &str, exec: bool) {
        ns(&mut self.f, Record::SetattrExec { at: loc(p), exec });
    }
    /// Seal a stage target; its file is selected with `bytes` as its content.
    pub(super) fn select(&mut self, stage: u64, bytes: &[u8]) {
        self.target = SyncTarget::Stage(stage);
        self.selected = Some(bytes.to_vec());
    }
}

/// What a row observed, for row-specific assertions.
pub(super) struct Report {
    pub(super) base_root: GrainId,
    pub(super) novel_objects: u64,
    pub(super) root: GrainId,
    /// Objects the production path read from the source.
    pub(super) gets: Vec<GrainId>,
    /// Payloads the production path asked for.
    pub(super) payload_calls: Vec<GrainId>,
    pub(super) uploads: Vec<(&'static str, Vec<u8>)>,
    pub(super) world: World,
    pub(super) rebuilt: usize,
    pub(super) rows: Vec<(String, String)>,
}

/// The kind of every entry a reader of `root` finds, by path.
fn read_rows(root: GrainId, objects: &dyn GrainSource) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut work = vec![(root, String::new())];
    while let Some((id, prefix)) = work.pop() {
        for entry in crate::writable_store::capture::entries(objects, id, 1).unwrap() {
            let path = format!(
                "{prefix}{}",
                std::str::from_utf8(entry.name.as_bytes()).unwrap()
            );
            match entry.kind {
                EntryKind::Dir { child } => {
                    out.push((path.clone(), "dir".into()));
                    work.push((child, format!("{path}/")));
                }
                EntryKind::File { exec, size, grains } => {
                    let payload = manifest::node::file_payload(size, &grains).unwrap();
                    out.push((path, format!("file {} exec={exec}", GrainId::of(&payload))));
                }
                EntryKind::Symlink { target } => {
                    out.push((
                        path,
                        format!("link {}", std::str::from_utf8(target.as_bytes()).unwrap()),
                    ));
                }
                EntryKind::Fifo | EntryKind::Socket => unreachable!(),
            }
        }
    }
    out.sort();
    out
}
fn projected_rows(entries: &[OverlayEntry]) -> Vec<(String, String)> {
    let mut out: Vec<_> = entries
        .iter()
        .map(|entry| {
            let path = entry
                .path
                .iter()
                .map(|n| std::str::from_utf8(n.as_bytes()).unwrap())
                .collect::<Vec<_>>()
                .join("/");
            let kind = match &entry.kind {
                OverlayKind::Directory => "dir".to_string(),
                OverlayKind::File {
                    content: Some(content),
                } => format!("file {content} exec={}", entry.exec),
                OverlayKind::Symlink { target } => {
                    format!("link {}", std::str::from_utf8(target.as_bytes()).unwrap())
                }
                OverlayKind::File { content: None } => unreachable!(),
            };
            (path, kind)
        })
        .collect();
    out.sort();
    out
}

pub(super) struct Base {
    pub(super) world: World,
    pub(super) entries: Vec<OverlayEntry>,
    /// Raw bytes of the base's inline files by content id, for copy-up.
    raw: BTreeMap<GrainId, Vec<u8>>,
    cap: u64,
}
impl Base {
    pub(super) fn new() -> Self {
        Self {
            world: World::default(),
            entries: Vec::new(),
            raw: BTreeMap::new(),
            cap: 1_048_576,
        }
    }
    pub(super) fn set_cap(&mut self, cap: u64) {
        self.cap = cap;
    }
    pub(super) fn dir(&mut self, p: &str) -> &mut Self {
        self.entries.push(dir(p));
        self
    }
    pub(super) fn file(&mut self, p: &str, bytes: &[u8]) -> &mut Self {
        let content = self.world.inline(bytes);
        self.raw.insert(content.0, bytes.to_vec());
        self.entries.push(file(p, content, false));
        self
    }
    pub(super) fn exec(&mut self, p: &str, bytes: &[u8]) -> &mut Self {
        let content = self.world.inline(bytes);
        self.entries.push(file(p, content, true));
        self
    }
    pub(super) fn spilled(&mut self, p: &str, tag: u16) -> &mut Self {
        let content = self.world.spilled(tag);
        self.entries.push(file(p, content, false));
        self
    }
}

/// The published base every row starts from.
pub(super) struct Published {
    pub(super) remote: Remote,
    pub(super) bytes: Vec<u8>,
    pub(super) trusted: TrustedKeys,
    pub(super) verified: VerifiedBase,
}
pub(super) async fn publish(base: &mut Base) -> Published {
    publish_at(base, 0).await
}
async fn publish_at(base: &mut Base, width: u8) -> Published {
    let root = manifest_of(&mut base.world, &base.entries);
    let remote = Remote::default();
    let (bytes, trusted) = super::sync_objects::base_with_policy(
        &remote,
        root,
        &base.world.objects,
        Policy {
            min_prefix_bits: width,
        },
    )
    .await;
    let verified = verified(&bytes, &trusted, &base.world.objects, &remote).await;
    Published {
        remote,
        bytes,
        trusted,
        verified,
    }
}
pub(super) fn open(base: &Base, published: &Published) -> Fixture {
    let f = Fixture::with_base_capped(base.entries.clone(), Source(base.raw.clone()), base.cap);
    f.overlay.journal.lock().unwrap().header.base_root = GrainId::of(&published.bytes);
    f
}

/// What a fresh reader of the accepted root finds, and that the accepted binmap
/// resolves everything it reaches. Returns the objects it read and its rows.
fn assert_reader(
    remote: &Remote,
    incremental: &crate::AcceptedSyncProjection,
) -> (Objects, Vec<(String, String)>) {
    let lookup = remote
        .read_objects(incremental.accepted.doc.binmap_index)
        .expect("the fresh routed reader must recover the entire closure");
    let root = incremental.accepted.doc.manifest_root;
    let rows = read_rows(root, &lookup);
    assert_eq!(
        rows,
        projected_rows(incremental.projection().entries()),
        "a reader of the accepted root does not find the projected tree"
    );
    (lookup, rows)
}

/// Accept the sealed boundary through both builders and compare them.
pub(super) async fn accept_both(
    ctx: &mut Ctx,
    published: &Published,
    queue: &SyncProjectionQueue,
    boundary: &SyncBoundary,
    selected: &[DurableFile],
) -> Report {
    let calls = RefCell::new(Vec::new());
    let payloads = ctx.world.payloads.clone();
    let payload = |content: GrainId| {
        calls.borrow_mut().push(content);
        payloads
            .get(&content)
            .map(|(_, grains)| grains.clone())
            .ok_or(PublishError::BadPlan)
    };
    let source = Counting {
        objects: &ctx.world.objects,
        gets: std::sync::Mutex::default(),
    };
    published.remote.log.lock().unwrap().clear();
    let stored = published.remote.dump();
    let incremental = accept_sync_projection(
        queue,
        boundary,
        selected.to_vec(),
        &published.verified,
        &published.trusted,
        &source,
        payload,
        &published.remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await
    .expect("incremental acceptance");
    let incremental_objects = published.remote.dump();
    let uploads = std::mem::take(&mut *published.remote.log.lock().unwrap());
    let gets = std::mem::take(&mut *source.gets.lock().unwrap());
    let payload_calls = calls.borrow().clone();
    let (lookup, rows) = assert_reader(&published.remote, &incremental);
    published.remote.restore(stored);
    let root = incremental.accepted.doc.manifest_root;
    let reference = accept_sync_projection_full(
        queue,
        boundary,
        selected.to_vec(),
        &published.verified,
        &published.trusted,
        &source,
        |content| {
            payloads
                .get(&content)
                .map(|(_, grains)| grains.clone())
                .ok_or(PublishError::BadPlan)
        },
        &published.remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await
    .expect("whole-tree acceptance");
    published.remote.assert_stored(&incremental_objects);
    let reference_uploads = std::mem::take(&mut *published.remote.log.lock().unwrap());
    assert_eq!(
        incremental.accepted.doc, reference.accepted.doc,
        "the incremental root differs from the whole-tree build"
    );
    assert_eq!(
        format!("{:?}", incremental.accepted.summary),
        format!("{:?}", reference.accepted.summary),
        "the acceptance summary differs from the whole-tree build"
    );
    assert_eq!(
        uploads, reference_uploads,
        "the upload sequence differs from the whole-tree build"
    );
    for id in reference.nodes.keys() {
        assert!(
            incremental.nodes.contains_key(id) || ctx.world.objects.0.contains_key(id),
            "a node the whole-tree build made is neither built nor in the base"
        );
    }
    Report {
        novel_objects: incremental.summary().novel_objects,
        base_root: granary_core::root::decode_root(&published.bytes)
            .unwrap()
            .manifest_root,
        root,
        gets,
        payload_calls,
        uploads,
        world: World {
            objects: lookup,
            payloads,
        },
        rebuilt: incremental.projection().rebuild_set().len(),
        rows,
    }
}

/// Build the base, run `script` and seal.
async fn prepare(
    base: Base,
    script: impl FnOnce(&mut Ctx),
) -> (
    Ctx,
    Published,
    SyncProjectionQueue,
    SyncBoundary,
    Vec<DurableFile>,
) {
    prepare_at(base, 0, script).await
}
async fn prepare_at(
    mut base: Base,
    width: u8,
    script: impl FnOnce(&mut Ctx),
) -> (
    Ctx,
    Published,
    SyncProjectionQueue,
    SyncBoundary,
    Vec<DurableFile>,
) {
    let published = publish_at(&mut base, width).await;
    let f = open(&base, &published);
    let mut ctx = Ctx {
        f,
        world: std::mem::take(&mut base.world),
        target: SyncTarget::Directory(None),
        selected: None,
        generation: 0,
    };
    script(&mut ctx);
    let boundary = ctx
        .f
        .overlay
        .seal_sync(&mut ctx.f.store, &ctx.f.owner, ctx.target)
        .unwrap();
    let mut queue = SyncProjectionQueue::default();
    queue.reserve(&boundary).unwrap();
    let selected: Vec<DurableFile> = match ctx.selected.take() {
        None => {
            assert!(
                boundary.files().is_empty(),
                "the row left a dirty file the seal captured"
            );
            vec![]
        }
        Some(bytes) => {
            assert_eq!(boundary.files().len(), 1);
            let (content, size) = ctx.world.inline(&bytes);
            vec![DurableFile {
                inode: boundary.files()[0].entry().unwrap().inode,
                size,
                content,
                content_boundary: boundary.through_seq(),
            }]
        }
    };
    (ctx, published, queue, boundary, selected)
}

/// Build the base, run `script`, seal and compare the two builders.
pub(super) async fn check(base: Base, script: impl FnOnce(&mut Ctx)) -> Report {
    let (mut ctx, published, queue, boundary, selected) = prepare(base, script).await;
    let report = accept_both(&mut ctx, &published, &queue, &boundary, &selected).await;
    ctx.f.overlay.release_sync_boundary(&boundary).unwrap();
    report
}

/// The production path's refusal of a row that must not be accepted.
async fn refusal(base: Base, script: impl FnOnce(&mut Ctx)) -> PublishError {
    let (ctx, published, queue, boundary, selected) = prepare(base, script).await;
    let payloads = ctx.world.payloads.clone();
    published.remote.log.lock().unwrap().clear();
    let result = accept_sync_projection(
        &queue,
        &boundary,
        selected,
        &published.verified,
        &published.trusted,
        &ctx.world.objects,
        |content| {
            payloads
                .get(&content)
                .map(|(_, grains)| grains.clone())
                .ok_or(PublishError::BadPlan)
        },
        &published.remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await;
    let error = result.expect_err("the row was accepted");
    assert!(
        published.remote.log.lock().unwrap().is_empty(),
        "a refused projection uploaded something"
    );
    error
}

fn small() -> Base {
    let mut base = Base::new();
    base.dir("a")
        .file("a/x", b"ax")
        .file("a/y", b"ay")
        .dir("b")
        .file("b/z", b"bz")
        .file("top", b"top");
    base
}

#[tokio::test]
async fn a_clean_fsync_reuses_the_base_root() {
    let report = check(small(), |_| {}).await;
    assert_eq!(report.root, report.base_root);
    assert_eq!(report.rebuilt, 0);
    assert!(report.payload_calls.is_empty());
    assert_eq!(
        report
            .uploads
            .iter()
            .map(|(kind, _)| *kind)
            .collect::<Vec<_>>(),
        ["meta"],
        "a clean fsync uploads only its sheaf"
    );
    assert!(
        report.gets.is_empty(),
        "a clean fsync read objects: {:?}",
        report.gets
    );
}

#[tokio::test]
async fn a_synced_move_across_directories_matches() {
    let report = check(small(), |c| c.rename("a/x", "b/x")).await;
    assert_ne!(report.root, report.base_root);
    assert_eq!(report.rebuilt, 3, "root and both parents");
}

#[tokio::test]
async fn a_never_synced_file_and_its_rename_leave_the_base_root() {
    let report = check(small(), |c| {
        let s = c.create("a/u");
        c.write(s, b"unsynced");
        c.rename("a/u", "b/u");
    })
    .await;
    assert_eq!(report.root, report.base_root);
    assert_eq!(report.rebuilt, 0, "an excluded effect dirtied a directory");
    assert!(
        report.rows.iter().all(|(path, _)| !path.ends_with("/u")),
        "a never-synced file reached the tree"
    );
}

#[tokio::test]
async fn a_directory_move_keeps_synced_and_empty_children_and_drops_unsynced() {
    let mut base = Base::new();
    base.dir("d").dir("d/q").file("d/s", b"s");
    let report = check(base, |c| {
        let u = c.create("d/u");
        c.write(u, b"u");
        let k = c.create("d/k");
        c.sync(k, b"k");
        c.rename("d", "e");
    })
    .await;
    let paths: Vec<_> = report.rows.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(paths, ["e", "e/k", "e/q", "e/s"]);
}

#[tokio::test]
async fn a_never_synced_replacement_keeps_the_old_durable_target() {
    let mut base = Base::new();
    base.file("x", b"old");
    let report = check(base, |c| {
        let y = c.create("y");
        c.write(y, b"new");
        c.rename("y", "x");
        c.remove("x");
    })
    .await;
    assert_eq!(report.root, report.base_root);
}

#[tokio::test]
async fn a_synced_replacement_names_the_new_content_atomically() {
    let mut base = Base::new();
    base.file("x", b"old");
    let report = check(base, |c| {
        let y = c.create("y");
        c.sync(y, b"new");
        c.rename("y", "x");
    })
    .await;
    assert_eq!(report.rows.len(), 1);
}

#[tokio::test]
async fn replacing_a_never_synced_target_with_a_durable_source() {
    let report = check(Base::new(), |c| {
        let x = c.create("x");
        c.write(x, b"never");
        let y = c.create("y");
        c.sync(y, b"durable");
        c.rename("y", "x");
    })
    .await;
    assert_eq!(report.rows.len(), 1);
}

#[tokio::test]
async fn a_never_synced_source_over_a_never_synced_target_leaves_it_absent() {
    let report = check(Base::new(), |c| {
        let x = c.create("x");
        c.write(x, b"never");
        let y = c.create("y");
        c.write(y, b"never too");
        c.rename("y", "x");
    })
    .await;
    assert!(report.rows.is_empty());
    assert_eq!(report.root, report.base_root);
}

#[tokio::test]
async fn a_rename_chain_appears_only_at_its_end() {
    let mut base = Base::new();
    base.dir("p").file("p/a", b"a");
    let report = check(base, |c| {
        c.rename("p/a", "p/b");
        c.rename("p/b", "c");
    })
    .await;
    let paths: Vec<_> = report.rows.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(paths, ["c", "p"]);
}

#[tokio::test]
async fn a_temporary_renamed_over_a_target_is_old_or_new() {
    for synced in [false, true] {
        let mut base = Base::new();
        base.file("x", b"old");
        let report = check(base, |c| {
            let t = c.create("t");
            if synced {
                c.sync(t, b"temp");
            } else {
                c.write(t, b"temp");
            }
            c.rename("t", "x");
        })
        .await;
        assert_eq!(report.root == report.base_root, !synced);
    }
}

#[tokio::test]
async fn symlinks_create_move_and_replace_without_file_selection() {
    let mut base = Base::new();
    base.file("x", b"old").dir("d");
    let report = check(base, |c| {
        c.symlink("l", "target");
        c.symlink("m", "other");
        c.rename("m", "d/m");
        c.rename("l", "x");
    })
    .await;
    let paths: Vec<_> = report.rows.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(paths, ["d", "d/m", "x"]);
}

#[tokio::test]
async fn an_empty_directory_created_since_the_base_and_untouched_now_is_built() {
    let report = check(small(), |c| c.mkdir("fresh")).await;
    assert!(report.rows.iter().any(|(p, k)| p == "fresh" && k == "dir"));
    // The directory is empty, its parent is the root, and nothing else changed.
    assert_eq!(report.rebuilt, 2);
}

#[tokio::test]
async fn a_directory_whose_only_children_are_never_synced_is_still_built_empty() {
    let report = check(small(), |c| {
        c.mkdir("fresh");
        let u = c.create("fresh/u");
        c.write(u, b"u");
    })
    .await;
    assert!(report.rows.iter().any(|(p, k)| p == "fresh" && k == "dir"));
    assert!(report.rows.iter().all(|(p, _)| p != "fresh/u"));
}

#[tokio::test]
async fn a_chain_twenty_deep_rebuilds_only_its_own_path() {
    let mut base = Base::new();
    let mut path = String::new();
    for i in 0..20 {
        if !path.is_empty() {
            path.push('/');
        }
        path.push('d');
        path.push_str(&i.to_string());
        base.dir(&path);
        base.dir(&format!("{path}/side"));
        base.file(&format!("{path}/keep"), b"keep");
    }
    let leaf = format!("{path}/new");
    let report = check(base, |c| {
        let s = c.create(&leaf);
        c.sync(s, b"deep");
    })
    .await;
    assert_eq!(report.rebuilt, 21, "twenty directories and the root");
    let side = report
        .world
        .objects
        .0
        .keys()
        .filter(|id| report.gets.contains(id))
        .count();
    // The twenty-one directories on the path, and the one novel grain.
    assert!(side <= 22, "reads beyond the changed path: {side}");
}

async fn crossing(count: usize, insert: bool) {
    let mut base = Base::new();
    base.cap = 1 << 30;
    base.dir("big");
    let content = base.world.inline(b"c");
    for i in 0..count {
        base.entries
            .push(file(&format!("big/f{i:06}"), content, false));
    }
    let report = check(base, |c| {
        if insert {
            let s = c.create("big/g");
            c.sync(s, b"g");
        } else {
            c.remove("big/f000007");
        }
    })
    .await;
    assert_eq!(
        report.rows.len(),
        count + 1 + usize::from(insert) - usize::from(!insert)
    );
}

#[tokio::test]
async fn directory_size_crossing_256_by_insert() {
    crossing(256, true).await;
}
#[tokio::test]
async fn directory_size_crossing_257_by_delete() {
    crossing(257, false).await;
}
#[tokio::test]
async fn directory_size_crossing_65536_by_insert() {
    crossing(65_536, true).await;
}
#[tokio::test]
async fn directory_size_crossing_65537_by_delete() {
    crossing(65_537, false).await;
}

#[tokio::test]
async fn a_moved_unchanged_directory_is_never_read_inside() {
    let mut base = Base::new();
    base.dir("src").dir("src/inner").file("src/inner/f", b"f");
    base.file("src/g", b"g").dir("dst");
    let report = check(base, |c| c.rename("src", "dst/src")).await;
    let inner = report
        .world
        .objects
        .0
        .keys()
        .filter(|id| report.gets.contains(id))
        .count();
    // The moved directory keeps its id; only the root and dst are rebuilt, and
    // their base B-trees are the only reads.
    assert!(
        inner <= 3,
        "the move read inside the moved directory: {inner}"
    );
    assert_eq!(report.rebuilt, 2, "root and the new parent");
}

#[tokio::test]
async fn a_moved_directory_with_an_inner_edit_rebuilds_its_path() {
    let mut base = Base::new();
    base.dir("src").dir("src/inner").file("src/inner/f", b"f");
    base.dir("dst");
    let report = check(base, |c| {
        let s = c.create("src/inner/new");
        c.sync(s, b"n");
        c.rename("src", "dst/src");
    })
    .await;
    assert!(report.rows.iter().any(|(p, _)| p == "dst/src/inner/new"));
}

#[tokio::test]
async fn a_directory_replaced_by_a_directory() {
    let mut base = Base::new();
    base.dir("old").file("old/f", b"f").dir("empty");
    check(base, |c| {
        c.remove("old/f");
        c.remove("old");
        c.rename("empty", "old");
    })
    .await;
}

#[tokio::test]
async fn a_directory_replaced_by_a_file_synced_and_never_synced() {
    for synced in [true, false] {
        let mut base = Base::new();
        base.dir("n").file("keep", b"k");
        check(base, |c| {
            c.remove("n");
            let s = c.create("n");
            if synced {
                c.sync(s, b"file");
            } else {
                c.write(s, b"file");
            }
        })
        .await;
    }
}

#[tokio::test]
async fn an_exec_flip_rebuilds_its_parent_and_keeps_the_content() {
    let mut base = Base::new();
    base.dir("bin")
        .exec("bin/run", b"run")
        .file("bin/doc", b"doc");
    let report = check(base, |c| c.chmod("bin/run", false)).await;
    assert!(
        report.payload_calls.is_empty(),
        "an exec flip fetched a payload"
    );
    assert_eq!(report.rebuilt, 2);
}

#[tokio::test]
async fn a_to_b_to_a_reproduces_the_base_root() {
    let report = check(small(), |c| {
        c.rename("a/x", "a/tmp");
        c.rename("a/tmp", "a/x");
    })
    .await;
    assert_eq!(report.root, report.base_root);
    assert!(report.rebuilt > 0, "the rename dirtied nothing");
}

#[tokio::test]
async fn an_unchanged_spilled_sibling_is_never_read_or_fetched() {
    let mut base = Base::new();
    base.dir("d").spilled("d/big", 7).file("d/small", b"s");
    let spill = base.world.payloads.values().find_map(|(_, g)| match g {
        FileGrains::Spill { root, .. } => Some(*root),
        FileGrains::Inline(_) => None,
    });
    let report = check(base, |c| {
        let s = c.create("d/new");
        c.sync(s, b"n");
    })
    .await;
    let spill = spill.unwrap();
    assert!(
        !report.gets.contains(&spill),
        "an unchanged spilled sibling's grain list was fetched"
    );
    assert!(report.payload_calls.len() <= 1);
}

#[tokio::test]
async fn a_changed_spilled_file_uploads_its_grain_list() {
    let mut base = Base::new();
    base.dir("d").file("d/small", b"s");
    let tag = 9;
    let report = check(base, move |c| {
        let (content, size) = c.world.spilled(tag);
        let s = c.create("d/spilled");
        c.write(s, &vec![0; usize::try_from(size).unwrap()]);
        c.sync_as(s, content);
    })
    .await;
    assert!(report.rows.iter().any(|(p, _)| p == "d/spilled"));
}

#[tokio::test]
async fn a_changed_file_whose_grain_list_lies_is_refused_before_any_upload() {
    let mut base = small();
    let refs: Vec<GrainRef> = (0..130_u8)
        .map(|i| {
            base.world.objects.0.insert(GrainId::of(&[i]), vec![i]);
            GrainRef {
                id: GrainId::of(&[i]),
                unpacked_len: 1,
            }
        })
        .collect();
    let list = manifest::build_grain_list(&refs).unwrap();
    base.world.objects.0.extend(list.nodes);
    let root = list.root;
    let error = refusal(base, move |c| {
        // The payload claims 200 grains over a list that holds 130.
        let (content, size) = c.world.register_spill_claim(130, 200, root);
        let s = c.create("a/lie");
        c.write(s, &[0; 130]);
        c.sync_as(s, content);
        assert_eq!(size, 130);
    })
    .await;
    assert!(
        matches!(error, PublishError::BadPlan),
        "wrong refusal for a lying grain list: {error}"
    );
}

#[tokio::test]
async fn a_never_synced_create_in_an_untouched_directory_changes_nothing() {
    let report = check(small(), |c| {
        let s = c.create("a/ghost");
        c.write(s, b"ghost");
    })
    .await;
    assert_eq!(report.root, report.base_root);
    assert_eq!(report.rebuilt, 0);
}

#[tokio::test]
async fn a_selected_overwrite_of_a_base_file_rebuilds_its_parent_only() {
    let report = check(small(), |c| {
        let s = c.copy_up("a/x");
        c.write(s, b"changed");
        c.select(s, b"changed");
    })
    .await;
    assert_eq!(report.rebuilt, 2, "root and a");
    assert_eq!(
        report.payload_calls.len(),
        1,
        "only the changed file asks for its payload"
    );
}

/// A seeded sequence of operations over a small tree; each seed is a row.
#[tokio::test]
async fn seeded_random_operation_sequences_match() {
    use granary_core::rng::{Rng as _, SeededRng};
    for seed in 0..24_u64 {
        let mut base = Base::new();
        base.dir("a").dir("a/b").dir("c");
        for i in 0..6 {
            base.file(&format!("a/f{i}"), format!("a{i}").as_bytes());
            base.file(&format!("a/b/g{i}"), format!("g{i}").as_bytes());
            base.file(&format!("c/h{i}"), format!("h{i}").as_bytes());
        }
        base.file("root", b"root");
        check(base, move |c| {
            let mut rng = SeededRng::new(seed);
            let mut counter = 0_u32;
            for _ in 0..(3 + rng.below(8)) {
                let names: Vec<String> =
                    c.f.overlay
                        .namespace
                        .entries
                        .keys()
                        .map(|p| {
                            p.iter()
                                .map(|n| std::str::from_utf8(n.as_bytes()).unwrap())
                                .collect::<Vec<_>>()
                                .join("/")
                        })
                        .collect();
                let files: Vec<&String> = names
                    .iter()
                    .filter(|n| {
                        matches!(
                            c.f.overlay.namespace.entries[&path_of(n)].kind,
                            OverlayKind::File { .. }
                        )
                    })
                    .collect();
                let dirs: Vec<&String> = names
                    .iter()
                    .filter(|n| {
                        matches!(
                            c.f.overlay.namespace.entries[&path_of(n)].kind,
                            OverlayKind::Directory
                        )
                    })
                    .collect();
                counter += 1;
                let pick =
                    |rng: &mut SeededRng, n: usize| usize::try_from(rng.below(n as u64)).unwrap();
                match rng.below(6) {
                    0 if !files.is_empty() => {
                        let victim = files[pick(&mut rng, files.len())].clone();
                        c.remove(&victim);
                    }
                    1 if !files.is_empty() => {
                        let from = files[pick(&mut rng, files.len())].clone();
                        let parent = dirs[pick(&mut rng, dirs.len())].clone();
                        let to = format!("{parent}/m{counter}");
                        c.rename(&from, &to);
                    }
                    2 => {
                        let parent = dirs[pick(&mut rng, dirs.len())].clone();
                        let s = c.create(&format!("{parent}/n{counter}"));
                        if rng.below(2) == 0 {
                            c.sync(s, format!("n{counter}").as_bytes());
                        } else {
                            c.write(s, b"unsynced");
                        }
                    }
                    3 => {
                        let parent = dirs[pick(&mut rng, dirs.len())].clone();
                        c.mkdir(&format!("{parent}/k{counter}"));
                    }
                    4 if !files.is_empty() => {
                        let victim = files[pick(&mut rng, files.len())].clone();
                        let exec = rng.below(2) == 0;
                        c.chmod(&victim, exec);
                    }
                    _ if files.len() >= 2 => {
                        let from = files[pick(&mut rng, files.len())].clone();
                        let over = files[pick(&mut rng, files.len())].clone();
                        if from != over {
                            c.rename(&from, &over);
                        }
                    }
                    _ => {}
                }
            }
        })
        .await;
    }
}

/// A first capture is accepted and admitted; the next one carries it forward.
#[tokio::test]
async fn carried_forward_and_failed_capture_fallback_match() {
    for fail_first in [false, true] {
        let mut base = small();
        let published = publish(&mut base).await;
        let f = open(&base, &published);
        let mut ctx = Ctx {
            f,
            world: std::mem::take(&mut base.world),
            target: SyncTarget::Directory(None),
            selected: None,
            generation: 0,
        };
        let stage = ctx.copy_up("a/x");
        ctx.write(stage, b"first");
        let first = ctx
            .f
            .overlay
            .seal_sync(&mut ctx.f.store, &ctx.f.owner, SyncTarget::Stage(stage))
            .unwrap();
        let mut queue = SyncProjectionQueue::default();
        queue.reserve(&first).unwrap();
        let (content, size) = ctx.world.inline(b"first");
        let selected = vec![DurableFile {
            inode: first.files()[0].entry().unwrap().inode,
            size,
            content,
            content_boundary: first.through_seq(),
        }];
        let report = accept_both(&mut ctx, &published, &queue, &first, &selected).await;
        assert!(report.rebuilt > 0);
        if fail_first {
            queue.fail(&first).unwrap();
        } else {
            let accepted = accept_sync_projection(
                &queue,
                &first,
                selected.clone(),
                &published.verified,
                &published.trusted,
                &ctx.world.objects,
                |c| {
                    ctx.world
                        .payloads
                        .get(&c)
                        .map(|(_, g)| g.clone())
                        .ok_or(PublishError::BadPlan)
                },
                &published.remote,
                now(),
                Policy::default(),
                |_| crate::PublishError::BadPlan,
            )
            .await
            .unwrap();
            queue.admit(&accepted).unwrap();
        }
        // A later directory seal; the first capture's file is still dirty-free.
        ctx.f.overlay.release_sync_boundary(&first).unwrap();
        let second = ctx
            .f
            .overlay
            .seal_sync(&mut ctx.f.store, &ctx.f.owner, SyncTarget::Directory(None))
            .unwrap();
        queue.reserve(&second).unwrap();
        let carried = accept_both(&mut ctx, &published, &queue, &second, &[]).await;
        let has = carried
            .rows
            .iter()
            .any(|(p, k)| p == "a/x" && k.contains(&content.to_string()));
        assert_eq!(has, !fail_first, "carry-forward and fallback disagree");
        ctx.f.overlay.release_sync_boundary(&second).unwrap();
    }
}

#[tokio::test]
async fn binmap_widths_match_full_root_bytes_bins_and_order() {
    let mut cases = 0;
    for width in [0, 1, 8, 12] {
        for edit in [false, true] {
            let (mut ctx, published, queue, boundary, selected) = prepare_at(small(), width, |c| {
                if edit {
                    let stage = c.copy_up("a/x");
                    c.write(stage, b"changed");
                    c.select(stage, b"changed");
                } else {
                    c.rename("a/x", "b/moved");
                }
            })
            .await;
            accept_both(&mut ctx, &published, &queue, &boundary, &selected).await;
            ctx.f.overlay.release_sync_boundary(&boundary).unwrap();
            cases += 1;
        }
    }
    assert_eq!(cases, 8);
}

/// Add physically backed, unreachable old mappings while retaining width zero.
/// Their bytes and ordinals are still part of the old relation the build preserves.
async fn seed_extra_mappings(published: &mut Published, count: u32) {
    use granary_core::binstore::BinStore;
    use granary_core::{binfmt, binmap};
    let mut doc = granary_core::root::decode_root(&published.bytes).unwrap();
    let index = binmap::decode_binmap_index(
        &published
            .remote
            .get_meta("v", &doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(index.prefix_bits, 0);
    let mut bins = binmap::decode_bin_table(
        &published
            .remote
            .get_meta("v", &index.bin_table)
            .await
            .unwrap(),
    )
    .unwrap();
    let mut entries = binmap::decode_shard(
        &published
            .remote
            .get_meta("v", index.shards.first().unwrap())
            .await
            .unwrap(),
    )
    .unwrap();
    let mut codec = granary_store::codec::GrainCodec::new().unwrap();
    for begin in (0..count).step_by(10_000) {
        let frames: Vec<_> = (begin..count.min(begin + 10_000))
            .map(|n| {
                let bytes = n.to_le_bytes();
                binfmt::PackedFrame {
                    id: GrainId::of(&bytes),
                    frame: codec.compress_grain(&bytes).unwrap(),
                }
            })
            .collect();
        let bytes = binfmt::encode_bin(&frames).unwrap();
        let digest = *GrainId::of(&bytes).digest();
        let ordinal = u32::try_from(bins.len()).unwrap();
        bins.push(digest);
        for entry in binfmt::decode_bin(&bytes).unwrap() {
            entries.push(binmap::ShardEntry {
                id: entry.id,
                bin_ordinal: ordinal,
                offset: entry.offset,
                comp_len: entry.comp_len,
            });
        }
        published.remote.put_bin(&digest, bytes).await.unwrap();
    }
    entries.sort_unstable_by_key(|entry| entry.id);
    let bytes = binmap::encode_shard(&entries).unwrap();
    let shard = GrainId::of(&bytes);
    published.remote.put_meta("v", &shard, bytes).await.unwrap();
    let bytes = binmap::encode_bin_table(&bins).unwrap();
    let table = GrainId::of(&bytes);
    published.remote.put_meta("v", &table, bytes).await.unwrap();
    let bytes = binmap::encode_binmap_index(0, table, &[shard]).unwrap();
    doc.binmap_index = GrainId::of(&bytes);
    published
        .remote
        .put_meta("v", &doc.binmap_index, bytes)
        .await
        .unwrap();
    let key = granary_store::crypto::SigningKey::from_seed(&[39; 32]).unwrap();
    doc.sigs.clear();
    doc.sigs.push(granary_core::root::RootSig {
        key_id: key.key_id(),
        sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    });
    published.bytes = granary_core::root::encode_root(&doc).unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one target crossing compares the manifest, packing, append-only relation and independently signed readable roots"
)]
async fn target_crossing_preserves_relation_with_distinct_readable_roots() {
    use granary_core::binstore::BinStore;
    let mut base = Base::new();
    base.file("keep", b"keep");
    let mut published = publish(&mut base).await;
    seed_extra_mappings(&mut published, 21_397).await;
    published.verified = verified(
        &published.bytes,
        &published.trusted,
        &base.world.objects,
        &published.remote,
    )
    .await;
    let f = open(&base, &published);
    let mut ctx = Ctx {
        f,
        world: std::mem::take(&mut base.world),
        target: SyncTarget::Directory(None),
        selected: None,
        generation: 0,
    };
    let stage = ctx.create("edit");
    ctx.write(stage, b"edit");
    ctx.select(stage, b"edit");
    let boundary = ctx
        .f
        .overlay
        .seal_sync(&mut ctx.f.store, &ctx.f.owner, ctx.target)
        .unwrap();
    let mut queue = SyncProjectionQueue::default();
    queue.reserve(&boundary).unwrap();
    let (content, size) = ctx.world.inline(b"edit");
    let selected = vec![DurableFile {
        inode: boundary.files()[0].entry().unwrap().inode,
        content,
        size,
        content_boundary: boundary.through_seq(),
    }];
    let payload = |id| {
        ctx.world
            .payloads
            .get(&id)
            .map(|(_, grains)| grains.clone())
            .ok_or(PublishError::BadPlan)
    };
    let stored = published.remote.dump();
    published.remote.log.lock().unwrap().clear();
    let mut partial = accept_sync_projection(
        &queue,
        &boundary,
        selected.clone(),
        &published.verified,
        &published.trusted,
        &ctx.world.objects,
        payload,
        &published.remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await
    .unwrap();
    let partial_bins: Vec<_> = published
        .remote
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|(kind, _)| *kind == "bin")
        .cloned()
        .collect();
    let reader_a = published
        .remote
        .read_objects(partial.accepted.doc.binmap_index)
        .unwrap();
    let key = granary_store::crypto::SigningKey::from_seed(&[39; 32]).unwrap();
    let sign = |mut doc: granary_core::root::RootDoc| {
        doc.writer_uuid = [61; 16];
        doc.sigs.push(granary_core::root::RootSig {
            key_id: key.key_id(),
            sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
        });
        granary_core::root::encode_root(&doc).unwrap()
    };
    let bytes_a = sign(partial.accepted.doc.clone());
    let state_a = crate::publish::state_from_head(
        &published.remote,
        boundary.volume(),
        partial.accepted.doc.seq,
        &bytes_a,
        &published.trusted,
    )
    .await
    .unwrap();
    let table_a = state_a.bins.clone();
    let relation_a: BTreeMap<_, _> = state_a
        .known
        .values()
        .map(|entry| {
            (
                entry.id,
                (
                    state_a.bins[entry.bin_ordinal as usize],
                    entry.offset,
                    entry.comp_len,
                ),
            )
        })
        .collect();
    assert!(
        partial.accepted.take_complete().is_err(),
        "partial acceptance made a complete-map claim"
    );
    published.remote.restore(stored);
    published.remote.log.lock().unwrap().clear();
    let reference = accept_sync_projection_full(
        &queue,
        &boundary,
        selected,
        &published.verified,
        &published.trusted,
        &ctx.world.objects,
        payload,
        &published.remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await
    .unwrap();
    let reference_bins: Vec<_> = published
        .remote
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|(kind, _)| *kind == "bin")
        .cloned()
        .collect();
    let reader_b = published
        .remote
        .read_objects(reference.accepted.doc.binmap_index)
        .unwrap();
    let bytes_b = sign(reference.accepted.doc.clone());
    let state_b = crate::publish::state_from_head(
        &published.remote,
        boundary.volume(),
        reference.accepted.doc.seq,
        &bytes_b,
        &published.trusted,
    )
    .await
    .unwrap();
    let relation_b: BTreeMap<_, _> = state_b
        .known
        .values()
        .map(|entry| {
            (
                entry.id,
                (
                    state_b.bins[entry.bin_ordinal as usize],
                    entry.offset,
                    entry.comp_len,
                ),
            )
        })
        .collect();
    assert_eq!(partial.summary().prefix_bits, 0);
    assert_eq!(reference.summary().prefix_bits, 1);
    assert_eq!(
        partial.accepted.doc.manifest_root,
        reference.accepted.doc.manifest_root
    );
    assert_eq!(
        partial.accepted.doc.sheaf_head,
        reference.accepted.doc.sheaf_head
    );
    assert_eq!(
        partial.summary().novel_objects,
        reference.summary().novel_objects
    );
    assert_eq!(partial_bins, reference_bins);
    assert_eq!(table_a, state_b.bins);
    assert_eq!(relation_a, relation_b);
    assert_eq!(
        reader_a.0, reader_b.0,
        "fresh readers recovered different object bytes"
    );
    assert_ne!(
        partial.accepted.doc.binmap_index,
        reference.accepted.doc.binmap_index
    );
    assert_ne!(bytes_a, bytes_b);
    for (bytes, objects) in [(&bytes_a, &reader_a), (&bytes_b, &reader_b)] {
        let doc = granary_store::crypto::check_head(bytes, "v", 2, &published.trusted).unwrap();
        manifest::validate_dir_tree(&doc.manifest_root, &|id| objects.0.get(id).cloned()).unwrap();
        assert_eq!(
            read_rows(doc.manifest_root, objects),
            projected_rows(partial.projection().entries())
        );
    }
    // Table and sheaf equality is independent of either index's partitioning.
    let index_b = granary_core::binmap::decode_binmap_index(
        &published
            .remote
            .get_meta("v", &reference.accepted.doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        granary_core::binmap::decode_bin_table(
            &published
                .remote
                .get_meta("v", &index_b.bin_table)
                .await
                .unwrap()
        )
        .unwrap(),
        table_a
    );
}

#[tokio::test]
async fn cross_file_dedup_uploads_only_the_changed_manifest() {
    for width in [0, 1, 8, 12] {
        let mut base = Base::new();
        base.file("keep", b"shared").file("other", b"shared");
        let (mut ctx, published, queue, boundary, selected) = prepare_at(base, width, |c| {
            let stage = c.create("new");
            c.write(stage, b"shared");
            c.select(stage, b"shared");
        })
        .await;
        let report = accept_both(&mut ctx, &published, &queue, &boundary, &selected).await;
        assert_eq!(
            report.novel_objects, 1,
            "a shared grain was treated as novel"
        );
        assert_eq!(report.rows.len(), 3);
        assert_eq!(
            report.world.objects.get(&GrainId::of(b"shared")).unwrap(),
            b"shared"
        );
        ctx.f.overlay.release_sync_boundary(&boundary).unwrap();
    }
}
