// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    ClientMetrics, DurableFile, Policy, SyncProjectionQueue, SyncTarget, VerifiedBase,
    accept_sync_projection, rechunk_captured,
};
use granary_core::binstore::BinStore;
use granary_core::grainsource::{GrainSource, GrainSourceError};
use granary_core::manifest::{self, FileGrains, GrainRef};
use granary_core::root::{RootSig, Timestamp};
use granary_core::rootstore::RootStoreError;
use granary_store::crypto::{SigningKey, TrustedKeys};

#[derive(Default)]
pub(super) struct Objects(pub(super) BTreeMap<GrainId, Vec<u8>>);
impl GrainSource for Objects {
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
#[derive(Default)]
pub(super) struct Remote {
    bins: Mutex<BTreeMap<[u8; 32], Vec<u8>>>,
    meta: Mutex<BTreeMap<GrainId, Vec<u8>>>,
    pub(super) puts: Mutex<Vec<&'static str>>,
    fail: Mutex<Option<usize>>,
    /// Every upload in order, as (kind, identity).
    pub(super) log: Mutex<Vec<(&'static str, Vec<u8>)>>,
    /// The kind of every metadata object fetched, in order.
    pub(super) fetched: Mutex<Vec<&'static str>>,
    pub(super) reads: Mutex<Vec<(GrainId, usize)>>,
    pub(super) get_failure: Mutex<Option<&'static str>>,
}
/// A remote's stored objects.
pub(super) struct Stored {
    bins: BTreeMap<[u8; 32], Vec<u8>>,
    meta: BTreeMap<GrainId, Vec<u8>>,
}
impl Remote {
    pub(super) fn assert_stored(&self, expected: &Stored) {
        assert_eq!(
            *self.bins.lock().unwrap(),
            expected.bins,
            "bin bytes differ from full acceptance"
        );
        assert_eq!(
            *self.meta.lock().unwrap(),
            expected.meta,
            "shard/table/index/sheaf bytes differ from full acceptance"
        );
    }
    pub(super) fn overwrite_meta(&self, id: GrainId, bytes: Vec<u8>) {
        self.meta.lock().unwrap().insert(id, bytes);
    }
    pub(super) fn read_objects(&self, index_id: GrainId) -> Result<Objects, String> {
        use granary_core::{binfmt, binmap};
        let meta = self.meta.lock().unwrap();
        let fetch = |id: &GrainId| -> Result<&Vec<u8>, String> {
            let bytes = meta.get(id).ok_or_else(|| "missing metadata".to_owned())?;
            if GrainId::of(bytes) != *id {
                return Err("bad hash".to_owned());
            }
            Ok(bytes)
        };
        let index = binmap::decode_binmap_index(fetch(&index_id)?).map_err(|e| e.to_string())?;
        let table =
            binmap::decode_bin_table(fetch(&index.bin_table)?).map_err(|e| e.to_string())?;
        let mut objects = Objects::default();
        let bins = self.bins.lock().unwrap();
        let mut codec = granary_store::codec::GrainCodec::new().unwrap();
        let mut bin_indices = BTreeMap::new();
        for digest in &table {
            let bin = bins.get(digest).ok_or_else(|| "missing bin".to_owned())?;
            if GrainId::of(bin).digest() != digest {
                return Err("bad bin hash".to_owned());
            }
            let own: BTreeMap<_, _> = binfmt::decode_bin(bin)
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|entry| (entry.id, entry))
                .collect();
            bin_indices.insert(*digest, own);
        }
        for (at, id) in index.shards.iter().enumerate() {
            let entries = binmap::decode_shard(fetch(id)?).map_err(|e| e.to_string())?;
            binmap::validate_routing(&entries, index.prefix_bits, at).map_err(|e| e.to_string())?;
            binmap::validate_ordinals(&entries, u32::try_from(table.len()).unwrap())
                .map_err(|e| e.to_string())?;
            for entry in &entries {
                let routed = binmap::find_entry(&entries, &entry.id).unwrap();
                let bin = bins
                    .get(&table[routed.bin_ordinal as usize])
                    .ok_or_else(|| "missing bin".to_owned())?;
                let own = bin_indices[&table[routed.bin_ordinal as usize]]
                    .get(&entry.id)
                    .ok_or_else(|| "missing extent".to_owned())?;
                if own.offset != routed.offset || own.comp_len != routed.comp_len {
                    return Err("wrong extent".to_owned());
                }
                let frame = binfmt::frame_bytes(bin, own).map_err(|e| e.to_string())?;
                let bytes = codec.decompress_frame(frame).map_err(|e| e.to_string())?;
                if GrainId::of(&bytes) != entry.id || objects.0.insert(entry.id, bytes).is_some() {
                    return Err("bad or duplicate grain".to_owned());
                }
            }
        }
        Ok(objects)
    }
    pub(super) fn remove_meta(&self, id: GrainId) {
        self.meta.lock().unwrap().remove(&id);
    }
    /// The stored objects, to put the remote back as it was.
    pub(super) fn dump(&self) -> Stored {
        Stored {
            bins: self.bins.lock().unwrap().clone(),
            meta: self.meta.lock().unwrap().clone(),
        }
    }
    pub(super) fn restore(&self, stored: Stored) {
        *self.bins.lock().unwrap() = stored.bins;
        *self.meta.lock().unwrap() = stored.meta;
    }
    fn attempt(&self, kind: &'static str) -> Result<(), RootStoreError> {
        let mut puts = self.puts.lock().unwrap();
        puts.push(kind);
        if *self.fail.lock().unwrap() == Some(puts.len()) {
            return Err(RootStoreError::Backend(
                "accepted answer unavailable".into(),
            ));
        }
        Ok(())
    }
}
impl BinStore for Remote {
    async fn put_bin(&self, digest: &[u8; 32], bytes: Vec<u8>) -> Result<bool, RootStoreError> {
        assert_eq!(GrainId::of(&bytes).digest(), digest);
        self.log.lock().unwrap().push(("bin", digest.to_vec()));
        self.attempt("bin")?;
        Ok(self.bins.lock().unwrap().insert(*digest, bytes).is_none())
    }
    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        VolumeName::from_bytes(volume.as_bytes()).unwrap();
        assert_eq!(GrainId::of(&bytes), *id);
        self.log
            .lock()
            .unwrap()
            .push(("meta", id.digest().to_vec()));
        self.attempt("meta")?;
        Ok(self.meta.lock().unwrap().insert(*id, bytes).is_none())
    }
    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        VolumeName::from_bytes(volume.as_bytes()).unwrap();
        let failure = *self.get_failure.lock().unwrap();
        match failure {
            Some("transport") => return Err(RootStoreError::Backend("unavailable".into())),
            Some("shed") => {
                return Err(RootStoreError::Unavailable {
                    operation: "GET meta",
                    status: 503,
                });
            }
            Some("hold") => std::future::pending::<()>().await,
            _ => (),
        }
        let found = self.meta.lock().unwrap().get(id).cloned();
        if let Some(bytes) = &found {
            use granary_core::encoding::ObjectType;
            self.reads.lock().unwrap().push((*id, bytes.len()));
            let kind = match granary_core::encoding::open_envelope(bytes).map(|(kind, _)| kind) {
                Ok(ObjectType::BinmapShard) if failure == Some("shard") => {
                    return Err(RootStoreError::Backend("unavailable shard".into()));
                }
                Ok(ObjectType::BinmapIndex | ObjectType::BinTable | ObjectType::BinmapShard) => {
                    "binmap"
                }
                Ok(ObjectType::Sheaf) => "sheaf",
                _ => "manifest",
            };
            self.fetched.lock().unwrap().push(kind);
        }
        found.ok_or(RootStoreError::NotFound)
    }
    async fn get_bin_range(
        &self,
        digest: &[u8; 32],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        let bins = self.bins.lock().unwrap();
        let bin = bins.get(digest).ok_or(RootStoreError::NotFound)?;
        let offset = usize::try_from(offset).unwrap();
        let end = offset + len as usize;
        Ok(bin[offset..end.min(bin.len())].to_vec())
    }
}
pub(super) fn now() -> Timestamp {
    Timestamp {
        secs: 1_000,
        nanos: 0,
    }
}
pub(super) async fn base(remote: &Remote) -> (Vec<u8>, TrustedKeys) {
    let tree = manifest::build_dir(&[]).unwrap();
    let root = tree.root;
    base_with_manifest(remote, root, &Objects(tree.nodes.into_iter().collect())).await
}
pub(super) async fn base_with_manifest(
    remote: &Remote,
    root: GrainId,
    source: &Objects,
) -> (Vec<u8>, TrustedKeys) {
    base_with_policy(remote, root, source, Policy::default()).await
}
pub(super) async fn base_with_policy(
    remote: &Remote,
    root: GrainId,
    source: &Objects,
    policy: Policy,
) -> (Vec<u8>, TrustedKeys) {
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let accepted = crate::publish::accept_from_state(
        remote,
        source,
        root,
        crate::HarvestStats::default(),
        &VolumeName::from_bytes(b"v").unwrap(),
        now(),
        policy,
        crate::publish::RemoteState::empty(),
    )
    .await
    .unwrap();
    let mut doc = accepted.doc;
    doc.writer_uuid = [61; 16];
    let prefix = granary_core::root::signing_prefix_of(&doc).unwrap();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&prefix),
    });
    remote.puts.lock().unwrap().clear();
    (
        granary_core::root::encode_root(&doc).unwrap(),
        TrustedKeys::new([*key.public_key()]).unwrap(),
    )
}
fn empty_tree() -> Objects {
    Objects(
        manifest::build_dir(&[])
            .unwrap()
            .nodes
            .into_iter()
            .collect(),
    )
}
pub(super) async fn verified(
    bytes: &[u8],
    trusted: &TrustedKeys,
    source: &dyn GrainSource,
    remote: &Remote,
) -> VerifiedBase {
    VerifiedBase::attach(bytes.to_vec(), "v", trusted, source, remote)
        .await
        .unwrap()
}
fn capture(f: &mut Fixture, base: &[u8], bytes: &[u8]) -> SyncBoundary {
    f.overlay.journal.lock().unwrap().header.base_root = GrainId::of(base);
    let id = f.create();
    f.write(id, bytes);
    f.overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap()
}
fn payload(boundary: &SyncBoundary, bytes: &[u8]) -> (Vec<DurableFile>, FileGrains, Objects) {
    let grain = GrainRef {
        id: GrainId::of(bytes),
        unpacked_len: u32::try_from(bytes.len()).unwrap(),
    };
    let grains = FileGrains::Inline(vec![grain]);
    let content = GrainId::of(&manifest::node::file_payload(bytes.len() as u64, &grains).unwrap());
    (
        vec![DurableFile {
            inode: boundary.files()[0].entry().unwrap().inode,
            size: bytes.len() as u64,
            content,
            content_boundary: boundary.through_seq(),
        }],
        grains,
        Objects(BTreeMap::from([(grain.id, bytes.to_vec())])),
    )
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one accepted queue compares scoped carry with complete isolation after deletion"
)]
async fn accepted_projection_carries_forward_before_receipt_and_failed_upload_falls_back() {
    let remote = Remote::default();
    let (base, trusted) = base(&remote).await;
    let mut f = Fixture::new();
    let b = capture(&mut f, &base, b"accepted");
    let mut queue = SyncProjectionQueue::default();
    queue.reserve(&b).unwrap();
    let (selected, grains, source) = payload(&b, b"accepted");
    let c = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Directory(None))
        .unwrap();
    queue.reserve(&c).unwrap();
    let mut other_queue = SyncProjectionQueue::default();
    other_queue.reserve(&c).unwrap();
    let later = accept_sync_projection(
        &other_queue,
        &c,
        vec![],
        &verified(&base, &trusted, &empty_tree(), &remote).await,
        &trusted,
        &source,
        |_| Ok(grains.clone()),
        &remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await
    .unwrap();
    assert!(
        queue.admit(&later).is_err(),
        "later capability bypassed unresolved admission"
    );
    assert!(
        accept_sync_projection(
            &queue,
            &c,
            vec![],
            &verified(&base, &trusted, &empty_tree(), &remote).await,
            &trusted,
            &source,
            |_| Ok(grains.clone()),
            &remote,
            now(),
            Policy::default(),
            |_| crate::PublishError::BadPlan,
        )
        .await
        .is_err(),
        "later projection bypassed unresolved admission"
    );
    let accepted = accept_sync_projection(
        &queue,
        &b,
        selected,
        &verified(&base, &trusted, &empty_tree(), &remote).await,
        &trusted,
        &source,
        |_| Ok(grains.clone()),
        &remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await
    .unwrap();
    queue.admit(&accepted).unwrap();
    assert!(queue.admit(&accepted).is_err());
    assert!(queue.fail(&b).is_err());
    let next = accept_sync_projection(
        &queue,
        &c,
        vec![],
        &verified(&base, &trusted, &empty_tree(), &remote).await,
        &trusted,
        &source,
        |_| Ok(grains.clone()),
        &remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await
    .unwrap();
    assert_eq!(
        next.projection().entries().len(),
        1,
        "accepted unrelated file lost before receipt"
    );
    assert_eq!(
        next.projection().entries()[0].kind,
        accepted.projection().entries()[0].kind
    );
    assert_eq!(
        next.summary().manifest_root,
        accepted.summary().manifest_root
    );
    assert_eq!(next.accepted.doc.parent, Some(GrainId::of(&base)));
    assert!(next.accepted.doc.sigs.is_empty());

    // A complete snapshot must not import the queue's now-deleted payload.
    // This pins projection independently of the engine's empty-queue drain.
    queue.admit(&next).unwrap();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Delete {
                at: at("f"),
                kind: codec::DeleteKind::File {
                    stage_id: b.files().first().unwrap().entry().unwrap().stage_id,
                },
            },
        )
        .unwrap();
    let complete = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Tree)
        .unwrap()
        .for_complete_commit();
    queue.reserve(&complete).unwrap();
    assert_eq!((complete.files().len(), complete.entries().len()), (0, 0));
    let projection = queue.project(&complete, &[]).unwrap();
    assert_eq!(
        (
            projection.entries().len(),
            projection.changed_payloads().len()
        ),
        (0, 0)
    );
}

#[tokio::test]
async fn every_object_acceptance_barrier_precedes_projection_admission() {
    let remote = Remote::default();
    let (base_bytes, trusted) = base(&remote).await;
    let mut f = Fixture::new();
    let b = capture(&mut f, &base_bytes, b"new bytes");
    let (selected, grains, source) = payload(&b, b"new bytes");
    let mut queue = SyncProjectionQueue::default();
    queue.reserve(&b).unwrap();
    accept_sync_projection(
        &queue,
        &b,
        selected,
        &verified(&base_bytes, &trusted, &empty_tree(), &remote).await,
        &trusted,
        &source,
        |_| Ok(grains.clone()),
        &remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await
    .unwrap();
    let barriers = remote.puts.lock().unwrap().len();
    assert_eq!(
        barriers, 5,
        "missing bin/shard/table/index/sheaf acceptance barrier"
    );
    for failure in 1..=barriers {
        let remote = Remote::default();
        let (base_bytes, trusted) = base(&remote).await;
        *remote.fail.lock().unwrap() = Some(failure);
        let mut f = Fixture::new();
        let b = capture(&mut f, &base_bytes, b"new bytes");
        let (selected, grains, source) = payload(&b, b"new bytes");
        let c = f
            .overlay
            .seal_sync(&mut f.store, &f.owner, SyncTarget::Directory(None))
            .unwrap();
        let mut queue = SyncProjectionQueue::default();
        queue.reserve(&b).unwrap();
        queue.reserve(&c).unwrap();
        assert!(
            accept_sync_projection(
                &queue,
                &b,
                selected,
                &verified(&base_bytes, &trusted, &empty_tree(), &remote).await,
                &trusted,
                &source,
                |_| Ok(grains.clone()),
                &remote,
                now(),
                Policy::default(),
                |_| crate::PublishError::BadPlan,
            )
            .await
            .is_err(),
            "failed barrier granted acceptance capability"
        );
        assert_eq!(remote.puts.lock().unwrap().len(), failure);
        queue.fail(&b).unwrap();
        *remote.fail.lock().unwrap() = None;
        let fallback = accept_sync_projection(
            &queue,
            &c,
            vec![],
            &verified(&base_bytes, &trusted, &empty_tree(), &remote).await,
            &trusted,
            &source,
            |_| Ok(grains.clone()),
            &remote,
            now(),
            Policy::default(),
            |_| crate::PublishError::BadPlan,
        )
        .await
        .unwrap();
        assert!(
            fallback.projection().entries().is_empty(),
            "failed unaccepted capture leaked into later root"
        );
    }
}

#[tokio::test]
async fn stale_base_foreign_payload_corrupt_grain_and_missing_parent_sheaf_refuse() {
    let remote = Remote::default();
    let (base, trusted) = base(&remote).await;
    let mut f = Fixture::new();
    let b = capture(&mut f, &base, b"checked bytes");
    let (selected, grains, mut source) = payload(&b, b"checked bytes");
    let mut queue = SyncProjectionQueue::default();
    queue.reserve(&b).unwrap();
    for mode in 0..4 {
        let mut wrong = selected.clone();
        let mut base_bytes = base.clone();
        if mode == 0 {
            wrong[0].inode += 1;
        }
        if mode == 1 {
            let mut doc = granary_core::root::decode_root(&base).unwrap();
            doc.writer_uuid[0] ^= 1;
            let key = SigningKey::from_seed(&[39; 32]).unwrap();
            let prefix = granary_core::root::signing_prefix_of(&doc).unwrap();
            doc.sigs[0].sig = key.sign(&prefix);
            base_bytes = granary_core::root::encode_root(&doc).unwrap();
        }
        if mode == 2 {
            source.0.values_mut().for_each(|bytes| bytes.push(0));
        }
        if mode == 3 {
            source.0.values_mut().for_each(|bytes| {
                bytes.pop();
            });
            let doc = granary_core::root::decode_root(&base).unwrap();
            remote.meta.lock().unwrap().remove(&doc.sheaf_head);
        }
        assert!(
            accept_sync_projection(
                &queue,
                &b,
                wrong,
                &verified(&base_bytes, &trusted, &empty_tree(), &remote).await,
                &trusted,
                &source,
                |_| Ok(grains.clone()),
                &remote,
                now(),
                Policy::default(),
                |_| crate::PublishError::BadPlan,
            )
            .await
            .is_err(),
            "unverified closure was accepted"
        );
        assert!(
            remote.puts.lock().unwrap().is_empty(),
            "bad closure caused upload"
        );
    }
}

fn rechunk_fixture(
    original: &[u8],
    edits: &[(u64, &[u8])],
) -> (Fixture, SyncBoundary, FileGrains, Objects, ClientMetrics) {
    let mut objects = Objects::default();
    let refs: Vec<_> = granary_core::thresh::grains(original)
        .map(|grain| {
            let bytes = original[grain.offset..grain.offset + grain.length].to_vec();
            let id = GrainId::of(&bytes);
            objects.0.insert(id, bytes);
            GrainRef {
                id,
                unpacked_len: u32::try_from(grain.length).unwrap(),
            }
        })
        .collect();
    let grains = if refs.len() <= manifest::FILE_INLINE_MAX_REFS as usize {
        FileGrains::Inline(refs)
    } else {
        let built = manifest::build_grain_list(&refs).unwrap();
        objects.0.extend(built.nodes);
        FileGrains::Spill {
            grain_count: u32::try_from(refs.len()).unwrap(),
            root: built.root,
        }
    };
    let content =
        GrainId::of(&manifest::node::file_payload(original.len() as u64, &grains).unwrap());
    let entry = OverlayEntry {
        path: vec![name("f")],
        inode: 1,
        kind: OverlayKind::File {
            content: Some(content),
        },
        stage_id: None,
        size: original.len() as u64,
        exec: false,
    };
    let mut source = Source::default();
    source.0.insert(content, original.to_vec());
    let mut f = Fixture::with_base(vec![entry], source);
    f.overlay.config.cap = 268_435_456;
    let stage = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
        .unwrap();
    for (offset, bytes) in edits {
        f.overlay
            .write(&mut f.store, &f.owner, stage, *offset, bytes)
            .unwrap();
    }
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(stage))
        .unwrap();
    (f, b, grains, objects, ClientMetrics::new(&mut Fixed))
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one complete failed overwrite and fallback schedule"
)]
async fn failed_overwrite_retains_previous_durable_payload() {
    let remote = Remote::default();
    let old_grains = FileGrains::Inline(vec![GrainRef {
        id: GrainId::of(b"old"),
        unpacked_len: 3,
    }]);
    let old_content = GrainId::of(&manifest::node::file_payload(3, &old_grains).unwrap());
    let tree = manifest::build_dir(&[manifest::DirEntry {
        name: name("f"),
        kind: manifest::EntryKind::File {
            exec: false,
            size: 3,
            grains: old_grains.clone(),
        },
    }])
    .unwrap();
    let root = tree.root;
    let mut source = Objects(
        tree.nodes
            .into_iter()
            .chain([(GrainId::of(b"old"), b"old".to_vec())])
            .collect(),
    );
    let (base_bytes, trusted) = base_with_manifest(&remote, root, &source).await;
    let mut immutable = Source::default();
    immutable.0.insert(old_content, b"old".to_vec());
    let mut f = Fixture::with_base(
        vec![OverlayEntry {
            path: vec![name("f")],
            inode: 1,
            kind: OverlayKind::File {
                content: Some(old_content),
            },
            stage_id: None,
            size: 3,
            exec: false,
        }],
        immutable,
    );
    f.overlay.journal.lock().unwrap().header.base_root = GrainId::of(&base_bytes);
    let stage = f
        .overlay
        .copy_up(&mut f.store, &f.owner, at("f"), &mut f.source)
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, stage, 0, b"new")
        .unwrap();
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(stage))
        .unwrap();
    let c = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Directory(None))
        .unwrap();
    let (selected, grains, new) = payload(&b, b"new");
    source.0.extend(new.0);
    let mut queue = SyncProjectionQueue::default();
    queue.reserve(&b).unwrap();
    queue.reserve(&c).unwrap();
    *remote.fail.lock().unwrap() = Some(5);
    assert!(
        accept_sync_projection(
            &queue,
            &b,
            selected,
            &verified(&base_bytes, &trusted, &source, &remote).await,
            &trusted,
            &source,
            |_| Ok(grains.clone()),
            &remote,
            now(),
            Policy::default(),
            |_| crate::PublishError::BadPlan,
        )
        .await
        .is_err()
    );
    queue.fail(&b).unwrap();
    *remote.fail.lock().unwrap() = None;
    let fallback = accept_sync_projection(
        &queue,
        &c,
        vec![],
        &verified(&base_bytes, &trusted, &source, &remote).await,
        &trusted,
        &source,
        |_| Ok(old_grains.clone()),
        &remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await
    .unwrap();
    assert_eq!(
        fallback.summary().manifest_root,
        root,
        "failed overwrite displaced durable checkpoint"
    );
    assert_eq!(
        fallback.projection().entries()[0].kind,
        OverlayKind::File {
            content: Some(old_content)
        }
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one nested spilled closure with missing-list control"
)]
async fn spilled_payload_and_nested_manifest_nodes_are_in_accepted_closure() {
    let remote = Remote::default();
    let (base_bytes, trusted) = base(&remote).await;
    let mut f = Fixture::new();
    f.overlay.journal.lock().unwrap().header.base_root = GrainId::of(&base_bytes);
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Create {
                at: at("d"),
                kind: codec::CreateKind::Dir,
            },
        )
        .unwrap();
    let stage = f
        .overlay
        .create_file(
            &mut f.store,
            &f.owner,
            codec::Location {
                parent: codec::Parent::new(vec![name("d")]).unwrap(),
                name: name("f"),
            },
            false,
        )
        .unwrap();
    f.overlay
        .write(&mut f.store, &f.owner, stage, 0, &[7; 129])
        .unwrap();
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(stage))
        .unwrap();
    let refs = vec![
        GrainRef {
            id: GrainId::of(&[7]),
            unpacked_len: 1
        };
        129
    ];
    let list = manifest::build_grain_list(&refs).unwrap();
    let grains = FileGrains::Spill {
        grain_count: 129,
        root: list.root,
    };
    let mut source = Objects(list.nodes.into_iter().collect());
    source.0.insert(GrainId::of(&[7]), vec![7]);
    let content = GrainId::of(&manifest::node::file_payload(129, &grains).unwrap());
    let selected = vec![DurableFile {
        inode: b.files()[0].entry().unwrap().inode,
        size: 129,
        content,
        content_boundary: b.through_seq(),
    }];
    let mut queue = SyncProjectionQueue::default();
    queue.reserve(&b).unwrap();
    let accepted = accept_sync_projection(
        &queue,
        &b,
        selected.clone(),
        &verified(&base_bytes, &trusted, &empty_tree(), &remote).await,
        &trusted,
        &source,
        |_| Ok(grains.clone()),
        &remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await
    .unwrap();
    let packed: BTreeSet<_> = remote
        .bins
        .lock()
        .unwrap()
        .values()
        .flat_map(|bytes| {
            granary_core::binfmt::decode_bin(bytes)
                .unwrap()
                .into_iter()
                .map(|entry| entry.id)
        })
        .collect();
    assert!(
        packed.contains(&list.root),
        "spill metadata omitted from accepted bin closure"
    );
    assert!(packed.contains(&accepted.summary().manifest_root));
    assert_eq!(
        accepted.summary().novel_objects,
        4,
        "nested directory/list/grain closure incomplete"
    );
    queue.admit(&accepted).unwrap();
    let mut missing = source;
    missing.0.remove(&list.root);
    let mut queue = SyncProjectionQueue::default();
    queue.reserve(&b).unwrap();
    assert!(
        accept_sync_projection(
            &queue,
            &b,
            selected,
            &verified(&base_bytes, &trusted, &empty_tree(), &remote).await,
            &trusted,
            &missing,
            |_| Ok(grains.clone()),
            &remote,
            now(),
            Policy::default(),
            |_| crate::PublishError::BadPlan,
        )
        .await
        .is_err(),
        "absent spill list was replaced with full-file work"
    );
}

#[test]
fn projection_queue_rejects_reversed_and_foreign_seals() {
    let mut f = Fixture::new();
    let stage = f.create();
    f.write(stage, b"bytes");
    let first = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(stage))
        .unwrap();
    let second = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(stage))
        .unwrap();
    let mut queue = SyncProjectionQueue::default();
    queue.reserve(&second).unwrap();
    assert!(queue.reserve(&first).is_err());
    assert!(queue.reserve(&second).is_err());
    let mut queue = SyncProjectionQueue::default();
    queue.reserve(&first).unwrap();
    let mut foreign = second.clone();
    foreign.instance[0] ^= 1;
    assert!(
        queue.reserve(&foreign).is_err(),
        "foreign context entered projection queue"
    );
    assert!(queue.fail(&foreign).is_err());
    queue.fail(&first).unwrap();
    assert!(queue.fail(&first).is_err());
}
fn run_rechunk(
    f: &mut Fixture,
    boundary: &SyncBoundary,
    grains: Option<&FileGrains>,
    source: &Objects,
    metrics: &ClientMetrics,
) -> Result<crate::RechunkedFile, crate::CoordinationError> {
    run_rechunk_with_sink(f, boundary, grains, source, metrics, |_, _| Ok(()))
}
fn run_rechunk_with_sink(
    f: &mut Fixture,
    boundary: &SyncBoundary,
    grains: Option<&FileGrains>,
    source: &Objects,
    metrics: &ClientMetrics,
    put: impl FnMut(GrainId, &[u8]) -> Result<(), crate::CoordinationError>,
) -> Result<crate::RechunkedFile, crate::CoordinationError> {
    rechunk_captured(
        &boundary.files()[0],
        grains,
        source,
        |offset, n| {
            let mut bytes = Vec::new();
            let mut at = offset;
            while bytes.len() < n {
                let aligned = at / 65_536 * 65_536;
                let parts = f.overlay.captured_parts(
                    &mut f.store,
                    &f.owner,
                    boundary,
                    &boundary.files()[0],
                    aligned,
                )?;
                let mut block = Vec::new();
                for part in parts {
                    match part {
                        CapturedPart::Dirty {
                            bytes,
                            start,
                            length,
                        } => block.extend_from_slice(&bytes[start..start + length]),
                        CapturedPart::Zero(n) => block.resize(block.len() + n, 0),
                        CapturedPart::Immutable {
                            content,
                            offset,
                            length,
                        } => block.extend(f.source.read_verified(content, offset, length)?),
                    }
                }
                let start = usize::try_from(at - aligned).unwrap();
                let count = (n - bytes.len()).min(block.len() - start);
                bytes.extend_from_slice(&block[start..start + count]);
                at += count as u64;
            }
            Ok(bytes)
        },
        put,
        metrics,
    )
}

#[test]
fn fallback_counter_includes_full_cutter_work_before_sink_failure() {
    let original = vec![1; 4_194_304];
    let changed = vec![2; original.len()];
    let (mut f, b, grains, source, metrics) = rechunk_fixture(&original, &[(0, &changed)]);
    metrics.set_available(crate::MetricsGroup::Sync, true);
    let mut puts = 0;
    let result = run_rechunk_with_sink(&mut f, &b, Some(&grains), &source, &metrics, |_, _| {
        puts += 1;
        if puts == 2 {
            Err(crate::CoordinationError::Refused("SyncObjectSink"))
        } else {
            Ok(())
        }
    });
    assert!(result.is_err());
    assert_eq!(puts, 2, "sink failed before fixture reached captured EOF");
    assert!(
        metrics
            .snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap()
            .contains("granary_client_sync_rechunk_fallbacks_total 1\n"),
        "completed fallback disappeared with sink refusal"
    );
}

#[tokio::test]
async fn orphan_grains_are_accepted_without_a_root_leaf() {
    let remote = Remote::default();
    let (base_bytes, trusted) = base(&remote).await;
    let mut f = Fixture::new();
    f.overlay.journal.lock().unwrap().header.base_root = GrainId::of(&base_bytes);
    f.overlay.config.cap = 268_435_456;
    let stage = f.create();
    f.write(stage, &vec![7; 4_194_304]);
    f.overlay
        .open_stage(&mut f.store, &f.owner, &[name("f")])
        .unwrap();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Delete {
                at: at("f"),
                kind: codec::DeleteKind::File {
                    stage_id: Some(stage),
                },
            },
        )
        .unwrap();
    let b = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(stage))
        .unwrap();
    assert!(b.files()[0].entry().is_none());
    let data = vec![7; 2_097_152];
    let id = GrainId::of(&data);
    let grains = FileGrains::Inline(vec![
        GrainRef {
            id,
            unpacked_len: 2_097_152,
        };
        2
    ]);
    let source = Objects(BTreeMap::from([(id, data)]));
    let mut queue = SyncProjectionQueue::default();
    queue.reserve(&b).unwrap();
    assert!(
        accept_sync_projection(
            &queue,
            &b,
            vec![],
            &verified(&base_bytes, &trusted, &empty_tree(), &remote).await,
            &trusted,
            &source,
            |_| Err(crate::PublishError::BadPlan),
            &remote,
            now(),
            Policy::default(),
            |_| crate::PublishError::BadPlan,
        )
        .await
        .is_err(),
        "missing orphan payload accepted"
    );
    let selection = crate::SyncObjectSelection {
        selected: vec![],
        orphaned: BTreeMap::from([(0, grains)]),
    };
    let accepted = accept_sync_projection(
        &queue,
        &b,
        selection,
        &verified(&base_bytes, &trusted, &empty_tree(), &remote).await,
        &trusted,
        &source,
        |_| Err(crate::PublishError::BadPlan),
        &remote,
        now(),
        Policy::default(),
        |_| crate::PublishError::BadPlan,
    )
    .await
    .expect("orphan repeated grains were not deduplicated");
    assert!(accepted.projection().entries().is_empty());
    let packed: BTreeSet<_> = remote
        .bins
        .lock()
        .unwrap()
        .values()
        .flat_map(|bytes| {
            granary_core::binfmt::decode_bin(bytes)
                .unwrap()
                .into_iter()
                .map(|entry| entry.id)
        })
        .collect();
    assert!(
        packed.contains(&id),
        "orphan grain omitted from accepted closure"
    );
    assert_eq!(accepted.summary().novel_objects, 1);
}

#[test]
fn checkpoint_authentication_and_fallback_counter_are_not_dedup_observations() {
    let original = vec![1; 4_194_304];
    let changed = vec![2; original.len()];
    let (mut f, b, grains, source, metrics) = rechunk_fixture(&original, &[(0, &changed)]);
    metrics.set_available(crate::MetricsGroup::Sync, true);
    assert!(
        run_rechunk(&mut f, &b, None, &source, &metrics).is_err(),
        "missing checkpoint triggered whole-file fallback"
    );
    let mut wrong = grains.clone();
    if let FileGrains::Inline(ref mut refs) = wrong {
        refs[0].id = GrainId::of(b"foreign");
    }
    assert!(
        run_rechunk(&mut f, &b, Some(&wrong), &source, &metrics).is_err(),
        "foreign checkpoint accepted"
    );
    let output = run_rechunk(&mut f, &b, Some(&grains), &source, &metrics).unwrap();
    assert!(output.stats.fallback);
    assert!(
        run_rechunk(&mut f, &b, Some(&grains), &source, &metrics)
            .unwrap()
            .stats
            .fallback
    );
    assert!(
        metrics
            .snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap()
            .contains("granary_client_sync_rechunk_fallbacks_total 1\n")
    );
    let (mut f, b, grains, source, metrics) = rechunk_fixture(&original, &[(2_097_155, b"x")]);
    metrics.set_available(crate::MetricsGroup::Sync, true);
    let output = run_rechunk(&mut f, &b, Some(&grains), &source, &metrics).unwrap();
    assert!(!output.stats.fallback);
    assert!(
        metrics
            .snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap()
            .contains("granary_client_sync_rechunk_fallbacks_total 0\n")
    );
    assert_eq!(
        output.stats.cutter_bytes, 2_097_152,
        "unchanged prefix was recut"
    );
    let mut expected = original;
    expected[2_097_155] = b'x';
    assert_eq!(
        output.content,
        GrainId::of(
            &manifest::node::file_payload(
                expected.len() as u64,
                &FileGrains::Inline(
                    granary_core::thresh::grains(&expected)
                        .map(|grain| GrainRef {
                            id: GrainId::of(&expected[grain.offset..grain.offset + grain.length]),
                            unpacked_len: u32::try_from(grain.length).unwrap(),
                        })
                        .collect()
                )
            )
            .unwrap()
        )
    );
}

#[tokio::test]
async fn corrupt_source_never_uploads_novel_objects() {
    let remote = Remote::default();
    let grain = GrainId::of(b"expected");
    let tree = manifest::build_dir(&[manifest::DirEntry {
        name: name("f"),
        kind: manifest::EntryKind::File {
            exec: false,
            size: 8,
            grains: FileGrains::Inline(vec![GrainRef {
                id: grain,
                unpacked_len: 8,
            }]),
        },
    }])
    .unwrap();
    let root = tree.root;
    let mut source = Objects(tree.nodes.into_iter().collect());
    source.0.insert(grain, b"tampered".to_vec());
    assert!(
        crate::publish::accept_from_state(
            &remote,
            &source,
            root,
            crate::HarvestStats::default(),
            &VolumeName::from_bytes(b"v").unwrap(),
            now(),
            Policy::default(),
            crate::publish::RemoteState::empty()
        )
        .await
        .is_err(),
        "corrupt novel object granted acceptance capability"
    );
    assert!(remote.puts.lock().unwrap().is_empty());
}

#[test]
fn rechunk_reads_sealed_version_while_later_writes_progress() {
    let original = vec![1; 2_097_182];
    let (mut f, b, grains, source, metrics) = rechunk_fixture(&original, &[(2_097_155, b"a")]);
    let stage = b.files()[0].capture_token().unwrap().stage_id();
    f.overlay
        .write(&mut f.store, &f.owner, stage, 2_097_155, b"b")
        .unwrap();
    let output = run_rechunk(&mut f, &b, Some(&grains), &source, &metrics).unwrap();
    let mut expected = original;
    expected[2_097_155] = b'a';
    let refs = granary_core::thresh::grains(&expected)
        .map(|grain| GrainRef {
            id: GrainId::of(&expected[grain.offset..grain.offset + grain.length]),
            unpacked_len: u32::try_from(grain.length).unwrap(),
        })
        .collect();
    assert_eq!(
        output.content,
        GrainId::of(
            &manifest::node::file_payload(expected.len() as u64, &FileGrains::Inline(refs))
                .unwrap()
        ),
        "post-seal writer leaked into re-chunked payload"
    );
    assert_eq!(
        f.io.bytes(&f.overlay.stage_path(stage))[codec::STAGING_HEADER_LEN + 2_097_155],
        b'b'
    );
}
