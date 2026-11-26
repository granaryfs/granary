// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use granary_client::{ResolveTarget, RootVerifier, resolve_at_verified};
use granary_core::manifest::{
    DirEntry, EntryKind as ManifestEntryKind, FileGrains, GrainRef, Name,
};
use granary_core::root::{RootDoc, RootSig, Timestamp, VolumeName};
use granary_core::{binfmt, binmap, manifest, root, sheaf};
use granary_store::crypto::SigningKey;
use tokio::sync::Notify;

struct ClientSeam {
    service: GrainService<FakeSeam>,
    arrived: AtomicUsize,
    release: Notify,
}

impl ClientSeam {
    async fn get(&self, path: &str, range: Option<String>) -> Response<Full<Bytes>> {
        let mut req = request(Method::GET, path, Some(DA), empty());
        if let Some(range) = range {
            req.headers_mut()
                .insert(RANGE, HeaderValue::from_str(&range).unwrap());
        }
        through(&self.service, req).await
    }
}

impl RootStore for ClientSeam {
    async fn put_root(&self, v: &str, n: u64, b: Vec<u8>) -> Result<(), RootStoreError> {
        self.service.store.put_root(v, n, b).await
    }
    async fn get_root(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        let response = self.get(&format!("/volume/{v}/root/{n:020}"), None).await;
        assert_eq!(response.status(), 200);
        Ok(Some(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        ))
    }
    async fn read_hint(&self, v: &str, t: Option<&HintToken>) -> Result<HintRead, RootStoreError> {
        self.service.store.read_hint(v, t).await
    }
    async fn write_hint(&self, v: &str, n: u64) -> Result<(), RootStoreError> {
        self.service.store.write_hint(v, n).await
    }
    async fn max_seq(&self, v: &str) -> Result<Option<u64>, RootStoreError> {
        self.service.store.max_seq(v).await
    }

    async fn max_seq_above(&self, v: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        self.service.store.max_seq_above(v, floor).await
    }
}
impl BinStore for ClientSeam {
    async fn put_meta(&self, v: &str, id: &GrainId, b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.service.store.put_meta(v, id, b).await
    }
    async fn get_meta(&self, v: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        let response = self.get(&format!("/volume/{v}/meta/{id}"), None).await;
        assert_eq!(response.status(), 200);
        Ok(response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec())
    }
    async fn put_bin(&self, d: &[u8; 32], b: Vec<u8>) -> Result<bool, RootStoreError> {
        self.service.store.put_bin(d, b).await
    }
    async fn get_bin_range(&self, d: &[u8; 32], o: u64, n: u32) -> Result<Vec<u8>, RootStoreError> {
        let response = self
            .get(
                &format!("/bin/{}", hex64(d)),
                Some(format!("bytes={o}-{}", o + u64::from(n) - 1)),
            )
            .await;
        assert_eq!(response.status(), 206);
        if n > 2 * 1024 * 1024 {
            // Retain each answer until all 32 client fetches exist. The server
            // has finished its bounded dispatch; this is response delivery.
            let notified = self.release.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.arrived.fetch_add(1, Ordering::SeqCst) + 1 == 32 {
                self.release.notify_waiters();
            }
            notified.await;
        }
        Ok(response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec())
    }
}

async fn meta(store: &FakeSeam, bytes: Vec<u8>) -> GrainId {
    let id = GrainId::of(&bytes);
    store.put_meta("v", &id, bytes).await.unwrap();
    id
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one signed tree and the full-window delivery barrier jointly witness cold resolve completion"
)]
async fn defaults_full_window_cold_resolve() {
    let fx = Fx::new("controls-cold-resolve");
    let held = fx.fill_cap();
    let frames: Vec<_> = (1..=32).map(|n| raw_frame(2 * 1024 * 1024, n)).collect();
    let refs = frames
        .iter()
        .map(|f| GrainRef {
            id: f.id,
            unpacked_len: 2 * 1024 * 1024,
        })
        .collect();
    let dir = manifest::build_dir(&[DirEntry {
        name: Name::new(b"full.bin".to_vec()).unwrap(),
        kind: ManifestEntryKind::File {
            exec: false,
            size: 64 * 1024 * 1024,
            grains: FileGrains::Inline(refs),
        },
    }])
    .unwrap();
    let mut frames = frames;
    let mut codec = granary_store::codec::GrainCodec::new().unwrap();
    for (id, bytes) in &dir.nodes {
        frames.push(binfmt::PackedFrame {
            id: *id,
            frame: codec.compress_grain(bytes).unwrap(),
        });
    }
    let bin = binfmt::encode_bin(&frames).unwrap();
    let mut entries: Vec<_> = binfmt::decode_bin(&bin)
        .unwrap()
        .into_iter()
        .map(|entry| binmap::ShardEntry {
            id: entry.id,
            bin_ordinal: 0,
            offset: entry.offset,
            comp_len: entry.comp_len,
        })
        .collect();
    entries.sort_by_key(|entry| entry.id);
    let digest = *GrainId::of(&bin).digest();
    let store = &fx.service.store;
    store.put_bin(&digest, bin).await.unwrap();
    let shard = meta(store, binmap::encode_shard(&entries).unwrap()).await;
    let table = meta(store, binmap::encode_bin_table(&[digest]).unwrap()).await;
    let index = meta(
        store,
        binmap::encode_binmap_index(0, table, &[shard]).unwrap(),
    )
    .await;
    let stamp = Timestamp { secs: 0, nanos: 0 };
    let sheaf = meta(
        store,
        sheaf::encode_sheaf(&sheaf::SheafDoc {
            parent: None,
            manifest_root: dir.root,
            timestamp: stamp,
            ops: vec![sheaf::SheafOp::PublishTree],
        })
        .unwrap(),
    )
    .await;
    let key = SigningKey::from_seed(&[7; 32]).unwrap();
    let mut doc = RootDoc {
        volume: VolumeName::new("v".into()).unwrap(),
        seq: 1,
        parent: None,
        writer_uuid: [0; 16],
        epoch: 1,
        timestamp: stamp,
        chunker_spec: granary_core::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: dir.root,
        binmap_index: index,
        sheaf_head: sheaf,
        sigs: vec![RootSig {
            key_id: key.key_id(),
            sig: [0; 64],
        }],
    };
    let unsigned = root::encode_root(&doc).unwrap();
    doc.sigs[0].sig = key.sign(root::signed_prefix(&unsigned).unwrap());
    store
        .put_root("v", 1, root::encode_root(&doc).unwrap())
        .await
        .unwrap();
    let client = ClientSeam {
        service: fx.service.clone(),
        arrived: AtomicUsize::new(0),
        release: Notify::new(),
    };
    let before = fx.reader.snapshot().sequence;
    let mut emitted = std::collections::BTreeSet::new();
    let result = timeout(
        Duration::from_secs(30),
        resolve_at_verified(
            &client,
            "v",
            1,
            &RootVerifier::trusting(*key.public_key()).unwrap(),
            None,
            ResolveTarget::WholeTree,
            &mut |id, bytes| {
                assert_eq!(id, GrainId::of(bytes), "verified content reaches the sink");
                if bytes.len() == 2 * 1024 * 1024 {
                    assert!(emitted.insert(id));
                }
                Ok(())
            },
        ),
    )
    .await
    .expect("the full client window must complete")
    .unwrap();
    assert_eq!(result.seq, 1);
    assert_eq!(emitted.len(), 32, "every content grain was emitted");
    assert_eq!(
        client.arrived.load(Ordering::SeqCst),
        32,
        "all 32 calls held together"
    );
    assert_eq!(
        emitted.len() * 2 * 1024 * 1024,
        64 * 1024 * 1024,
        "the full decompressed byte window was exercised"
    );
    assert_eq!(fx.controls.in_flight(A), 4);
    assert_eq!(
        fx.reader.snapshot().sequence,
        before,
        "cold resolve never consults enrollment"
    );
    drop(held);
}
