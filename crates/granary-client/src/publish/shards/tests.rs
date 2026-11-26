// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::{
    root::{self, RootDoc, RootSig, Timestamp},
    rootstore::RootStoreError,
};
use granary_store::crypto::SigningKey;
use std::{
    future::Future,
    sync::{Mutex, atomic::AtomicUsize},
    task::{Context, Poll, Waker},
};

#[derive(Default)]
struct Memory {
    meta: Mutex<BTreeMap<GrainId, Vec<u8>>>,
    reads: Mutex<Vec<(GrainId, usize)>>,
    puts: Mutex<Vec<GrainId>>,
    fail_at: AtomicUsize,
    hold_table: AtomicBool,
    assert_memo: Mutex<Option<Arc<Exhaustion>>>,
}
impl BinStore for Memory {
    async fn get_meta(&self, _: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        let bytes = self
            .meta
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(RootStoreError::NotFound)?;
        let (kind, _) = granary_core::encoding::open_envelope(&bytes).unwrap();
        if kind == granary_core::encoding::ObjectType::BinTable
            && self.hold_table.load(Ordering::Acquire)
        {
            std::future::pending::<()>().await;
        }
        if kind == granary_core::encoding::ObjectType::BinmapShard
            && let Some(memo) = self.assert_memo.lock().unwrap().as_ref()
        {
            assert!(
                memo.exhausted.load(Ordering::Acquire),
                "policy floor was not decided before the first shard GET"
            );
        }
        let mut reads = self.reads.lock().unwrap();
        reads.push((*id, bytes.len()));
        if self.fail_at.load(Ordering::Acquire) == reads.len() {
            return Err(RootStoreError::Backend("unavailable".into()));
        }
        Ok(bytes)
    }
    async fn put_meta(
        &self,
        _: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        self.puts.lock().unwrap().push(*id);
        Ok(self.meta.lock().unwrap().insert(*id, bytes).is_none())
    }
    async fn put_bin(&self, _: &[u8; 32], _: Vec<u8>) -> Result<bool, RootStoreError> {
        panic!("preflight uploaded a bin")
    }
    async fn get_bin_range(&self, _: &[u8; 32], _: u64, _: u32) -> Result<Vec<u8>, RootStoreError> {
        panic!("shard loader fetched a bin")
    }
}

fn entry(id: GrainId, ordinal: u32) -> ShardEntry {
    ShardEntry {
        id,
        bin_ordinal: ordinal,
        offset: 512,
        comp_len: 32,
    }
}
fn ids(count: u32) -> Vec<GrainId> {
    (0..count).map(|n| GrainId::of(&n.to_le_bytes())).collect()
}
fn state_at(width: u8, entries: &[ShardEntry]) -> State {
    let mut state = State::from_full(RemoteState::empty());
    state.prefix_bits = width;
    state.bins = vec![[7; 32]];
    let table = binmap::encode_bin_table(&state.bins).unwrap();
    let table_id = GrainId::of(&table);
    state.table = Some((table_id, table));
    state.loaded.clear();
    for at in 0..1 << width {
        state.loaded.insert(at, vec![]);
    }
    for entry in entries {
        state
            .loaded
            .get_mut(&binmap::shard_for(&entry.id, width))
            .unwrap()
            .push(*entry);
    }
    for bucket in state.loaded.values_mut() {
        bucket.sort_unstable_by_key(|entry| entry.id);
    }
    state.prior_shards = state
        .loaded
        .values()
        .map(|bucket| GrainId::of(&binmap::encode_shard(bucket).unwrap()))
        .collect();
    let index = binmap::encode_binmap_index(width, table_id, &state.prior_shards).unwrap();
    state.index_id = Some(GrainId::of(&index));
    state.index_bytes = Some(index);
    state
}
fn install(state: &State) -> (Memory, VolumeName, Vec<u8>, TrustedKeys) {
    let memory = Memory::default();
    let mut meta = memory.meta.lock().unwrap();
    let (table_id, table) = state.table.as_ref().unwrap();
    meta.insert(*table_id, table.clone());
    meta.insert(state.index_id.unwrap(), state.index_bytes.clone().unwrap());
    for (at, entries) in &state.loaded {
        meta.insert(
            state.prior_shards[*at],
            binmap::encode_shard(entries).unwrap(),
        );
    }
    drop(meta);
    let volume = VolumeName::from_bytes(b"v").unwrap();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let mut doc = RootDoc {
        volume: volume.clone(),
        seq: 1,
        parent: None,
        writer_uuid: [61; 16],
        epoch: 1,
        timestamp: Timestamp {
            secs: 1000,
            nanos: 0,
        },
        chunker_spec: granary_core::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: GrainId::of(b"manifest"),
        binmap_index: state.index_id.unwrap(),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![],
    };
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
    });
    (
        memory,
        volume,
        root::encode_root(&doc).unwrap(),
        TrustedKeys::new([*key.public_key()]).unwrap(),
    )
}
async fn load(
    memory: &Memory,
    volume: &VolumeName,
    bytes: &[u8],
    keys: &TrustedKeys,
    policy: Policy,
    memo: Arc<Exhaustion>,
) -> State {
    State::load(memory, volume, bytes, keys, policy, false, memo)
        .await
        .unwrap()
}
fn relation(state: &State, built: &Build) -> BTreeMap<GrainId, ([u8; 32], u64, u32)> {
    let index = binmap::decode_binmap_index(&built.index_bytes).unwrap();
    let table = binmap::decode_bin_table(&built.table_bytes).unwrap();
    let mut result = BTreeMap::new();
    for (at, id) in index.shards.iter().enumerate() {
        let entries = if let Some((stored, bytes)) = built.shards.get(&at) {
            assert_eq!(stored, id);
            binmap::decode_shard(bytes).unwrap()
        } else {
            assert_eq!(state.prior_shards[at], *id);
            state.loaded[&at].clone()
        };
        binmap::validate_routing(&entries, index.prefix_bits, at).unwrap();
        binmap::validate_ordinals(&entries, u32::try_from(table.len()).unwrap()).unwrap();
        for entry in entries {
            assert!(
                result
                    .insert(
                        entry.id,
                        (
                            table[entry.bin_ordinal as usize],
                            entry.offset,
                            entry.comp_len
                        )
                    )
                    .is_none()
            );
        }
    }
    result
}

#[tokio::test]
async fn shard_equivalence_corpus() {
    let original = ids(24)
        .into_iter()
        .map(|id| entry(id, 0))
        .collect::<Vec<_>>();
    let new = ids(48)
        .into_iter()
        .skip(24)
        .map(|id| entry(id, 1))
        .collect::<Vec<_>>();
    let mut cases = 0;
    for width in [0, 1, 8, 12] {
        for additions in [vec![], new[..1].to_vec(), new.clone()] {
            let full = state_at(width, &original);
            let (remote, volume, bytes, keys) = install(&full);
            let mut partial = load(
                &remote,
                &volume,
                &bytes,
                &keys,
                Policy::default(),
                Arc::default(),
            )
            .await;
            // All-known and mixed-known candidates, with dedup before selection.
            let candidates: Vec<_> = original
                .iter()
                .chain(additions.iter())
                .map(|e| e.id)
                .collect();
            let novel = partial.select(&remote, "v", &candidates).await.unwrap();
            assert_eq!(novel, additions.iter().map(|e| e.id).collect::<Vec<_>>());
            let bins = if additions.is_empty() {
                full.bins.clone()
            } else {
                vec![[7; 32], [8; 32]]
            };
            let a = build(&partial, &bins, &additions, Policy::default()).unwrap();
            let b = build(&full, &bins, &additions, Policy::default()).unwrap();
            assert_eq!(a.index_bytes, b.index_bytes);
            assert_eq!(a.table_bytes, b.table_bytes);
            assert_eq!(relation(&full, &a), relation(&full, &b));
            for (at, (_, shard)) in &b.shards {
                let partial_id = binmap::decode_binmap_index(&a.index_bytes).unwrap().shards[*at];
                assert_eq!(partial_id, GrainId::of(shard));
            }
            let token = verify(
                &partial,
                &bins,
                &additions,
                &candidates,
                Policy::default(),
                a,
            )
            .unwrap();
            assert!(
                token.complete.is_none(),
                "partial state became a complete-map witness"
            );
            assert_eq!(
                token.work.encoded.len(),
                additions
                    .iter()
                    .map(|e| binmap::shard_for(&e.id, width))
                    .collect::<BTreeSet<_>>()
                    .len()
            );
            verify(&full, &bins, &additions, &candidates, Policy::default(), b).unwrap();
            cases += 1;
        }
    }
    assert_eq!(cases, 12);
    // Digest MSBs differ even though every encoded id has the same tag.
    let mut raw = GrainId::of(b"vector").to_bytes();
    raw[1] = 0x80;
    raw[2] = 0x10;
    let id = GrainId::from_bytes(&raw).unwrap();
    assert_eq!(binmap::shard_for(&id, 1), 1);
    assert_eq!(binmap::shard_for(&id, 8), 128);
    assert_eq!(binmap::shard_for(&id, 12), 2049);
}

#[tokio::test]
async fn sync_keeps_base_width_across_target() {
    let original: Vec<_> = ids(21_399).into_iter().map(|id| entry(id, 0)).collect();
    let full = state_at(0, &original);
    let (remote, volume, bytes, keys) = install(&full);
    let mut partial = load(
        &remote,
        &volume,
        &bytes,
        &keys,
        Policy::default(),
        Arc::default(),
    )
    .await;
    let added = entry(GrainId::of(b"across target"), 0);
    partial.select(&remote, "v", &[added.id]).await.unwrap();
    let a = build(&partial, &partial.bins, &[added], Policy::default()).unwrap();
    let b = build(&full, &full.bins, &[added], Policy::default()).unwrap();
    assert_eq!(a.prefix_bits, 0, "normal sync widened at the policy target");
    assert_eq!(partial.work.fetched.len(), 1);
    assert_eq!(b.prefix_bits, 1);
    assert_ne!(a.index_id, b.index_id);
    let mut doc = root::decode_root(&bytes).unwrap();
    doc.seq += 1;
    doc.parent = Some(GrainId::of(&bytes));
    doc.epoch += 1;
    let sheaf = granary_core::sheaf::encode_sheaf(&granary_core::sheaf::SheafDoc {
        parent: Some(doc.sheaf_head),
        manifest_root: doc.manifest_root,
        timestamp: doc.timestamp,
        ops: vec![granary_core::sheaf::SheafOp::PublishTree],
    })
    .unwrap();
    doc.sheaf_head = GrainId::of(&sheaf);
    doc.binmap_index = a.index_id;
    let partial_root = root::encode_root(&doc).unwrap();
    doc.binmap_index = b.index_id;
    assert_ne!(partial_root, root::encode_root(&doc).unwrap());
    assert_eq!(a.table_bytes, b.table_bytes);
    assert_eq!(relation(&full, &a), relation(&full, &b));
    verify(
        &partial,
        &partial.bins,
        &[added],
        &[added.id],
        Policy::default(),
        a,
    )
    .unwrap();
    verify(
        &full,
        &full.bins,
        &[added],
        &[added.id],
        Policy::default(),
        b,
    )
    .unwrap();
}

#[tokio::test]
async fn bad_final_bytes_never_get_an_upload_capability() {
    for full in [false, true] {
        for corruption in [
            "wrong slot",
            "dropped entry",
            "renumbered table",
            "omitted addition",
        ] {
            let old = [entry(GrainId::of(b"old"), 0)];
            let new = [entry(GrainId::of(b"new"), 1)];
            let mut state = state_at(8, &old);
            state.full = full;
            let remote = Memory::default();
            if !full {
                state
                    .loaded
                    .entry(binmap::shard_for(&new[0].id, 8))
                    .or_default();
            }
            let bins = [[7; 32], [8; 32]];
            let mut built = build(&state, &bins, &new, Policy::default()).unwrap();
            // The control itself always injects bad bytes before verification.
            let at = binmap::shard_for(&new[0].id, 8);
            match corruption {
                "wrong slot" => {
                    let mut index = binmap::decode_binmap_index(&built.index_bytes).unwrap();
                    index.shards.swap(at, (at + 1) % 256);
                    built.index_bytes =
                        binmap::encode_binmap_index(8, built.table_id, &index.shards).unwrap();
                    built.index_id = GrainId::of(&built.index_bytes);
                }
                "renumbered table" => {
                    built.table_bytes = binmap::encode_bin_table(&[[8; 32], [7; 32]]).unwrap();
                    built.table_id = GrainId::of(&built.table_bytes);
                    let index = binmap::decode_binmap_index(&built.index_bytes).unwrap();
                    built.index_bytes =
                        binmap::encode_binmap_index(8, built.table_id, &index.shards).unwrap();
                    built.index_id = GrainId::of(&built.index_bytes);
                }
                _ => {
                    let victim = if corruption == "dropped entry" {
                        binmap::shard_for(&old[0].id, 8)
                    } else {
                        at
                    };
                    let empty = binmap::encode_shard(&[]).unwrap();
                    let id = GrainId::of(&empty);
                    built.shards.insert(victim, (id, empty));
                    let mut index = binmap::decode_binmap_index(&built.index_bytes).unwrap();
                    index.shards[victim] = id;
                    built.index_bytes =
                        binmap::encode_binmap_index(8, built.table_id, &index.shards).unwrap();
                    built.index_id = GrainId::of(&built.index_bytes);
                }
            }
            let outcome = match verify(
                &state,
                &bins,
                &new,
                &[old[0].id, new[0].id],
                Policy::default(),
                built,
            ) {
                Ok(token) => token.upload(&remote, "v").await.map(|_| ()),
                Err(error) => Err(error),
            };
            assert!(
                matches!(outcome, Err(PublishError::BinmapConstruction)),
                "bad final bytes reached acceptance: full={full}, {corruption}"
            );
            assert!(
                remote.puts.lock().unwrap().is_empty(),
                "verification failure uploaded metadata"
            );
        }
    }
}

#[test]
fn empty_additions_with_appended_bins_rebuilds_index() {
    let old = entry(GrainId::of(b"old"), 0);
    for full in [false, true] {
        let mut state = state_at(8, &[old]);
        state.full = full;
        let unchanged = build(&state, &state.bins, &[], Policy::default()).unwrap();
        assert_eq!(unchanged.index_bytes, *state.index_bytes.as_ref().unwrap());
        let mut bins = state.bins.clone();
        bins.push([8; 32]);
        let built = build(&state, &bins, &[], Policy::default()).unwrap();
        let index = binmap::decode_binmap_index(&built.index_bytes).unwrap();
        assert_eq!(index.bin_table, built.table_id, "index names the old table");
        assert_eq!(binmap::decode_bin_table(&built.table_bytes).unwrap(), bins);
        assert_eq!(index.shards, state.prior_shards);
        assert_ne!(built.index_id, state.index_id.unwrap());
        verify(&state, &bins, &[], &[old.id], Policy::default(), built).unwrap();
    }
}

#[test]
fn unloaded_membership_is_not_absence() {
    let mut state = state_at(8, &[]);
    state.full = false;
    state.loaded.clear();
    assert!(matches!(
        state.lookup(&GrainId::of(b"candidate")),
        Err(PublishError::BinmapConstruction)
    ));
}

#[tokio::test]
async fn policy_floor_precedes_shard_get_and_memo_survives_refusal_and_cancel() {
    let original = state_at(1, &[entry(GrainId::of(b"old"), 0)]);
    for cancel in [false, true] {
        let (remote, volume, bytes, keys) = install(&original);
        let memo = Arc::<Exhaustion>::default();
        *remote.assert_memo.lock().unwrap() = Some(memo.clone());
        if cancel {
            remote.hold_table.store(true, Ordering::Release);
        } else {
            remote.fail_at.store(3, Ordering::Release);
        }
        {
            let mut work = std::pin::pin!(State::load(
                &remote,
                &volume,
                &bytes,
                &keys,
                Policy { min_prefix_bits: 8 },
                false,
                memo.clone()
            ));
            let result = work.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            if cancel {
                assert!(matches!(result, Poll::Pending));
            } else {
                assert!(matches!(result, Poll::Ready(Err(PublishError::Remote(_)))));
            }
        }
        assert!(
            memo.exhausted.load(Ordering::Acquire),
            "first trigger was lost on refusal/cancellation"
        );
        remote.hold_table.store(false, Ordering::Release);
        remote.fail_at.store(0, Ordering::Release);
        let second = load(
            &remote,
            &volume,
            &bytes,
            &keys,
            Policy::default(),
            memo.clone(),
        )
        .await;
        assert!(second.full);
        assert!(second.work.memo_bypass);
        assert!(!second.work.first_trigger);
        assert_eq!(memo.counts(), (1, 1));
        let reset = load(
            &remote,
            &volume,
            &bytes,
            &keys,
            Policy::default(),
            Arc::default(),
        )
        .await;
        assert!(
            !reset.full,
            "a newly validated base did not reset exhaustion"
        );
    }
}

#[tokio::test]
async fn overflow_completes_from_validated_routes_without_duplicate_get_or_charge() {
    let mut all = ids(binmap::SHARD_MAX_ENTRIES * 3)
        .into_iter()
        .filter(|id| binmap::shard_for(id, 1) == 0);
    let old: Vec<_> = all
        .by_ref()
        .take(binmap::SHARD_MAX_ENTRIES as usize)
        .map(|id| entry(id, 0))
        .collect();
    assert_eq!(old.len(), binmap::SHARD_MAX_ENTRIES as usize);
    let addition = entry(all.next().unwrap(), 0);
    let original = state_at(1, &old);
    let (remote, volume, bytes, keys) = install(&original);
    let memo = Arc::<Exhaustion>::default();
    let mut state = load(
        &remote,
        &volume,
        &bytes,
        &keys,
        Policy::default(),
        memo.clone(),
    )
    .await;
    assert_eq!(
        state.select(&remote, "v", &[addition.id]).await.unwrap(),
        vec![addition.id]
    );
    assert!(state.full);
    assert!(memo.exhausted.load(Ordering::Acquire));
    assert!(state.work.first_trigger);
    assert_eq!(
        state
            .work
            .fetched
            .iter()
            .map(|(at, _, _)| *at)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(
        remote
            .reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| *id == original.prior_shards[0])
            .count(),
        1
    );
    assert!(
        remote.puts.lock().unwrap().is_empty(),
        "overflow preflight uploaded bins or metadata"
    );
    let built = build(&state, &state.bins, &[addition], Policy::default()).unwrap();
    assert!(built.prefix_bits > 1);
    let reference = build(&original, &original.bins, &[addition], Policy::default()).unwrap();
    assert_eq!(built.index_bytes, reference.index_bytes);
    assert_eq!(built.table_bytes, reference.table_bytes);
    assert_eq!(built.shards, reference.shards);
    verify(
        &state,
        &state.bins,
        &[addition],
        &[addition.id],
        Policy::default(),
        built,
    )
    .unwrap();
    let second = load(&remote, &volume, &bytes, &keys, Policy::default(), memo).await;
    assert!(second.work.memo_bypass);
}

#[tokio::test]
async fn exact_cap_stays_partial_and_width_ceiling_skew_refuses() {
    let skew: Vec<_> = ids(binmap::SHARD_MAX_ENTRIES)
        .into_iter()
        .map(|id| {
            let mut raw = id.to_bytes();
            raw[1] = 0;
            raw[2] &= 15;
            entry(GrainId::from_bytes(&raw).unwrap(), 0)
        })
        .collect();
    let mut state = state_at(12, &skew[..skew.len() - 1]);
    state.full = false;
    let (remote, volume, bytes, keys) = install(&state);
    let mut partial = load(
        &remote,
        &volume,
        &bytes,
        &keys,
        Policy::default(),
        Arc::default(),
    )
    .await;
    partial
        .select(&remote, "v", &[skew.last().unwrap().id])
        .await
        .unwrap();
    assert!(!partial.full);
    let built = build(
        &partial,
        &partial.bins,
        &[*skew.last().unwrap()],
        Policy::default(),
    )
    .unwrap();
    verify(
        &partial,
        &partial.bins,
        &[*skew.last().unwrap()],
        &[skew.last().unwrap().id],
        Policy::default(),
        built,
    )
    .unwrap();
    let full = state_at(12, &skew);
    let mut raw = GrainId::of(b"one over cap").to_bytes();
    raw[1] = 0;
    raw[2] &= 15;
    let added = entry(GrainId::from_bytes(&raw).unwrap(), 0);
    assert!(matches!(
        build(&full, &full.bins, &[added], Policy::default()),
        Err(PublishError::EncodeBinmap(_))
    ));
}

#[tokio::test]
async fn table_reuse_append_dedup_and_cap() {
    let state = state_at(8, &[]);
    let (remote, _, _, _) = install(&state);
    let built = build(&state, &state.bins, &[], Policy::default()).unwrap();
    let token = verify(&state, &state.bins, &[], &[], Policy::default(), built).unwrap();
    token.upload(&remote, "v").await.unwrap();
    assert!(
        remote.puts.lock().unwrap().is_empty(),
        "unchanged table or index was PUT"
    );
    let addition = entry(GrainId::of(b"already stored bin frame"), 0);
    let built = build(&state, &state.bins, &[addition], Policy::default()).unwrap();
    let token = verify(
        &state,
        &state.bins,
        &[addition],
        &[addition.id],
        Policy::default(),
        built,
    )
    .unwrap();
    token.upload(&remote, "v").await.unwrap();
    assert!(remote.puts.lock().unwrap().len() >= 2);
    assert!(
        !remote
            .puts
            .lock()
            .unwrap()
            .contains(&state.table.as_ref().unwrap().0),
        "a new mapping to an existing ordinal PUT the unchanged table"
    );
    assert!(binmap::encode_bin_table(&[[7; 32], [7; 32]]).is_err());
    let bins: Vec<_> = (0..binmap::BIN_TABLE_MAX_BINS)
        .map(|n| *GrainId::of(&n.to_le_bytes()).digest())
        .collect();
    assert!(binmap::encode_bin_table(&bins).is_ok());
    let mut overflow = bins;
    overflow.push([255; 32]);
    assert!(binmap::encode_bin_table(&overflow).is_err());
}

#[tokio::test]
async fn additions_are_verified_at_the_final_reader_route() {
    let old = entry(GrainId::of(b"old"), 0);
    let added = entry(GrainId::of(b"added"), 0);
    let state = state_at(8, &[old]);
    let built = build(&state, &state.bins, &[added], Policy::default()).unwrap();
    let index = binmap::decode_binmap_index(&built.index_bytes).unwrap();
    let route = binmap::shard_for(&added.id, index.prefix_bits);
    let (_, bytes) = &built.shards[&route];
    let routed = binmap::decode_shard(bytes).unwrap();
    let reader_can_find = binmap::find_entry(&routed, &added.id) == Some(&added);
    let verified = verify(
        &state,
        &state.bins,
        &[added],
        &[old.id, added.id],
        Policy::default(),
        built,
    );
    assert!(
        verified.is_ok(),
        "final-byte verifier refused constructed insertion: {verified:?}; reader_can_find={reader_can_find}"
    );
    assert!(reader_can_find, "a fresh routed reader lost the addition");
}

#[tokio::test]
async fn unselected_shards_add_no_fetch_or_encode_work() {
    let candidate = GrainId::of(b"new");
    let selected = binmap::shard_for(&candidate, 8);
    let old = ids(50)
        .into_iter()
        .filter(|id| binmap::shard_for(id, 8) == selected)
        .map(|id| entry(id, 0))
        .collect::<Vec<_>>();
    let extras = ids(10_000)
        .into_iter()
        .filter(|id| binmap::shard_for(id, 8) != selected)
        .map(|id| entry(id, 0))
        .collect::<Vec<_>>();
    let mut observations = Vec::new();
    for extra in [vec![], extras] {
        let all: Vec<_> = old.iter().copied().chain(extra).collect();
        let original = state_at(8, &all);
        let (remote, volume, bytes, keys) = install(&original);
        let mut partial = load(
            &remote,
            &volume,
            &bytes,
            &keys,
            Policy::default(),
            Arc::default(),
        )
        .await;
        assert_eq!(
            partial.select(&remote, "v", &[candidate]).await.unwrap(),
            vec![candidate]
        );
        let addition = entry(candidate, 0);
        let built = build(&partial, &partial.bins, &[addition], Policy::default()).unwrap();
        let token = verify(
            &partial,
            &partial.bins,
            &[addition],
            &[candidate],
            Policy::default(),
            built,
        )
        .unwrap();
        observations.push((partial.work.fetched, token.work.encoded));
    }
    assert_eq!(observations[0], observations[1]);
    assert_eq!(observations[0].0.len(), 1);
    assert_eq!(observations[0].1, vec![selected]);
}
