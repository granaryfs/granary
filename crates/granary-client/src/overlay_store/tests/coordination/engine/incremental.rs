// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! What one fsync costs, and what the engine accepts as its base.

use super::*;
use crate::overlay_store::tests::incremental::{Base, World, file, manifest_of};
use crate::overlay_store::tests::sync_objects::Remote as ObjectRemote;
use granary_core::manifest::GrainRef;
use granary_core::overlay_journal::{Location, Parent};

pub(super) async fn basis_of(base: &mut Base) -> Basis {
    basis_at(base, 0).await
}

#[expect(
    clippy::too_many_lines,
    reason = "engine publication and disk-error assertions share the same warmed incarnation"
)]
async fn warmed_commit_cache_loss(reject: bool) {
    let mut observed = Vec::new();
    for corrupt in [false, true] {
        let mut base = Base::new();
        base.file("keep", b"authenticated base")
            .file("other", b"other");
        let fixture = Fixture::over(basis_of(&mut base).await).await.unwrap();
        let path = vec![Name::new(b"keep".to_vec()).unwrap()];
        let data = GrainId::of(b"authenticated base");
        let payload = manifest::node::file_payload(
            18,
            &FileGrains::Inline(vec![GrainRef {
                id: data,
                unpacked_len: 18,
            }]),
        )
        .unwrap();
        let entry = base
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .unwrap()
            .clone();
        let generation = {
            let mut local = fixture.store.lock().unwrap();
            local.put_immutable(data, b"authenticated base").unwrap();
            local
                .put_immutable(GrainId::of(&payload), &payload)
                .unwrap();
            let (cold, cold_work) =
                crate::overlay_store::local_content::measure_local_reads(|| {
                    local.overlay_transaction(|t| t.read_base(&path, 2, 5))
                });
            let (warm, warm_work) =
                crate::overlay_store::local_content::measure_local_reads(|| {
                    local.overlay_transaction(|t| t.read_base(&path, 2, 5))
                });
            assert_eq!(
                (
                    base.entries.len(),
                    cold.unwrap(),
                    warm.unwrap(),
                    cold_work,
                    warm_work
                ),
                (
                    2,
                    b"thent".to_vec(),
                    b"thent".to_vec(),
                    (2, payload.len() + 18),
                    (0, 0)
                ),
                "nonempty engine clean-base/resident-range premise"
            );
            local
                .overlay_transaction(|t| {
                    t.preparation_context(&entry)
                        .map(|(_, generation)| generation)
                })
                .unwrap()
        };
        let lane = fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let warm = fixture
            .store
            .lock()
            .unwrap()
            .range_cache_snapshot_for_test();
        assert_eq!(
            (warm.0, warm.1 > 0, warm.2 > 0, warm.3 > 0, warm.4 > 0),
            (generation, true, true, true, true),
            "cache must remain warm before replacement: {warm:?}"
        );
        if reject {
            fixture
                .remote
                .publication_plan
                .lock()
                .unwrap()
                .push_back(commits::PublishPlan::Reject);
        }
        Box::pin(fixture.engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut commits::Delay,
            crate::RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
        .unwrap();
        damage_commit_grain(&fixture, data, corrupt);
        let mut local = fixture.store.lock().unwrap();
        let after = if reject {
            let cache = local.range_cache_snapshot_for_test();
            assert_eq!(
                cache,
                (generation + 1, 0, 0, 0, 0),
                "fenced replacement retained verified ranges"
            );
            cache.0
        } else {
            local
                .overlay_transaction(|t| {
                    t.preparation_context(&entry)
                        .map(|(_, generation)| generation)
                })
                .unwrap()
        };
        let (answer, work) = crate::overlay_store::local_content::measure_local_reads(|| {
            local
                .overlay_transaction(|t| t.read_base(&path, 2, 5))
                .map_err(|error| error.to_string())
        });
        observed.push((
            corrupt,
            after - generation,
            answer,
            work.0,
            fixture.remote.publication_sends.lock().unwrap().len(),
        ));
    }
    let (missing, damaged, reads) = if reject {
        (
            "intent fenced (ESTALE), recorded generation None",
            "intent fenced (ESTALE), recorded generation None",
            0,
        )
    } else {
        (
            "overlay recovery awaits verified content",
            "overlay content authentication failed",
            2,
        )
    };
    assert_eq!(
        (observed.len(), observed),
        (
            2,
            vec![
                (false, 1, Err(missing.to_owned()), reads, 1),
                (true, 1, Err(damaged.to_owned()), reads, 1),
            ]
        ),
        "engine replacement must invalidate verified ranges on both disk-error routes: reject={reject}"
    );
}

#[expect(
    clippy::used_underscore_binding,
    reason = "the fixture retains scratch for the engine lifetime; damage must use that exact owned root"
)]
fn damage_commit_grain(fixture: &Fixture, data: GrainId, corrupt: bool) {
    if corrupt {
        super::super::local_content::corrupt_object(&fixture._scratch, data);
    } else {
        super::super::local_content::remove_object(&fixture._scratch, data);
    }
}

#[tokio::test]
async fn landed_engine_commit_discards_warmed_verified_ranges_before_service() {
    warmed_commit_cache_loss(false).await;
}

#[tokio::test]
async fn rejected_engine_commit_discards_warmed_verified_ranges_before_service() {
    warmed_commit_cache_loss(true).await;
}
async fn basis_at(base: &mut Base, width: u8) -> Basis {
    let root = manifest_of(&mut base.world, &base.entries);
    let objects = ObjectRemote::default();
    let (bytes, trusted) = crate::overlay_store::tests::sync_objects::base_with_policy(
        &objects,
        root,
        &base.world.objects,
        crate::Policy {
            min_prefix_bits: width,
        },
    )
    .await;
    Basis {
        objects,
        bytes,
        trusted,
        nodes: base.world.objects.0.clone(),
        entries: base.entries.clone(),
    }
}

fn nested(dir: &str, leaf: &str) -> Location {
    Location {
        parent: Parent::new(vec![Name::new(dir.as_bytes().to_vec()).unwrap()]).unwrap(),
        name: Name::new(leaf.as_bytes().to_vec()).unwrap(),
    }
}

/// Count each indexed position once, even when empty positions share an id.
async fn complete_binmap_cost(basis: &Basis) -> (u64, u64) {
    let doc = granary_core::root::decode_root(&basis.bytes).unwrap();
    let bytes = basis
        .objects
        .get_meta("v", &doc.binmap_index)
        .await
        .unwrap();
    let index = granary_core::binmap::decode_binmap_index(&bytes).unwrap();
    let mut read_bytes = bytes.len() as u64
        + basis
            .objects
            .get_meta("v", &index.bin_table)
            .await
            .unwrap()
            .len() as u64;
    for id in &index.shards {
        read_bytes += basis.objects.get_meta("v", id).await.unwrap().len() as u64;
    }
    (
        read_bytes,
        8 * read_bytes + 1024 * (2 + index.shards.len()) as u64,
    )
}

fn assert_complete_binmap_load(fixture: &Fixture, before_get_bytes: u64, expected: (u64, u64)) {
    assert_eq!(
        fixture.engine.binmap_get_bytes() - before_get_bytes,
        expected.0,
        "fallback binmap GET bytes must equal one complete load"
    );
    assert_eq!(
        fixture.engine.last_spend()["binmap"],
        expected.1,
        "fallback binmap charge must equal one complete load"
    );
}

async fn measure_attach(basis: &Basis, grains: u32, label: &str) {
    let source = Arc::new(crate::overlay_store::tests::sync_objects::Objects(
        basis.nodes.clone(),
    ));
    let mut elapsed = Vec::new();
    let mut map_elapsed = Vec::new();
    let (expected_bytes, _) = complete_binmap_cost(basis).await;
    for _ in 0..5 {
        let source = source.clone();
        let keys = basis.trusted.clone();
        let bytes = basis.bytes.clone();
        basis.objects.reads.lock().unwrap().clear();
        let runtime = TokioSyncRuntime;
        let deadline = runtime.now() + crate::DEFAULT_RESOLUTION_BOUND;
        let start = runtime.now();
        let map = runtime
            .timeout_at(
                deadline,
                crate::VerifiedBase::attach_map(&bytes, "v", &keys, &basis.objects),
            )
            .await
            .unwrap()
            .unwrap();
        map_elapsed.push(runtime.now().duration_since(start).as_secs_f64());
        let mappings = map.known.len();
        let verified = runtime
            .timeout_at(
                deadline,
                runtime.blocking(move || {
                    crate::VerifiedBase::attach_validated(bytes, "v", &keys, source.as_ref(), map)
                }),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        elapsed.push(runtime.now().duration_since(start).as_secs_f64());
        assert!(runtime.now() < deadline);
        assert_eq!(verified.id(), GrainId::of(&basis.bytes));
        let reads = basis.objects.reads.lock().unwrap();
        assert_eq!(
            reads.iter().map(|(_, len)| *len as u64).sum::<u64>(),
            expected_bytes
        );
        println!(
            "attach {label}: grains={grains} mappings={mappings} GETs={} binmap_bytes={expected_bytes}",
            reads.len()
        );
    }
    println!("attach {label}: map_seconds={map_elapsed:?} validation_seconds={elapsed:?}");
}

#[tokio::test]
#[ignore = "wall time measurement using large existing volume fixtures"]
async fn attach_validation_wall_time_for_large_bases() {
    for count in [100_000, granary_core::binmap::SHARD_MAX_ENTRIES] {
        let mut base = Base::new();
        base.dir("hot").file("hot/keep", b"keep");
        let refs: Vec<_> = (0..count)
            .map(|n| {
                let bytes = n.to_le_bytes().to_vec();
                let id = GrainId::of(&bytes);
                base.world.objects.0.insert(id, bytes);
                GrainRef {
                    id,
                    unpacked_len: 4,
                }
            })
            .collect();
        let spill = manifest::build_grain_list(&refs).unwrap();
        base.world.objects.0.extend(spill.nodes);
        let content = base
            .world
            .register_spill_claim(4 * u64::from(count), count, spill.root);
        base.entries.push(file("cold", content, false));
        let basis = basis_at(&mut base, 8).await;
        measure_attach(&basis, count + 1, "reachable-spill").await;
    }
    // This is the largest base exercised by the existing occupancy fixtures:
    // one full width-zero shard, including physically backed orphan grains.
    let mut base = Base::new();
    base.file("keep", b"keep");
    let mut basis = basis_at(&mut base, 0).await;
    seed_mappings(&mut basis, granary_core::binmap::SHARD_MAX_ENTRIES - 2).await;
    measure_attach(
        &basis,
        granary_core::binmap::SHARD_MAX_ENTRIES - 1,
        "full-shard",
    )
    .await;
}

/// What one fsync did, with the binmap's own objects left out: an fsync still
/// loads the whole binmap, and that cost is tracked on its own.
#[derive(Debug, PartialEq, Eq)]
struct Probe {
    charged: BTreeMap<&'static str, u64>,
    gets: u64,
    meta_gets: usize,
}

async fn probe(fixture: &Fixture, stage: u64) -> Result<Probe, CoordinationError> {
    let gets = fixture.content.gets.load(Ordering::Relaxed);
    fixture.remote.objects.fetched.lock().unwrap().clear();
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await?;
    let mut charged = fixture.engine.last_spend();
    charged.remove("binmap");
    charged.remove("put_binmap");
    let meta_gets = fixture
        .remote
        .objects
        .fetched
        .lock()
        .unwrap()
        .iter()
        .filter(|kind| **kind != "binmap")
        .count();
    Ok(Probe {
        charged,
        gets: fixture.content.gets.load(Ordering::Relaxed) - gets,
        meta_gets,
    })
}

/// A hot directory beside `cold` unrelated one-grain files; create one file in
/// the hot directory and fsync it, then change it and fsync again.
async fn edit_beside(cold: usize) -> Result<[Probe; 2], CoordinationError> {
    let mut base = Base::new();
    base.dir("hot").dir("cold");
    for i in 0..4 {
        base.file(&format!("hot/keep{i}"), format!("keep{i}").as_bytes());
    }
    for i in 0..cold {
        base.file(&format!("cold/c{i:06}"), format!("cold {i}").as_bytes());
    }
    base.set_cap(1 << 30);
    let fixture = Fixture::over(basis_of(&mut base).await).await?;
    let stage = fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            let stage = t.create_file(nested("hot", "edited"), false)?;
            t.write(stage, 0, &[1; 3000])?;
            Ok(stage)
        })
        .unwrap();
    let created = probe(&fixture, stage).await?;
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(stage, 100, &[2; 50]).map(|_| ()))
        .unwrap();
    let changed = probe(&fixture, stage).await?;
    fixture.settled().await;
    Ok([created, changed])
}

#[tokio::test]
async fn fsync_charge_independent_of_volume() {
    let small = edit_beside(2_000)
        .await
        .expect("the 2,000-file base refused its fsync");
    let large = edit_beside(20_000)
        .await
        .expect("the 20,000-file base refused its fsync");
    for (small, large) in small.iter().zip(&large) {
        assert_eq!(
            small, large,
            "an fsync's charge, reads or fetches changed with the unrelated volume"
        );
    }
    // The control: the same edit beside a small base succeeds and charges.
    let control = edit_beside(200).await.expect("the 200-file base refused");
    assert_eq!(control[0], small[0]);
    assert!(small[0].charged.values().sum::<u64>() > 0);
}

/// An insert into a very large directory re-encodes the whole directory, so it
/// is the case the bound refuses: with the predicted class.
#[tokio::test]
async fn an_insert_into_an_oversized_directory_refuses_workspace() {
    let mut base = Base::new();
    base.dir("big");
    let content = base.world.inline(b"same");
    for i in 0..18_000 {
        base.entries
            .push(file(&format!("big/f{i:06}"), content, false));
    }
    base.set_cap(1 << 30);
    let fixture = Fixture::over(basis_of(&mut base).await).await.unwrap();
    let stage = fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            let stage = t.create_file(nested("big", "g"), false)?;
            t.write(stage, 0, b"g")?;
            Ok(stage)
        })
        .unwrap();
    let error = fixture
        .engine
        .sync(
            SyncTarget::Stage(stage),
            SyncOptions {
                workspace_bytes: 16_777_216,
                ..SyncOptions::default()
            },
        )
        .wait()
        .await
        .unwrap_err();
    assert!(
        matches!(error, CoordinationError::Refused("SyncWorkspaceExhausted")),
        "expected the workspace refusal, got {error}"
    );
}

fn lying_spill(claimed: u32) -> Base {
    let mut base = Base::new();
    let mut world = World::default();
    let refs: Vec<GrainRef> = (0..130_u8)
        .map(|i| {
            world.objects.0.insert(GrainId::of(&[i]), vec![i]);
            GrainRef {
                id: GrainId::of(&[i]),
                unpacked_len: 1,
            }
        })
        .collect();
    let list = manifest::build_grain_list(&refs).unwrap();
    world.objects.0.extend(list.nodes);
    let content = world.register_spill_claim(130, claimed, list.root);
    base.world = world;
    base.entries.push(file("lie", content, false));
    base
}

#[tokio::test]
async fn engine_base_is_only_a_verified_base() {
    // A sound base attaches.
    Fixture::over(basis_of(&mut lying_spill(130)).await)
        .await
        .expect("a sound spilled base attaches");
    // A base whose manifest is not local refuses, however well it is signed.
    let mut absent = lying_spill(130);
    let mut basis = basis_of(&mut absent).await;
    basis.nodes.clear();
    assert!(matches!(
        Fixture::over(basis).await,
        Err(CoordinationError::Refused("SyncBase"))
    ));
}

#[tokio::test]
async fn a_signed_base_with_a_doctored_spill_tree_refuses_at_attach() {
    let result = Fixture::over(basis_of(&mut lying_spill(200)).await).await;
    assert!(
        matches!(result, Err(CoordinationError::Refused("SyncBase"))),
        "a correctly signed base with a lying grain-list claim attached"
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one volume fixture pins routed read and rewrite sets, workspace charges and a fresh remote reader"
)]
async fn fsync_binmap_charge_above_old_grain_cliff() {
    use crate::overlay_store::tests::sync_objects::base_with_policy;
    let mut base = Base::new();
    base.dir("hot").file("hot/keep", b"keep");
    let refs: Vec<_> = (0..100_000_u32)
        .map(|n| {
            let bytes = n.to_le_bytes().to_vec();
            let id = GrainId::of(&bytes);
            base.world.objects.0.insert(id, bytes);
            GrainRef {
                id,
                unpacked_len: 4,
            }
        })
        .collect();
    let spill = manifest::build_grain_list(&refs).unwrap();
    base.world.objects.0.extend(spill.nodes);
    let content = base
        .world
        .register_spill_claim(400_000, 100_000, spill.root);
    base.entries.push(file("cold", content, false));
    let root = manifest_of(&mut base.world, &base.entries);
    let objects = ObjectRemote::default();
    let (bytes, trusted) = base_with_policy(
        &objects,
        root,
        &base.world.objects,
        crate::Policy { min_prefix_bits: 8 },
    )
    .await;
    let doc = granary_core::root::decode_root(&bytes).unwrap();
    let index = granary_core::binmap::decode_binmap_index(
        &objects.get_meta("v", &doc.binmap_index).await.unwrap(),
    )
    .unwrap();
    assert_eq!(index.prefix_bits, 8);
    let fixture = Fixture::over(Basis {
        objects,
        bytes,
        trusted,
        nodes: base.world.objects.0.clone(),
        entries: base.entries,
    })
    .await
    .unwrap();
    let stage = fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            let stage = t.create_file(nested("hot", "edited"), false)?;
            t.write(stage, 0, b"small hot edit")?;
            Ok(stage)
        })
        .unwrap();
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .expect("a tiny edit above the grain cliff must fit the default workspace");
    assert!(fixture.engine.last_spend().values().sum::<u64>() <= 16_777_216);
    let registered = fixture.remote.authority.lock().unwrap().root.clone();
    let work = fixture.engine.last_binmap_work();
    let candidates: Vec<_> = crate::publish::collect_objects_pruned(
        &fixture
            .remote
            .objects
            .read_objects(
                granary_core::root::decode_root(&registered)
                    .unwrap()
                    .binmap_index,
            )
            .unwrap(),
        &granary_core::root::decode_root(&registered)
            .unwrap()
            .manifest_root,
        &std::collections::BTreeSet::from([spill.root]),
    )
    .unwrap()
    .into_iter()
    .filter(|id| *id != spill.root)
    .collect();
    let routes: std::collections::BTreeSet<_> = candidates
        .iter()
        .map(|id| granary_core::binmap::shard_for(id, 8))
        .collect();
    let novel_routes: std::collections::BTreeSet<_> = candidates
        .iter()
        .filter(|id| !base.world.objects.0.contains_key(id))
        .map(|id| granary_core::binmap::shard_for(id, 8))
        .collect();
    assert_eq!(
        work.fetched
            .iter()
            .map(|(at, _, _)| *at)
            .collect::<std::collections::BTreeSet<_>>(),
        routes
    );
    assert_eq!(
        work.rewritten
            .iter()
            .map(|(at, _)| *at)
            .collect::<std::collections::BTreeSet<_>>(),
        novel_routes
    );
    assert_eq!(work.candidates, candidates.len());
    assert!(work.candidates <= 8);
    assert!(work.fetched.len() <= 8);
    assert!(work.fetched.iter().all(|(_, _, count)| *count <= 600));
    let doc = granary_core::root::decode_root(&registered).unwrap();
    let fresh = fixture
        .remote
        .objects
        .read_objects(doc.binmap_index)
        .unwrap();
    manifest::validate_dir_tree(&doc.manifest_root, &|id| fresh.0.get(id).cloned()).unwrap();
    assert_eq!(
        fresh.0.get(&GrainId::of(b"small hot edit")).unwrap(),
        b"small hot edit"
    );
    let charged = fixture.engine.last_spend();
    let base_doc =
        granary_core::root::decode_root(&fixture.remote.published.lock().unwrap()[&1]).unwrap();
    let base_index = granary_core::binmap::decode_binmap_index(
        &fixture
            .remote
            .objects
            .get_meta("v", &base_doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    let table_bytes = fixture
        .remote
        .objects
        .get_meta("v", &base_index.bin_table)
        .await
        .unwrap();
    let bins = granary_core::binmap::decode_bin_table(&table_bytes).unwrap();
    let read_bytes = 44
        + 33 * index.shards.len()
        + table_bytes.len()
        + work
            .fetched
            .iter()
            .map(|(_, bytes, _)| bytes)
            .sum::<usize>();
    assert_eq!(
        charged["binmap"],
        8 * read_bytes as u64 + 1024 * (2 + work.fetched.len()) as u64
    );
    let new_index = granary_core::binmap::decode_binmap_index(
        &fixture
            .remote
            .objects
            .get_meta("v", &doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    let new_table = fixture
        .remote
        .objects
        .get_meta("v", &new_index.bin_table)
        .await
        .unwrap();
    let write_bytes = work.rewritten.iter().map(|(_, bytes)| bytes).sum::<usize>()
        + new_table.len()
        + 44
        + 33 * index.shards.len();
    assert_eq!(
        charged["put_binmap"],
        8 * write_bytes as u64 + 1024 * (work.rewritten.len() + 2) as u64
    );
    assert_eq!(
        work.encoded,
        work.rewritten.iter().map(|(at, _)| *at).collect::<Vec<_>>()
    );
    println!(
        "C={} K={} bins={} R={:?} U={:?} binmap_GET_charge={} binmap_PUT_charge={} total={}",
        work.candidates,
        work.novel,
        bins.len(),
        work.fetched,
        work.rewritten,
        charged["binmap"],
        charged["put_binmap"],
        charged.values().sum::<u64>()
    );
}

#[tokio::test]
async fn missing_untouched_binmap_shard_refuses_at_attach() {
    let mut base = Base::new();
    base.file("keep", b"keep");
    let basis = basis_of(&mut base).await;
    let doc = granary_core::root::decode_root(&basis.bytes).unwrap();
    let index = granary_core::binmap::decode_binmap_index(
        &basis
            .objects
            .get_meta("v", &doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    basis.objects.remove_meta(index.shards[0]);
    assert!(
        matches!(
            Fixture::over(basis).await,
            Err(CoordinationError::Refused("SyncBase"))
        ),
        "an initially missing shard must refuse attach"
    );
}

async fn alter_map(
    basis: &mut Basis,
    change: impl FnOnce(&mut Vec<Vec<granary_core::binmap::ShardEntry>>),
) {
    use granary_core::binmap;
    let mut doc = granary_core::root::decode_root(&basis.bytes).unwrap();
    let index = binmap::decode_binmap_index(
        &basis
            .objects
            .get_meta("v", &doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    let mut shards = Vec::new();
    for id in &index.shards {
        shards.push(binmap::decode_shard(&basis.objects.get_meta("v", id).await.unwrap()).unwrap());
    }
    change(&mut shards);
    let mut shard_ids = Vec::new();
    for mut entries in shards {
        entries.sort_unstable_by_key(|entry| entry.id);
        let bytes = binmap::encode_shard(&entries).unwrap();
        let id = GrainId::of(&bytes);
        basis.objects.put_meta("v", &id, bytes).await.unwrap();
        shard_ids.push(id);
    }
    let bytes =
        binmap::encode_binmap_index(index.prefix_bits, index.bin_table, &shard_ids).unwrap();
    doc.binmap_index = GrainId::of(&bytes);
    basis
        .objects
        .put_meta("v", &doc.binmap_index, bytes)
        .await
        .unwrap();
    doc.sigs.clear();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    });
    basis.bytes = granary_core::root::encode_root(&doc).unwrap();
    basis.objects.puts.lock().unwrap().clear();
}

#[tokio::test]
async fn attach_rejects_misrouting_and_every_containment_gap() {
    let mut base = lying_spill(130);
    let valid = basis_at(&mut base, 8).await;
    let manifest_root = granary_core::root::decode_root(&valid.bytes)
        .unwrap()
        .manifest_root;
    Fixture::over(valid).await.unwrap();
    let ids = crate::publish::collect_objects(&base.world.objects, &manifest_root).unwrap();
    assert!(ids.len() >= 132);
    for missing in ids {
        let mut basis = basis_at(&mut base, 8).await;
        alter_map(&mut basis, |shards| {
            for entries in shards {
                entries.retain(|entry| entry.id != missing);
            }
        })
        .await;
        assert!(
            matches!(
                Fixture::over(basis).await,
                Err(CoordinationError::Refused("SyncBase"))
            ),
            "uncovered closure attached: {missing}"
        );
    }
    let mut basis = basis_at(&mut base, 8).await;
    alter_map(&mut basis, |shards| {
        let at = shards
            .iter()
            .position(|entries| !entries.is_empty())
            .unwrap();
        let entry = shards[at].pop().unwrap();
        shards[(at + 1) % 256].push(entry);
    })
    .await;
    assert!(
        matches!(
            Fixture::over(basis).await,
            Err(CoordinationError::Refused("SyncBase"))
        ),
        "misrouted base attached before a candidate could re-add the id"
    );
}

#[tokio::test(start_paused = true)]
async fn attach_deadline_and_transport_keep_their_dispositions() {
    let mut base = Base::new();
    base.file("keep", b"keep");
    let basis = basis_of(&mut base).await;
    *basis.objects.get_failure.lock().unwrap() = Some("transport");
    assert!(matches!(
        Fixture::over(basis).await,
        Err(CoordinationError::Recovery(
            crate::RecoveryError::Preparation(crate::PublishError::Remote(
                RootStoreError::Backend(_)
            ))
        ))
    ));
    let basis = basis_of(&mut base).await;
    *basis.objects.get_failure.lock().unwrap() = Some("hold");
    assert!(matches!(
        Fixture::over(basis).await,
        Err(CoordinationError::Refused("SyncDeadline"))
    ));
}

#[tokio::test]
async fn custody_loss_after_valid_attach_is_deferred_until_full_read() {
    let mut base = Base::new();
    base.file("keep", b"keep");
    let basis = basis_at(&mut base, 8).await;
    let doc = granary_core::root::decode_root(&basis.bytes).unwrap();
    let index = granary_core::binmap::decode_binmap_index(
        &basis
            .objects
            .get_meta("v", &doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    let fixture = Fixture::over(basis).await.unwrap();
    let stage = fixture.create("edited", b"edited");
    let lost = granary_core::binmap::shard_for(&doc.manifest_root, 8);
    fixture.remote.objects.remove_meta(index.shards[lost]);
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    assert!(
        !fixture
            .engine
            .last_binmap_work()
            .fetched
            .iter()
            .any(|(at, _, _)| *at == lost)
    );
    let registered = fixture.remote.authority.lock().unwrap().root.clone();
    let doc = granary_core::root::decode_root(&registered).unwrap();
    assert!(
        fixture
            .remote
            .objects
            .read_objects(doc.binmap_index)
            .is_err()
    );
    let keys = TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()]).unwrap();
    assert!(
        crate::publish::state_from_head(
            fixture.remote.objects.as_ref(),
            &doc.volume,
            doc.seq,
            &registered,
            &keys
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn oversized_shard_get_refuses_without_fallback_or_bin_put_and_reports_bytes() {
    let mut base = Base::new();
    base.file("keep", b"keep");
    let mut basis = basis_at(&mut base, 0).await;
    seed_mappings(&mut basis, 50_000).await;
    let fixture = Fixture::over(basis).await.unwrap();
    fixture.remote.objects.reads.lock().unwrap().clear();
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.namespace_record(granary_core::overlay_journal::Record::Move {
                from: at("keep"),
                to: at("temporary"),
            })?;
            t.namespace_record(granary_core::overlay_journal::Record::Move {
                from: at("temporary"),
                to: at("keep"),
            })
        })
        .unwrap();
    let result = fixture
        .engine
        .sync(
            SyncTarget::Tree,
            SyncOptions {
                workspace_bytes: 16_777_216,
                ..SyncOptions::default()
            },
        )
        .wait()
        .await;
    assert!(matches!(
        result,
        Err(CoordinationError::Refused("SyncWorkspaceExhausted"))
    ));
    assert_eq!(fixture.engine.binmap_exhaustion_counts().unwrap(), (0, 0));
    assert!(fixture.remote.objects.puts.lock().unwrap().is_empty());
    assert!(fixture.remote.attempts.lock().unwrap().is_empty());
    let reads = fixture.remote.objects.reads.lock().unwrap().clone();
    let mut transferred = 0;
    for (id, len) in reads {
        let bytes = fixture.remote.objects.get_meta("v", &id).await.unwrap();
        if granary_core::encoding::open_envelope(&bytes).is_ok_and(|(kind, _)| {
            matches!(
                kind,
                granary_core::encoding::ObjectType::BinmapIndex
                    | granary_core::encoding::ObjectType::BinTable
                    | granary_core::encoding::ObjectType::BinmapShard
            )
        }) {
            transferred += len;
        }
    }
    assert!(transferred > 2_097_152);
    assert_eq!(
        fixture.engine.refused_metadata_get_bytes(),
        (14 + 49 * 50_002) as u64
    );
    assert_eq!(fixture.engine.binmap_get_bytes(), transferred as u64);
}

#[tokio::test]
async fn fetched_bad_hash_and_ordinal_refuse_without_registration() {
    for bad in ["hash", "ordinal", "type"] {
        let mut base = Base::new();
        base.file("keep", b"keep");
        let mut basis = basis_at(&mut base, 8).await;
        if bad == "ordinal" {
            alter_map(&mut basis, |shards| {
                shards.iter_mut().flatten().next().unwrap().bin_ordinal = 25;
            })
            .await;
        } else if bad == "type" {
            let mut doc = granary_core::root::decode_root(&basis.bytes).unwrap();
            let mut index = granary_core::binmap::decode_binmap_index(
                &basis
                    .objects
                    .get_meta("v", &doc.binmap_index)
                    .await
                    .unwrap(),
            )
            .unwrap();
            let at = granary_core::binmap::shard_for(&doc.manifest_root, index.prefix_bits);
            index.shards[at] = doc.sheaf_head;
            let bytes = granary_core::binmap::encode_binmap_index(
                index.prefix_bits,
                index.bin_table,
                &index.shards,
            )
            .unwrap();
            doc.binmap_index = GrainId::of(&bytes);
            basis
                .objects
                .put_meta("v", &doc.binmap_index, bytes)
                .await
                .unwrap();
            doc.sigs.clear();
            let key = SigningKey::from_seed(&[39; 32]).unwrap();
            doc.sigs.push(RootSig {
                key_id: key.key_id(),
                sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
            });
            basis.bytes = granary_core::root::encode_root(&doc).unwrap();
        } else {
            let doc = granary_core::root::decode_root(&basis.bytes).unwrap();
            let index = granary_core::binmap::decode_binmap_index(
                &basis
                    .objects
                    .get_meta("v", &doc.binmap_index)
                    .await
                    .unwrap(),
            )
            .unwrap();
            let mut bytes = basis.objects.get_meta("v", &index.shards[0]).await.unwrap();
            bytes[0] ^= 1;
            basis.objects.overwrite_meta(index.shards[0], bytes);
        }
        assert!(
            matches!(
                Fixture::over(basis).await,
                Err(CoordinationError::Refused("SyncBase"))
            ),
            "initial corrupt map attached: {bad}"
        );
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one near-cap binmap scenario checks refusal, fallback acceptance and commit reuse"
)]
async fn overflow_fallback_keeps_boundary_budget_and_memo_through_commit() {
    let mut base = Base::new();
    base.file("keep", b"keep");
    let mut basis = basis_at(&mut base, 0).await;
    seed_mappings(&mut basis, granary_core::binmap::SHARD_MAX_ENTRIES - 2).await;
    let expected = complete_binmap_cost(&basis).await;
    let fixture = Fixture::over_capped(basis, 536_870_912).await.unwrap();
    let stage = fixture.create("edited", b"edited");
    // The same near-cap base refuses on GET under a 16 MiB workspace;
    // that observed transfer is not an overflow trigger or a bin upload.
    assert!(matches!(
        fixture
            .engine
            .sync(
                SyncTarget::Stage(stage),
                SyncOptions {
                    workspace_bytes: 16_777_216,
                    ..SyncOptions::default()
                }
            )
            .wait()
            .await,
        Err(CoordinationError::Refused("SyncWorkspaceExhausted"))
    ));
    assert_eq!(fixture.engine.binmap_exhaustion_counts().unwrap(), (0, 0));
    assert_eq!(
        fixture.engine.refused_metadata_get_bytes(),
        14 + 49 * u64::from(granary_core::binmap::SHARD_MAX_ENTRIES)
    );
    assert!(fixture.remote.objects.puts.lock().unwrap().is_empty());
    assert!(fixture.remote.attempts.lock().unwrap().is_empty());
    assert_eq!(fixture.marks(), 0);
    let options = SyncOptions {
        workspace_bytes: 268_435_456,
        ..SyncOptions::default()
    };
    fixture.remote.objects.reads.lock().unwrap().clear();
    let before_get_bytes = fixture.engine.binmap_get_bytes();
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), options)
        .wait()
        .await
        .unwrap();
    assert_complete_binmap_load(&fixture, before_get_bytes, expected);
    let first = fixture.engine.last_binmap_work();
    assert!(first.first_trigger);
    assert_eq!(first.fetched.len(), 1);
    assert_eq!(fixture.engine.binmap_exhaustion_counts().unwrap(), (1, 0));
    let first_doc =
        granary_core::root::decode_root(&fixture.remote.authority.lock().unwrap().root).unwrap();
    assert_eq!(first_doc.parent, Some(fixture.base));
    assert!(fixture.engine.last_spend().values().sum::<u64>() <= options.workspace_bytes);
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), options)
        .wait()
        .await
        .unwrap();
    assert!(fixture.engine.last_binmap_work().memo_bypass);
    assert_eq!(fixture.engine.binmap_exhaustion_counts().unwrap(), (1, 1));
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(commits::PublishPlan::Land);
    let lane = fixture
        .engine
        .construct_commit(options, &mut Entropy(73))
        .await
        .unwrap();
    let landed = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(78),
        &mut commits::Delay,
        crate::RecoveryIntent::Continue,
        options,
    ))
    .await
    .unwrap();
    let crate::PublicationOutcome::Landed(done) = landed.outcome else {
        panic!("commit did not land")
    };
    let doc = granary_core::root::decode_root(&done.root).unwrap();
    let index = granary_core::binmap::decode_binmap_index(
        &fixture
            .remote
            .objects
            .get_meta("v", &doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(index.prefix_bits > 0);
    assert_eq!(fixture.engine.binmap_exhaustion_counts().unwrap(), (0, 0));
    fixture
        .engine
        .sync(SyncTarget::Tree, options)
        .wait()
        .await
        .unwrap();
    let after = fixture.engine.last_binmap_work();
    assert!(!after.memo_bypass && !after.first_trigger);
    assert!(
        after.fetched.is_empty(),
        "clean landed sync loaded shards instead of just the table"
    );
}

#[tokio::test]
async fn enlarged_table_refuses_before_shards_or_bin_put() {
    let mut base = Base::new();
    base.file("keep", b"keep");
    let mut basis = basis_at(&mut base, 8).await;
    let mut doc = granary_core::root::decode_root(&basis.bytes).unwrap();
    let mut index = granary_core::binmap::decode_binmap_index(
        &basis
            .objects
            .get_meta("v", &doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    let mut bins = granary_core::binmap::decode_bin_table(
        &basis.objects.get_meta("v", &index.bin_table).await.unwrap(),
    )
    .unwrap();
    bins.extend((0..65_536_u32).map(|n| *GrainId::of(&n.to_le_bytes()).digest()));
    let table = granary_core::binmap::encode_bin_table(&bins).unwrap();
    let refused_bytes = table.len() as u64;
    index.bin_table = GrainId::of(&table);
    basis
        .objects
        .put_meta("v", &index.bin_table, table)
        .await
        .unwrap();
    let bytes =
        granary_core::binmap::encode_binmap_index(8, index.bin_table, &index.shards).unwrap();
    doc.binmap_index = GrainId::of(&bytes);
    basis
        .objects
        .put_meta("v", &doc.binmap_index, bytes)
        .await
        .unwrap();
    doc.sigs.clear();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    });
    basis.bytes = granary_core::root::encode_root(&doc).unwrap();
    basis.objects.puts.lock().unwrap().clear();
    let fixture = Fixture::over(basis).await.unwrap();
    fixture.remote.objects.reads.lock().unwrap().clear();
    let stage = fixture.create("edit", b"edit");
    assert!(matches!(
        fixture
            .engine
            .sync(
                SyncTarget::Stage(stage),
                SyncOptions {
                    workspace_bytes: 16_777_216,
                    ..SyncOptions::default()
                }
            )
            .wait()
            .await,
        Err(CoordinationError::Refused("SyncWorkspaceExhausted"))
    ));
    assert_eq!(fixture.engine.binmap_exhaustion_counts().unwrap(), (0, 0));
    assert_eq!(fixture.engine.refused_metadata_get_bytes(), refused_bytes);
    assert_eq!(fixture.remote.objects.reads.lock().unwrap().len(), 2);
    assert!(fixture.remote.objects.puts.lock().unwrap().is_empty());
    assert!(fixture.remote.attempts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn overflow_fallback_workspace_refusal_keeps_the_remaining_budget_and_memo() {
    let mut base = Base::new();
    base.file("keep", b"keep");
    let mut basis = basis_at(&mut base, 0).await;
    seed_mappings(&mut basis, granary_core::binmap::SHARD_MAX_ENTRIES - 2).await;
    let expected = complete_binmap_cost(&basis).await;
    let fixture = Fixture::over_capped(basis, 536_870_912).await.unwrap();
    let stage = fixture.create("edited", b"edited");
    fixture.remote.objects.reads.lock().unwrap().clear();
    let before_get_bytes = fixture.engine.binmap_get_bytes();
    let options = SyncOptions {
        workspace_bytes: 100_000_000,
        ..SyncOptions::default()
    };
    assert!(matches!(
        fixture
            .engine
            .sync(SyncTarget::Stage(stage), options)
            .wait()
            .await,
        Err(CoordinationError::Refused("SyncWorkspaceExhausted"))
    ));
    assert_complete_binmap_load(&fixture, before_get_bytes, expected);
    assert_eq!(fixture.engine.binmap_exhaustion_counts().unwrap(), (1, 0));
    assert!(fixture.remote.attempts.lock().unwrap().is_empty());
    assert_eq!(fixture.marks(), 0);
    let old_root = fixture.remote.published.lock().unwrap()[&1].clone();
    assert_eq!(GrainId::of(&old_root), fixture.base);
    assert!(matches!(
        fixture
            .engine
            .sync(
                SyncTarget::Stage(stage),
                SyncOptions {
                    workspace_bytes: 16_777_216,
                    ..SyncOptions::default()
                }
            )
            .wait()
            .await,
        Err(CoordinationError::Refused("SyncWorkspaceExhausted"))
    ));
    assert_eq!(fixture.engine.binmap_exhaustion_counts().unwrap(), (1, 1));
    let shard_bytes = 14 + 49 * u64::from(granary_core::binmap::SHARD_MAX_ENTRIES);
    assert_eq!(fixture.engine.refused_metadata_get_bytes(), shard_bytes);
    let doc = granary_core::root::decode_root(&old_root).unwrap();
    let index = granary_core::binmap::decode_binmap_index(
        &fixture
            .remote
            .objects
            .get_meta("v", &doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    let table_bytes = fixture
        .remote
        .objects
        .get_meta("v", &index.bin_table)
        .await
        .unwrap()
        .len() as u64;
    assert_eq!(
        fixture.engine.binmap_get_bytes(),
        2 * (77 + table_bytes + shard_bytes)
    );
    assert!(fixture.remote.attempts.lock().unwrap().is_empty());
    assert_eq!(fixture.marks(), 0);
}

#[tokio::test]
async fn missing_shared_empty_shard_refuses_at_attach() {
    let mut base = Base::new();
    base.file("keep", b"keep");
    let valid = basis_at(&mut base, 8).await;
    Fixture::over(valid).await.unwrap();
    let basis = basis_at(&mut base, 8).await;
    let doc = granary_core::root::decode_root(&basis.bytes).unwrap();
    let index = granary_core::binmap::decode_binmap_index(
        &basis
            .objects
            .get_meta("v", &doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    let empty = GrainId::of(&granary_core::binmap::encode_shard(&[]).unwrap());
    assert!(index.shards.iter().filter(|id| **id == empty).count() > 1);
    basis.objects.remove_meta(empty);
    assert!(
        matches!(
            Fixture::over(basis).await,
            Err(CoordinationError::Refused("SyncBase"))
        ),
        "missing shared empty shard attached without whole-binmap validation"
    );
}

#[tokio::test]
async fn bad_final_binmap_never_registers() {
    use crate::publish::shards::injection::{self, Corruption};
    for mode in ["partial", "commit", "fallback"] {
        for corruption in [Corruption::Slot, Corruption::DropEntry] {
            let mut base = Base::new();
            base.file("keep", b"keep");
            let mut basis = basis_at(&mut base, if mode == "fallback" { 0 } else { 8 }).await;
            if mode == "fallback" {
                seed_mappings(&mut basis, granary_core::binmap::SHARD_MAX_ENTRIES - 2).await;
            }
            let fixture = Fixture::over_capped(basis, 536_870_912).await.unwrap();
            let stage = fixture.create("edited", b"edited");
            let options = SyncOptions {
                workspace_bytes: 268_435_456,
                ..SyncOptions::default()
            };
            let full = mode != "partial";
            let result = {
                let _injected = injection::arm(fixture.base, full, corruption);
                if mode == "commit" {
                    fixture
                        .engine
                        .construct_commit(options, &mut Entropy(72))
                        .await
                        .map(|_| ())
                } else {
                    fixture
                        .engine
                        .sync(SyncTarget::Stage(stage), options)
                        .wait()
                        .await
                }
            };
            let unreadable = if result.is_ok() && mode != "commit" {
                let doc =
                    granary_core::root::decode_root(&fixture.remote.authority.lock().unwrap().root)
                        .unwrap();
                match fixture.remote.objects.read_objects(doc.binmap_index) {
                    Err(_) => true,
                    Ok(objects) => crate::publish::collect_objects(&objects, &doc.manifest_root)
                        .map_or(true, |ids| ids.iter().any(|id| !objects.has(id))),
                }
            } else {
                false
            };
            assert!(
                matches!(
                    result,
                    Err(CoordinationError::Recovery(
                        crate::RecoveryError::Preparation(crate::PublishError::BinmapConstruction)
                    ))
                ),
                "bad final bytes reached acceptance: full={full}, mode={mode}, corruption={corruption:?}, unreadable={unreadable}, result={result:?}"
            );
            assert!(
                fixture.remote.attempts.lock().unwrap().is_empty(),
                "bad final bytes registered"
            );
            assert!(
                fixture
                    .remote
                    .objects
                    .puts
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|kind| *kind == "bin"),
                "unverified binmap metadata crossed acceptance"
            );
            assert_eq!(fixture.marks(), 0, "bad final bytes advanced a checkpoint");
            // The same captured data succeeds once the bound injection is disarmed.
            if mode == "commit" {
                fixture
                    .engine
                    .construct_commit(options, &mut Entropy(77))
                    .await
                    .unwrap();
            } else {
                fixture
                    .engine
                    .sync(SyncTarget::Stage(stage), options)
                    .wait()
                    .await
                    .unwrap();
            }
        }
    }
}

/// Occupancy controls retain real bin bytes and decoder-derived extents, even
/// for mappings outside the live manifest. Attach validates their whole map.
async fn seed_mappings(basis: &mut Basis, count: u32) {
    use granary_core::{binfmt, binmap};
    let mut doc = granary_core::root::decode_root(&basis.bytes).unwrap();
    let index = binmap::decode_binmap_index(
        &basis
            .objects
            .get_meta("v", &doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(index.prefix_bits, 0);
    let mut bins =
        binmap::decode_bin_table(&basis.objects.get_meta("v", &index.bin_table).await.unwrap())
            .unwrap();
    let mut entries = binmap::decode_shard(
        &basis
            .objects
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
        basis.objects.put_bin(&digest, bytes).await.unwrap();
    }
    entries.sort_unstable_by_key(|entry| entry.id);
    let bytes = binmap::encode_shard(&entries).unwrap();
    let shard = GrainId::of(&bytes);
    basis.objects.put_meta("v", &shard, bytes).await.unwrap();
    let bytes = binmap::encode_bin_table(&bins).unwrap();
    let table = GrainId::of(&bytes);
    basis.objects.put_meta("v", &table, bytes).await.unwrap();
    let bytes = binmap::encode_binmap_index(0, table, &[shard]).unwrap();
    doc.binmap_index = GrainId::of(&bytes);
    basis
        .objects
        .put_meta("v", &doc.binmap_index, bytes)
        .await
        .unwrap();
    doc.sigs.clear();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    });
    basis.bytes = granary_core::root::encode_root(&doc).unwrap();
    basis.objects.puts.lock().unwrap().clear();
    basis
        .objects
        .read_objects(doc.binmap_index)
        .expect("the occupancy control's entire old map must be physically readable");
}

/// Binmap reads since the last call, by their role in `roles`, a map's other
/// objects counted as "other"; the remote's read logs are cleared.
fn binmap_reads(
    fixture: &Fixture,
    roles: &BTreeMap<GrainId, &'static str>,
) -> BTreeMap<&'static str, usize> {
    let fetched = std::mem::take(&mut *fixture.remote.objects.fetched.lock().unwrap());
    let reads = std::mem::take(&mut *fixture.remote.objects.reads.lock().unwrap());
    let mut counts = BTreeMap::new();
    for ((id, _), kind) in reads.iter().zip(&fetched) {
        if *kind == "binmap" {
            *counts
                .entry(roles.get(id).copied().unwrap_or("other"))
                .or_default() += 1;
        }
    }
    counts
}

/// A published sync accepts its projection against the base's complete
/// binmap: one index, one table and every shard position per acceptance,
/// even for a clean call, and its in-process landing reuses that map with
/// no further binmap read. A durable-prepared sync of the same file loads
/// only the shards its objects route to. A shard that cannot be read refuses
/// the sync before any publication.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the partial control, two published calls and the refused read share one base"
)]
async fn projected_binmap_requests_are_full() {
    let mut base = Base::new();
    for i in 0..32 {
        base.file(&format!("f{i:02}"), format!("base file {i}").as_bytes());
    }
    let basis = basis_at(&mut base, 8).await;
    let doc = granary_core::root::decode_root(&basis.bytes).unwrap();
    let index = granary_core::binmap::decode_binmap_index(
        &basis
            .objects
            .get_meta("v", &doc.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    let mut roles = BTreeMap::from([(doc.binmap_index, "index"), (index.bin_table, "table")]);
    for id in &index.shards {
        roles.insert(*id, "shard");
    }
    let positions = index.shards.len();
    let fixture = &Fixture::over(basis).await.unwrap();
    binmap_reads(fixture, &roles);
    let stage = fixture.create("edited", b"a small delta");
    let publish = |target: SyncTarget, seed: u8| async move {
        fixture
            .engine
            .sync_published(
                move |local: &mut crate::writable_store::WritableStore<SimIo>| {
                    local.overlay_transaction(|t| t.seal_sync(target)).map(Some)
                },
                SyncOptions::default(),
                Entropy(seed),
            )
            .wait()
            .await
    };
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    let partial = binmap_reads(fixture, &roles);
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(stage, 0, b"A").map(|_| ()))
        .unwrap();
    publish(SyncTarget::Stage(stage), 70).await.unwrap();
    let full = binmap_reads(fixture, &roles);
    // The landing is the next base: a clean call loads all of its map.
    let landed = fixture
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    let landed_index = granary_core::binmap::decode_binmap_index(
        &fixture
            .remote
            .objects
            .get_meta(
                "v",
                &granary_core::root::decode_root(&landed)
                    .unwrap()
                    .binmap_index,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    // The read of the landed index above is not the engine's.
    binmap_reads(fixture, &roles);
    let sends = fixture.remote.publication_sends.lock().unwrap().len();
    // A clean directory call still publishes.
    publish(SyncTarget::Directory(None), 72).await.unwrap();
    let clean = binmap_reads(fixture, &roles);
    let clean_sends = fixture.remote.publication_sends.lock().unwrap().len() - sends;
    *fixture.remote.objects.get_failure.lock().unwrap() = Some("shard");
    let refused = publish(SyncTarget::Directory(None), 74).await;
    let refused_sends = fixture.remote.publication_sends.lock().unwrap().len() - sends;
    assert_eq!(
        (
            positions > 1,
            partial.get("index").copied(),
            partial.get("shard").copied().unwrap_or(0) < positions,
            full,
            clean.values().sum::<usize>(),
            clean_sends,
            refused.as_ref().err().map(crate::sync_mount_error),
            refused_sends,
        ),
        (
            true,
            Some(1),
            true,
            BTreeMap::from([("index", 1), ("shard", positions), ("table", 1)]),
            landed_index.shards.len() + 2,
            1,
            Some(granary_fuse::MountSyncError::Backend(
                granary_fuse::MountError::Unavailable
            )),
            1,
        ),
        "a published acceptance loads the whole map once, partial: {partial:?}"
    );
}
