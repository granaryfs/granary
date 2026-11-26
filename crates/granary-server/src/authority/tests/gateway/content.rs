// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

mod availability;

use super::*;
use crate::{ValidationError, ValidationLimits};
use granary_client::{Policy, VerifiedBase, merge_manifests, prepare_from_manifest};
use granary_core::binstore::BinStore;
use granary_core::grainsource::{GrainSource, GrainSourceError};
use granary_core::identity::WriterIdentity;
use granary_core::manifest::{self, DirEntry, EntryKind, FileGrains, GrainRef, Name};
use object_store::{ObjectStoreExt, memory::InMemory, path::Path};

#[derive(Default)]
struct Objects(BTreeMap<GrainId, Vec<u8>>);
impl GrainSource for Objects {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(GrainSourceError::Missing(*id))
    }
    fn has(&self, id: &GrainId) -> bool {
        self.0.contains_key(id)
    }
}
impl Objects {
    fn tree(&mut self, files: &[DirEntry]) -> GrainId {
        let tree = manifest::build_dir(files).unwrap();
        self.0.extend(tree.nodes);
        tree.root
    }

    fn file(&mut self, name: &[u8], bytes: &[u8]) -> DirEntry {
        let id = GrainId::of(bytes);
        self.0.insert(id, bytes.to_vec());
        DirEntry {
            name: Name::new(name.to_vec()).unwrap(),
            kind: EntryKind::File {
                exec: false,
                size: bytes.len() as u64,
                grains: FileGrains::Inline(vec![GrainRef {
                    id,
                    unpacked_len: u32::try_from(bytes.len()).unwrap(),
                }]),
            },
        }
    }
}

async fn prepare(store: &(impl RootStore + BinStore), objects: &Objects, id: GrainId) -> Vec<u8> {
    prepare_for(&a(), store, objects, id).await
}

async fn prepare_for(
    volume: &VolumeName,
    store: &(impl RootStore + BinStore),
    objects: &Objects,
    id: GrainId,
) -> Vec<u8> {
    prepare_from_manifest(
        store,
        objects,
        id,
        granary_client::HarvestStats::default(),
        volume,
        &publisher(),
        &WriterIdentity::from_bytes([7; 16]),
        FixedClock.now(),
        Policy::default(),
    )
    .await
    .unwrap()
    .root_bytes
}

#[cfg(feature = "crash-points")]
pub(in crate::authority::tests) async fn empty_tree_fixture(
    store: &(impl RootStore + BinStore),
) -> Vec<u8> {
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    prepare(store, &objects, tree).await
}

fn object_path(namespace: &str, id: GrainId) -> Path {
    let hex = hex(id);
    Path::from(format!("{namespace}/{}/{}", &hex[..2], hex))
}

fn meta_path(id: GrainId) -> Path {
    object_path(&format!("meta/{}", a().as_str()), id)
}

fn gateway_submission(op: u8, candidate: &[u8]) -> Submission {
    Submission::new(
        TenantName::parse("test").unwrap().to_tenant(),
        PRINCIPAL.to_principal(),
        a(),
        Epoch::from_bytes([WORLD_EPOCH; EPOCH_LEN]),
        Operation::new(vec![op]).unwrap(),
        candidate.to_vec(),
    )
}

async fn submit(fx: &Fx, op: u8, candidate: &[u8]) -> Answer {
    fx.handle.submit(gateway_submission(op, candidate)).await
}

async fn land(fx: &Fx, http: bool, op: u8, bytes: &[u8]) {
    if http {
        check(&fx.send(publish(op, bytes.to_vec())).await, 202, None);
    } else {
        assert!(matches!(
            submit(fx, op, bytes).await,
            Answer::Accepted { .. }
        ));
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while !matches!(submit(fx, op, bytes).await, Answer::Landed { .. }) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn refused(
    fx: &Fx,
    http: bool,
    op: u8,
    bytes: &[u8],
    error: ValidationError,
    status: u16,
    token: &str,
) {
    let before = fx.bytes().await;
    let appends = fx.log.append_calls();
    let root_puts = fx.store.root_puts.load(Ordering::Relaxed);
    if http {
        check(
            &fx.send(publish(op, bytes.to_vec())).await,
            status,
            Some(token),
        );
    } else {
        assert_eq!(submit(fx, op, bytes).await, Answer::Validation(error));
    }
    assert_eq!(fx.bytes().await, before);
    assert_eq!(fx.log.append_calls(), appends);
    assert_eq!(fx.store.root_puts.load(Ordering::Relaxed), root_puts);
}

fn decisions(records: &[Record]) -> usize {
    records
        .iter()
        .filter(|r| matches!(r.body(), RecordBody::Decision { .. }))
        .count()
}

#[tokio::test]
async fn refusals_leave_no_bytes_or_binding_and_exact_retry_lands() {
    for http in [false, true] {
        let backend = Arc::new(InMemory::new());
        let (fx, driver) = Fx::with_content(backend.clone(), ValidationLimits::default()).await;
        let mut run = spawn_driver(driver);
        let mut objects = Objects::default();
        let tree = objects.tree(&[]);
        let bytes = prepare(&fx.store, &objects, tree).await;
        let root = root::decode_root(&bytes).unwrap();
        let sheaf = meta_path(root.sheaf_head);
        let saved = backend.get(&sheaf).await.unwrap().bytes().await.unwrap();
        backend
            .put(&sheaf, Bytes::from_static(b"bad").into())
            .await
            .unwrap();
        refused(
            &fx,
            http,
            1,
            &bytes,
            ValidationError::InvalidReference,
            400,
            "invalid-reference",
        )
        .await;
        backend.put(&sheaf, saved.into()).await.unwrap();
        let index = granary_core::binmap::decode_binmap_index(
            &fx.store
                .get_meta(a().as_str(), &root.binmap_index)
                .await
                .unwrap(),
        )
        .unwrap();
        let table = granary_core::binmap::decode_bin_table(
            &fx.store
                .get_meta(a().as_str(), &index.bin_table)
                .await
                .unwrap(),
        )
        .unwrap();
        let bin = GrainId::from_parts(granary_core::hash::HashAlgorithm::Blake3, table[0]);
        for (ordinal, object) in [
            sheaf,
            meta_path(root.binmap_index),
            meta_path(index.bin_table),
            meta_path(index.shards[0]),
            object_path("bins", bin),
        ]
        .into_iter()
        .enumerate()
        {
            let saved = backend.get(&object).await.unwrap().bytes().await.unwrap();
            backend.delete(&object).await.unwrap();
            fx.refill((ordinal as i128 + 1) * 10);
            refused(
                &fx,
                http,
                1,
                &bytes,
                ValidationError::MissingReference,
                400,
                "missing-reference",
            )
            .await;
            backend.put(&object, saved.into()).await.unwrap();
        }
        fx.refill(100);
        land(&fx, http, 1, &bytes).await;
        assert_eq!(decisions(&fx.records().await), 1);
        assert_eq!(fx.store.root_puts.load(Ordering::Relaxed), 1);
        fx.handle.stop().await;
        run.join_next().await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn listing_exhaustion_precedes_damage_at_both_entry_points() {
    for http in [false, true] {
        let backend = Arc::new(InMemory::new());
        let limits = ValidationLimits {
            steps: 2,
            ..ValidationLimits::default()
        };
        let (fx, driver) = Fx::with_content(backend.clone(), limits).await;
        let mut run = spawn_driver(driver);
        let prefix = format!("root/{}", a().as_str());
        // The first listed root alone is damaged. Rule 6 must consume the
        // whole listing and refuse the allowance before checking either root.
        for seq in 1..=2 {
            backend
                .put(
                    &Path::from(format!("{prefix}/{seq:020}")),
                    Bytes::from_static(b"bad").into(),
                )
                .await
                .unwrap();
        }
        refused(
            &fx,
            http,
            1,
            &good_root(&a(), 1, None, 1),
            ValidationError::WorkLimit,
            413,
            "publish-work-limit",
        )
        .await;
        fx.handle.stop().await;
        run.join_next().await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn stale_and_replay_precede_content_and_restart_reports_damage() {
    let backend = Arc::new(InMemory::new());
    let (mut fx, driver) = Fx::with_content(backend.clone(), ValidationLimits::default()).await;
    let mut run = spawn_driver(driver);
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    let genesis = prepare(&fx.store, &objects, tree).await;
    let stale = good_root(&a(), 2, Some(GrainId::of(&genesis)), 2);
    assert!(matches!(
        submit(&fx, 2, &stale).await,
        Answer::StaleBase { .. }
    ));
    land(&fx, false, 1, &genesis).await;
    let successor = prepare(&fx.store, &objects, tree).await;
    let doc = root::decode_root(&genesis).unwrap();
    let bytes = fx
        .store
        .get_meta(a().as_str(), &doc.binmap_index)
        .await
        .unwrap();
    let index = granary_core::binmap::decode_binmap_index(&bytes).unwrap();
    let shard = meta_path(index.shards[0]);
    let saved = backend.get(&shard).await.unwrap().bytes().await.unwrap();
    backend.delete(&shard).await.unwrap();
    assert!(matches!(
        submit(&fx, 1, &genesis).await,
        Answer::Landed { .. }
    ));
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();

    let (handle, driver) = start(fx.parts(), boot(2), configs(&[a()])).await.unwrap();
    fx.handle = handle.clone();
    fx.service = fx.service_with_budget(handle, crate::adapter::WRITE_BODY_BUDGET_BYTES);
    let mut run = spawn_driver(driver);
    refused(
        &fx,
        true,
        2,
        &successor,
        ValidationError::Unavailable,
        503,
        "unavailable",
    )
    .await;
    assert!(matches!(
        submit(&fx, 1, &genesis).await,
        Answer::Landed { .. }
    ));
    let before = fx.bytes().await;
    let appends = fx.log.append_calls();
    assert_eq!(
        retry_intake(&fx, 2, &successor).await,
        Answer::VolumeDamaged
    );
    let response = tokio::time::timeout(Duration::from_secs(5), async {
        let mut clock = 0;
        loop {
            clock += 10;
            fx.refill(clock);
            let response = fx.send(publish(2, successor.clone())).await;
            if response.status().as_u16() != 503 {
                return response;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    check(&response, 409, Some("volume-damaged"));
    assert_eq!(fx.bytes().await, before);
    assert_eq!(fx.log.append_calls(), appends);
    assert_eq!(decisions(&fx.records().await), 1);
    backend.put(&shard, saved.into()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match retry_intake(&fx, 2, &successor).await {
                Answer::VolumeDamaged => tokio::task::yield_now().await,
                answer => {
                    assert!(matches!(answer, Answer::Accepted { .. }), "{answer:?}");
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

async fn retry_intake(fx: &Fx, op: u8, candidate: &[u8]) -> Answer {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match submit(fx, op, candidate).await {
                Answer::Validation(ValidationError::Unavailable) => tokio::task::yield_now().await,
                outcome => return outcome,
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn restarted_intake_with_small_slices_leaves_another_volume_free_to_publish() {
    use crate::authority::content::intake::Gate;
    let backend = Arc::new(InMemory::new());
    let limits = ValidationLimits {
        reads: 8,
        ..ValidationLimits::default()
    };
    let (mut fx, initial) = Fx::with_backend(
        false,
        &[a(), b()],
        &[],
        &[a(), b()],
        Some((backend, limits)),
    )
    .await;
    let mut run = spawn_driver(initial);
    let mut objects = Objects::default();
    let mut tree = objects.tree(&[]);
    for op in 1..=10 {
        if op == 2 {
            let file = objects.file(b"second-bin", b"added after genesis");
            tree = objects.tree(&[file]);
        }
        let head = prepare(&fx.store, &objects, tree).await;
        land(&fx, false, op, &head).await;
    }
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();

    let mut parts = fx.parts();
    let gate = Arc::new(Gate::default());
    parts.admission = parts.admission.with_limits(limits, 1);
    parts.admission.intake_gate = Some(gate.clone());
    let (handle, driver) = start(parts, boot(2), configs(&[a(), b()])).await.unwrap();
    fx.handle = handle;
    let mut run = spawn_driver(driver);
    let successor = prepare(&fx.store, &objects, tree).await;
    assert_eq!(
        submit(&fx, 11, &successor).await,
        Answer::Validation(ValidationError::WorkLimit)
    );
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    let before = fx.bytes().await;
    assert_eq!(
        submit(&fx, 11, &successor).await,
        Answer::Validation(ValidationError::Unavailable)
    );
    assert_eq!(fx.bytes().await, before);

    let independent = prepare_for(&b(), &fx.store, &objects, tree).await;
    let independent = submission(&b(), 1, &independent);
    assert!(matches!(
        fx.handle.submit(independent.clone()).await,
        Answer::Accepted { .. }
    ));
    assert!(matches!(
        settle(&fx.handle, &independent).await,
        Answer::Landed { .. }
    ));
    gate.release.notify_one();
    assert!(matches!(
        retry_intake(&fx, 11, &successor).await,
        Answer::Accepted { .. }
    ));
    assert!(matches!(
        settle(&fx.handle, &gateway_submission(11, &successor)).await,
        Answer::Landed { .. }
    ));
    assert_eq!(decisions(&fx.records().await), 11);
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn intake_discards_proof_when_head_moves_during_the_walk() {
    use std::pin::pin;

    use crate::authority::content::intake::{Gate, Outcome, run};
    use crate::authority::join::{Raced, race};
    let backend = Arc::new(InMemory::new());
    let store = granary_store::backend::GranaryStore::new(backend.clone());
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    let genesis = prepare(&store, &objects, tree).await;
    store.put_root(a().as_str(), 1, genesis).await.unwrap();
    let successor = prepare(&store, &objects, tree).await;
    let limits = ValidationLimits {
        reads: 1,
        ..ValidationLimits::default()
    };
    let mut admission = crate::Admission::memory(backend).with_limits(limits, 2);
    let gate = Arc::new(Gate::default());
    admission.intake_gate = Some(gate.clone());
    let keys = TrustedKeys::new([*publisher().public_key()]).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        let mut intake = pin!(run(&admission, Arc::new(FixedClock), a(), keys));
        let move_head = pin!(async {
            gate.entered.notified().await;
            store.put_root(a().as_str(), 2, successor).await.unwrap();
            gate.release.notify_one();
        });
        match race(intake.as_mut(), move_head).await {
            Raced::First(outcome) => panic!("intake ended before the gate: {outcome:?}"),
            Raced::Second(()) => intake.await,
        }
    })
    .await
    .unwrap();
    assert!(matches!(outcome, Outcome::Retry), "{outcome:?}");
}

#[tokio::test]
async fn lost_candidate_does_not_supply_the_winners_baseline() {
    let (fx, mut driver) =
        Fx::with_content(Arc::new(InMemory::new()), ValidationLimits::default()).await;
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    let candidate = prepare(&fx.store, &objects, tree).await;
    let competitor_file = objects.file(b"winner", b"other publisher");
    let competitor_tree = objects.tree(&[competitor_file]);
    let winner = prepare(&fx.store, &objects, competitor_tree).await;
    let engine = Engine {
        log: &driver.log,
        store: &driver.store,
        clock: driver.clock.as_ref(),
        rng: &driver.rng,
        secure_random: &driver.secure_random,
        pause: &driver.pause,
        gate: &driver.gate,
        shared: &driver.shared,
    };
    let request = submission(&a(), 1, &candidate);
    assert!(matches!(
        driver.workers[0].admit(&engine, &request).await,
        Answer::Accepted { .. }
    ));
    fx.store
        .put_root(a().as_str(), 1, winner.clone())
        .await
        .unwrap();

    let mut run = spawn_driver(driver);
    loop {
        match fx.handle.submit(request.clone()).await {
            Answer::Open { .. } => tokio::task::yield_now().await,
            Answer::Lost { occupant, .. } => {
                assert_eq!(occupant, GrainId::of(&winner));
                break;
            }
            other => panic!("expected lost publication, got {other:?}"),
        }
    }
    let successor = prepare(&fx.store, &objects, competitor_tree).await;
    refused(
        &fx,
        true,
        2,
        &successor,
        ValidationError::Unavailable,
        503,
        "unavailable",
    )
    .await;
    assert_eq!(decisions(&fx.records().await), 1);
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn old_grain_edge_with_false_length_is_refused_at_worker_and_gateway() {
    let (fx, driver) =
        Fx::with_content(Arc::new(InMemory::new()), ValidationLimits::default()).await;
    let mut run = spawn_driver(driver);
    let mut objects = Objects::default();
    let file = objects.file(b"actual", b"four");
    let tree = objects.tree(&[file]);
    let genesis = prepare(&fx.store, &objects, tree).await;
    land(&fx, false, 1, &genesis).await;
    let tree = objects.tree(&[DirEntry {
        name: Name::new(b"new-edge".to_vec()).unwrap(),
        kind: EntryKind::File {
            exec: false,
            size: 5,
            grains: FileGrains::Inline(vec![GrainRef {
                id: GrainId::of(b"four"),
                unpacked_len: 5,
            }]),
        },
    }]);
    let candidate = prepare(&fx.store, &objects, tree).await;
    for http in [false, true] {
        refused(
            &fx,
            http,
            2,
            &candidate,
            ValidationError::InvalidReference,
            400,
            "invalid-reference",
        )
        .await;
    }
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn real_client_genesis_edits_rebase_and_readback() {
    let (fx, driver) =
        Fx::with_content(Arc::new(InMemory::new()), ValidationLimits::default()).await;
    let mut run = spawn_driver(driver);
    let remote = conformance::Client(fx.service.clone());
    let mut objects = Objects::default();
    let left = objects.file(b"left", b"old left");
    let old_right = objects.file(b"right", b"old right");
    let base = objects.tree(&[left.clone(), old_right.clone()]);
    let genesis = prepare(&remote, &objects, base).await;
    land(&fx, true, 1, &genesis).await;

    let new_left = objects.file(b"left", b"new left");
    let new_right = objects.file(b"right", b"new right");
    let local_tree = objects.tree(&[new_left.clone(), old_right.clone()]);
    let local = prepare(&remote, &objects, local_tree).await;
    let remote_tree = objects.tree(&[left, new_right.clone()]);
    let winner = prepare(&remote, &objects, remote_tree).await;
    fx.refill(10);
    land(&fx, true, 2, &winner).await;
    check(&fx.send(publish(3, local)).await, 409, Some("stale-base"));

    let head = VerifiedBase::attach(winner, a().as_str(), &configs_key(), &objects, &remote)
        .await
        .unwrap();
    let local = [overlay_file(&new_left, 1), overlay_file(&old_right, 2)];
    let merged = merge_manifests(base, &local, &head, &objects).unwrap();
    let files: Vec<_> = merged
        .iter()
        .map(|entry| {
            let name = entry.path.first().unwrap();
            let file = [&new_left, &new_right]
                .into_iter()
                .find(|file| &file.name == name)
                .unwrap();
            assert_eq!(entry.kind, overlay_file(file, 0).kind);
            file.clone()
        })
        .collect();
    assert_eq!(files.len(), 2);
    let merged = objects.tree(&files);
    let rebased = prepare(&remote, &objects, merged).await;
    fx.refill(20);
    land(&fx, true, 3, &rebased).await;
    assert_eq!(decisions(&fx.records().await), 3);
    let (read, contents) = granary_client::resolve_at_collecting(&remote, a().as_str(), 3)
        .await
        .unwrap();
    assert_eq!(read.doc.manifest_root, merged);
    for bytes in [b"new left".as_slice(), b"new right"] {
        assert_eq!(contents.get(&GrainId::of(bytes)).unwrap(), bytes);
    }
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

fn configs_key() -> TrustedKeys {
    TrustedKeys::new([*publisher().public_key()]).unwrap()
}

fn file_payload(file: &DirEntry) -> GrainId {
    let EntryKind::File { grains, size, .. } = &file.kind else {
        unreachable!()
    };
    GrainId::of(&manifest::node::file_payload(*size, grains).unwrap())
}

fn overlay_file(file: &DirEntry, inode: u64) -> granary_client::OverlayEntry {
    let EntryKind::File { size, .. } = file.kind else {
        unreachable!()
    };
    granary_client::OverlayEntry {
        path: vec![file.name.clone()],
        inode,
        kind: granary_client::OverlayKind::File {
            content: Some(file_payload(file)),
        },
        stage_id: None,
        size,
        exec: false,
    }
}
