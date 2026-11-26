// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

mod pool;
mod store_faults;

use super::*;

#[derive(Debug, Default)]
struct TickClock(AtomicI64);
impl Clock for TickClock {
    // Every observation finds one more millisecond gone: elapsed time
    // proportional to the work done, like a store with per-call latency.
    fn now(&self) -> Timestamp {
        let nanos = self.0.fetch_add(1_000_000, Ordering::Relaxed);
        Timestamp {
            secs: 1_760_000_000 + nanos / 1_000_000_000,
            nanos: u32::try_from(nanos % 1_000_000_000).unwrap(),
        }
    }
}

fn files(objects: &mut Objects, n: usize) -> Vec<DirEntry> {
    (0..n)
        .map(|i| {
            objects.file(
                format!("f{i:06}").as_bytes(),
                format!("payload of file {i}").as_bytes(),
            )
        })
        .collect()
}

#[tokio::test]
async fn real_client_default_limits_8300_files_then_one_added_file() {
    let (fx, driver) =
        Fx::with_content(Arc::new(InMemory::new()), ValidationLimits::default()).await;
    let mut run = spawn_driver(driver);
    let mut objects = Objects::default();
    let mut entries = files(&mut objects, 8_300);
    let tree = objects.tree(&entries);
    let genesis = prepare(&fx.store, &objects, tree).await;
    land(&fx, true, 1, &genesis).await;
    entries.push(objects.file(b"zz-added", b"one new small file"));
    let tree = objects.tree(&entries);
    let edit = prepare(&fx.store, &objects, tree).await;
    fx.refill(10);
    land(&fx, true, 2, &edit).await;
    assert_eq!(decisions(&fx.records().await), 2);
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn real_client_delete_reuse_revert_sequence_is_never_refused() {
    let (fx, driver) =
        Fx::with_content(Arc::new(InMemory::new()), ValidationLimits::default()).await;
    let mut run = spawn_driver(driver);
    let mut objects = Objects::default();
    let a_file = objects.file(b"a", b"alpha content");
    let b_file = objects.file(b"b", b"beta content");
    let c_file = objects.file(b"c", b"gamma content");
    let c_reuses_a = objects.file(b"c", b"alpha content");
    let renamed = objects.file(b"renamed", b"gamma content");
    let trees = [
        vec![a_file.clone(), b_file.clone(), c_file.clone()],
        vec![a_file.clone(), b_file.clone()],
        vec![a_file.clone(), b_file.clone(), c_reuses_a],
        vec![a_file.clone()],
        vec![],
        vec![a_file.clone(), b_file.clone(), c_file.clone()],
        vec![a_file.clone(), b_file.clone(), c_file],
        vec![a_file, b_file, renamed],
    ];
    for (index, entries) in trees.iter().enumerate() {
        let op = u8::try_from(index + 1).unwrap();
        let tree = objects.tree(entries);
        let bytes = prepare(&fx.store, &objects, tree).await;
        let answer = submit(&fx, op, &bytes).await;
        assert!(
            matches!(answer, Answer::Accepted { .. }),
            "publish {op}: {answer:?}"
        );
        assert!(matches!(
            settle(&fx.handle, &gateway_submission(op, &bytes)).await,
            Answer::Landed { .. }
        ));
    }
    assert_eq!(decisions(&fx.records().await), trees.len());
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn lost_then_winner_baseline_is_rebuilt_by_intake_and_successor_lands() {
    let (fx, mut driver) =
        Fx::with_content(Arc::new(InMemory::new()), ValidationLimits::default()).await;
    let proofs = driver
        .shared
        .admission
        .as_ref()
        .unwrap()
        .config
        .proofs()
        .clone();
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
    assert!(proofs.live_bytes() > 0);
    assert_eq!(proofs.resident_bytes(), 0);
    fx.store
        .put_root(a().as_str(), 1, winner.clone())
        .await
        .unwrap();
    let mut run = spawn_driver(driver);
    loop {
        match fx.handle.submit(request.clone()).await {
            Answer::Open { .. } => tokio::task::yield_now().await,
            Answer::Lost { .. } => break,
            other => panic!("expected lost publication, got {other:?}"),
        }
    }
    assert_eq!(proofs.live_bytes(), 0);
    assert!(!proofs.has_landed(&a()));
    // A successor that is only valid over the LOSER's tree (it names the
    // loser as parent) stays stale; one over the winner is first held
    // for intake and then lands.
    let successor = prepare(&fx.store, &objects, competitor_tree).await;
    assert_eq!(
        submit(&fx, 2, &successor).await,
        Answer::Validation(ValidationError::Unavailable)
    );
    let answer = retry_intake(&fx, 2, &successor).await;
    assert!(matches!(answer, Answer::Accepted { .. }), "{answer:?}");
    assert!(matches!(
        settle(&fx.handle, &gateway_submission(2, &successor)).await,
        Answer::Landed { .. }
    ));
    assert_eq!(decisions(&fx.records().await), 2);
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn objects_verified_on_one_volume_do_not_satisfy_another() {
    let backend = Arc::new(InMemory::new());
    let (fx, driver) = Fx::with_backend(
        false,
        &[a(), b()],
        &[],
        &[a(), b()],
        Some((backend.clone(), ValidationLimits::default())),
    )
    .await;
    let mut run = spawn_driver(driver);
    let mut objects = Objects::default();
    let file = objects.file(b"shared", b"same bytes on both volumes");
    let tree = objects.tree(&[file]);
    let first = prepare(&fx.store, &objects, tree).await;
    land(&fx, false, 1, &first).await;

    let second = prepare_for(&b(), &fx.store, &objects, tree).await;
    let root = root::decode_root(&second).unwrap();
    let index = granary_core::binmap::decode_binmap_index(
        &fx.store
            .get_meta(b().as_str(), &root.binmap_index)
            .await
            .unwrap(),
    )
    .unwrap();
    let other = |id| object_path(&format!("meta/{}", b().as_str()), id);
    let request = submission(&b(), 1, &second);
    for object in [
        other(root.sheaf_head),
        other(root.binmap_index),
        other(index.bin_table),
        other(index.shards[0]),
    ] {
        let saved = backend.get(&object).await.unwrap().bytes().await.unwrap();
        backend.delete(&object).await.unwrap();
        assert_eq!(
            fx.handle.submit(request.clone()).await,
            Answer::Validation(ValidationError::MissingReference),
            "{object}"
        );
        backend.put(&object, saved.into()).await.unwrap();
    }
    assert!(matches!(
        fx.handle.submit(request.clone()).await,
        Answer::Accepted { .. }
    ));
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn restart_then_head_moves_during_intake_at_the_worker() {
    use crate::authority::content::intake::Gate;
    let backend = Arc::new(InMemory::new());
    let volumes = [a(), b()];
    let (mut fx, initial) = Fx::with_backend(
        false,
        &volumes,
        &[],
        &volumes,
        Some((backend, ValidationLimits::default())),
    )
    .await;
    let mut run = spawn_driver(initial);
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    let genesis = prepare(&fx.store, &objects, tree).await;
    land(&fx, false, 1, &genesis).await;
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();

    let mut parts = fx.parts();
    let gate = Arc::new(Gate::default());
    parts.admission.intake_gate = Some(gate.clone());
    parts.admission.limit_proofs(608);
    let (handle, driver) = start(parts, boot(2), configs(&volumes)).await.unwrap();
    fx.handle = handle;
    let proofs = driver
        .shared
        .admission
        .as_ref()
        .unwrap()
        .config
        .proofs()
        .clone();
    let mut run = spawn_driver(driver);
    let other = prepare_for(&b(), &fx.store, &objects, tree).await;
    let other = submission(&b(), 1, &other);
    assert!(matches!(
        fx.handle.submit(other.clone()).await,
        Answer::Accepted { .. }
    ));
    assert!(matches!(
        settle(&fx.handle, &other).await,
        Answer::Landed { .. }
    ));

    let mine_file = objects.file(b"mine", b"my edit");
    let mine_tree = objects.tree(&[mine_file]);
    let mine = prepare(&fx.store, &objects, mine_tree).await;
    let theirs_file = objects.file(b"theirs", b"a foreign writer");
    let theirs_tree = objects.tree(&[theirs_file]);
    let theirs = prepare(&fx.store, &objects, theirs_tree).await;

    let before = fx.bytes().await;
    assert_eq!(
        submit(&fx, 2, &mine).await,
        Answer::Validation(ValidationError::Unavailable)
    );
    assert_eq!(fx.bytes().await, before);
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert!(proofs.has_landed(&b()));
    assert_eq!(proofs.live_bytes(), 1_216);
    fx.store
        .put_root(a().as_str(), 2, theirs.clone())
        .await
        .unwrap();
    gate.release.notify_one();
    let answer = retry_intake(&fx, 2, &mine).await;
    assert!(matches!(answer, Answer::StaleBase { .. }), "{answer:?}");
    assert!(
        proofs.has_landed(&b()),
        "failed intake keeps the other volume"
    );
    assert!(!proofs.has_landed(&a()));
    assert_eq!(proofs.live_bytes(), 608);

    gate.release.notify_one();
    let on_top = prepare(&fx.store, &objects, mine_tree).await;
    let answer = retry_intake(&fx, 3, &on_top).await;
    assert!(matches!(answer, Answer::Accepted { .. }), "{answer:?}");
    assert!(matches!(
        settle(&fx.handle, &gateway_submission(3, &on_top)).await,
        Answer::Landed { .. }
    ));
    assert_eq!(decisions(&fx.records().await), 2);
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn intake_completes_across_time_and_read_slices() {
    use crate::authority::content::intake::{Outcome, run};
    let backend = Arc::new(InMemory::new());
    let store = granary_store::backend::GranaryStore::new(backend.clone());
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    for seq in 1..=150 {
        let root = prepare(&store, &objects, tree).await;
        store.put_root(a().as_str(), seq, root).await.unwrap();
    }
    let keys = || TrustedKeys::new([*publisher().public_key()]).unwrap();
    let second = Duration::from_secs(1);

    let admission = crate::Admission::memory(backend.clone());
    let outcome = run(&admission, Arc::new(FixedClock), a(), keys()).await;
    assert!(
        matches!(outcome, Outcome::Verified(_)),
        "control {outcome:?}"
    );

    let sliced = ValidationLimits {
        reads: 4,
        wall_time: second,
        ..ValidationLimits::default()
    };
    let admission = crate::Admission::memory(backend.clone()).with_limits(sliced, 2);
    let outcome = run(&admission, Arc::new(TickClock::default()), a(), keys()).await;
    assert!(
        matches!(outcome, Outcome::Verified(_)),
        "sliced {outcome:?}"
    );

    let roomy = ValidationLimits {
        wall_time: second,
        ..ValidationLimits::default()
    };
    let admission = crate::Admission::memory(backend).with_limits(roomy, 2);
    for attempt in 1..=3 {
        let outcome = run(&admission, Arc::new(TickClock::default()), a(), keys()).await;
        assert!(
            matches!(outcome, Outcome::Verified(_)),
            "attempt {attempt} with reads = 8192: {outcome:?}"
        );
    }
}

async fn restart(
    fx: &mut Fx,
    initial: GatewayDriver,
    admission: crate::Admission,
    volumes: &[VolumeName],
) -> GatewayDriver {
    let mut run = spawn_driver(initial);
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
    let mut parts = fx.parts();
    parts.admission = admission;
    let (handle, driver) = start(parts, boot(2), configs(volumes)).await.unwrap();
    fx.service = fx.service_with_budget(handle.clone(), crate::adapter::WRITE_BODY_BUDGET_BYTES);
    fx.handle = handle;
    driver
}

async fn first_bin(store: &impl BinStore, volume: &VolumeName, root: &[u8]) -> [u8; 32] {
    use granary_core::binmap::{decode_bin_table, decode_binmap_index};
    let root = root::decode_root(root).unwrap();
    let index = store
        .get_meta(volume.as_str(), &root.binmap_index)
        .await
        .unwrap();
    let table = decode_binmap_index(&index).unwrap().bin_table;
    decode_bin_table(&store.get_meta(volume.as_str(), &table).await.unwrap()).unwrap()[0]
}

#[tokio::test]
async fn cold_intake_detects_corruption_in_an_inherited_bin() {
    use crate::authority::content::intake::{Outcome, run};
    use granary_core::hash::HashAlgorithm;

    let backend = Arc::new(InMemory::new());
    let store = granary_store::backend::GranaryStore::new(backend.clone());
    let mut objects = Objects::default();
    let mut entries = files(&mut objects, 3);
    let tree = objects.tree(&entries);
    let genesis = prepare(&store, &objects, tree).await;
    store
        .put_root(a().as_str(), 1, genesis.clone())
        .await
        .unwrap();
    entries.push(objects.file(b"new", b"one new small file"));
    let tree = objects.tree(&entries);
    let child = prepare(&store, &objects, tree).await;
    store.put_root(a().as_str(), 2, child).await.unwrap();

    let digest = first_bin(&store, &a(), &genesis).await;
    let old = object_path("bins", GrainId::from_parts(HashAlgorithm::Blake3, digest));
    let bytes = backend.get(&old).await.unwrap().bytes().await.unwrap();
    let entries = granary_core::binfmt::decode_bin(&bytes).unwrap();
    let file = entries
        .iter()
        .find(|entry| entry.id == GrainId::of(b"payload of file 1"))
        .unwrap();
    let mut damaged = bytes.to_vec();
    damaged[usize::try_from(file.offset).unwrap()] ^= 1;
    backend.put(&old, damaged.into()).await.unwrap();

    let admission = crate::Admission::memory(backend.clone());
    let intake = || {
        run(
            &admission,
            Arc::new(FixedClock),
            a(),
            TrustedKeys::new([*publisher().public_key()]).unwrap(),
        )
    };
    assert!(matches!(intake().await, Outcome::Damaged(head) if head.head_seq == 2));
    backend.put(&old, bytes.into()).await.unwrap();
    assert!(matches!(intake().await, Outcome::Verified(_)));
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "the test owns the driver and gated submitters in one JoinSet"
)]
async fn the_next_validation_slot_goes_to_the_waiting_volume() {
    use crate::authority::{
        content::store::BinGate,
        join::{Raced, race},
    };
    use std::future::{Future, poll_fn};
    use std::pin::pin;
    use std::task::Poll;
    use tokio::sync::Semaphore;

    let volumes = [a(), b(), c()];
    let [a, b, c] = &volumes;
    let backend = Arc::new(InMemory::new());
    let (mut fx, initial) = Fx::with_backend(
        false,
        &volumes,
        &[],
        &volumes,
        Some((backend.clone(), ValidationLimits::default())),
    )
    .await;
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    let bad_a = prepare_for(a, &fx.store, &objects, tree).await;
    let bad_b = prepare_for(b, &fx.store, &objects, tree).await;
    let digest = first_bin(&fx.store, a, &bad_a).await;
    let bin = GrainId::from_parts(granary_core::hash::HashAlgorithm::Blake3, digest);
    backend.delete(&object_path("bins", bin)).await.unwrap();
    let new_file = objects.file(b"victim", b"valid distinct content");
    let tree = objects.tree(&[new_file]);
    let good = prepare_for(c, &fx.store, &objects, tree).await;

    let gate = Arc::new(BinGate {
        digest,
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let mut admission = crate::Admission::memory(backend);
    admission.bin_gate = Some(gate.clone());
    let driver = restart(&mut fx, initial, admission, &volumes).await;

    let flood = |volume: VolumeName, candidate: Vec<u8>| {
        let handle = fx.handle.clone();
        async move {
            for op in 1..=12 {
                assert_eq!(
                    handle.submit(submission(&volume, op, &candidate)).await,
                    Answer::Validation(ValidationError::MissingReference)
                );
            }
        }
    };
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(flood(a.clone(), bad_a));
    tasks.spawn(flood(b.clone(), bad_b));
    let mut run = Box::pin(driver.run());
    let waiting = submission(c, 1, &good);
    let mut victim = pin!(fx.handle.submit(waiting.clone()));
    // Poll the driver explicitly so the victim asks for a slot while both
    // are held at the whole-bin read, before either flood can resubmit.
    tokio::time::timeout(Duration::from_secs(5), async {
        match race(run.as_mut(), pin!(gate.entered.acquire_many(2))).await {
            Raced::First(result) => panic!("driver exited: {result:?}"),
            Raced::Second(permit) => permit.unwrap().forget(),
        }
    })
    .await
    .unwrap();
    poll_fn(|cx| {
        assert!(victim.as_mut().poll(cx).is_pending());
        assert!(run.as_mut().poll(cx).is_pending());
        assert!(victim.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;

    tasks.spawn(async { assert_eq!(run.await, RunEnd::Stopped) });
    gate.release.add_permits(1);
    let answer = tokio::time::timeout(Duration::from_secs(5), victim.as_mut())
        .await
        .unwrap();
    assert!(matches!(answer, Answer::Accepted { .. }), "{answer:?}");
    assert!(matches!(
        settle(&fx.handle, &waiting).await,
        Answer::Landed { .. }
    ));
    gate.release.add_permits(23);
    tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..2 {
            tasks.join_next().await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(fx.store.root_puts.load(Ordering::Relaxed), 1);
    for volume in [a, b] {
        assert_eq!(
            fx.log.read(volume).await.unwrap().unwrap(),
            encode_envelope(&envelope(volume, WORLD_EPOCH)).as_bytes()
        );
    }
    fx.handle.stop().await;
    tasks.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn an_evicted_volume_resumes_after_intake() {
    use crate::authority::content::intake::Gate;

    let volumes = [a(), b(), c()];
    let [a, b, c] = &volumes;
    let backend = Arc::new(InMemory::new());
    let (mut fx, initial) = Fx::with_backend(
        false,
        &volumes,
        &[],
        &volumes,
        Some((backend.clone(), ValidationLimits::default())),
    )
    .await;
    let mut admission = crate::Admission::memory(backend);
    admission.limit_proofs(1_300);
    let gate = Arc::new(Gate::default());
    admission.intake_gate = Some(gate.clone());
    let driver = restart(&mut fx, initial, admission, &volumes).await;
    let mut run = spawn_driver(driver);
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    // C already has a stored head. Its cold intake can displace B's proof
    // after A and B land and A's proof is touched again.
    let genesis = prepare_for(c, &fx.store, &objects, tree).await;
    fx.store.put_root(c.as_str(), 1, genesis).await.unwrap();
    let retry = async |request: &Submission| {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match fx.handle.submit(request.clone()).await {
                    Answer::Validation(ValidationError::Unavailable) => {
                        tokio::task::yield_now().await;
                    }
                    answer => return answer,
                }
            }
        })
        .await
        .unwrap()
    };
    for (volume, op) in [(a, 1), (b, 1), (a, 2), (c, 1), (a, 3)] {
        let bytes = prepare_for(volume, &fx.store, &objects, tree).await;
        let request = submission(volume, op, &bytes);
        let answer = fx.handle.submit(request.clone()).await;
        let answer = if volume == c {
            assert_eq!(answer, Answer::Validation(ValidationError::Unavailable));
            tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
                .await
                .unwrap();
            gate.release.notify_one();
            retry(&request).await
        } else {
            answer
        };
        assert!(
            matches!(answer, Answer::Accepted { .. }),
            "{volume:?}: {answer:?}"
        );
        assert!(matches!(
            settle(&fx.handle, &request).await,
            Answer::Landed { .. }
        ));
    }
    let bytes = prepare_for(b, &fx.store, &objects, tree).await;
    let before = fx.log.read(b).await.unwrap();
    let puts = fx.store.root_puts.load(Ordering::Relaxed);
    check(
        &fx.send(publish_to(b, 2, bytes.clone())).await,
        503,
        Some("unavailable"),
    );
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert_eq!(fx.log.read(b).await.unwrap(), before);
    assert_eq!(fx.store.root_puts.load(Ordering::Relaxed), puts);
    gate.release.notify_one();
    let request = submission(b, 2, &bytes);
    let answer = retry(&request).await;
    assert!(matches!(answer, Answer::Accepted { .. }), "{answer:?}");
    assert!(matches!(
        settle(&fx.handle, &request).await,
        Answer::Landed { .. }
    ));
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn real_client_default_limits_scale_past_one_binmap_shard() {
    for n in [45_000, 90_000] {
        let (fx, driver) =
            Fx::with_content(Arc::new(InMemory::new()), ValidationLimits::default()).await;
        let mut run = spawn_driver(driver);
        let mut objects = Objects::default();
        let mut entries = files(&mut objects, n);
        let tree = objects.tree(&entries);
        let genesis = prepare(&fx.store, &objects, tree).await;
        let root = root::decode_root(&genesis).unwrap();
        let index = granary_core::binmap::decode_binmap_index(
            &fx.store
                .get_meta(a().as_str(), &root.binmap_index)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(index.prefix_bits >= 2, "{n} files: {}", index.prefix_bits);
        land(&fx, true, 1, &genesis).await;
        entries.push(objects.file(b"zz-added", b"one new small file"));
        let tree = objects.tree(&entries);
        let edit = prepare(&fx.store, &objects, tree).await;
        fx.refill(10);
        land(&fx, true, 2, &edit).await;
        assert_eq!(decisions(&fx.records().await), 2);
        fx.handle.stop().await;
        run.join_next().await.unwrap().unwrap();
    }
}
