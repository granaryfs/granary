// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

async fn land_genesis(fx: &Fx, volume: &VolumeName, objects: &Objects, tree: GrainId) {
    let bytes = prepare_for(volume, &fx.store, objects, tree).await;
    let request = submission(volume, 1, &bytes);
    let answer = fx.handle.submit(request.clone()).await;
    assert!(
        matches!(answer, Answer::Accepted { .. }),
        "{volume:?}: {answer:?}"
    );
    assert!(matches!(
        settle(&fx.handle, &request).await,
        Answer::Landed { .. }
    ));
}

#[tokio::test]
async fn new_volume_genesis_is_admitted_when_landed_proofs_fill_the_pool() {
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
    admission.limit_proofs(1_216);
    let driver = restart(&mut fx, initial, admission, &volumes).await;
    let proofs = driver
        .shared
        .admission
        .as_ref()
        .unwrap()
        .config
        .proofs()
        .clone();
    let mut run = spawn_driver(driver);
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    for volume in &volumes {
        land_genesis(&fx, volume, &objects, tree).await;
    }
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
    assert!(!proofs.has_landed(a));
    assert!(proofs.has_landed(b));
    assert!(proofs.has_landed(c));
    assert_eq!(proofs.resident_bytes(), 1_216);
    assert_eq!(proofs.live_bytes(), 1_216);
}

#[tokio::test]
async fn third_volume_publishing_beside_two_open_entries_keeps_its_proof() {
    let volumes = [a(), b(), c()];
    let backend = Arc::new(InMemory::new());
    let (fx, mut driver) = Fx::with_backend(
        false,
        &volumes,
        &[],
        &volumes,
        Some((backend, ValidationLimits::default())),
    )
    .await;
    let proofs = driver
        .shared
        .admission
        .as_ref()
        .unwrap()
        .config
        .proofs()
        .clone();
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
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    let mut requests = Vec::new();
    // Drive only admission so A and B are still open when C is accepted.
    for (volume, worker) in volumes.iter().zip(&mut driver.workers) {
        let bytes = prepare_for(volume, &fx.store, &objects, tree).await;
        let request = submission(volume, 1, &bytes);
        let answer = worker.admit(&engine, &request).await;
        assert!(
            matches!(answer, Answer::Accepted { .. }),
            "{volume:?}: {answer:?}"
        );
        requests.push(request);
        assert_eq!(proofs.resident_bytes(), 0);
    }
    assert_eq!(fx.store.root_puts.load(Ordering::Relaxed), 0);
    let mut run = spawn_driver(driver);
    for request in &requests {
        assert!(matches!(
            settle(&fx.handle, request).await,
            Answer::Landed { .. }
        ));
    }
    let c = c();
    let edit = prepare_for(&c, &fx.store, &objects, tree).await;
    let request = submission(&c, 2, &edit);
    let answer = fx.handle.submit(request.clone()).await;
    assert!(
        matches!(answer, Answer::Accepted { .. }),
        "C's first successor: {answer:?}"
    );
    assert!(matches!(
        settle(&fx.handle, &request).await,
        Answer::Landed { .. }
    ));
    assert!(proofs.has_landed(&c));
    assert_eq!(proofs.resident_bytes(), 3 * 608);
    assert_eq!(proofs.live_bytes(), 3 * 608);
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn wedged_entry_releases_its_pending_proof() {
    stuck_entry_releases_its_pending_proof(ReadFault::OverCap, StuckState::Wedged).await;
}

#[tokio::test]
async fn unresolved_entry_releases_its_pending_proof() {
    stuck_entry_releases_its_pending_proof(ReadFault::Transport, StuckState::Unresolved).await;
}

async fn stuck_entry_releases_its_pending_proof(fault: ReadFault, state: StuckState) {
    use crate::authority::join::{JoinAll, Joined};
    use crate::authority::tests::publication::HeldPause;

    let (fx, mut driver) =
        Fx::with_content(Arc::new(InMemory::new()), ValidationLimits::default()).await;
    let proofs = driver.shared.admission.as_ref().unwrap().config.proofs();
    let pause = HeldPause::default();
    let engine = Engine {
        log: &driver.log,
        store: &fx.store.inner,
        clock: driver.clock.as_ref(),
        rng: &driver.rng,
        secure_random: &driver.secure_random,
        pause: &pause,
        gate: &driver.gate,
        shared: &driver.shared,
    };
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    let candidate = prepare(&fx.store, &objects, tree).await;
    let request = gateway_submission(1, &candidate);
    let mut worker = driver.workers.pop().unwrap();
    assert!(matches!(
        worker.admit(&engine, &request).await,
        Answer::Accepted { .. }
    ));
    assert_eq!(proofs.live_bytes(), 608);
    fx.store.inner.set_read_fault(&a(), 1, Some(fault));

    let check = async {
        pause.wait(1).await;
        let rows = fx.handle.report(Duration::from_mins(1)).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, state);
        assert_eq!(proofs.live_bytes(), 0, "{state:?} proof still charged");
        driver.shared.stop.request();
    };
    let tasks: [Joined<'_>; 2] = [Box::pin(worker.run(&engine)), Box::pin(check)];
    JoinAll::new(tasks).await;
}

#[tokio::test]
async fn unclaimed_intake_handoff_does_not_hold_up_another_volumes_intake() {
    use crate::authority::content::intake::Gate;

    let volumes = [a(), b()];
    let [a, b] = &volumes;
    let backend = Arc::new(InMemory::new());
    let (mut fx, initial) = Fx::with_backend(
        false,
        &volumes,
        &[],
        &volumes,
        Some((backend.clone(), ValidationLimits::default())),
    )
    .await;
    let gate = Arc::new(Gate::default());
    let mut admission = crate::Admission::memory(backend);
    admission.intake_gate = Some(gate.clone());
    let driver = restart(&mut fx, initial, admission, &volumes).await;
    let proofs = driver
        .shared
        .admission
        .as_ref()
        .unwrap()
        .config
        .proofs()
        .clone();
    let mut run = spawn_driver(driver);
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);

    for volume in &volumes {
        let head = prepare_for(volume, &fx.store, &objects, tree).await;
        fx.store.put_root(volume.as_str(), 1, head).await.unwrap();
        let next = prepare_for(volume, &fx.store, &objects, tree).await;
        let request = submission(volume, 1, &next);
        assert_eq!(
            fx.handle.submit(request).await,
            Answer::Validation(ValidationError::Unavailable)
        );
        tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
            .await
            .unwrap_or_else(|_| panic!("{volume:?} did not reach the intake recheck"));
        gate.release.notify_one();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !proofs.has_landed(volume) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    assert!(proofs.has_landed(a));
    assert!(proofs.has_landed(b));
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn sliced_intake_holds_its_ticket_for_a_proof_that_cannot_fit() {
    use crate::authority::content::intake::Gate;

    let volumes = [a(), b(), c()];
    let [a, b, c] = &volumes;
    let backend = Arc::new(InMemory::new());
    let limits = ValidationLimits {
        reads: 8,
        ..ValidationLimits::default()
    };
    let (mut fx, initial) = Fx::with_backend(
        false,
        &volumes,
        &[],
        &volumes,
        Some((backend.clone(), limits)),
    )
    .await;
    let mut admission = crate::Admission::memory(backend).with_limits(limits, 2);
    admission.limit_proofs(608);
    let gate = Arc::new(Gate::default());
    admission.intake_gate = Some(gate.clone());
    let driver = restart(&mut fx, initial, admission, &volumes).await;
    let proofs = driver
        .shared
        .admission
        .as_ref()
        .unwrap()
        .config
        .proofs()
        .clone();
    let mut run = spawn_driver(driver);

    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    let file = objects.file(b"file", b"mapped content");
    let larger_tree = objects.tree(&[file]);
    let first_a = prepare_for(a, &fx.store, &objects, larger_tree).await;
    let first_b = prepare_for(b, &fx.store, &objects, tree).await;
    fx.store
        .put_root(a.as_str(), 1, first_a.clone())
        .await
        .unwrap();
    fx.store.put_root(b.as_str(), 1, first_b).await.unwrap();
    land_genesis(&fx, c, &objects, tree).await;

    let next_a = prepare_for(a, &fx.store, &objects, larger_tree).await;
    let next_b = prepare_for(b, &fx.store, &objects, tree).await;
    let request_b = submission(b, 1, &next_b);
    assert_eq!(
        submit(&fx, 1, &next_a).await,
        Answer::Validation(ValidationError::Unavailable)
    );
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert!(proofs.has_landed(c));
    assert_eq!(proofs.resident_bytes(), 608);
    assert!(proofs.live_bytes() > 2 * 608);

    assert_eq!(
        fx.handle.submit(request_b.clone()).await,
        Answer::Validation(ValidationError::Unavailable)
    );
    // The other intake cannot reach the gate while A holds the whole-job ticket.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), gate.entered.notified())
            .await
            .is_err()
    );
    gate.release.notify_one();

    let stale = submit(&fx, 2, &first_a).await;
    assert!(matches!(stale, Answer::StaleBase { .. }), "{stale:?}");

    let answer = retry_intake(&fx, 1, &next_a).await;
    assert!(
        matches!(answer, Answer::Accepted { .. }),
        "handoff serves the exact head: {answer:?}"
    );
    assert!(matches!(
        settle(&fx.handle, &gateway_submission(1, &next_a)).await,
        Answer::Landed { .. }
    ));
    // B can now use the same ticket and reach its recheck.
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified())
        .await
        .unwrap();
    assert!(!proofs.has_landed(a));
    assert!(proofs.has_landed(c));
    gate.release.notify_one();
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}

#[tokio::test]
async fn intake_handoff_requires_the_exact_root_and_releases_its_ticket_on_expiry() {
    use crate::authority::content::intake::{Outcome, run};

    let backend = Arc::new(InMemory::new());
    let store = granary_store::backend::GranaryStore::new(backend.clone());
    let mut objects = Objects::default();
    let tree = objects.tree(&[]);
    let root = prepare(&store, &objects, tree).await;
    store.put_root(a().as_str(), 1, root.clone()).await.unwrap();
    let mut admission = crate::Admission::memory(backend);
    admission.limit_proofs(0);
    let proofs = admission.proofs();
    let intake = || async {
        let outcome = run(
            &admission,
            Arc::new(FixedClock),
            a(),
            TrustedKeys::new([*publisher().public_key()]).unwrap(),
        )
        .await;
        let Outcome::Verified(verified) = outcome else {
            panic!("expected successful intake, got {outcome:?}");
        };
        let (_, handoff) = verified.promote(proofs, FixedClock.now());
        assert_eq!(proofs.live_bytes(), 608);
        handoff.unwrap()
    };

    let stale = intake().await;
    assert!(
        stale
            .claim(&a(), GrainId::of(b"other root"), FixedClock.now())
            .is_none()
    );
    assert_eq!(proofs.live_bytes(), 0);

    let handoff = intake().await;
    let expiry = handoff.expiration();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(30)).await;
    expiry.await;
    assert_eq!(proofs.live_bytes(), 0);
    assert!(
        handoff
            .claim(&a(), GrainId::of(&root), FixedClock.now())
            .is_none()
    );
}
