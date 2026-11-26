// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A projected sync's preparation: it seals and registers like any sync,
//! closes the commit lane before admission reopens, and a refusal before its
//! boundary leaves the lane open and every reservation released.

use super::*;
use crate::writable_store::WritableStore;

pub(super) type Seal = Box<
    dyn FnOnce(&mut WritableStore<SimIo>) -> Result<Option<crate::SyncBoundary>, CoordinationError>
        + Send,
>;

pub(super) fn seal(target: SyncTarget) -> Seal {
    Box::new(move |local| local.overlay_transaction(|t| t.seal_sync(target)).map(Some))
}

/// The overlay's captured charge, which holds every engine graph, and its
/// reserve, which holds a projected replacement bound, freshly computed.
pub(super) fn reservations(f: &Fixture) -> (u64, u64) {
    let summary = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| Ok(t.observation()?.summary))
        .unwrap();
    (summary.captured_bytes, summary.reserved_bytes)
}

pub(super) fn lane_closed(f: &Fixture) -> bool {
    f.store.lock().unwrap().sync_provenance_for_test().2
}

fn records(f: &Fixture) -> u64 {
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| Ok(t.summary().records))
        .unwrap()
}

fn synced(f: &Fixture) -> String {
    f.metrics()
        .lines()
        .filter(|line| line.starts_with("granary_client_syncs_total"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn projected_seal_refusal_balances_graphs() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("x", b"projected");
    let initial = reservations(&fixture);
    let faults = fixture.store.lock().unwrap().fault_control();
    let mut cases = 0;
    for case in ["seal refuses", "target refuses", "preparation refuses"] {
        for round in 0..2 {
            let target = match case {
                "target refuses" => SyncTarget::Stage(stage + 100),
                _ => SyncTarget::Stage(stage),
            };
            let sealing: Seal = match case {
                "seal refuses" => Box::new(|_| Err(CoordinationError::Refused("SealRefused"))),
                _ => seal(target),
            };
            if case == "preparation refuses" {
                faults.arm("sync.capture", "after", 1, FaultAction::Fail);
            }
            let result = fixture
                .engine
                .prepare_projected(sealing, SyncOptions::default())
                .await;
            faults.resume();
            assert_eq!(
                (
                    result.is_err(),
                    reservations(&fixture),
                    lane_closed(&fixture),
                    fixture.remote.attempts.lock().unwrap().len(),
                ),
                (true, initial, false, 0),
                "{case}, round {round}: {result:?}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 6);
    fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .map(|capture| fixture.engine.discard_commit(capture).unwrap())
        .unwrap();
}

/// Two hundred directories, each create a record whose parent a projected
/// residual may lift: about 850 KB of replacement reserve.
fn directories(f: &Fixture) {
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            for i in 0..200 {
                t.namespace_record(Record::Create {
                    at: at(&format!("d{i}")),
                    kind: codec::CreateKind::Dir,
                })?;
            }
            Ok(())
        })
        .unwrap();
}

/// Refused at the projected lane's own reserve: the cap holds the sync's
/// graph and more than an ordinary sync needs, but not the replacement
/// bound. The refusal leaves every reservation as it found it.
#[tokio::test]
async fn projected_seal_refusal_at_the_lane_reserve_balances_graphs() {
    let measured = Fixture::new().await;
    directories(&measured);
    let (captured, reserved) = reservations(&measured);
    let charged = measured
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| Ok(t.observation()?.summary.charged_bytes))
        .unwrap();
    let cap = charged + captured + reserved + 425_000;
    let fixture = Fixture::over_capped(Basis::empty().await, cap)
        .await
        .unwrap();
    directories(&fixture);
    let initial = reservations(&fixture);
    let mut outcomes = Vec::new();
    for _ in 0..2 {
        let result = fixture
            .engine
            .prepare_projected(seal(SyncTarget::Directory(None)), SyncOptions::default())
            .await;
        let after = fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| Ok(t.observation()?.summary))
            .map(|summary| (summary.captured_bytes, summary.reserved_bytes))
            .map_err(|error| error.to_string());
        outcomes.push((
            matches!(
                result,
                Err(CoordinationError::Overlay(OverlayError::Refused(
                    "OverlayCapacityExhausted"
                )))
            ),
            after,
            lane_closed(&fixture),
        ));
    }
    // Control: the same cap admits an ordinary sync.
    let ordinary = fixture
        .engine
        .sync(SyncTarget::Directory(None), SyncOptions::default())
        .wait()
        .await
        .map_err(|error| error.to_string());
    assert_eq!(
        (outcomes, ordinary),
        (vec![(true, Ok(initial), false); 2], Ok(())),
        "a refused lane reserve releases what it reserved"
    );
}

#[tokio::test]
async fn projected_prepare_failure_reopens_admission() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("x", b"projected");
    let initial = reservations(&fixture);
    let faults = fixture.store.lock().unwrap().fault_control();
    // The lane closes before the prepared Register is sent; the send fails.
    faults.arm("sync.registration", "before_dispatch", 1, FaultAction::Fail);
    let refused = fixture
        .engine
        .prepare_projected(seal(SyncTarget::Stage(stage)), SyncOptions::default())
        .await;
    faults.resume();
    let retained = fixture.pending_registrations();
    let (queued, failed, lane) = fixture.store.lock().unwrap().sync_provenance_for_test();
    // Only the eligibility queue's charge for its one file stays, as after
    // any failed sync, until the next seal discards the drained queue.
    let queue = 256 + 512;
    assert_eq!(
        (
            refused.as_ref().err().map(ToString::to_string),
            lane,
            reservations(&fixture),
            retained.len(),
            retained.iter().all(|pending| pending.context.is_empty()),
            queued.is_empty(),
            failed.len(),
        ),
        (
            Some("intent refused: SyncInjectedFault".to_owned()),
            false,
            (initial.0 + queue, initial.1),
            1,
            true,
            true,
            1,
        ),
        "a failed projected preparation must keep its exact request and reopen the lane"
    );
    // The next sync and an ordinary commit both proceed.
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .map(|capture| fixture.engine.discard_commit(capture).unwrap())
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::too_many_lines,
    reason = "one held registration observes the closed lane, its reserve, a refused commit, a later write and the sealed context together"
)]
async fn projected_preparation_closes_before_other_commit() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("x", b"sealed");
    let sealed = records(&fixture);
    let observed = synced(&fixture);
    let initial = reservations(&fixture);
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        FaultAction::Block,
    );
    let mut preparing = Box::pin(
        fixture
            .engine
            .prepare_projected(seal(SyncTarget::Stage(stage)), SyncOptions::default()),
    );
    hold_at_seam(
        &mut preparing,
        &faults,
        "sync.registration",
        "before_dispatch",
    )
    .await;
    // The held lane reserves its replacement bound: x's create may take a
    // parent of the greatest legal length, and its stage a recreate.
    let held = reservations(&fixture);
    assert_eq!(
        (held.0 > initial.0, held.1 - initial.1),
        (true, 4226 + 2),
        "the projected seal reserves its lane before registration"
    );
    // Registration is held after the lane closed: no ordinary commit can
    // capture, while writes still proceed.
    let commit = fixture.engine.begin_commit(SyncOptions::default()).await;
    let written = fixture.store.lock().unwrap().overlay_transaction(|t| {
        t.write(stage, 6, b" later")?;
        t.create_file(at("w"), false)
    });
    assert_eq!(
        (
            lane_closed(&fixture),
            commit.as_ref().err().map(ToString::to_string),
            written.is_ok(),
        ),
        (
            true,
            Some("intent refused: SyncCommitInFlight".to_owned()),
            true
        ),
        "the projected lane must be closed before its registration is sent"
    );
    faults.resume();
    let capture = preparing.await.unwrap().unwrap();
    let entries: Vec<_> = capture
        .capture
        .entries()
        .iter()
        .map(|entry| {
            (
                entry.path.clone(),
                entry.size,
                matches!(entry.kind, OverlayKind::File { content: Some(_) }),
            )
        })
        .collect();
    assert_eq!(
        (
            entries,
            capture.capture.through_seq(),
            capture.accepted.boundary().through_seq(),
            capture.accepted.projection().entries().len(),
            capture.deadline > TokioSyncRuntime.now(),
            capture.root == fixture.remote.authority.lock().unwrap().root,
            capture.mapped.is_some(),
            lane_closed(&fixture),
            synced(&fixture) == observed,
        ),
        (
            vec![(vec![name("x")], 6, true)],
            sealed,
            sealed,
            1,
            true,
            true,
            true,
            true,
            true,
        ),
        "the capture binds its seal's cursor and projection, registered, under the lane, unobserved"
    );
    // The capture's own disposal reopens the lane and releases its charge.
    fixture.engine.discard_projected(capture).unwrap();
    fixture
        .engine
        .begin_commit(SyncOptions::default())
        .await
        .map(|capture| fixture.engine.discard_commit(capture).unwrap())
        .unwrap();
    fixture
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default())
        .wait()
        .await
        .unwrap();
    assert_ne!(
        synced(&fixture),
        observed,
        "control: a caller's own sync is observed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn projected_seal_waits_for_earlier_completions() {
    let fixture = Fixture::new().await;
    let earlier = fixture.create("y", b"earlier");
    let stage = fixture.create("x", b"projected");
    let faults = fixture.store.lock().unwrap().fault_control();
    // An earlier sync's answer arrives but is not yet applied: its capture
    // still owes completion.
    faults.arm("sync.registration", "after_response", 1, FaultAction::Block);
    let waiter = fixture
        .engine
        .sync(SyncTarget::Stage(earlier), SyncOptions::default());
    fired(&faults, "sync.registration", "after_response").await;
    let mut preparing = Box::pin(
        fixture
            .engine
            .prepare_projected(seal(SyncTarget::Stage(stage)), SyncOptions::default()),
    );
    let early = tokio::time::timeout(Duration::from_millis(200), &mut preparing).await;
    let sent = fixture.remote.attempts.lock().unwrap().len();
    faults.resume();
    waiter.wait().await.unwrap();
    // A seal that did not wait has finished already and cannot be awaited.
    let capture = if let Ok(prepared) = &early {
        format!("{prepared:?}")
    } else {
        let capture = preparing.await.unwrap().unwrap();
        let serial = capture.serial;
        fixture.engine.discard_projected(capture).unwrap();
        format!("{serial}")
    };
    assert_eq!(
        (
            early.is_err(),
            sent,
            fixture.remote.attempts.lock().unwrap().len(),
        ),
        (true, 1, 2),
        "the projected seal must wait until the earlier capture completes: {capture}"
    );
}

/// A projected preparation queued behind a lane wakes when that lane
/// reopens, far inside its own deadline: a commit's install, a discarded
/// commit construction and a discarded projected capture each wake it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn projected_preparation_queued_behind_a_lane_proceeds_once_it_installs_or_is_discarded() {
    let mut outcomes = Vec::new();
    for case in ["installed", "discarded", "projected discarded"] {
        let fixture = Fixture::new().await;
        fixture.create("x", b"committed");
        let (mut lane, mut capture, mut projected) = (None, None, None);
        match case {
            "installed" => {
                lane = Some(
                    fixture
                        .engine
                        .construct_commit(SyncOptions::default(), &mut Entropy(70))
                        .await
                        .unwrap(),
                );
            }
            "discarded" => {
                capture = Some(
                    fixture
                        .engine
                        .begin_commit(SyncOptions::default())
                        .await
                        .unwrap(),
                );
            }
            _ => {
                projected = fixture
                    .engine
                    .prepare_projected(seal(SyncTarget::Directory(None)), SyncOptions::default())
                    .await
                    .unwrap();
            }
        }
        let mut preparing = Box::pin(
            fixture
                .engine
                .prepare_projected(seal(SyncTarget::Directory(None)), SyncOptions::default()),
        );
        let queued = tokio::time::timeout(Duration::from_millis(100), &mut preparing).await;
        if let Some(lane) = lane {
            let landed = Box::pin(fixture.engine.drive_commit(
                &lane,
                &mut Entropy(80),
                &mut Delay,
                RecoveryIntent::Continue,
                SyncOptions::default(),
            ))
            .await
            .unwrap();
            assert!(matches!(landed.outcome, PublicationOutcome::Landed(_)));
        }
        if let Some(capture) = capture {
            fixture.engine.discard_commit(capture).unwrap();
        }
        if let Some(projected) = projected {
            fixture.engine.discard_projected(projected).unwrap();
        }
        let prepared = if queued.is_err() {
            tokio::time::timeout(Duration::from_secs(5), preparing)
                .await
                .map(|prepared| {
                    prepared
                        .map(|capture| capture.is_some())
                        .map_err(|e| e.to_string())
                })
        } else {
            Ok(Err("did not queue".to_owned()))
        };
        outcomes.push((case, queued.is_err(), prepared.ok()));
    }
    assert_eq!(
        outcomes,
        [
            ("installed", true, Some(Ok(true))),
            ("discarded", true, Some(Ok(true))),
            ("projected discarded", true, Some(Ok(true))),
        ],
        "a projected preparation queued behind a lane proceeds once that lane reopens"
    );
}

/// A settlement that refuses after the failed registration persisted leaves
/// the lane open and its reservations released, like any refusal after the
/// seal.
#[tokio::test]
async fn projected_settlement_refusal_reopens_the_lane() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("x", b"projected");
    let initial = reservations(&fixture);
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("sync.registration", "before_dispatch", 1, FaultAction::Fail);
    fixture.engine.refuse_next_settle_for_test();
    let refused = fixture
        .engine
        .prepare_projected(seal(SyncTarget::Stage(stage)), SyncOptions::default())
        .await;
    faults.resume();
    // As after any failed sync, the eligibility queue keeps its one file's
    // charge until the next seal discards it.
    let queue = 256 + 512;
    assert_eq!(
        (
            refused.as_ref().err().map(ToString::to_string),
            lane_closed(&fixture),
            reservations(&fixture),
        ),
        (
            Some("intent refused: SyncInjectedFault".to_owned()),
            false,
            (initial.0 + queue, initial.1),
        ),
        "a refused settlement must reopen the lane and release its reservations"
    );
    fixture
        .engine
        .prepare_projected(seal(SyncTarget::Stage(stage)), SyncOptions::default())
        .await
        .map(|capture| fixture.engine.discard_projected(capture.unwrap()).unwrap())
        .unwrap();
}

/// A failed caller's disposition that does not persist poisons the store:
/// the lane stays closed, the documented exception.
#[tokio::test]
async fn projected_disposition_persistence_failure_keeps_the_lane_closed() {
    let fixture = Fixture::new().await;
    let stage = fixture.create("x", b"projected");
    let faults = fixture.store.lock().unwrap().fault_control();
    faults.arm("intent.pending", "build", 18, FaultAction::Fail);
    fixture.remote.hold_first.store(true, Ordering::Relaxed);
    fixture.remote.unknown.store(true, Ordering::Relaxed);
    let mut preparing = Box::pin(
        fixture
            .engine
            .prepare_projected(seal(SyncTarget::Stage(stage)), SyncOptions::default()),
    );
    let mut entered = Box::pin(fixture.remote.entered.notified());
    std::future::poll_fn(|cx| {
        assert!(
            preparing.as_mut().poll(cx).is_pending(),
            "preparation ended before its send"
        );
        entered.as_mut().poll(cx)
    })
    .await;
    tokio::time::pause();
    fixture.remote.release.notify_one();
    let result = preparing.await;
    let poisoned = fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0))
        .err()
        .map(|error| error.to_string());
    assert_eq!(
        (
            result.is_err(),
            faults.fired().len(),
            lane_closed(&fixture),
            poisoned,
        ),
        (
            true,
            1,
            true,
            Some("intent refused: IntentPersistencePoisoned".to_owned()),
        ),
        "an unpersisted disposition must poison and keep the lane closed: {result:?}"
    );
}
