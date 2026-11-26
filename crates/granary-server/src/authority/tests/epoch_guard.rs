// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule 0's precedence, fresh evidence, and the handle's terminal precedence.

use std::future::poll_fn;
use std::pin::pin;
use std::task::Poll;

use super::*;

fn old_epoch() -> Epoch {
    Epoch::from_bytes([0xFF; EPOCH_LEN])
}

fn mismatch(head: Option<VerifiedHead>) -> Answer {
    Answer::EpochMismatch {
        epoch: World::position(1).epoch,
        head,
    }
}

fn head(seq: u64, bytes: &[u8]) -> VerifiedHead {
    VerifiedHead::new(Some(HeadRef {
        head_seq: seq,
        head_id: GrainId::of(bytes),
    }))
}

#[test]
fn epoch_guard_precedes_all_candidate_and_binding_checks() {
    let c1 = good_root(&a(), 1, None, 1);
    let c2 = good_root(&a(), 2, Some(GrainId::of(&c1)), 1);
    let foreign = good_root(&a(), 2, Some(GrainId::of(&c1)), 2);
    let d1 = decision_of(1, 1, &c1);
    let d2 = decision_of(2, 2, &c2);
    let records = vec![
        d1.clone(),
        attestation(&d1),
        landed(&d1),
        d2.clone(),
        attestation(&d2),
        lost(&d2, GrainId::of(&foreign)),
    ];
    let world = World::with_records(&a(), &records, Faults::none());
    world.plant(&a(), 1, &c1);
    world.plant(&a(), 2, &foreign);
    let before = read_log(&world.log, &a());
    let (handle, driver) = world.start(&[a()]);
    let store = world.store.clone();
    let admin = world.sim.admin();
    let (end, ()) = run_beside(0, driver, async move {
        let next = good_root(&a(), 3, Some(GrainId::of(&foreign)), 1);
        for (operation, candidate) in [
            (1, b"malformed".as_slice()), // decoding before binding
            (1, c1.as_slice()),           // recorded landed candidate
            (2, c2.as_slice()),           // recorded lost candidate
            (1, next.as_slice()),         // landed binding
            (3, next.as_slice()),         // otherwise eligible for a decision
        ] {
            let sub = submission_at(old_epoch(), &a(), operation, candidate);
            assert_eq!(sub.epoch(), old_epoch());
            assert_eq!(
                handle.submit(sub).await,
                mismatch(Some(head(2, &foreign))),
                "epoch guard must precede candidate and binding checks"
            );
        }
        let sub = submission_at(old_epoch(), &a(), 1, b"malformed");
        assert!(admin.delete_root(&a(), 2));
        assert_eq!(
            handle.submit(sub.clone()).await,
            mismatch(Some(head(1, &c1))),
            "head must be resolved afresh after an out-of-band change"
        );
        store.set_read_fault(&a(), 1, Some(ReadFault::Transport));
        assert_eq!(
            handle.submit(sub.clone()).await,
            mismatch(None),
            "failed head read"
        );
        store.set_read_fault(&a(), 1, None);
        assert!(admin.delete_root(&a(), 1));
        assert!(admin.plant_root(&a(), 1, b"invalid stored root".to_vec()));
        assert_eq!(
            handle.submit(sub.clone()).await,
            mismatch(None),
            "failed head verification"
        );
        assert!(admin.delete_root(&a(), 1));
        assert_eq!(
            handle.submit(sub).await,
            mismatch(Some(VerifiedHead::new(None)))
        );
        assert!(
            matches!(
                handle.submit(submission(&a(), 1, &c1)).await,
                Answer::Landed { .. }
            ),
            "matching epochs still reach recorded-candidate lookup"
        );
        handle.stop().await;
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(
        read_log(&world.log, &a()),
        before,
        "mismatch writes nothing"
    );
    assert!(calls(&world.sim, "append").is_empty());
    assert!(world.puts(&a(), 1).is_empty());
    assert_eq!(world.log.violations(), []);
}

#[test]
fn epoch_guard_covers_open_publication() {
    let c1 = good_root(&a(), 1, None, 1);
    let d1 = decision_of(1, 1, &c1);
    let world = World::with_records(&a(), &[d1.clone(), attestation(&d1)], Faults::none());
    // A held publication read lets the serving loop answer with the entry open.
    world.plant(&a(), 1, &c1);
    world.store.hold_read(&a(), 1);
    let store = world.store.clone();
    let before = read_log(&world.log, &a());
    let log = Arc::clone(&world.log);
    let (handle, driver) = world.start(&[a()]);
    let (end, ()) = run_beside(0, driver, async move {
        while !store.hold_reached() {
            yield_once().await;
        }
        let next = good_root(&a(), 2, Some(GrainId::of(&c1)), 1);
        for (operation, candidate) in [
            (1, b"malformed".as_slice()),
            (1, c1.as_slice()),   // recorded open candidate
            (1, next.as_slice()), // open binding
            (2, next.as_slice()), // otherwise NotDecided
        ] {
            assert_eq!(
                handle
                    .submit(submission_at(old_epoch(), &a(), operation, candidate))
                    .await,
                mismatch(Some(head(1, &c1))),
                "epoch guard must run while publication is open"
            );
            assert_eq!(
                handle.volume_view(&a()),
                Some(VolumeView::Log {
                    epoch: World::position(1).epoch,
                    head: Some(head(1, &c1)),
                    open: Some(OpenPosition {
                        entry_seq: 1,
                        candidate_id: GrainId::of(&c1)
                    }),
                })
            );
        }
        store.set_read_fault(&a(), 1, Some(ReadFault::Transport));
        assert_eq!(
            handle
                .submit(submission_at(old_epoch(), &a(), 1, b"malformed"))
                .await,
            mismatch(None)
        );
        assert_eq!(
            handle.volume_view(&a()),
            Some(VolumeView::Log {
                epoch: World::position(1).epoch,
                head: None,
                open: Some(OpenPosition {
                    entry_seq: 1,
                    candidate_id: GrainId::of(&c1)
                }),
            })
        );
        store.set_read_fault(&a(), 1, None);
        assert_eq!(
            log.read(&a()).await.unwrap(),
            before,
            "mismatch writes nothing while open"
        );
        assert!(matches!(
            handle.submit(submission(&a(), 1, &c1)).await,
            Answer::Open { .. }
        ));
        store.release();
        handle.stop().await;
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(world.log.violations(), []);
}

#[test]
fn no_log_has_no_epoch() {
    let world = World::new(Faults::none());
    let (handle, driver) = world.start(&[a()]);
    let (end, ()) = run_beside(0, driver, async move {
        for epoch in [
            old_epoch(),
            World::position(1).epoch,
            Epoch::from_bytes([0; EPOCH_LEN]),
        ] {
            assert_eq!(
                handle
                    .submit(submission_at(epoch, &a(), 1, b"malformed"))
                    .await,
                Answer::NoLog,
                "a missing log has no epoch to mismatch"
            );
        }
        handle.stop().await;
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(read_log(&world.log, &a()), None);
    assert!(calls(&world.sim, "initialise").is_empty());
    assert!(calls(&world.sim, "append").is_empty());
    assert!(
        world
            .sim
            .trace()
            .render()
            .lines()
            .all(|line| !line.contains("max-seq") && !line.contains("get-root")),
        "NoLog needs no head read"
    );
}

#[test]
fn requested_stop_precedes_volume_lookup_while_worker_is_held() {
    for seed_n in 0..8 {
        let c1 = good_root(&a(), 1, None, 1);
        let d1 = decision_of(1, 1, &c1);
        let world = World::with_records(&a(), &[d1.clone(), attestation(&d1)], Faults::none());
        world.store.hold_read(&a(), 1);
        let (handle, driver) = world.start(&[a()]);
        let store = world.store.clone();
        let (end, stopped) = run_beside(seed_n, driver, async move {
            while !store.hold_reached() {
                yield_once().await;
            }
            let mut stop = pin!(handle.stop());
            poll_fn(|cx| {
                assert!(stop.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert!(handle.inner.shared.stop.requested());
            assert!(handle.inner.ended.borrow().is_none());
            assert_eq!(
                handle
                    .submit(submission_at(old_epoch(), &b(), 1, b"malformed"))
                    .await,
                Answer::Stopped,
                "seed {seed_n}: requested stop must precede volume lookup"
            );
            store.release();
            stop.await
        });
        assert_eq!(end, RunEnd::Stopped, "seed {seed_n}");
        assert_eq!(stopped, RunEnd::Stopped, "seed {seed_n}");
        assert_eq!(world.log.violations(), [], "seed {seed_n}");
    }
}

#[test]
fn requested_stop_precedes_initialise_volume_lookup_while_worker_is_held() {
    for seed_n in 0..8 {
        let c1 = good_root(&a(), 1, None, 1);
        let d1 = decision_of(1, 1, &c1);
        let world = World::with_records(&a(), &[d1.clone(), attestation(&d1)], Faults::none());
        world.store.hold_read(&a(), 1);
        let (handle, driver) = world.start(&[a()]);
        let store = world.store.clone();
        let (end, stopped) = run_beside(seed_n, driver, async move {
            while !store.hold_reached() {
                yield_once().await;
            }
            let mut stop = pin!(handle.stop());
            poll_fn(|cx| {
                assert!(stop.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert!(handle.inner.shared.stop.requested());
            assert!(handle.inner.ended.borrow().is_none());
            assert_eq!(
                handle.initialise(&b()).await,
                Err(InitialiseError::Stopped),
                "seed {seed_n}: requested stop must precede initialise volume lookup"
            );
            store.release();
            stop.await
        });
        assert_eq!(end, RunEnd::Stopped, "seed {seed_n}");
        assert_eq!(stopped, RunEnd::Stopped, "seed {seed_n}");
        assert_eq!(world.log.violations(), [], "seed {seed_n}");
    }
}

#[test]
fn terminal_authority_precedes_volume_lookup() {
    for abandoned in [false, true] {
        let world = World::with_empty_logs(&[a()], Faults::none());
        let (handle, driver) = world.start(&[a()]);
        if abandoned {
            drop(driver);
            assert_eq!(
                block({
                    let handle = handle.clone();
                    async move { handle.stop().await }
                }),
                RunEnd::Abandoned
            );
        } else {
            let stop = handle.clone();
            assert_eq!(
                run_beside(0, driver, async move { stop.stop().await }).0,
                RunEnd::Stopped
            );
        }
        for volume in [a(), b()] {
            let handle = handle.clone();
            assert_eq!(
                block(async move {
                    handle
                        .submit(submission_at(old_epoch(), &volume, 1, b"malformed"))
                        .await
                }),
                Answer::Stopped,
                "terminal authority must precede volume lookup (abandoned={abandoned})"
            );
        }
        let shared = Arc::clone(&handle.inner.shared);
        block(async move {
            super::super::gate::LogGate::default()
                .fence(
                    &shared.fence,
                    Fence {
                        call: LogCall::WriteMarker,
                        volume: None,
                        cause: FenceCause::Failed(LogIoError::SyncFailed),
                    },
                )
                .await;
        });
        for volume in [a(), b()] {
            let handle = handle.clone();
            assert_eq!(
                block(async move {
                    handle
                        .submit(submission_at(old_epoch(), &volume, 1, b"malformed"))
                        .await
                }),
                Answer::Fenced,
                "fence retains precedence over terminal state"
            );
        }
    }
}

#[test]
fn in_flight_epoch_answer_finishes_before_wedge_clears_memo() {
    use std::sync::atomic::AtomicBool;

    use super::observation::assert_verified_status;
    use super::publication::{
        HeldPause, ScriptedVolume, list_above, list_roots, read_root, wait_until, write_root,
    };

    let base_world = ScriptedVolume::new(&[]);
    let base = Some(GrainId::of(&base_world.plant(4)[3]));
    let candidate = good_root(&a(), 5, base, 1);
    let occupant = good_root(&a(), 5, base, 2);
    let newer = good_root(&a(), 6, Some(GrainId::of(&occupant)), 3);
    let decision = decision_of(1, 1, &candidate);
    let records = [decision.clone(), attestation(&decision)];
    let world = ScriptedVolume::new(&records);
    world.plant(4);
    let put = write_root(5, &candidate);
    world.store.fail(put.clone(), false);
    let pause = HeldPause::default();
    let (handle, driver) = world.start(pause.clone());
    let store = world.store.clone();
    let (end, ()) = run_beside(0, driver, async move {
        pause.wait(1).await;
        store.set(a().as_str(), 5, Some(occupant.clone()));
        let sub = submission_at(old_epoch(), &a(), 1, b"epoch probe");
        let prior = Some(head(5, &occupant));
        assert_eq!(handle.submit(sub.clone()).await, mismatch(prior));
        let open = OpenPosition {
            entry_seq: 1,
            candidate_id: GrainId::of(&candidate),
        };
        assert_verified_status(&handle, prior, open);

        store.set(a().as_str(), 6, Some(newer.clone()));
        store.set(a().as_str(), 2, None);
        assert!(!store.take_calls().is_empty());
        let held_put = store.park(put.clone());
        pause.release();
        wait_until(|| held_put.reached()).await;
        let held_read = store.park(read_root(4));
        let classified = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&classified);
        store.after(read_root(2), move |_| flag.store(true, Ordering::SeqCst));
        let mut reply = pin!(handle.submit(sub.clone()));
        poll_fn(|cx| {
            assert!(reply.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        wait_until(|| held_read.reached()).await;
        held_put.release();
        wait_until(|| classified.load(Ordering::SeqCst)).await;
        assert_verified_status(&handle, prior, open);
        held_read.release();

        let after = Some(head(6, &newer));
        assert_eq!(reply.await, mismatch(after));
        assert_verified_status(&handle, after, open);
        pause.wait(2).await;
        assert_eq!(
            store.take_calls(),
            [
                put,
                list_above(4),
                read_root(6),
                read_root(5),
                read_root(4),
                read_root(5),
                read_root(4),
                read_root(3),
                read_root(2)
            ]
        );
        let rows = handle.report(AMPLE_BOUND).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, StuckState::Wedged);
        assert_eq!(
            handle.submit(submission(&a(), 1, &newer)).await,
            Answer::OperationBound(Bound::Open {
                position: World::position(1),
                candidate_id: open.candidate_id
            })
        );
        assert_verified_status(&handle, after, open);
        assert_eq!(store.take_calls(), []);

        assert_eq!(handle.submit(sub).await, mismatch(None));
        assert_eq!(
            store.take_calls(),
            [
                list_roots(),
                read_root(6),
                read_root(5),
                read_root(4),
                read_root(3),
                read_root(2)
            ]
        );
        assert_verified_status(&handle, None, open);
        handle.stop().await;
    });
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(committed(&world.log, &a()), records);
}
