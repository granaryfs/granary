// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::blocked::{Probe, instrument};
use super::*;

#[tokio::test]
async fn status_publication_follows_commit() {
    for lost_outcome in [false, true] {
        let candidate = good_root(&a(), 1, None, 1);
        let d = decision_for(&candidate);
        let (fx, driver) = Fx::new(false, &[a()], &[]).await;
        let probe = Arc::new(Probe::default());
        let mut driver = instrument(driver, probe.clone());
        let mut worker = driver.workers.remove(0);
        let verified = lost_outcome.then_some(VerifiedHead::new(None));
        fx.handle.inner.views[&a()].verified(worker.state(), verified);
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
        let outcome = if lost_outcome {
            lost(&d, GrainId::of(b"other"))
        } else {
            landed(&d)
        };
        for (n, record) in [d.clone(), attestation(&d), outcome].iter().enumerate() {
            let before = fx.handle.volume_view(&a());
            probe.arm(false);
            let mut commit = pin!(worker.commit(&engine, record));
            poll_fn(|cx| {
                assert!(commit.as_mut().poll(cx).is_pending());
                if probe.entered.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
            assert_eq!(
                fx.handle.volume_view(&a()),
                before,
                "record {n} is not durable"
            );
            let calls = probe.calls.load(Ordering::SeqCst);
            status_bytes(fx.send(get(&a())).await, 200, None).await;
            assert_eq!(probe.calls.load(Ordering::SeqCst), calls);
            probe.released.store(true, Ordering::SeqCst);
            commit.await.unwrap();
            let value = fx.handle.volume_view(&a()).unwrap().status().unwrap();
            assert_eq!(
                value.head,
                verified.map(|_| codec::Head::new(None)),
                "commits preserve the last verification"
            );
            assert_eq!(
                value.open,
                (n < 2).then_some(codec::OpenPosition {
                    entry_seq: 1,
                    candidate_id: GrainId::of(&candidate)
                })
            );
        }
    }
}

#[tokio::test]
async fn status_failed_append_or_apply_leaves_view_unchanged() {
    for failure in 0..3 {
        let (fx, driver) = Fx::new(false, &[a()], &[]).await;
        let probe = Arc::new(Probe::default());
        let mut driver = instrument(driver, probe.clone());
        let mut worker = driver.workers.remove(0);
        let d = decision_for(&good_root(&a(), 1, None, 1));
        if failure == 0 {
            probe.fail.store(true, Ordering::SeqCst);
        }
        if failure == 1 {
            worker.state_mut().unwrap().refuse_next_apply(ApplyError {
                seq: 1,
                rule: GrammarRule::Rule1SequencePosition,
            });
        }
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
        let before = fx.handle.volume_view(&a());
        let record = if failure == 2 { attestation(&d) } else { d };
        assert!(worker.commit(&engine, &record).await.is_err());
        assert_eq!(fx.handle.volume_view(&a()), before);
        assert_eq!(
            fx.handle.terminal_state(),
            if failure < 2 {
                Some(TerminalState::Fenced)
            } else {
                None
            }
        );
    }
}

#[tokio::test]
async fn status_replay_and_initialise() {
    let candidate = good_root(&a(), 1, None, 1);
    let d = decision_for(&candidate);
    for records in [
        vec![d.clone()],
        vec![d.clone(), attestation(&d)],
        vec![d.clone(), attestation(&d), landed(&d)],
    ] {
        let (fx, driver) = Fx::new(false, &[a()], &records).await;
        let view = fx.handle.volume_view(&a()).unwrap().status().unwrap();
        assert_eq!(view.head, None);
        assert_eq!(view.epoch, Epoch::from_bytes([WORLD_EPOCH; 16]));
        assert_eq!(view.open.is_some(), records.len() < 3);
        let mut run = spawn_driver(driver);
        // A refused initialise cannot replace a recovered log projection.
        let before_epoch = view.epoch;
        assert_eq!(
            fx.handle.initialise(&a()).await,
            Err(InitialiseError::LogHasRecords)
        );
        assert_eq!(
            fx.handle.volume_view(&a()).unwrap().status().unwrap().epoch,
            before_epoch
        );
        fx.handle.stop().await;
        run.join_next().await.unwrap().unwrap();
    }
    let (fx, driver) = Fx::new(false, &[], &[]).await;
    let mut run = spawn_driver(driver);
    assert_eq!(fx.handle.volume_view(&a()), Some(VolumeView::NoLog));
    let Initialised::Created { epoch } = fx.handle.initialise(&a()).await.unwrap() else {
        panic!("created")
    };
    let view =
        codec::decode_status(&status_bytes(fx.send(get(&a())).await, 200, None).await).unwrap();
    assert_eq!(
        view,
        codec::VolumeStatus {
            epoch,
            head: None,
            open: None
        }
    );
    fx.handle
        .submit(submission_at(
            Epoch::from_bytes([0xFF; 16]),
            &a(),
            1,
            b"invalid",
        ))
        .await;
    let view = codec::VolumeStatus {
        head: Some(codec::Head::new(None)),
        ..view
    };
    assert_eq!(
        fx.handle.initialise(&a()).await,
        Ok(Initialised::Kept { epoch })
    );
    assert_eq!(fx.handle.volume_view(&a()).unwrap().status().unwrap(), view);
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}
