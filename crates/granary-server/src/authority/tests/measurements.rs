// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in wall-clock measurements. Collection and export belong to the harness.

use super::*;
use std::time::Instant;

mod capture;
mod hostile;
mod io;
mod observers;
mod occupancy;
mod output;
mod pivot;
mod rows;
mod server_child;
mod trace;
mod transport;
use capture::Capture;

#[expect(
    clippy::disallowed_methods,
    reason = "the independent harness stopwatch is the measurement's subject"
)]
fn stopwatch() -> Instant {
    Instant::now()
}

/// Catches missing callsites, queue spans closed after service, and a poll
/// span around the whole driver instead of individual slots.
#[test]
fn authority_measurement_spans_bound_the_named_work() {
    let capture = Capture::new(4096);
    let dispatch = tracing::Dispatch::new(capture.clone());
    tracing::dispatcher::with_default(&dispatch, || {
        let world = World::with_empty_logs(&[a(), b()], Faults::none());
        let (handle, driver) = world.start(&[a(), b()]);
        let (end, answers) = run_beside(0, driver, async move {
            let bytes = good_root(&a(), 1, None, 1);
            let first = handle.submit(submission(&a(), 1, &bytes)).await;
            let again = handle.submit(submission(&a(), 1, &bytes)).await;
            handle.stop().await;
            (first, again)
        });
        assert_eq!(end, RunEnd::Stopped);
        assert!(matches!(answers.0, Answer::Accepted { .. }), "{answers:?}");
    });
    let (samples, lost) = capture.take();
    assert_eq!(lost, 0);
    for (name, phase) in [
        ("authority_queue", ""),
        ("authority_validation", ""),
        ("authority_chain", "resolve_head"),
        ("authority_chain", "classify_seq"),
        ("authority_log_wait", ""),
        ("authority_worker_poll", ""),
    ] {
        assert!(
            samples.iter().any(|s| s.name == name && s.phase == phase),
            "missing span {name}/{phase}; captured={samples:?}"
        );
    }
    let queues: Vec<_> = samples
        .iter()
        .filter(|s| s.name == "authority_queue")
        .collect();
    assert_eq!(queues.len(), 2, "both submissions close their queue spans");
    for queue in queues {
        assert!(
            samples
                .iter()
                .any(|s| s.name == "authority_validation" && s.start >= queue.end),
            "queue must close before validation: {queue:?}"
        );
    }
    for slot in 0..2 {
        assert!(
            samples
                .iter()
                .any(|s| s.name == "authority_worker_poll" && s.slot == slot),
            "missing per-slot poll {slot}"
        );
    }
}

#[test]
fn authority_measurement_log_wait_ends_before_the_log_call() {
    let capture = Capture::new(64);
    let dispatch = tracing::Dispatch::new(capture.clone());
    tracing::dispatcher::with_default(&dispatch, || {
        let result = block(async move {
            let gate = LogGate::default();
            let fence = super::super::gate::FenceCell::default();
            gate.settling(
                &fence,
                LogCall::Append,
                None,
                || {
                    let (spans, lost) = capture.take();
                    assert_eq!(lost, 0);
                    assert!(
                        spans.iter().any(|s| s.name == "authority_log_wait"),
                        "log wait must close before the log call: {spans:?}"
                    );
                    async { Ok(()) }
                },
                |value| value.map_err(FenceCause::Failed),
            )
            .await
        });
        assert_eq!(result, Ok(()));
    });
}

#[test]
fn authority_measurement_queue_closes_while_publication_is_open() {
    let capture = Capture::new(4096);
    let dispatch = tracing::Dispatch::new(capture.clone());
    let probe = capture.clone();
    tracing::dispatcher::with_default(&dispatch, || {
        let world = World::with_empty_logs(&[a()], Faults::none());
        world.store.hold_read(&a(), 1);
        let held = world.store.clone();
        let (handle, driver) = world.start(&[a()]);
        let (end, answer) =
            run_beside(0, driver, async move {
                let bytes = good_root(&a(), 1, None, 1);
                assert!(matches!(
                    handle.submit(submission(&a(), 1, &bytes)).await,
                    Answer::Accepted { .. }
                ));
                for _ in 0..64 {
                    if held.hold_reached() {
                        break;
                    }
                    yield_once().await;
                }
                assert!(
                    held.hold_reached(),
                    "classification did not reach the held read"
                );
                probe.take();
                let answer = handle.submit(submission(&a(), 1, &bytes)).await;
                let (samples, lost) = probe.take();
                assert_eq!(lost, 0);
                let queues: Vec<_> = samples
                    .iter()
                    .filter(|s| s.name == "authority_queue")
                    .collect();
                assert_eq!(
                    queues.len(),
                    1,
                    "Serving::answer must close the queued submission: {samples:?}"
                );
                assert!(
                    samples.iter().any(|s| s.name == "authority_validation"
                        && s.start >= queues.first().unwrap().end),
                    "queue must close before open-entry validation: {samples:?}"
                );
                held.release();
                handle.stop().await;
                answer
            });
        assert_eq!(end, RunEnd::Stopped);
        assert!(matches!(answer, Answer::Open { .. }), "{answer:?}");
    });
}

#[test]
fn authority_measurement_collector_reports_lost_samples() {
    let capture = Capture::new(1);
    let dispatch = tracing::Dispatch::new(capture.clone());
    tracing::dispatcher::with_default(&dispatch, || {
        drop(tracing::trace_span!("authority_validation"));
        drop(tracing::trace_span!("authority_validation"));
    });
    let (samples, lost) = capture.take();
    assert_eq!(
        (samples.len(), lost),
        (1, 1),
        "overflow must be visible, not a smaller apparently complete population"
    );
    let (samples, lost) = capture.take();
    assert_eq!((samples.len(), lost), (0, 0));
}

#[test]
fn authority_measurement_validation_includes_a_malformed_candidate() {
    let capture = Capture::new(4096);
    let dispatch = tracing::Dispatch::new(capture.clone());
    tracing::dispatcher::with_default(&dispatch, || {
        let world = World::with_empty_logs(&[a()], Faults::none());
        let (handle, driver) = world.start(&[a()]);
        let (_, answer) = run_beside(0, driver, async move {
            let answer = handle.submit(submission(&a(), 1, b"invalid root")).await;
            handle.stop().await;
            answer
        });
        assert!(matches!(answer, Answer::InvalidCandidate(_)), "{answer:?}");
    });
    let (samples, lost) = capture.take();
    assert_eq!(lost, 0);
    assert_eq!(
        samples
            .iter()
            .filter(|s| s.name == "authority_validation")
            .count(),
        1,
        "validation must span decoding refusals too: {samples:?}"
    );
}

#[test]
fn authority_measurement_chain_spans_cover_both_entry_points() {
    let capture = Capture::new(128);
    let dispatch = tracing::Dispatch::new(capture.clone());
    tracing::dispatcher::with_default(&dispatch, || {
        block(async {
            let store = TestStore::new(Sim::new().node(1, Faults::none()));
            let keys = TrustedKeys::new([*publisher().public_key()]).unwrap();
            let bytes = good_root(&a(), 1, None, 1);
            store
                .put_root(a().as_str(), 1, bytes.clone())
                .await
                .unwrap();
            let mut memo = super::super::chain::ChainMemo::default();
            assert!(
                super::super::chain::resolve_head(&store, &a(), &keys, &mut memo)
                    .await
                    .is_ok()
            );
            assert_eq!(
                super::super::chain::classify_seq(&store, &a(), &keys, 1, None, &bytes).await,
                super::super::chain::Classification::Landed
            );
            store.set_read_fault(&a(), 1, Some(ReadFault::Transport));
            assert_eq!(
                super::super::chain::resolve_head(&store, &a(), &keys, &mut memo).await,
                Err(super::super::chain::Unverified::Unread)
            );
            assert_eq!(
                super::super::chain::classify_seq(&store, &a(), &keys, 1, None, &bytes).await,
                super::super::chain::Classification::Unresolved
            );
        });
    });
    let (samples, lost) = capture.take();
    assert_eq!(lost, 0);
    for phase in ["resolve_head", "classify_seq"] {
        assert_eq!(
            samples
                .iter()
                .filter(|s| s.name == "authority_chain" && s.phase == phase)
                .count(),
            2,
            "chain phase {phase} must cover success and failed reads: {samples:?}"
        );
    }
}

#[test]
fn authority_measurement_poll_spans_name_each_unfinished_slot() {
    let capture = Capture::new(128);
    let dispatch = tracing::Dispatch::new(capture.clone());
    tracing::dispatcher::with_default(&dispatch, || {
        use super::super::join::{JoinAll, Joined};
        let futures: Vec<Joined<'_>> = vec![Box::pin(async {}), Box::pin(std::future::pending())];
        let mut joined = Box::pin(JoinAll::new(futures));
        assert!(
            joined
                .as_mut()
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
                .is_pending()
        );
    });
    let (samples, lost) = capture.take();
    assert_eq!(lost, 0);
    let slots: Vec<_> = samples
        .iter()
        .filter(|s| s.name == "authority_worker_poll")
        .map(|s| s.slot)
        .collect();
    assert_eq!(
        slots,
        [0, 1, 1],
        "the finished slot is not polled on the second pass"
    );
}
