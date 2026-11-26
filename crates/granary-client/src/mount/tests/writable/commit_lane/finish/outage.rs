// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A start that finishes a commit while the authority answers
//! `503 unavailable` later than the start's own phase bound.

use super::*;
use std::time::Duration;

/// The phase bound the starts run under.
const PHASE: Duration = Duration::from_secs(2);
/// How long the authority takes to answer `503 unavailable`.
const SLOW: Duration = Duration::from_secs(3);
/// More start attempts than the charged budget of eight allows.
const ATTEMPTS: usize = 9;
const CAP: u16 = 64;

/// A retained lane whose first drive was cut before its submission, on a
/// stopped process: the next start finishes it.
fn retained_lane(exemptions: u16) -> Stopped {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    let object = dirty(&mut fixture);
    fixture
        .faults
        .arm("sync.commit", "before_submit", 1, crate::FaultAction::Fail);
    let lane = fixture.construct(70).unwrap();
    let cut = fixture.drive(&lane, 80);
    assert!(
        cut.as_ref()
            .is_err_and(|error| error.to_string().contains("SyncInjectedFault")),
        "premise: the first drive is cut: {cut:?}"
    );
    fixture
        .ready
        .backend_for_test()
        .overlay_close(object)
        .unwrap();
    if exemptions > 0 {
        fixture
            .mediator()
            .with(|store| {
                let scope = store.snapshot().scope.clone();
                let volume = store.snapshot().volume.clone();
                let mut record = store
                    .publication_transaction(|j| j.load(&scope, &volume))?
                    .unwrap();
                let generation = record.generation;
                record.generation += 1;
                record.unavailable_exemptions = exemptions;
                store.overlay_transaction(|t| {
                    for attempt in 1..=u64::from(exemptions) {
                        t.record_commit_attempt(
                            lane.boundary_seq(),
                            record.publication_id,
                            attempt,
                        )?;
                    }
                    Ok(())
                })?;
                store.publication_transaction(|j| j.replace(generation, &record))
            })
            .unwrap();
    }
    stop(fixture)
}

/// A shutdown cut before constructing a commit, leaving a dirty journal only.
pub(super) fn residual_work() -> Stopped {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(fixture.ready.backend_for_test(), "a", DIRTY);
    fixture.faults.arm(
        "sync.registration",
        "before_dispatch",
        1,
        crate::FaultAction::Block,
    );
    let (cut, stopped) = shut_down(fixture, BOUND, no_shutdown_change);
    assert_eq!(
        (cut, retained_evidence(&stopped)),
        (Outcome::Incomplete(Cause::Deadline), None),
        "premise: shutdown cut before a commit was retained"
    );
    stopped
}

/// Durably retained attempts, exemptions and fence after a process stops.
pub(super) fn retained_evidence(stopped: &Stopped) -> Option<(u64, u16, bool)> {
    let input = input(&stopped.tree, &stopped.paths);
    let mut store = Store::open(&stopped.paths.store).unwrap();
    let record = store
        .publications(input.euid)
        .unwrap()
        .load(input.scope.as_ref().unwrap(), &input.volume)
        .unwrap()?;
    let bytes = std::fs::read(overlay_area(&stopped.paths, &input).join("journal")).unwrap();
    let progress = journal::scan_journal(&bytes)
        .unwrap()
        .state
        .commit_progress(&record.publication_id)?;
    Some((
        progress.attempts,
        record.unavailable_exemptions,
        progress.fenced,
    ))
}

#[test]
fn start_attempts_during_a_slow_503_outage_do_not_fence_the_store() {
    slow_outage(&retained_lane(0), b"f.txt", &dirty_bytes());
}

#[test]
fn residual_start_attempts_during_a_slow_503_outage_do_not_fence_the_store() {
    slow_outage(&residual_work(), b"a", DIRTY);
}

/// The first start after nine unavailable answers lands the retained commit.
fn slow_outage(stopped: &Stopped, path: &[u8], expected_bytes: &[u8]) {
    let rt = runtime();
    let base = remote_seq(&stopped.tree, &rt);
    stopped.state.lock().unwrap().publish_unavailable = Some((usize::MAX, SLOW));
    finish_hooks_for_test(FinishHooks {
        bound: Some(PHASE),
        ..FinishHooks::default()
    });
    let before = publications(stopped);
    let outcomes: Vec<_> = (0..ATTEMPTS)
        .map(|_| {
            let events = Events::default();
            (outcome(&restart(stopped, &events)), start_endings(&events))
        })
        .collect();
    finish_hooks_for_test(FinishHooks::default());
    let sent = publications(stopped) - before;
    let retained = retained_evidence(stopped);
    stopped.state.lock().unwrap().publish_unavailable = None;
    let events = Events::default();
    let mut after = restart(stopped, &events);
    let bytes = after.as_mut().ok().map(|ready| read_back(ready, path));
    assert_eq!(
        (
            outcomes,
            sent,
            retained,
            outcome(&after),
            remote_seq(&stopped.tree, &rt),
            bytes,
        ),
        (
            vec![("WritableAuthorityUnavailable", start_incomplete("failed")); ATTEMPTS],
            ATTEMPTS,
            Some((ATTEMPTS as u64, u16::try_from(ATTEMPTS).unwrap(), false)),
            "Ok",
            base + 1,
            Some(Ok(expected_bytes.to_vec())),
        ),
        "after the outage: {:?}",
        after.as_ref().err()
    );
}

fn start_incomplete(cause: &str) -> Vec<(String, String, String)> {
    vec![("start".into(), "incomplete".into(), cause.into())]
}

#[test]
fn retained_start_refuses_dispatch_with_too_little_time() {
    assert_dispatch_refused(&retained_lane(0), Some((0, 0, false)));
}

#[test]
fn capped_start_refuses_dispatch_with_too_little_time() {
    assert_dispatch_refused(&retained_lane(CAP), Some((u64::from(CAP), CAP, false)));
}

#[test]
fn residual_start_refuses_dispatch_with_too_little_time() {
    assert_dispatch_refused(&residual_work(), None);
}

#[track_caller]
fn assert_dispatch_refused(stopped: &Stopped, before: Option<(u64, u16, bool)>) {
    assert_eq!(
        retained_evidence(stopped),
        before,
        "premise: durable attempt and exemption counts before the start"
    );
    stopped.state.lock().unwrap().publish_unavailable = Some((1, SLOW));
    let sent = publications(stopped);
    let events = Events::default();
    finish_hooks_for_test(FinishHooks {
        bound: Some(PHASE),
        budget: Some(PHASE),
        ..FinishHooks::default()
    });
    let result = restart(stopped, &events);
    finish_hooks_for_test(FinishHooks::default());
    assert_eq!(
        (
            outcome(&result),
            publications(stopped),
            retained_evidence(stopped),
            start_endings(&events)
        ),
        (
            "WritableAuthorityUnavailable",
            sent,
            Some(before.unwrap_or((0, 0, false))),
            start_incomplete("deadline")
        ),
        "before the start: {before:?}, result: {:?}",
        result.as_ref().err()
    );
}

#[test]
fn start_cannot_extend_an_expired_pre_engine_deadline() {
    let stopped = retained_lane(0);
    let before = (publications(&stopped), retained_evidence(&stopped));
    let events = Events::default();
    finish_hooks_for_test(FinishHooks {
        bound: Some(PHASE),
        before_engine_delay: Some(PHASE + Duration::from_millis(100)),
        ..FinishHooks::default()
    });
    let result = restart(&stopped, &events);
    finish_hooks_for_test(FinishHooks::default());
    let kept = result.is_err().then(|| retained_evidence(&stopped));
    assert_eq!(
        (
            outcome(&result),
            publications(&stopped),
            kept,
            start_endings(&events)
        ),
        (
            "WritableAuthorityUnavailable",
            before.0,
            Some(before.1),
            start_incomplete("deadline")
        ),
        "after the expired handoff: {:?}",
        result.as_ref().err()
    );
}
