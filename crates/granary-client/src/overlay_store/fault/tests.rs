// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[cfg(feature = "overlay-fault-tests")]
#[test]
fn resumed_background_cut_preserves_the_downstream_refresh_hold() {
    let faults = FaultControl::default();
    let before = ("sync.commit_wait", "background");
    let next = ("sync.commit", "landed_refresh");
    faults.arm(before.0, before.1, 1, FaultAction::Block);
    let worker = faults.clone();
    let thread = std::thread::spawn(move || {
        assert_eq!(worker.sync_point(before.0, before.1, 0, None, "none"), None);
        assert_eq!(worker.sync_point(next.0, next.1, 1, None, "none"), None);
    });
    let wait = |(point, phase)| {
        let state = faults.inner.0.lock().unwrap();
        let (state, timeout) = faults
            .inner
            .1
            .wait_timeout_while(state, std::time::Duration::from_secs(2), |state| {
                !state
                    .sync_fired
                    .iter()
                    .any(|event| (event.name, event.phase) == (point, phase))
            })
            .unwrap();
        drop(state);
        if timeout.timed_out() {
            faults.resume();
        }
        assert!(!timeout.timed_out(), "did not reach {point}/{phase}");
    };
    wait(before);
    faults.resume_at(next.0, next.1);
    wait(next);
    let blocked = !thread.is_finished();
    faults.resume();
    thread.join().unwrap();
    assert!(blocked, "the first release must not release the second cut");
}

#[test]
fn repeated_block_arms_each_matching_occurrence_and_ignores_other_seams() {
    let faults = FaultControl::default();
    faults.arm_repeated(
        "sync.commit",
        "before_submit",
        std::num::NonZeroU64::new(3).unwrap(),
        FaultAction::Block,
    );
    assert_eq!(
        faults.sync_point("sync.commit", "other", 0, None, "none"),
        None,
        "a nonmatching phase consumed the repeated target"
    );

    for occurrence in 1..=3 {
        let control = faults.clone();
        let (done, finished) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = control.sync_point("sync.commit", "before_submit", 0, None, "none");
            done.send(result).unwrap();
        });
        let state = faults
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (state, timeout) = faults
            .inner
            .1
            .wait_timeout_while(state, std::time::Duration::from_secs(2), |state| {
                state.sync_fired.len() < occurrence
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !timeout.timed_out(),
            "repeated block did not fire at occurrence {occurrence}"
        );
        drop(state);
        assert!(
            finished.try_recv().is_err(),
            "occurrence {occurrence} did not remain blocked"
        );
        faults.resume_one();
        assert_eq!(
            finished.recv_timeout(std::time::Duration::from_secs(2)),
            Ok(None),
            "occurrence {occurrence} did not resume"
        );
    }
    assert_eq!(faults.sync_fired().len(), 3);
    faults.arm_repeated(
        "sync.commit",
        "before_submit",
        std::num::NonZeroU64::new(2).unwrap(),
        FaultAction::Block,
    );
    let control = faults.clone();
    let (done, finished) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = control.sync_point("sync.commit", "before_submit", 0, None, "none");
        done.send(result).unwrap();
    });
    let state = faults
        .inner
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (state, timeout) = faults
        .inner
        .1
        .wait_timeout_while(state, std::time::Duration::from_secs(2), |state| {
            state.sync_fired.is_empty()
        })
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(!timeout.timed_out(), "release control did not block");
    drop(state);
    faults.resume();
    assert_eq!(
        finished.recv_timeout(std::time::Duration::from_secs(2)),
        Ok(None),
        "release control did not resume"
    );
    assert_eq!(
        faults.sync_point("sync.commit", "before_submit", 0, None, "none"),
        None,
        "resume left a later repeated occurrence blocked"
    );
    assert_eq!(
        faults
            .sync_fired()
            .iter()
            .map(|event| event.occurrence)
            .collect::<Vec<_>>(),
        vec![1, 2],
        "matching repeated blocks, the nonmatching control, and release after resume"
    );
}

#[test]
fn repeated_sync_block_resume_one_releases_exactly_one_waiter() {
    let faults = FaultControl::default();
    faults.arm_repeated(
        "sync.commit",
        "before_submit",
        std::num::NonZeroU64::new(2).unwrap(),
        FaultAction::Block,
    );
    let (done, finished) = std::sync::mpsc::sync_channel(2);
    let mut waiters = Vec::new();
    for _ in 0..2 {
        let control = faults.clone();
        let done = done.clone();
        waiters.push(std::thread::spawn(move || {
            let result = control.sync_point("sync.commit", "before_submit", 0, None, "none");
            done.send(result).unwrap();
        }));
    }
    drop(done);

    let state = faults
        .inner
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (state, timeout) = faults
        .inner
        .1
        .wait_timeout_while(state, std::time::Duration::from_secs(2), |state| {
            state.sync_fired.len() < 2
        })
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(!timeout.timed_out(), "both repeated blocks did not fire");
    drop(state);

    faults.resume_one();
    assert_eq!(
        finished.recv_timeout(std::time::Duration::from_secs(2)),
        Ok(None),
        "one blocked occurrence did not resume"
    );
    assert_eq!(
        finished.recv_timeout(std::time::Duration::from_millis(100)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout),
        "one resume_one released both blocked occurrences"
    );
    faults.resume();
    assert_eq!(
        finished.recv_timeout(std::time::Duration::from_secs(2)),
        Ok(None),
        "the remaining blocked occurrence did not resume"
    );
    for waiter in waiters {
        waiter.join().unwrap();
    }
}

#[test]
fn repeated_record_block_resume_releases_all_waiters_and_stays_released() {
    let faults = FaultControl::default();
    faults.arm_repeated(
        "journal.append",
        "before",
        std::num::NonZeroU64::new(3).unwrap(),
        FaultAction::Block,
    );
    let (done, finished) = std::sync::mpsc::sync_channel(2);
    let mut waiters = Vec::new();
    for record_index in 0..2 {
        let control = faults.clone();
        let done = done.clone();
        waiters.push(std::thread::spawn(move || {
            let result = control.point("journal.append", "before", record_index);
            done.send(result).unwrap();
        }));
    }
    drop(done);

    let state = faults
        .inner
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (state, timeout) = faults
        .inner
        .1
        .wait_timeout_while(state, std::time::Duration::from_secs(2), |state| {
            state.fired.len() < 2
        })
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(!timeout.timed_out(), "both repeated blocks did not fire");
    drop(state);

    faults.resume();
    for remaining in (1..=2).rev() {
        assert_eq!(
            finished.recv_timeout(std::time::Duration::from_secs(2)),
            Ok(None),
            "resume stranded one of {remaining} blocked occurrences"
        );
    }
    for waiter in waiters {
        waiter.join().unwrap();
    }
    assert_eq!(
        faults.point("journal.append", "before", 2),
        None,
        "resume left the repeated target armed"
    );
}
