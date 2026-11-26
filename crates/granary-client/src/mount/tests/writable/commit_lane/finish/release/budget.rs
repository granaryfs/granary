// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The monotonic settlement time includes both exchanges and retry waits.

use super::*;
use crate::SyncRuntime as _;
use crate::overlay_test_support::ReleaseAnswer;
use crate::writable_start::{drive_inner, settle_recovery};
use granary_core::clock::Clock;
use granary_core::overlay_ownership::Pending;
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
enum Fault {
    Transport,
    Server,
    RateLimited,
    StalledSend,
}

fn release(carrier: &Carrier) -> &Pending {
    carrier
        .pending
        .iter()
        .find(|p| p.operation == Operation::Release)
        .unwrap()
}

fn paused_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap()
}

fn configure_fault(stopped: &Stopped, fault: Fault) -> (&'static str, Option<Duration>) {
    let mut state = stopped.state.lock().unwrap();
    match fault {
        Fault::Transport | Fault::Server => {
            state.release_delay = Some(Duration::from_secs(20));
            state.intent_wait_delay = Some(Duration::from_secs(20));
            state.release_answer = ReleaseAnswer::Unavailable;
            (
                if matches!(fault, Fault::Transport) {
                    "always_lost"
                } else {
                    "valid"
                },
                None,
            )
        }
        Fault::RateLimited => {
            state.release_answer = ReleaseAnswer::RateLimited(25);
            state.intent_wait_delay = Some(Duration::from_secs(25));
            ("valid", Some(Duration::from_secs(5)))
        }
        Fault::StalledSend => {
            state.release_delay = Some(Duration::from_secs(45));
            ("valid", None)
        }
    }
}

#[test]
fn retained_release_waits_and_sends_share_one_bounded_budget() {
    for (fault, expired) in [
        (Fault::Transport, true),
        (Fault::Server, true),
        (Fault::RateLimited, true),
        (Fault::StalledSend, true),
        (Fault::StalledSend, false),
    ] {
        let stopped = interrupted(Some(false), expired);
        let before = sends(&stopped);
        let prior = carrier(&stopped);
        let held = release(&prior);
        let old_row = row(&stopped);
        let time = Time(stopped.state.clone());
        let frozen_wall = time.now();
        let (rule, enclosing) = configure_fault(&stopped, fault);
        let runtime = paused_runtime();
        let context = runtime.enter();
        let started = crate::TokioSyncRuntime.now();
        let deadline = enclosing.map(|bound| started + bound);
        let remote = Authority::with_scope_and_rule(
            &stopped.tree,
            Some(prior.scope.clone()),
            &stopped.state,
            rule,
        );
        let mut local = super::super::recovery::local_store(&stopped);
        let mut rng = granary_core::rng::SeededRng::new(2);
        let result = settle_recovery(&mut local, &time, |store, request, landed| {
            drive_inner(
                store,
                &remote,
                &runtime,
                &prior.scope,
                request,
                stopped.tree.key.public_key(),
                &time,
                &mut rng,
                landed,
                deadline,
            )
        });
        let elapsed = crate::TokioSyncRuntime.now() - started;
        let limit = enclosing.unwrap_or(crate::DEFAULT_RESOLUTION_BOUND);
        let error = result.unwrap_err();
        assert_eq!(
            error.class(),
            crate::FailureClass::Unavailable,
            "{fault:?}: {error}"
        );
        assert!(
            (limit..=limit + Duration::from_millis(1)).contains(&elapsed),
            "{fault:?}: {elapsed:?}"
        );
        assert!(matches!(
            local.prepare_succession(&time),
            Err(crate::CoordinationError::Refused(
                "IntentOwnershipUnresolved"
            ))
        ));
        drop(local);
        drop(context);

        assert_eq!(time.now(), frozen_wall, "{fault:?}");
        assert_eq!(row(&stopped), old_row, "{fault:?}");
        let persisted = carrier(&stopped);
        assert_eq!(persisted.phase, Phase::Releasing, "{fault:?}");
        let pending = release(&persisted);
        assert_eq!(pending.body, held.body);
        assert_eq!(pending.first, held.first);
        assert_eq!(pending.attempts, held.attempts + 1);
        assert!(!pending.terminal && !pending.answered && pending.answer.is_empty());
        {
            let mut state = stopped.state.lock().unwrap();
            let sent = &state.sends[before..];
            if matches!(fault, Fault::StalledSend) {
                assert!(sent.is_empty());
            } else {
                assert_eq!(sent, std::slice::from_ref(&held.body), "{fault:?}");
                let (_, waited) = state.intent_wait_observed.unwrap();
                let spent_sending = if matches!(fault, Fault::RateLimited) {
                    0
                } else {
                    20
                };
                assert_eq!(
                    waited.as_secs(),
                    limit.as_secs() - spent_sending,
                    "{fault:?}"
                );
            }
            let now = state.tick + 1000;
            if matches!(fault, Fault::RateLimited) {
                assert_eq!(pending.eligible - now, 25_000);
            }
            state.tick += pending.eligible.saturating_sub(now);
            state.release_answer = ReleaseAnswer::Released;
        }
        let fixture =
            remount(stopped, 60).unwrap_or_else(|error| panic!("{fault:?}: remount: {error}"));
        assert_clean_release_after_remount(fixture);
    }
}

#[test]
fn retained_release_retries_exact_bytes_after_an_unknown_answer() {
    let stopped = interrupted(Some(false), true);
    let prior = carrier(&stopped);
    let pending = release(&prior);
    let before = sends(&stopped);
    stopped.state.lock().unwrap().release_lost_reply = true;
    let runtime = paused_runtime();
    let _context = runtime.enter();
    let remote = Authority::new(&stopped.tree, &stopped.state);
    let time = Time(stopped.state.clone());
    let mut local = super::super::recovery::local_store(&stopped);
    crate::recovery_prologue(
        &mut local,
        &remote,
        &runtime,
        &prior.scope,
        stopped.tree.key.public_key(),
        &time,
        &mut granary_core::rng::SeededRng::new(2),
    )
    .unwrap_or_else(|error| panic!("Release settlement: {error}"));
    drop(local);
    let state = stopped.state.lock().unwrap();
    assert_eq!(
        &state.sends[before..],
        &[pending.body.clone(), pending.body.clone()]
    );
    drop(state);
    let disk = carrier(&stopped);
    assert_eq!(disk.phase, Phase::Released);
    assert!(release(&disk).answered);
}

/// Rejects single-pass admission when only the Release supplies a deadline.
#[test]
fn startup_release_rewaits_with_its_own_deadline() {
    use std::sync::atomic::{AtomicU64, Ordering};

    struct SteppedWall {
        eligible: u64,
        reads: AtomicU64,
    }
    impl Clock for SteppedWall {
        fn now(&self) -> granary_core::root::Timestamp {
            let read = self.reads.fetch_add(1, Ordering::Relaxed);
            let tick = self.eligible - u64::from(read == 1);
            granary_core::root::Timestamp {
                secs: i64::try_from(tick / 1000).unwrap(),
                nanos: u32::try_from(tick % 1000).unwrap() * 1_000_000,
            }
        }
    }

    let stopped = interrupted(Some(false), true);
    let time = Time(stopped.state.clone());
    let mut local = super::super::recovery::local_store(&stopped);
    local.settle_expired_release(&time).unwrap();
    let prior = carrier(&stopped);
    let held = release(&prior);
    let before = sends(&stopped);
    let request = local.retained_requests().pop().unwrap();
    assert_eq!(request.bytes(), held.body);
    stopped.state.lock().unwrap().intent_wait_frozen = true;
    let wall = SteppedWall {
        eligible: held.eligible,
        reads: 0.into(),
    };
    let runtime = paused_runtime();
    let _context = runtime.enter();
    let started = crate::TokioSyncRuntime.now();
    let remote = Authority::new(&stopped.tree, &stopped.state);
    let result = drive_inner(
        &mut local,
        &remote,
        &runtime,
        &prior.scope,
        &request,
        stopped.tree.key.public_key(),
        &wall,
        &mut granary_core::rng::SeededRng::new(2),
        false,
        None,
    );
    let elapsed = crate::TokioSyncRuntime.now() - started;
    let persisted = carrier(&stopped);
    let state = stopped.state.lock().unwrap();
    let waited = state.intent_wait_observed.map(|(_, elapsed)| elapsed);
    assert_eq!(
        (
            result.map_err(|error| error.name()),
            &state.sends[before..],
            waited.is_some_and(|waited| {
                (Duration::from_millis(10)..=Duration::from_millis(11)).contains(&waited)
            }),
            elapsed < crate::DEFAULT_RESOLUTION_BOUND,
            (release(&persisted).attempts, release(&persisted).answered),
        ),
        (
            Ok(()),
            std::slice::from_ref(&held.body),
            true,
            true,
            (held.attempts + 1, true),
        ),
        "elapsed {elapsed:?}, re-wait {waited:?}",
    );
}

#[test]
fn retained_release_waits_for_a_frozen_wall_clock_within_the_budget() {
    let stopped = interrupted(Some(false), true);
    let time = Time(stopped.state.clone());
    let mut local = super::super::recovery::local_store(&stopped);
    local.settle_expired_release(&time).unwrap();
    let prior = carrier(&stopped);
    let held = release(&prior);
    let before = sends(&stopped);
    let old_row = row(&stopped);
    {
        let mut state = stopped.state.lock().unwrap();
        state.tick -= 20_000;
        state.intent_wait_frozen = true;
        assert_eq!(held.eligible, state.tick + 1000 + 20_000);
    }
    let frozen_wall = time.now();
    let runtime = paused_runtime();
    let context = runtime.enter();
    let started = crate::TokioSyncRuntime.now();
    let remote = Authority::new(&stopped.tree, &stopped.state);
    let result = crate::recovery_prologue(
        &mut local,
        &remote,
        &runtime,
        &prior.scope,
        stopped.tree.key.public_key(),
        &time,
        &mut granary_core::rng::SeededRng::new(2),
    );
    let elapsed = crate::TokioSyncRuntime.now() - started;
    let limit = crate::DEFAULT_RESOLUTION_BOUND;
    let error = result.unwrap_err();
    assert_eq!(
        (
            error.name(),
            error.class(),
            (limit..=limit + Duration::from_millis(1)).contains(&elapsed)
        ),
        ("SyncDeadline", crate::FailureClass::Unavailable, true),
        "a wait that leaves wall time frozen must consume the settlement budget (elapsed {elapsed:?})"
    );
    let succession = local.prepare_succession(&time);
    assert!(
        matches!(
            &succession,
            Err(crate::CoordinationError::Refused(
                "IntentOwnershipUnresolved"
            ))
        ),
        "{succession:?}"
    );
    drop(local);
    drop(context);

    let persisted = carrier(&stopped);
    assert_eq!(
        (
            time.now(),
            sends(&stopped),
            row(&stopped),
            persisted.phase,
            release(&persisted)
        ),
        (frozen_wall, before, old_row, Phase::Releasing, held),
        "frozen wall time must leave the Release unresolved and unsent"
    );
    {
        let mut state = stopped.state.lock().unwrap();
        state.intent_wait_frozen = false;
    }
    let fixture = remount(stopped, 60).unwrap_or_else(|error| panic!("moving clock: {error}"));
    assert_eq!(
        fixture.state.lock().unwrap().sends.get(before),
        Some(&held.body)
    );
    assert_clean_release_after_remount(fixture);
}
