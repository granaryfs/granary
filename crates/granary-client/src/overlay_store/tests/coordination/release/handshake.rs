// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A lost ownership grant followed by a refused replay can still resume.

use super::lifecycle::{readback, release_ok, reselect, start_like};
use super::*;

#[derive(Clone, Copy, Debug)]
enum Handshake {
    Acquire,
    ReleasedTakeover,
    LiveTakeover,
}

fn landed_handshake(
    shape: Handshake,
    why: &str,
) -> (
    Scratch,
    SimIo,
    WritableStore<SimIo>,
    Authority,
    PendingIntent,
) {
    let (scratch, io, mut client, mut authority) = if matches!(shape, Handshake::Acquire) {
        let scratch = Scratch::new();
        let io = SimIo::default();
        let client = start(&scratch, &io, 10);
        (scratch, io, client, Authority::default())
    } else {
        let (scratch, io, mut client, mut authority) = serving();
        if matches!(shape, Handshake::ReleasedTakeover) {
            release_ok(&mut client, &mut authority, 100, why);
        }
        drop(client);
        io.crash();
        let client = start(&scratch, &io, 20);
        (scratch, io, client, authority)
    };
    let at = Tick(1000);
    let handshake = if matches!(shape, Handshake::Acquire) {
        client.prepare_acquire(authority.cursor, &at)
    } else {
        client.prepare_succession(&at)
    }
    .unwrap_or_else(|error| panic!("{why}: prepare handshake: {error}"));
    client.dispatch(&handshake, &at).unwrap();
    let prior_epoch = authority.cursor;
    let granted = authority.send(&handshake);
    assert_eq!(
        (granted.status, authority.row.map(|row| row.epoch)),
        (200, Some(prior_epoch + 1)),
        "{why}: the handshake lands before its grant is lost"
    );
    (scratch, io, client, authority, handshake)
}

fn refused_replay_then_start(
    shape: Handshake,
    token: Option<&str>,
    refusal: &str,
    restart_between: bool,
) {
    let why = format!("{shape:?} 403/{token:?} restart_between={restart_between}");
    let (scratch, io, mut client, mut authority, handshake) = landed_handshake(shape, &why);
    let unknown = client.complete(
        &handshake,
        Err(IntentTransportError::Transport),
        &Tick(1001),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert!(
        matches!(unknown, Ok(IntentCompletion::Unknown)),
        "{why}: losing the grant reply must leave an unknown outcome, got {unknown:?}"
    );
    if restart_between {
        drop(client);
        io.crash();
        client = start(&scratch, &io, 30);
    }
    let retained = client.retained_requests();
    let requests: Vec<_> = retained
        .iter()
        .map(|request| (request.operation(), request.bytes()))
        .collect();
    assert_eq!(
        requests,
        [(Operation::Ownership, handshake.bytes())],
        "{why}: exact replay"
    );
    let retry = retained.first().unwrap();
    let eligible = client
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.operation == Operation::Ownership)
        .unwrap()
        .eligible;
    let refused = exchange_with(&mut client, retry, eligible.max(1100), || {
        reply(403, token, None, vec![])
    });
    assert!(
        matches!(&refused, Err(CoordinationError::Refused(name)) if *name == refusal),
        "{why}: replay must report {refusal}, got {refused:?}"
    );
    let after = client.snapshot();
    let phase = after.phase;
    let slots: Vec<_> = after
        .pending
        .iter()
        .filter(|pending| pending.operation == Operation::Ownership)
        .map(|pending| (pending.terminal, pending.answered, pending.attempts))
        .collect();
    drop(client);
    io.crash();

    let mut starts = Vec::new();
    let mut mounted = false;
    for n in 0u8..3 {
        let mut client = start(&scratch, &io, 40 + n);
        let result = start_like(&mut client, &mut authority, 5000 + u64::from(n) * 100_000);
        let phase = client.snapshot().phase;
        mounted = result.is_ok() && phase == Phase::OwnedStart;
        starts.push((result.err().map(|error| error.to_string()), phase));
        drop(client);
        io.crash();
        if mounted {
            break;
        }
    }

    let recover = if matches!(shape, Handshake::LiveTakeover) && !mounted {
        let mut client = start(&scratch, &io, 50);
        Some(
            reselect(&mut client, &authority, 900_000)
                .and_then(|takeover| exchange(&mut client, &mut authority, &takeover, 900_000))
                .map_err(|error| error.to_string()),
        )
    } else {
        None
    };

    if matches!(shape, Handshake::LiveTakeover) {
        assert!(
            mounted || matches!(recover, Some(Ok(IntentCompletion::Accepted(_)))),
            "{why}: a healthy start or acknowledged recovery takes ownership; starts {starts:?}; recovery {recover:?}"
        );
    } else {
        assert_eq!(
            (phase, slots, mounted),
            (Phase::Handshake, vec![(false, false, 2)], true),
            "{why}: the refused replay remains unresolved and a healthy start takes ownership; starts {starts:?}"
        );
    }
}

fn refused_replays_then_start(shape: Handshake) {
    let mut failure = None;
    for (token, refusal) in [
        (Some("no-principal"), "IntentTerminalRefusal"),
        (None, "IntentBackendDisagreement"),
    ] {
        for restart_between in [false, true] {
            // Report all four cases even when the first fails.
            let outcome = std::panic::catch_unwind(|| {
                refused_replay_then_start(shape, token, refusal, restart_between);
            });
            if let Err(assertion) = outcome {
                failure = Some(assertion);
            }
        }
    }
    if let Some(assertion) = failure {
        std::panic::resume_unwind(assertion);
    }
}

#[test]
fn refused_replay_of_a_landed_acquire_then_start() {
    refused_replays_then_start(Handshake::Acquire);
}

#[test]
fn refused_replay_of_a_landed_released_takeover_then_start() {
    refused_replays_then_start(Handshake::ReleasedTakeover);
}

#[test]
fn refused_replay_of_a_landed_live_takeover_then_start() {
    refused_replays_then_start(Handshake::LiveTakeover);
}

#[test]
fn lost_grant_then_restart_resumes() {
    for shape in [Handshake::Acquire, Handshake::ReleasedTakeover] {
        let why = format!("{shape:?}");
        let (scratch, io, client, mut authority, handshake) = landed_handshake(shape, &why);
        drop(client);
        io.crash();
        let mut client = start(&scratch, &io, 30);
        let before = authority.sends.len();
        let result = start_like(&mut client, &mut authority, 5000);
        assert_eq!(
            (
                result.err().map(|error| error.to_string()),
                client.snapshot().phase,
                authority.sends.get(before).map(Vec::as_slice),
            ),
            (None, Phase::OwnedStart, Some(handshake.bytes())),
            "{why}: a lost grant alone resumes after an exact replay on restart"
        );
    }
}

#[test]
fn sole_acquire_refusal_settles_then_start_acquires() {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let mut authority = Authority::default();
    let request = client
        .prepare_acquire(authority.cursor, &Tick(100))
        .unwrap();
    let refused = exchange_with(&mut client, &request, 100, || {
        reply(403, Some("no-principal"), None, vec![])
    });
    let pending = client.snapshot().pending.first().unwrap();
    assert_eq!(
        (
            refused.err().map(|error| error.to_string()),
            client.snapshot().phase,
            (pending.terminal, pending.answered, pending.attempts),
            authority.row,
        ),
        (
            Some("intent refused: IntentTerminalRefusal".to_owned()),
            Phase::Unowned,
            (true, true, 1),
            None,
        ),
        "a sole refusal has no earlier dispatch to preserve"
    );
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    let started = start_like(&mut client, &mut authority, 5000);
    assert_eq!(
        (
            started.err().map(|error| error.to_string()),
            client.snapshot().phase,
            authority.sends.as_slice(),
            authority.row.map(|row| row.epoch),
        ),
        (
            None,
            Phase::OwnedStart,
            &[client.snapshot().handshake.clone()][..],
            Some(1)
        ),
        "the next start sends one fresh Acquire"
    );
    assert_ne!(client.snapshot().handshake, request.bytes());
}

#[test]
fn first_dispatch_backend_disagreement_keeps_handshake() {
    let (scratch, io, mut client, mut authority, request) =
        landed_handshake(Handshake::Acquire, "first dispatch backend disagreement");
    let answer = reply(403, None, None, vec![]);
    let refused = client.complete(
        &request,
        Ok(&answer),
        &Tick(1001),
        &mut SeededRng::new(1),
        0,
        None,
    );
    let pending = client.snapshot().pending.first().unwrap();
    assert_eq!(
        (
            refused.err().map(|error| error.to_string()),
            client.snapshot().phase,
            (pending.terminal, pending.answered, pending.attempts),
        ),
        (
            Some("intent refused: IntentBackendDisagreement".to_owned()),
            Phase::Handshake,
            (false, false, 1)
        ),
        "a backend disagreement supplies no verdict even on the first dispatch"
    );
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    let before = authority.sends.len();
    let started = start_like(&mut client, &mut authority, 5000);
    assert_eq!(
        (
            started.err().map(|error| error.to_string()),
            client.snapshot().phase,
            authority.sends.get(before).map(Vec::as_slice),
        ),
        (None, Phase::OwnedStart, Some(request.bytes())),
        "the healthy start recovers the saved grant by exact replay"
    );
}

#[test]
fn expired_acquire_settles_at_the_persisted_tick() {
    let (scratch, io, mut client, mut authority, request) =
        landed_handshake(Handshake::Acquire, "Acquire expiry");
    let unknown = client.complete(
        &request,
        Err(IntentTransportError::Transport),
        &Tick(1001),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert!(
        matches!(unknown, Ok(IntentCompletion::Unknown)),
        "the lost grant keeps the handshake, got {unknown:?}"
    );
    let mut held = client.snapshot().pending.first().unwrap().clone();
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    let mut driven = Vec::new();
    let before = crate::writable_start::settle_recovery(
        &mut client,
        &Tick(held.expires - 1),
        |_, request, landed| {
            driven.push((request.operation(), request.bytes().to_vec(), landed));
            Ok(())
        },
    );
    assert_eq!(
        (
            before.map_err(|error| error.name()),
            client.snapshot().phase,
            driven.as_slice()
        ),
        (
            Ok(()),
            Phase::Handshake,
            &[(Operation::Ownership, held.body.clone(), false)][..]
        ),
        "the handshake remains eligible immediately before expiry"
    );

    driven.clear();
    let expired = crate::writable_start::settle_recovery(
        &mut client,
        &Tick(held.expires),
        |_, request, landed| {
            driven.push((request.operation(), request.bytes().to_vec(), landed));
            Ok(())
        },
    );
    held.terminal = true;
    assert_eq!(
        (
            expired.map_err(|error| error.name()),
            client.snapshot().phase,
            client.snapshot().pending.as_slice(),
            driven
        ),
        (Ok(()), Phase::Unowned, std::slice::from_ref(&held), vec![]),
        "settlement at the deadline preserves the unanswered evidence and prevents a replay"
    );
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 40);
    let row = authority.row.take();
    assert_eq!(
        row.map(|row| row.state),
        Some(ReceiptState::Released),
        "only a Released row can be evicted"
    );
    let before = authority.sends.len();
    let started = start_like(&mut client, &mut authority, held.expires + 100);
    assert_eq!(
        (
            started.err().map(|error| error.to_string()),
            client.snapshot().phase,
            authority.sends.len() - before,
            authority.row.map(|row| row.epoch),
        ),
        (None, Phase::OwnedStart, 1, row.map(|row| row.epoch + 1)),
        "the next start can acquire after eviction"
    );
}

#[test]
fn unstarted_consent_survives_and_armed_unsent_consent_expires() {
    let (_old_scratch, _old_io, old, authority) = serving();
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut config = config(&scratch.0);
    config.cap = 134_217_728;
    config.ownership_completion_reserve = REPLACEMENT_RESERVE;
    let selected = crate::SelectedRecovery::from_readback(
        config.scope.clone(),
        config.volume.clone(),
        old.writer_uuid(),
        &readback(&authority, old.writer_uuid()),
        |_, _| true,
    )
    .unwrap();
    let mut client = WritableStore::adopt_selected(
        Store::open(&scratch.0).unwrap(),
        config,
        io,
        &mut Entropy(30),
        FaultControl::default(),
        selected.acknowledge_displacement(),
    )
    .unwrap();
    let before = client.snapshot().clone();
    let marker = before.pending.first().unwrap();
    assert_eq!(
        (marker.expires, marker.attempts),
        (0, 0),
        "unstarted consent premise"
    );
    let mut driven = Vec::new();
    let unstarted =
        crate::writable_start::settle_recovery(&mut client, &Tick(100), |_, request, _| {
            driven.push(request.bytes().to_vec());
            Ok(())
        });
    assert_eq!(
        (
            unstarted.map_err(|error| error.name()),
            client.snapshot(),
            driven.as_slice()
        ),
        (Ok(()), &before, std::slice::from_ref(&marker.body)),
        "the zero-tick consent marker must survive retained settlement"
    );

    client.begin_selected_attempt(&Tick(100)).unwrap();
    let mut armed = client.snapshot().pending.first().unwrap().clone();
    assert_eq!(
        (armed.expires > 0, armed.attempts, &armed.body),
        (true, 0, &marker.body)
    );
    driven.clear();
    let expired = crate::writable_start::settle_recovery(
        &mut client,
        &Tick(armed.expires + 1),
        |_, request, _| {
            driven.push(request.bytes().to_vec());
            Ok(())
        },
    );
    armed.terminal = true;
    assert_eq!(
        (
            expired.map_err(|error| error.name()),
            client.snapshot().phase,
            client.snapshot().pending.as_slice(),
            driven
        ),
        (Ok(()), Phase::Unowned, std::slice::from_ref(&armed), vec![]),
        "the armed takeover must expire even without a dispatch"
    );
}

#[test]
fn kept_acquire_replay_after_eviction_requires_a_fresh_cursor() {
    let (scratch, io, mut client, mut authority, request) =
        landed_handshake(Handshake::Acquire, "evicted Acquire");
    let refused = exchange_with(&mut client, &request, 1100, || {
        reply(403, Some("no-principal"), None, vec![])
    });
    assert!(
        matches!(
            refused,
            Err(CoordinationError::Refused("IntentTerminalRefusal"))
        ),
        "the replay must be refused, got {refused:?}"
    );
    let evicted = authority.row.take();
    assert_eq!(
        evicted.map(|row| (row.epoch, row.state)),
        Some((authority.cursor, ReceiptState::Released)),
        "evicted row premise"
    );
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    let before = authority.sends.len();
    let stale = start_like(&mut client, &mut authority, 5000);
    assert_eq!(
        (
            stale.err().map(|error| error.to_string()),
            client.snapshot().phase,
            &authority.sends[before..]
        ),
        (
            Some("intent refused: IntentCursorChanged".to_owned()),
            Phase::Unowned,
            &[request.bytes().to_vec()][..]
        ),
        "eviction invalidates the exact replay's cursor and ends this start"
    );
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 40);
    let started = start_like(&mut client, &mut authority, 6000);
    assert_eq!(
        (
            started.err().map(|error| error.to_string()),
            client.snapshot().phase,
            authority.row.map(|row| row.epoch)
        ),
        (None, Phase::OwnedStart, evicted.map(|row| row.epoch + 1)),
        "the following start acquires from a fresh cursor"
    );
}
