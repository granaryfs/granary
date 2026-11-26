// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Release and succession across store reopens.

use super::*;

mod discard_eligibility;

const BOUND: std::time::Duration = crate::DEFAULT_RESOLUTION_BOUND;

fn rels(carrier: &Carrier) -> Vec<Pending> {
    carrier
        .pending
        .iter()
        .filter(|pending| pending.operation == Operation::Release)
        .cloned()
        .collect()
}

fn disk(io: &SimIo) -> Carrier {
    ownership::decode(&io.recovered_bytes("ownership").unwrap()).unwrap()
}

fn epoch(carrier: &Carrier) -> u64 {
    intent::decode_receipt(&carrier.current).unwrap().epoch
}

/// Model the start's settlement order through a single exchange per request,
/// then acquire or succeed. A matched landed refresh is not modelled.
pub(super) fn start_like(
    client: &mut WritableStore<SimIo>,
    authority: &mut Authority,
    at: u64,
) -> Result<(), CoordinationError> {
    client.settle_expired_release(&Tick(at))?;
    client.settle_expired_handshake(&Tick(at))?;
    if client.snapshot().phase == Phase::Fenced {
        return Ok(());
    }
    for request in client.retained_requests().into_iter().filter(|request| {
        matches!(
            request.operation(),
            Operation::Ownership | Operation::Release
        )
    }) {
        exchange(client, authority, &request, at)?;
        if client.snapshot().phase == Phase::Fenced {
            return Ok(());
        }
    }
    if client.snapshot().phase != Phase::Unowned {
        let request = client.prepare_succession(&Tick(at + 2))?;
        exchange(client, authority, &request, at + 2)?;
    }
    if client.snapshot().phase == Phase::Unowned {
        let request = client.prepare_acquire(authority.cursor, &Tick(at + 2))?;
        exchange(client, authority, &request, at + 2)?;
    }
    Ok(())
}

fn reg(client: &mut WritableStore<SimIo>, authority: &mut Authority, seed: u8, at: u64) {
    let request = client
        .prepare_registration(
            &root(client.writer_uuid(), seed),
            vec![],
            &Tick(at),
            |_, _| true,
        )
        .unwrap();
    let completion = exchange(client, authority, &request, at).unwrap();
    assert_eq!(
        completion,
        IntentCompletion::Accepted(authority.row.unwrap())
    );
}

pub(super) fn release_ok(
    client: &mut WritableStore<SimIo>,
    authority: &mut Authority,
    at: u64,
    why: &str,
) {
    let request = client
        .prepare_release(&Tick(at), BOUND, None)
        .unwrap_or_else(|error| panic!("{why}: release preparation refused: {error:?}"));
    let completion = exchange(client, authority, &request, at)
        .unwrap_or_else(|error| panic!("{why}: release exchange refused: {error:?}"));
    let row = authority.row.unwrap();
    assert_eq!(completion, IntentCompletion::Accepted(row), "{why}");
    assert_eq!(row.state, ReceiptState::Released, "{why}");
    assert_eq!(client.snapshot().phase, Phase::Released, "{why}");
    let pending = rels(client.snapshot());
    assert_eq!(pending.len(), 1, "{why}");
    assert_eq!(pending[0].body, request.bytes(), "{why}");
    assert!(pending[0].terminal && pending[0].answered, "{why}");
    assert_eq!(
        intent::decode_release(request.bytes()).unwrap().epoch,
        row.epoch,
        "{why}"
    );
}

#[test]
fn many_remount_cycles_store_level() {
    let (scratch, io, mut client, mut authority) = serving();
    let mut at = 100;
    let mut revision = client.snapshot().revision;
    let mut seed = 2u8;
    for cycle in 0u8..48 {
        let why = format!("cycle {cycle}");
        if cycle % 5 == 4 {
            // A release whose first reply is lost, retried in the same process.
            let request = client.prepare_release(&Tick(at), BOUND, None).unwrap();
            client.dispatch(&request, &Tick(at)).unwrap();
            let _landed = authority.send(&request);
            let unknown = client
                .complete(
                    &request,
                    Err(IntentTransportError::Transport),
                    &Tick(at + 1),
                    &mut SeededRng::new(1),
                    0,
                    None,
                )
                .unwrap();
            assert_eq!(unknown, IntentCompletion::Unknown, "{why}");
            let eligible = rels(client.snapshot())[0].eligible;
            let completion = exchange(&mut client, &mut authority, &request, eligible).unwrap();
            assert_eq!(
                completion,
                IntentCompletion::Accepted(authority.row.unwrap()),
                "{why}"
            );
            at = eligible + 10;
        } else {
            release_ok(&mut client, &mut authority, at, &why);
        }
        assert!(client.snapshot().revision > revision, "{why}");
        revision = client.snapshot().revision;
        drop(client);
        io.crash();
        assert_eq!(disk(&io).revision, revision, "{why}");
        client = start(&scratch, &io, 20 + cycle * 2);
        at += 100;
        start_like(&mut client, &mut authority, at).unwrap_or_else(|e| panic!("{why}: {e:?}"));
        assert_eq!(client.snapshot().phase, Phase::OwnedStart, "{why}");
        assert_eq!(rels(client.snapshot()).len(), 0, "{why}: post-grant slots");
        at += 10;
        match cycle % 4 {
            0 => {
                open(&mut client, &io);
                reg(&mut client, &mut authority, seed, at);
                seed = seed.wrapping_add(1);
            }
            1 => client.enter_recovery_serving().unwrap(),
            2 => {
                open(&mut client, &io);
                for _ in 0..3 {
                    reg(&mut client, &mut authority, seed, at);
                    seed = seed.wrapping_add(1);
                    at += 5;
                }
            }
            _ => {
                // A crash right after the grant, then a second succession.
                drop(client);
                io.crash();
                client = start(&scratch, &io, 21 + cycle * 2);
                start_like(&mut client, &mut authority, at)
                    .unwrap_or_else(|e| panic!("{why}: second succession {e:?}"));
                open(&mut client, &io);
                reg(&mut client, &mut authority, seed, at + 5);
                seed = seed.wrapping_add(1);
            }
        }
        assert_eq!(client.snapshot().phase, Phase::Serving, "{why}");
        assert!(
            client.snapshot().pending.len() <= 3,
            "{why}: {:?}",
            client.snapshot().pending.len()
        );
        at += 100;
    }
    release_ok(&mut client, &mut authority, at, "final");
}

const CUTS: [(&str, &str); 15] = [
    ("intent.reply", "before"),
    ("intent.evidence", "before"),
    ("intent.retire", "before"),
    ("intent.pending", "build"),
    ("intent.pending", "partial"),
    ("intent.pending", "before"),
    ("intent.pending", "after"),
    ("intent.pending", "sync"),
    ("intent.pending", "after_sync"),
    ("intent.pending", "rename"),
    ("intent.pending", "after_rename"),
    ("intent.pending", "dir_sync"),
    ("intent.pending", "after_dir_sync"),
    ("intent.retire", "after"),
    ("intent.evidence", "after"),
];

fn released_reopened(entropy: u8) -> (Scratch, SimIo, WritableStore<SimIo>, Authority) {
    let (scratch, io, mut client, mut authority) = serving();
    release_ok(&mut client, &mut authority, 100, "first release");
    drop(client);
    io.crash();
    let client = start(&scratch, &io, entropy);
    (scratch, io, client, authority)
}

fn injected(result: &Result<impl std::fmt::Debug, CoordinationError>) -> bool {
    matches!(
        result,
        Err(CoordinationError::Overlay(OverlayError::InjectedCrash))
    )
}

#[test]
fn crash_cuts_at_the_grant_that_retires_the_release() {
    let mut report = Vec::new();
    for (name, phase) in CUTS {
        let (scratch, io, mut client, mut authority) = released_reopened(30);
        let prior = rels(client.snapshot());
        assert_eq!(prior.len(), 1);
        let request = client.prepare_succession(&Tick(1010)).unwrap();
        client.dispatch(&request, &Tick(1010)).unwrap();
        let answer = authority.send(&request);
        client
            .fault_control()
            .arm(name, phase, 1, FaultAction::Crash);
        let result = client.complete(
            &request,
            Ok(&answer),
            &Tick(1011),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(injected(&result), "{name}/{phase}: {result:?}");
        assert_eq!(client.fault_control().fired().len(), 1, "{name}/{phase}");
        drop(client);
        io.crash();
        let on_disk = disk(&io);
        let mut client = start(&scratch, &io, 60);
        // Either the whole grant revision is durable or none of it.
        let granted = on_disk.phase == Phase::OwnedStart;
        assert_eq!(
            (on_disk.phase, rels(&on_disk).len()),
            if granted {
                (Phase::OwnedStart, 0)
            } else {
                (Phase::Handshake, 1)
            },
            "{name}/{phase}"
        );
        if !granted {
            assert_eq!(rels(&on_disk), prior, "{name}/{phase}");
        }
        start_like(&mut client, &mut authority, 2000)
            .unwrap_or_else(|e| panic!("{name}/{phase}: restart {e:?}"));
        assert_eq!(client.snapshot().phase, Phase::OwnedStart, "{name}/{phase}");
        assert_eq!(rels(client.snapshot()).len(), 0, "{name}/{phase}");
        open(&mut client, &io);
        reg(&mut client, &mut authority, 2, 2010);
        release_ok(
            &mut client,
            &mut authority,
            2020,
            &format!("{name}/{phase}"),
        );
        report.push((name, phase, granted));
    }
    assert_eq!(report.len(), CUTS.len());
    eprintln!("grant cuts: {report:?}");
}

#[test]
fn crash_cuts_at_the_next_release() {
    // step 0: prepare, 1: dispatch, 2: completion.
    let mut cases = 0;
    for step in 0..3 {
        for (name, phase) in CUTS {
            if step < 2 && name != "intent.pending" {
                continue;
            }
            let why = format!("step {step} {name}/{phase}");
            let (scratch, io, mut client, mut authority) = released_reopened(30);
            start_like(&mut client, &mut authority, 1010).unwrap();
            open(&mut client, &io);
            reg(&mut client, &mut authority, 2, 1020);
            let faults = client.fault_control();
            let mut landed = false;
            let result: Result<(), CoordinationError> = (|| {
                if step == 0 {
                    faults.arm(name, phase, 1, FaultAction::Crash);
                }
                let request = client.prepare_release(&Tick(1030), BOUND, None)?;
                if step == 1 {
                    faults.arm(name, phase, 1, FaultAction::Crash);
                }
                client.dispatch(&request, &Tick(1030))?;
                let answer = authority.send(&request);
                landed = true;
                if step == 2 {
                    faults.arm(name, phase, 1, FaultAction::Crash);
                }
                client.complete(
                    &request,
                    Ok(&answer),
                    &Tick(1031),
                    &mut SeededRng::new(1),
                    0,
                    None,
                )?;
                Ok(())
            })();
            assert!(injected(&result), "{why}: {result:?}");
            assert_eq!(faults.fired().len(), 1, "{why}");
            drop(client);
            io.crash();
            let on_disk = disk(&io);
            assert!(rels(&on_disk).len() <= 1, "{why}");
            let mut client = start(&scratch, &io, 60);
            start_like(&mut client, &mut authority, 1040).unwrap_or_else(|e| {
                panic!(
                    "{why}: landed={landed} disk={:?}/{:?}: restart {e:?}",
                    on_disk.phase,
                    rels(&on_disk)
                )
            });
            assert_eq!(client.snapshot().phase, Phase::OwnedStart, "{why}");
            assert_eq!(rels(client.snapshot()).len(), 0, "{why}");
            open(&mut client, &io);
            reg(&mut client, &mut authority, 3, 1050);
            release_ok(&mut client, &mut authority, 1060, &why);
            cases += 1;
        }
    }
    assert_eq!(cases, 10 + 10 + 15);
}

/// An authority applied the Release and only the reply was lost.
#[track_caller]
fn lose_release_reply(
    client: &mut WritableStore<SimIo>,
    authority: &mut Authority,
    request: &PendingIntent,
    at: u64,
) {
    client.dispatch(request, &Tick(at)).unwrap();
    let status = authority.send(request).status;
    assert_eq!(
        (status, authority.row.unwrap().state),
        (200, ReceiptState::Released),
        "Release landed before its reply was lost"
    );
    assert_eq!(
        client
            .complete(
                request,
                Err(IntentTransportError::Transport),
                &Tick(at + 1),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap(),
        IntentCompletion::Unknown
    );
}

#[test]
fn lost_release_reply_then_start_after_the_horizon() {
    let (scratch, io, mut client, mut authority) = serving();
    let request = client
        .prepare_release(&Tick(100), BOUND, Some(1000))
        .unwrap();
    lose_release_reply(&mut client, &mut authority, &request, 100);
    drop(client);
    io.crash();
    for attempt in 0..3u8 {
        let at = 5000 + u64::from(attempt) * 100;
        let mut client = start(&scratch, &io, 30 + attempt);
        let before = authority.sends.len();
        let expected_epoch = authority.row.unwrap().epoch;
        start_like(&mut client, &mut authority, at).unwrap();
        let sends = &authority.sends[before..];
        let takeover = if attempt == 0 {
            assert_eq!(sends.len(), 2);
            assert_eq!(sends[0], request.bytes());
            &sends[1]
        } else {
            assert_eq!(sends.len(), 1);
            &sends[0]
        };
        assert!(matches!(
            intent::decode_ownership(takeover).unwrap().mode,
            OwnershipMode::Takeover {
                expected_epoch: epoch,
                state: ReceiptState::Released,
                recovery_ack: false,
                ..
            } if epoch == expected_epoch
        ));
        assert_eq!(client.snapshot().phase, Phase::OwnedStart);
        assert!(rels(client.snapshot()).is_empty());
        open(&mut client, &io);
        reg(&mut client, &mut authority, 20 + attempt, at + 10);
        release_ok(
            &mut client,
            &mut authority,
            at + 20,
            "release after restart",
        );
        drop(client);
        io.crash();
    }
}

/// The same, restarted inside the horizon: the exact Release is sent again.
#[test]
fn lost_release_reply_then_remount_inside_the_horizon() {
    let (scratch, io, mut client, mut authority) = serving();
    let request = client.prepare_release(&Tick(100), BOUND, None).unwrap();
    lose_release_reply(&mut client, &mut authority, &request, 100);
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    start_like(&mut client, &mut authority, 1000).unwrap();
    assert_eq!(rels(client.snapshot()).len(), 0);
    open(&mut client, &io);
    reg(&mut client, &mut authority, 2, 1020);
    release_ok(&mut client, &mut authority, 1030, "after lost reply");
}

#[test]
fn refused_retry_of_a_landed_release_then_start() {
    for (token, refusal) in [
        (Some("no-principal"), "IntentTerminalRefusal"),
        (None, "IntentBackendDisagreement"),
    ] {
        for late in [false, true] {
            let why = format!("{token:?} late={late}");
            let (scratch, io, mut client, mut authority) = serving();
            let request = client
                .prepare_release(&Tick(100), BOUND, Some(1000))
                .unwrap();
            lose_release_reply(&mut client, &mut authority, &request, 100);
            let held = releases(client.snapshot()).next().unwrap().clone();
            drop(client);
            io.crash();

            let at = if late {
                held.expires + 1
            } else {
                held.eligible
            };
            let mut client = start(&scratch, &io, 30);
            client.settle_expired_release(&Tick(at)).unwrap();
            let retained = client.retained_requests();
            assert_eq!(retained.len(), 1, "{why}: {retained:?}");
            let retry = retained.first().unwrap();
            client.dispatch(retry, &Tick(at)).unwrap();
            let answer = reply(403, token, None, vec![]);
            let completion = client.complete(
                retry,
                Ok(&answer),
                &Tick(at + 1),
                &mut SeededRng::new(1),
                0,
                None,
            );
            let pending = releases(client.snapshot()).next().unwrap();
            assert_eq!(
                (
                    completion.err().map(|error| error.to_string()),
                    (
                        pending.terminal,
                        pending.answered,
                        pending.attempts,
                        pending.first
                    ),
                    pending.body.as_slice(),
                ),
                (
                    Some(format!("intent refused: {refusal}")),
                    (false, false, 2, held.first),
                    held.body.as_slice()
                ),
                "{why}: refused retry preserves the unresolved Release"
            );
            let succession = client.prepare_succession(&Tick(at + 2));
            assert!(
                matches!(
                    &succession,
                    Err(CoordinationError::Refused("IntentOwnershipUnresolved"))
                ),
                "{why}: {succession:?}"
            );
            drop(client);
            io.crash();

            let mut client = start(&scratch, &io, 40);
            let before = authority.sends.len();
            start_like(&mut client, &mut authority, at + 10)
                .unwrap_or_else(|error| panic!("{why}: healthy start: {error}"));
            let sends = &authority.sends[before..];
            assert_eq!(
                (client.snapshot().phase, sends.len(), sends.first()),
                (Phase::OwnedStart, 2, Some(&held.body)),
                "{why}"
            );
            assert!(
                matches!(
                    intent::decode_ownership(sends.last().unwrap())
                        .unwrap()
                        .mode,
                    OwnershipMode::Takeover {
                        state: ReceiptState::Released,
                        ..
                    }
                ),
                "{why}: succession must select Released"
            );
        }
    }
}

#[test]
fn sole_release_refusal_then_succession_of_the_live_row() {
    let (scratch, io, mut client, mut authority) = serving();
    let request = client.prepare_release(&Tick(100), BOUND, None).unwrap();
    client.dispatch(&request, &Tick(100)).unwrap();
    let answer = reply(403, Some("no-principal"), None, vec![]);
    let completion = client.complete(
        &request,
        Ok(&answer),
        &Tick(101),
        &mut SeededRng::new(1),
        0,
        None,
    );
    let retired = releases(client.snapshot()).next().unwrap();
    assert_eq!(
        (
            completion.err().map(|error| error.to_string()),
            retired.attempts,
            retired.terminal,
            retired.answered
        ),
        (
            Some("intent refused: IntentTerminalRefusal".to_owned()),
            1,
            true,
            true
        ),
        "sole Release refusal retires the request"
    );
    drop(client);
    io.crash();

    let mut client = start(&scratch, &io, 30);
    let before = authority.sends.len();
    start_like(&mut client, &mut authority, 110).unwrap();
    let sends = &authority.sends[before..];
    assert_eq!(
        (client.snapshot().phase, sends.len()),
        (Phase::OwnedStart, 1)
    );
    let takeover = intent::decode_ownership(sends.first().unwrap()).unwrap();
    let live = intent::decode_receipt(&client.snapshot().current)
        .unwrap()
        .state;
    assert!(matches!(live, ReceiptState::Live { .. }), "{live:?}");
    assert!(
        matches!(takeover.mode, OwnershipMode::Takeover { state, .. } if state == live),
        "{:?}",
        takeover.mode
    );
}

#[test]
fn first_release_backend_disagreement_then_healthy_start() {
    let (scratch, io, mut client, mut authority) = serving();
    let request = client.prepare_release(&Tick(100), BOUND, None).unwrap();
    client.dispatch(&request, &Tick(100)).unwrap();
    assert_eq!(
        (
            authority.send(&request).status,
            authority.row.unwrap().state
        ),
        (200, ReceiptState::Released),
        "Release landed before the backend disagreement"
    );
    let held = releases(client.snapshot()).next().unwrap().clone();
    let answer = reply(403, None, None, vec![]);
    let events = Capture::default();
    let completion = tracing::subscriber::with_default(events.subscriber(), || {
        client.complete(
            &request,
            Ok(&answer),
            &Tick(101),
            &mut SeededRng::new(1),
            0,
            None,
        )
    });
    assert_eq!(
        (
            completion.err().map(|error| error.to_string()),
            releases(client.snapshot()).next(),
            events.contains("op.failed", "session", "refused"),
            events.contains("op.failed", "unmount", "refused"),
        ),
        (
            Some("intent refused: IntentBackendDisagreement".to_owned()),
            Some(&held),
            true,
            true
        ),
        "first-dispatch backend disagreement preserves the unresolved Release"
    );
    let succession = client.prepare_succession(&Tick(102));
    assert!(
        matches!(
            &succession,
            Err(CoordinationError::Refused("IntentOwnershipUnresolved"))
        ),
        "{succession:?}"
    );
    drop(client);
    io.crash();

    let mut client = start(&scratch, &io, 30);
    let before = authority.sends.len();
    start_like(&mut client, &mut authority, 110).unwrap();
    let sends = &authority.sends[before..];
    assert_eq!(
        (client.snapshot().phase, sends.len(), sends.first()),
        (Phase::OwnedStart, 2, Some(&held.body))
    );
    assert!(matches!(
        intent::decode_ownership(sends.last().unwrap())
            .unwrap()
            .mode,
        OwnershipMode::Takeover {
            state: ReceiptState::Released,
            ..
        }
    ));
}

#[test]
fn rate_limited_release_then_refusal_keeps_the_release_unresolved() {
    let (_scratch, _io, mut client, _authority) = serving();
    let request = client.prepare_release(&Tick(100), BOUND, None).unwrap();
    client.dispatch(&request, &Tick(100)).unwrap();
    let rate_limit = reply(429, Some("rate-limited"), None, vec![]);
    assert_eq!(
        client
            .complete(
                &request,
                Ok(&rate_limit),
                &Tick(101),
                &mut SeededRng::new(1),
                1000,
                None
            )
            .unwrap(),
        IntentCompletion::Unknown
    );
    let eligible = releases(client.snapshot()).next().unwrap().eligible;
    client.dispatch(&request, &Tick(eligible)).unwrap();
    let held = releases(client.snapshot()).next().unwrap().clone();
    assert_eq!(held.attempts, 2);
    let answer = reply(403, Some("no-principal"), None, vec![]);
    let completion = client.complete(
        &request,
        Ok(&answer),
        &Tick(eligible + 1),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert_eq!(
        (
            completion.err().map(|error| error.to_string()),
            releases(client.snapshot()).next()
        ),
        (
            Some("intent refused: IntentTerminalRefusal".to_owned()),
            Some(&held)
        ),
        "a refusal after a recorded 429 preserves the unresolved Release"
    );
    let succession = client.prepare_succession(&Tick(eligible + 2));
    assert!(
        matches!(
            &succession,
            Err(CoordinationError::Refused("IntentOwnershipUnresolved"))
        ),
        "{succession:?}"
    );
}

/// Only explicit recovery may reuse the retained evidence after displacement.
#[test]
fn superseded_takeover_keeps_a_decodable_fenced_carrier() {
    let (scratch, io, mut client, mut authority) = released_reopened(30);
    let prior = rels(client.snapshot());
    authority.cursor += 1;
    authority.row = Some(Receipt {
        epoch: authority.cursor,
        instance: [40; 16],
        ..authority.row.unwrap()
    });
    let result = start_like(&mut client, &mut authority, 1010);
    assert!(
        matches!(result, Err(CoordinationError::Fenced { .. })),
        "{result:?}"
    );
    drop(client);
    io.crash();
    let on_disk = disk(&io);
    assert_eq!(
        (on_disk.phase, rels(&on_disk)),
        (Phase::Fenced, prior.clone())
    );
    let mut client = start(&scratch, &io, 50);
    let again = start_like(&mut client, &mut authority, 1020);
    assert!(
        matches!(again, Err(CoordinationError::Fenced { .. })),
        "{again:?}"
    );
    assert_eq!(rels(client.snapshot()), prior);
}

pub(super) fn readback(authority: &Authority, writer: [u8; 16]) -> IntentReply {
    let row = authority.row.unwrap();
    let rows = if authority.root.is_empty() {
        vec![]
    } else {
        vec![intent::ReadbackRow {
            writer,
            epoch: row.epoch,
            generation: row.generation,
            root: &authority.root,
        }]
    };
    reply(
        200,
        None,
        Some(intent::MEDIA_READBACK),
        intent::encode_readback(authority.cursor, &rows).unwrap(),
    )
}

pub(super) fn reselect(
    client: &mut WritableStore<SimIo>,
    authority: &Authority,
    at: u64,
) -> Result<PendingIntent, CoordinationError> {
    let writer = client.writer_uuid();
    let selection = crate::SelectedRecovery::from_readback(
        client.snapshot().scope.clone(),
        client.snapshot().volume.clone(),
        writer,
        &readback(authority, writer),
        |_, _| true,
    )?;
    client.reselect(selection.acknowledge_takeover(writer)?, &Tick(at))
}

/// A Release fenced by a displacement, then the acknowledged recovery
/// takeover, then recovery's own Release.
#[test]
fn fenced_release_then_acknowledged_recovery_release() {
    let (scratch, io, mut client, mut authority) = serving();
    let request = client.prepare_release(&Tick(100), BOUND, None).unwrap();
    authority.cursor += 1;
    authority.row = Some(Receipt {
        epoch: authority.cursor,
        instance: [99; 16],
        ..authority.row.unwrap()
    });
    let result = exchange(&mut client, &mut authority, &request, 100);
    assert!(
        matches!(result, Err(CoordinationError::Fenced { .. })),
        "{result:?}"
    );
    let fenced = rels(client.snapshot());
    assert!(fenced[0].terminal && fenced[0].answered);
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 50);
    let takeover = reselect(&mut client, &authority, 200).unwrap();
    let completion = exchange(&mut client, &mut authority, &takeover, 200).unwrap();
    assert_eq!(
        completion,
        IntentCompletion::Accepted(authority.row.unwrap())
    );
    assert_eq!(rels(client.snapshot()).len(), 0);
    let release = client.prepare_recovery_release(&Tick(300), BOUND).unwrap();
    exchange(&mut client, &mut authority, &release, 300).unwrap();
    assert_eq!(client.snapshot().phase, Phase::Released);
    assert_eq!(authority.row.unwrap().state, ReceiptState::Released);
}

/// A Release still unresolved when another request's reply fences the
/// carrier, then the acknowledged recovery takeover and recovery's Release.
#[test]
fn unresolved_release_under_a_fence_then_recovery_release() {
    for (expired, legacy) in [(false, false), (true, false), (false, true), (true, true)] {
        let (scratch, io, mut client, mut authority) = serving();
        let registered = register(&mut client, &mut authority, 2);
        let release = client
            .prepare_release(&Tick(100), BOUND, Some(1000))
            .unwrap();
        client.dispatch(&release, &Tick(100)).unwrap();
        let unknown = client
            .complete(
                &release,
                Err(IntentTransportError::Transport),
                &Tick(101),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
        assert_eq!(unknown, IntentCompletion::Unknown);
        // Another instance takes the row over; a duplicate reply to the
        // already answered registration reports it.
        authority.cursor += 1;
        authority.row = Some(Receipt {
            epoch: authority.cursor,
            instance: [99; 16],
            ..authority.row.unwrap()
        });
        let late = authority.send(&registered);
        let fenced = client.complete(
            &registered,
            Ok(&late),
            &Tick(102),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(
            matches!(fenced, Err(CoordinationError::Fenced { .. })),
            "{fenced:?}"
        );
        let mut held = releases(client.snapshot()).next().unwrap().clone();
        assert!(!held.terminal && !held.answered);
        drop(client);
        io.crash();
        let mut client = start(&scratch, &io, 50);
        let at = if expired { 5000 } else { 200 };
        let takeover = reselect(&mut client, &authority, at).unwrap();
        held.terminal = true;
        assert_eq!(rels(client.snapshot()), [held.clone()]);
        assert_eq!(client.retained_requests().len(), 1);
        assert_eq!(client.retained_requests()[0].bytes(), takeover.bytes());

        // Crash after consent, before sending the takeover. A carrier written
        // without retirement can still have the same unresolved Release here.
        drop(client);
        if legacy {
            let mut carrier = disk(&io);
            let pending = carrier
                .pending
                .iter_mut()
                .find(|p| p.operation == Operation::Release)
                .unwrap();
            pending.terminal = false;
            io.mutate_recovered("ownership", |bytes| {
                *bytes = ownership::encode(&carrier).unwrap();
            });
        }
        io.crash();
        let mut client = start(&scratch, &io, 50);
        let mut sent = Vec::new();
        crate::writable_start::settle_recovery(
            &mut client,
            &Tick(at),
            |client, request, landed| {
                assert!(!landed);
                assert_eq!(rels(client.snapshot()), [held.clone()]);
                assert_eq!(rels(&disk(&io)), [held.clone()]);
                sent.push(request.operation());
                assert_eq!(request.bytes(), takeover.bytes());
                exchange(client, &mut authority, request, at)?;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(sent, [Operation::Ownership]);
        assert!(rels(client.snapshot()).is_empty());
        let release = client
            .prepare_recovery_release(&Tick(at + 20), BOUND)
            .unwrap();
        exchange(&mut client, &mut authority, &release, at + 20).unwrap();
        assert_eq!(client.snapshot().phase, Phase::Released);
    }
}

/// Two stores (two hosts) of one writer identity cannot exist; two processes
/// of one store alternate instead: A serves, B's carrier copy goes stale.
/// Here one disk, instances alternating, and a stale process finishing late.
#[test]
fn alternating_instances_and_a_stale_process_release() {
    let (scratch, io, mut a, mut authority) = serving();
    for round in 0u8..6 {
        // B starts on the same store while A never released (A crashed).
        let stale_release_epoch = epoch(a.snapshot());
        drop(a);
        io.crash();
        let mut b = start(&scratch, &io, 40 + round);
        start_like(&mut b, &mut authority, 1000 + u64::from(round) * 1000).unwrap();
        assert!(epoch(b.snapshot()) > stale_release_epoch);
        open(&mut b, &io);
        reg(
            &mut b,
            &mut authority,
            10 + round,
            1010 + u64::from(round) * 1000,
        );
        if round % 2 == 0 {
            release_ok(
                &mut b,
                &mut authority,
                1020 + u64::from(round) * 1000,
                "even round",
            );
        }
        a = b;
    }
    if a.snapshot().phase == Phase::Serving {
        release_ok(&mut a, &mut authority, 9000, "last");
    }
}

/// Registers pending or retained with contexts beside the retained Release.
#[test]
fn pending_registers_beside_the_retained_release() {
    let (scratch, io, mut client, mut authority) = released_reopened(30);
    let prior = rels(client.snapshot());
    // Succession persists Ownership beside the terminal Release.
    let request = client.prepare_succession(&Tick(1010)).unwrap();
    let kinds: Vec<_> = client
        .snapshot()
        .pending
        .iter()
        .map(|p| p.operation)
        .collect();
    assert_eq!(kinds, [Operation::Ownership, Operation::Release]);
    // Lost grant reply, restart: the retained handshake resolves, then a
    // fresh succession; the release is retired exactly once.
    client.dispatch(&request, &Tick(1010)).unwrap();
    let _ = authority.send(&request);
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 50);
    assert_eq!(rels(client.snapshot()), prior);
    start_like(&mut client, &mut authority, 1020).unwrap();
    assert_eq!(rels(client.snapshot()).len(), 0);
    open(&mut client, &io);
    // Two registrations, the second unanswered (unknown), then a release
    // attempt: it must refuse on the drain, not on the codec.
    reg(&mut client, &mut authority, 2, 1030);
    let unanswered = client
        .prepare_registration(
            &root(client.writer_uuid(), 3),
            vec![],
            &Tick(1040),
            |_, _| true,
        )
        .unwrap();
    client.dispatch(&unanswered, &Tick(1040)).unwrap();
    let refused = client.prepare_release(&Tick(1050), BOUND, None);
    assert_eq!(
        refused.err().map(|e| e.to_string()),
        Some("intent refused: IntentDrainPending".to_owned())
    );
    let answer = authority.send(&unanswered);
    client
        .complete(
            &unanswered,
            Ok(&answer),
            &Tick(1051),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    release_ok(&mut client, &mut authority, 1060, "after drain");
    // A second release in the same epoch must not double the slot.
    let again = client.prepare_release(&Tick(1070), BOUND, None);
    assert_eq!(
        again.err().map(|e| e.to_string()),
        Some("intent refused: IntentDrainPending".to_owned())
    );
    assert_eq!(rels(client.snapshot()).len(), 1);
    assert_eq!(disk(&io).pending.len(), client.snapshot().pending.len());
}

/// A completed Release, a takeover fenced by another instance that then
/// registered, the acknowledged recovery takeover, recovery's Release, and a
/// mount cycle after it.
#[test]
fn fenced_takeover_then_acknowledged_recovery_release_then_cycle() {
    let (scratch, io, mut client, mut authority) = released_reopened(30);
    let prior = rels(client.snapshot());
    let live = root(client.writer_uuid(), 9);
    authority.cursor += 1;
    let row = authority.row.unwrap();
    authority.row = Some(Receipt {
        epoch: authority.cursor,
        instance: [40; 16],
        generation: row.generation + 1,
        state: ReceiptState::Live {
            prepared_root_id: GrainId::of(&live),
        },
        ..row
    });
    authority.root = live;
    let fenced = start_like(&mut client, &mut authority, 1010);
    assert!(
        matches!(fenced, Err(CoordinationError::Fenced { .. })),
        "{fenced:?}"
    );
    assert_eq!(rels(client.snapshot()), prior);
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 50);
    let takeover = reselect(&mut client, &authority, 2000).unwrap();
    // A crash between the consent and the grant keeps the release.
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 52);
    assert_eq!(rels(client.snapshot()), prior);
    let retained = client.retained_requests();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].bytes(), takeover.bytes());
    let completion = exchange(&mut client, &mut authority, &retained[0], 2010).unwrap();
    assert_eq!(
        completion,
        IntentCompletion::Accepted(authority.row.unwrap())
    );
    assert_eq!(rels(client.snapshot()).len(), 0);
    // The grant went to the process that wrote the consent; this one succeeds it.
    start_like(&mut client, &mut authority, 2020).unwrap();
    let release = client.prepare_recovery_release(&Tick(2030), BOUND).unwrap();
    exchange(&mut client, &mut authority, &release, 2030).unwrap();
    assert_eq!(client.snapshot().phase, Phase::Released);
    assert_eq!(authority.row.unwrap().state, ReceiptState::Released);
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 54);
    start_like(&mut client, &mut authority, 3000).unwrap();
    open(&mut client, &io);
    reg(&mut client, &mut authority, 11, 3010);
    release_ok(&mut client, &mut authority, 3020, "cycle after recovery");
}
