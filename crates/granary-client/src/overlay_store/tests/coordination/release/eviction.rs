// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Succession when the authority has evicted a Released row.

use super::lifecycle::start_like;
use super::*;

#[derive(Clone, Copy)]
enum BeforeEviction {
    Released,
    TransportLoss,
    BackendDisagreement,
    RefusedReplay { landed: bool },
}

fn retain_takeover(
    client: &mut WritableStore<SimIo>,
    authority: &mut Authority,
    before: BeforeEviction,
    why: &str,
) {
    let at = 1000;
    let takeover = client.prepare_succession(&Tick(at)).unwrap();
    let prior_epoch = authority.cursor;
    let landed = matches!(before, BeforeEviction::RefusedReplay { landed: true });
    if matches!(before, BeforeEviction::BackendDisagreement) {
        let first = exchange_with(client, &takeover, at, || reply(403, None, None, vec![]));
        assert!(
            matches!(
                first,
                Err(CoordinationError::Refused("IntentBackendDisagreement"))
            ),
            "{why}: first answer: {first:?}"
        );
    } else {
        client.dispatch(&takeover, &Tick(at)).unwrap();
        if landed {
            let answer = authority.send(&takeover);
            assert_eq!(
                (answer.status, authority.row.map(|row| row.epoch)),
                (200, Some(prior_epoch + 1)),
                "{why}: the grant lands before its reply is lost"
            );
        }
        let first = client.complete(
            &takeover,
            Err(IntentTransportError::Transport),
            &Tick(at + 1),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(
            matches!(first, Ok(IntentCompletion::Unknown)),
            "{why}: lost answer: {first:?}"
        );
    }
    let replay_refused = matches!(before, BeforeEviction::RefusedReplay { .. });
    if replay_refused {
        let refused = exchange_with(client, &takeover, 5000, || {
            reply(403, Some("no-principal"), None, vec![])
        });
        assert!(
            matches!(
                refused,
                Err(CoordinationError::Refused("IntentTerminalRefusal"))
            ),
            "{why}: replay answer: {refused:?}"
        );
    }
    let pending = client
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.operation == Operation::Ownership);
    assert_eq!(
        (
            client.snapshot().phase,
            pending.map(|p| (p.terminal, p.answered, p.attempts, p.body.as_slice())),
            authority.cursor
        ),
        (
            Phase::Handshake,
            Some((
                false,
                false,
                if replay_refused { 2 } else { 1 },
                takeover.bytes()
            )),
            prior_epoch + u64::from(landed)
        ),
        "{why}: unresolved takeover before eviction"
    );
}

fn start_after_eviction(
    why: &str,
    before: BeforeEviction,
) -> (Result<(), String>, Phase, u8, bool) {
    let (scratch, io, mut client, mut authority) = released_then_reopened();
    let old = intent::decode_receipt(&client.snapshot().current).unwrap();
    if !matches!(before, BeforeEviction::Released) {
        retain_takeover(&mut client, &mut authority, before, why);
    }

    // Eviction models elapsed authority retention independently of the
    // client clock. Retained requests are still within their local horizon.
    let evicted = authority.row.take();
    assert_eq!(
        (evicted.map(|row| row.state), authority.root.is_empty()),
        (Some(ReceiptState::Released), true),
        "{why}: authority state at eviction: {evicted:?}"
    );
    let sent_before = authority.sends.len();
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 40);
    let at = 7_200_000;
    let held = client
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.operation == Operation::Ownership && !pending.terminal);
    let window = held.map(|pending| (pending.eligible, pending.expires));
    assert_eq!(
        window.map(|(eligible, expires)| eligible <= at && at < expires),
        (!matches!(before, BeforeEviction::Released)).then_some(true),
        "{why}: retained takeover window {window:?} at client tick {at}"
    );
    let exact = held.map(|pending| pending.body.clone());
    let mut started = start_like(&mut client, &mut authority, at);
    let sent = authority.sends.get(sent_before);
    let mode = sent
        .and_then(|body| intent::decode_ownership(body).ok())
        .map(|ownership| ownership.mode);
    assert_eq!(
        (mode, exact.as_ref().is_none_or(|body| sent == Some(body))),
        (
            Some(OwnershipMode::Takeover {
                expected_epoch: old.epoch,
                generation: old.generation,
                state: ReceiptState::Released,
                recovery_ack: false,
            }),
            true
        ),
        "{why}: the first start sends a takeover of the evicted Released row"
    );

    if matches!(
        before,
        BeforeEviction::BackendDisagreement | BeforeEviction::RefusedReplay { .. }
    ) && !matches!(client.snapshot().phase, Phase::OwnedStart | Phase::Fenced)
        && client.snapshot().fence == 0
    {
        drop(client);
        io.crash();
        client = start(&scratch, &io, 41);
        started = start_like(&mut client, &mut authority, at + 5000);
    }
    let after = client.snapshot();
    (
        started.map_err(|error| error.to_string()),
        after.phase,
        after.fence,
        intent::decode_receipt(&after.current)
            .is_ok_and(|receipt| evicted.is_some_and(|old| receipt.epoch > old.epoch)),
    )
}

#[test]
fn released_row_eviction_allows_ownership_in_one_start() {
    let cases = [
        ("baseline", BeforeEviction::Released),
        ("transport-loss-not-landed", BeforeEviction::TransportLoss),
    ];
    assert_eq!(
        cases.map(|(why, before)| (why, start_after_eviction(why, before))),
        cases.map(|(why, _)| (why, (Ok(()), Phase::OwnedStart, 0, true))),
        "a clean Released snapshot takes fresh ownership in one start after eviction"
    );
}

#[test]
fn kept_takeover_allows_ownership_after_released_row_eviction() {
    let cases = [
        (
            "backend-first-not-landed",
            BeforeEviction::BackendDisagreement,
        ),
        (
            "lost-then-refused-not-landed",
            BeforeEviction::RefusedReplay { landed: false },
        ),
        (
            "lost-then-refused-landed",
            BeforeEviction::RefusedReplay { landed: true },
        ),
    ];
    assert_eq!(
        cases.map(|(why, before)| (why, start_after_eviction(why, before))),
        cases.map(|(why, _)| (why, (Ok(()), Phase::OwnedStart, 0, true))),
        "a kept takeover takes fresh ownership by the next start after eviction without fencing"
    );
}
