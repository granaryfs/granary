// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The fencing write keeps an unconsented succession that was sent and has
//! no answer of its own.

use super::*;

/// A registration dispatched before an unconsented succession is answered
/// `Superseded` after the succession was sent but left unanswered (the
/// authority applied it; the transport lost the reply). The fence comes from
/// the registration, not from the succession, so the succession is still an
/// unanswered request: its exact bytes are the only proof of what was sent.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one crash schedule checks retained evidence and its acknowledged replacement"
)]
fn unanswered_succession_survives_a_fence_from_another_request() {
    let (scratch, io, mut local, mut authority) = serving();
    let registration = local
        .prepare_registration(&root(local.writer_uuid(), 7), vec![], &Tick(10), |_, _| {
            true
        })
        .unwrap();
    local.dispatch(&registration, &Tick(10)).unwrap();
    let succession = local.prepare_succession(&Tick(11)).unwrap();
    local.dispatch(&succession, &Tick(11)).unwrap();
    // The authority applies the takeover; its reply is lost.
    let _lost = authority.send(&succession);
    let unknown = local.complete(
        &succession,
        Err(crate::IntentTransportError::Transport),
        &Tick(12),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert!(
        matches!(unknown, Ok(IntentCompletion::Unknown)),
        "{unknown:?}"
    );
    let mut expected = local
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.body == succession.bytes())
        .cloned()
        .unwrap_or_else(|| panic!("missing succession in {:?}", local.snapshot().pending));
    assert_eq!(
        (expected.terminal, expected.answered, expected.attempts),
        (false, false, 1)
    );
    expected.terminal = true;
    // The older registration is now answered by the store's own successor.
    let answer = authority.send(&registration);
    let fenced = local.complete(
        &registration,
        Ok(&answer),
        &Tick(13),
        &mut SeededRng::new(1),
        0,
        None,
    );
    eprintln!("registration completion: {fenced:?}");
    drop(local);
    io.crash();
    let mut reopened = start(&scratch, &io, 40);
    let carrier = reopened.snapshot();
    eprintln!(
        "reopened phase={:?} fence={} pending={}",
        carrier.phase,
        carrier.fence,
        carrier.pending.len()
    );
    let retained = carrier
        .pending
        .iter()
        .any(|pending| pending.body == succession.bytes());
    // The fence is durable, and the unanswered request keeps its exact bytes.
    assert_eq!(
        (
            matches!(fenced, Err(CoordinationError::Fenced { .. })),
            carrier.phase,
            retained
        ),
        (true, Phase::Fenced, true),
        "(completion fenced, reopened phase, unanswered succession retained): {fenced:?}"
    );
    assert_eq!(carrier.fence, 1);
    assert_eq!(
        carrier
            .pending
            .iter()
            .find(|pending| pending.body == succession.bytes()),
        Some(&expected)
    );

    let row = authority.row.unwrap();
    let writer = reopened.writer_uuid();
    let readback = intent::encode_readback(
        authority.cursor,
        &[intent::ReadbackRow {
            writer,
            epoch: row.epoch,
            generation: row.generation,
            root: &authority.root,
        }],
    )
    .unwrap();
    let selection = crate::SelectedRecovery::from_readback(
        carrier.scope.clone(),
        carrier.volume.clone(),
        writer,
        &reply(200, None, Some(intent::MEDIA_READBACK), readback),
        |_, _| true,
    )
    .unwrap();
    let takeover = reopened
        .reselect(selection.acknowledge_takeover(writer).unwrap(), &Tick(41))
        .unwrap();
    let mode = intent::decode_ownership(takeover.bytes()).unwrap().mode;
    assert!(
        matches!(mode, OwnershipMode::Takeover { recovery_ack: true, expected_epoch, .. } if expected_epoch == row.epoch),
        "{mode:?}"
    );
    let selected = reopened.snapshot().clone();
    assert_eq!(selected.validate(), Ok(()));
    drop(reopened);
    io.crash();
    let reopened = start(&scratch, &io, 50);
    let carrier = reopened.snapshot();
    let ownership = carrier
        .pending
        .iter()
        .filter(|pending| pending.operation == Operation::Ownership)
        .map(|pending| pending.body.as_slice())
        .collect::<Vec<_>>();
    assert_eq!(
        (carrier, carrier.phase, carrier.fence, ownership),
        (&selected, Phase::Handshake, 1, vec![takeover.bytes()])
    );
}

/// The succession expires unanswered at mount or recovery, which leaves the
/// carrier `Unowned`; the older registration is then answered `Superseded`.
/// The displacement must still be recorded durably.
#[test]
fn a_displacement_after_an_expired_succession_is_durable() {
    let (scratch, io, mut local, mut authority) = serving();
    let registration = local
        .prepare_registration(&root(local.writer_uuid(), 7), vec![], &Tick(10), |_, _| {
            true
        })
        .unwrap();
    local.dispatch(&registration, &Tick(10)).unwrap();
    let succession = local.prepare_succession(&Tick(11)).unwrap();
    local.dispatch(&succession, &Tick(11)).unwrap();
    let _lost = authority.send(&succession);
    let unknown = local.complete(
        &succession,
        Err(crate::IntentTransportError::Transport),
        &Tick(12),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert!(
        matches!(unknown, Ok(IntentCompletion::Unknown)),
        "{unknown:?}"
    );
    let late = Tick(200_000_000);
    local.settle_expired_handshake(&late).unwrap();
    assert_eq!(local.snapshot().phase, Phase::Unowned);
    let answer = authority.send(&registration);
    let fenced = local.complete(
        &registration,
        Ok(&answer),
        &late,
        &mut SeededRng::new(1),
        0,
        None,
    );
    eprintln!("registration completion: {fenced:?}");
    drop(local);
    io.crash();
    let reopened = start(&scratch, &io, 40);
    let carrier = reopened.snapshot();
    eprintln!(
        "reopened phase={:?} fence={} pending={}",
        carrier.phase,
        carrier.fence,
        carrier.pending.len()
    );
    assert_eq!(
        (carrier.phase, carrier.fence),
        (Phase::Fenced, 1),
        "{fenced:?}"
    );
}

#[test]
fn an_absent_registration_keeps_the_unanswered_succession() {
    for expire_first in [false, true] {
        let (scratch, io, mut local, mut authority) = serving();
        let registration = local
            .prepare_registration(&root(local.writer_uuid(), 7), vec![], &Tick(10), |_, _| {
                true
            })
            .unwrap();
        local.dispatch(&registration, &Tick(10)).unwrap();
        let succession = local.prepare_succession(&Tick(11)).unwrap();
        local.dispatch(&succession, &Tick(11)).unwrap();
        let _lost = authority.send(&succession);
        let unknown = local.complete(
            &succession,
            Err(crate::IntentTransportError::Transport),
            &Tick(12),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(
            matches!(unknown, Ok(IntentCompletion::Unknown)),
            "{unknown:?}"
        );
        let at = if expire_first {
            let late = Tick(200_000_000);
            local.settle_expired_handshake(&late).unwrap();
            assert_eq!(local.snapshot().phase, Phase::Unowned);
            late
        } else {
            Tick(13)
        };
        authority.row = None;
        let answer = authority.send(&registration);
        let fenced = local.complete(
            &registration,
            Ok(&answer),
            &at,
            &mut SeededRng::new(1),
            0,
            None,
        );
        drop(local);
        io.crash();
        let mut reopened = start(&scratch, &io, 40);
        let carrier = reopened.snapshot();
        let kept = carrier
            .pending
            .iter()
            .find(|p| p.body == succession.bytes())
            .map(|p| (p.terminal, p.answered, p.attempts));
        assert_eq!(
            (carrier.phase, carrier.fence, kept),
            (Phase::Fenced, 2, Some((true, false, 1))),
            "{fenced:?}"
        );
        assert!(reopened.dispatch(&succession, &Tick(41)).is_err());
        let late_answer = authority.send(&succession);
        let late = reopened.complete(
            &succession,
            Ok(&late_answer),
            &Tick(42),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(late.is_err());
        assert_eq!(reopened.snapshot().phase, Phase::Fenced);
    }
}

#[test]
fn answered_succession_is_retired_when_a_later_registration_fences() {
    let (scratch, io, mut local, mut authority) = serving();
    let succession = local.prepare_succession(&Tick(10)).unwrap();
    local.dispatch(&succession, &Tick(10)).unwrap();
    let answer = authority.send(&succession);
    let completion = local.complete(
        &succession,
        Ok(&answer),
        &Tick(11),
        &mut SeededRng::new(1),
        0,
        None,
    );
    let granted = authority.row.unwrap();
    let answered = local
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.body == succession.bytes())
        .map(|pending| (pending.terminal, pending.answered, pending.attempts));
    assert_eq!(
        (completion.unwrap(), answered),
        (IntentCompletion::Accepted(granted), Some((true, true, 1)))
    );

    let registration = local
        .prepare_registration(&root(local.writer_uuid(), 7), vec![], &Tick(12), |_, _| {
            true
        })
        .unwrap();
    local.dispatch(&registration, &Tick(12)).unwrap();
    authority.cursor += 1;
    authority.row = Some(Receipt {
        epoch: authority.cursor,
        instance: [99; 16],
        ..granted
    });
    let answer = authority.send(&registration);
    let fenced = local.complete(
        &registration,
        Ok(&answer),
        &Tick(13),
        &mut SeededRng::new(1),
        0,
        None,
    );
    drop(local);
    io.crash();
    let reopened = start(&scratch, &io, 40);
    let carrier = reopened.snapshot();
    assert_eq!(
        (
            matches!(fenced, Err(CoordinationError::Fenced { .. })),
            carrier.phase,
            carrier.fence,
            carrier.pending.iter().any(|p| p.body == succession.bytes()),
        ),
        (true, Phase::Fenced, 1, false),
        "{fenced:?}"
    );
}

#[test]
fn never_dispatched_succession_is_retired_when_an_older_registration_fences() {
    let (scratch, io, mut local, mut authority) = serving();
    let registration = local
        .prepare_registration(&root(local.writer_uuid(), 7), vec![], &Tick(10), |_, _| {
            true
        })
        .unwrap();
    local.dispatch(&registration, &Tick(10)).unwrap();
    let succession = local.prepare_succession(&Tick(11)).unwrap();
    let prepared = local
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.body == succession.bytes())
        .map(|pending| (pending.terminal, pending.answered, pending.attempts));
    assert_eq!(prepared, Some((false, false, 0)));

    authority.cursor += 1;
    authority.row = Some(Receipt {
        epoch: authority.cursor,
        instance: [99; 16],
        ..authority.row.unwrap()
    });
    let answer = authority.send(&registration);
    let fenced = local.complete(
        &registration,
        Ok(&answer),
        &Tick(12),
        &mut SeededRng::new(1),
        0,
        None,
    );
    drop(local);
    io.crash();
    let reopened = start(&scratch, &io, 40);
    let carrier = reopened.snapshot();
    assert_eq!(
        (
            matches!(fenced, Err(CoordinationError::Fenced { .. })),
            carrier.phase,
            carrier.fence,
            carrier.pending.iter().any(|p| p.body == succession.bytes()),
        ),
        (true, Phase::Fenced, 1, false),
        "{fenced:?}"
    );
}
