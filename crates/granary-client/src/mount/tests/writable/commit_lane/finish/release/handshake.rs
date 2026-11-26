// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Writable start after a lost takeover grant and a refused replay.

use super::*;

fn log_after_failed_start(stopped: &Stopped, writer: [u8; 16], log: &mut Vec<String>) {
    stopped.state.lock().unwrap().tick += 100_000;
    match start_remount(stopped, 71) {
        Ok(_) => log.push("healthy start 1: mounted".to_owned()),
        Err(error) => log.push(format!(
            "healthy start 1: {}: {error:?}; carrier {:?}",
            error.name(),
            carrier(stopped).phase
        )),
    }
    let plain = recover_with(stopped, writer, None, 130)
        .map(|outcome| format!("{outcome:?}"))
        .map_err(|error| error.to_string());
    let acked = recover_with(stopped, writer, Some(writer), 135)
        .map(|outcome| format!("{outcome:?}"))
        .map_err(|error| error.to_string());
    log.push(format!(
        "gran recover: {plain:?}; --acknowledge-takeover: {acked:?}; carrier {:?}; row {:?}",
        carrier(stopped).phase,
        row(stopped)
    ));
    let after_recover = start_remount(stopped, 90).map(|_| ());
    log.push(format!("start after recover: {after_recover:?}"));
}

#[test]
fn start_after_a_refused_replay_of_a_landed_takeover() {
    for refuse in [false, true] {
        let fixture = fixture_with(crate::SyncProfile::default());
        let (outcome, stopped) = shut_down_as(
            fixture,
            Trigger::Signal,
            crate::sync::DEFAULT_SHUTDOWN_BOUND,
        );
        assert!(matches!(outcome, Outcome::Clean), "{outcome:?}");
        let released = carrier(&stopped);
        let before = row(&stopped);
        assert_eq!(
            (released.phase, before.state),
            (Phase::Released, ReceiptState::Released)
        );
        {
            let mut state = stopped.state.lock().unwrap();
            state.ownership_strict = true;
            state.ownership_lost_grants = 1;
            state.ownership_refusals = u32::from(refuse);
        }
        if !refuse {
            let fixture = remount(stopped, 60)
                .unwrap_or_else(|error| panic!("control: a lost grant alone must resume: {error}"));
            {
                let state = fixture.state.lock().unwrap();
                assert_eq!(
                    (state.ownership_lost_grants, state.row.map(|row| row.epoch)),
                    (0, Some(before.epoch + 1)),
                    "control: one grant landed and its reply was lost"
                );
            }
            assert_clean_release_after_remount(fixture);
            eprintln!("control: a lost grant alone resumed and shut down cleanly");
            continue;
        }

        let sent_before = sends(&stopped);
        let refused = start_remount(&stopped, 60)
            .err()
            .unwrap_or_else(|| panic!("the refused start mounted"));
        let landed = row(&stopped);
        let ownership_sends = handshakes(&stopped, sent_before);
        let exact_replay = {
            let state = stopped.state.lock().unwrap();
            let mut sent = state.sends.iter().skip(sent_before);
            sent.next().is_some_and(|first| sent.next() == Some(first))
        };
        assert_eq!(
            (
                refused.name(),
                ownership_sends,
                exact_replay,
                landed.epoch,
                landed.state
            ),
            (
                "IntentTerminalRefusal",
                2,
                true,
                before.epoch + 1,
                ReceiptState::Released
            ),
            "the landed takeover lost its grant and the exact replay was refused"
        );

        let after = carrier(&stopped);
        let slots: Vec<_> = after
            .pending
            .iter()
            .filter(|pending| pending.operation == Operation::Ownership)
            .map(|pending| (pending.terminal, pending.answered, pending.attempts))
            .collect();
        let mut log = vec![
            format!("refused start: {}: {refused:?}", refused.name()),
            format!(
                "carrier {:?} ownership slots {slots:?}; ownership sends {ownership_sends}; authority row {landed:?}",
                after.phase
            ),
        ];
        stopped.state.lock().unwrap().tick += 100_000;
        let first = start_remount(&stopped, 70);
        if let Err(error) = &first {
            log.push(format!(
                "healthy start 0: {}: {error:?}; carrier {:?}",
                error.name(),
                carrier(&stopped).phase
            ));
            log_after_failed_start(&stopped, released.writer, &mut log);
        }
        assert!(
            first.is_ok(),
            "the first healthy start must mount after the refused replay: {log:#?}"
        );
    }
}

#[test]
fn persistent_takeover_refusal_across_starts_and_recovery() {
    let fixture = fixture_with(crate::SyncProfile::default());
    let (outcome, stopped) = shut_down_as(
        fixture,
        Trigger::Signal,
        crate::sync::DEFAULT_SHUTDOWN_BOUND,
    );
    assert_eq!(outcome, Outcome::Clean);
    let released = row(&stopped);
    let writer = carrier(&stopped).writer;
    {
        let mut state = stopped.state.lock().unwrap();
        state.ownership_strict = true;
        state.ownership_lost_grants = 1;
        state.ownership_refusals = 3;
    }
    let before = sends(&stopped);
    let first = start_remount(&stopped, 60).err().map(|error| error.name());
    let mut held = carrier(&stopped);
    let landed = row(&stopped);
    let pending = held
        .pending
        .iter()
        .find(|pending| pending.operation == Operation::Ownership)
        .unwrap();
    let exact = pending.body.clone();
    assert_eq!(
        (
            first,
            held.phase,
            (pending.terminal, pending.answered, pending.attempts),
            &stopped.state.lock().unwrap().sends[before..],
            landed.epoch,
            landed.state,
        ),
        (
            Some("IntentTerminalRefusal"),
            Phase::Handshake,
            (false, false, 2),
            &[exact.clone(), exact.clone()][..],
            released.epoch + 1,
            ReceiptState::Released
        ),
        "first start loses a landed grant and keeps the refused exact replay"
    );

    for (attempt, recovery) in [(3, false), (4, true)] {
        let before = sends(&stopped);
        let result = if recovery {
            recover_with(&stopped, writer, None, 130)
                .err()
                .map(|error| error.to_string())
        } else {
            start_remount(&stopped, 70)
                .err()
                .map(|error| error.name().to_owned())
        };
        let after = carrier(&stopped);
        let remote = row(&stopped);
        held.revision = after.revision;
        held.pending
            .iter_mut()
            .find(|pending| pending.operation == Operation::Ownership)
            .unwrap()
            .attempts = attempt;
        assert_eq!(
            (
                result.as_deref(),
                &after,
                &stopped.state.lock().unwrap().sends[before..],
                remote
            ),
            (
                Some("IntentTerminalRefusal"),
                &held,
                std::slice::from_ref(&exact),
                landed
            ),
            "recovery={recovery}: the refusal changes only the dispatch count and persistence revision"
        );
    }

    let before = sends(&stopped);
    let fixture = remount(stopped, 80).unwrap_or_else(|error| panic!("healthy start: {error}"));
    assert_eq!(
        fixture.state.lock().unwrap().sends.get(before),
        Some(&exact)
    );
    assert_clean_release_after_remount(fixture);
}
