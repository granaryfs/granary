// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn completed_publication_can_leave_owned_start_with_fresh_registration() {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let mut authority = Authority::default();
    acquire(&mut client, &mut authority);
    open(&mut client, &io);
    let fixture =
        include_bytes!("../../../../../granary-core/tests/vectors/retained-submission/ready.bin");
    let mut submission = granary_core::retained_submission::decode(fixture).unwrap();
    submission.scope = client.snapshot().scope.clone();
    submission.volume = client.snapshot().volume.clone();
    for candidate in &mut submission.candidates {
        let mut doc = granary_core::root::decode_root(&candidate.root).unwrap();
        doc.volume = submission.volume.clone();
        candidate.root = granary_core::root::encode_root(&doc).unwrap();
        candidate.id = GrainId::of(&candidate.root);
    }
    let mut frozen = granary_core::root::decode_root(&submission.frozen.initial_root).unwrap();
    frozen.volume = submission.volume.clone();
    submission.frozen.initial_root = granary_core::root::encode_root(&frozen).unwrap();
    client
        .publication_transaction(|p| p.begin(&submission))
        .unwrap();
    register(&mut client, &mut authority, 1);
    assert_eq!(client.snapshot().phase, Phase::OwnedStart);
    let candidate = &submission.candidates[0];
    submission.phase = granary_core::retained_submission::Phase::Complete(
        granary_core::retained_submission::Completion {
            seq: candidate.seq,
            id: candidate.id,
            root: candidate.root.clone(),
            receipt: None,
        },
    );
    submission.current = None;
    let previous = client
        .publication_transaction(|p| p.load(&submission.scope, &submission.volume))
        .unwrap()
        .unwrap()
        .generation;
    submission.generation = previous + 1;
    client
        .publication_transaction(|p| p.replace(previous, &submission))
        .unwrap();
    assert_eq!(
        client.snapshot().phase,
        Phase::OwnedStart,
        "record completion alone does not promote ownership"
    );
    assert!(matches!(
        client.prepare_release(&Tick(10), crate::DEFAULT_RESOLUTION_BOUND, None),
        Err(CoordinationError::Refused("IntentDrainPending"))
    ));
    register(&mut client, &mut authority, 2);
    assert_eq!(
        client.snapshot().phase,
        Phase::Serving,
        "fresh registration is an existing path out of owned-start"
    );
    client
        .prepare_release(&Tick(10), crate::DEFAULT_RESOLUTION_BOUND, None)
        .unwrap();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one selected-takeover schedule checks four refusals, restart and successful fresh acquisition"
)]
fn terminal_selected_takeover_refusal_allows_fresh_acquire_after_restart() {
    for (status, token, refusal) in [
        (409, "intent-changed", "IntentSelectionChanged"),
        (409, "intent-epoch-exhausted", "IntentEpochExhausted"),
        (400, "bad-request", "IntentTerminalRefusal"),
        (403, "no-principal", "IntentTerminalRefusal"),
    ] {
        let (_s, _io, _old, authority) = serving();
        let scratch = Scratch::new();
        let io = SimIo::default();
        let mut config = config(&scratch.0);
        config.cap = 134_217_728;
        config.ownership_completion_reserve = REPLACEMENT_RESERVE;
        let row = authority.row.unwrap();
        let readback = intent::encode_readback(
            authority.cursor,
            &[intent::ReadbackRow {
                writer: row.writer,
                epoch: row.epoch,
                generation: row.generation,
                root: &authority.root,
            }],
        )
        .unwrap();
        let selected = crate::SelectedRecovery::from_readback(
            config.scope.clone(),
            config.volume.clone(),
            row.writer,
            &reply(200, None, Some(intent::MEDIA_READBACK), readback),
            |_, _| true,
        )
        .unwrap();
        let mut client = WritableStore::adopt_selected(
            Store::open(&scratch.0).unwrap(),
            config,
            io.clone(),
            &mut Entropy(30),
            FaultControl::default(),
            selected.acknowledge_displacement(),
        )
        .unwrap();
        let request = client.begin_selected_attempt(&Tick(10)).unwrap();
        client.dispatch(&request, &Tick(10)).unwrap();
        let answer = if token == "intent-changed" {
            reply(
                status,
                Some(token),
                Some(intent::MEDIA_RECEIPT),
                intent::encode_receipt(Receipt {
                    generation: row.generation + 1,
                    state: ReceiptState::Live {
                        prepared_root_id: grain(99),
                    },
                    ..row
                })
                .unwrap(),
            )
        } else {
            reply(status, Some(token), None, vec![])
        };
        let result = client.complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert_eq!(
            (
                result.err().map(|error| error.to_string()),
                client.snapshot().phase
            ),
            (Some(format!("intent refused: {refusal}")), Phase::Unowned),
            "terminal selected takeover returns to unowned: {token}"
        );
        assert!(client.snapshot().grant.is_empty());
        assert!(client.retained_requests().is_empty());
        drop(client);
        io.crash();
        let mut client = start(&scratch, &io, 40);
        assert_eq!(client.snapshot().phase, Phase::Unowned);
        let mut absent = Authority {
            cursor: authority.cursor,
            ..Authority::default()
        };
        let request = client.prepare_acquire(absent.cursor, &Tick(20)).unwrap();
        client.dispatch(&request, &Tick(20)).unwrap();
        let answer = absent.send(&request);
        let result = client.complete(
            &request,
            Ok(&answer),
            &Tick(21),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(
            result.is_ok(),
            "fresh acquire accepts grant after terminal takeover: {result:?}"
        );
        assert_eq!(
            client.snapshot().phase,
            Phase::OwnedStart,
            "fresh acquire after terminal takeover survives restart"
        );
    }
}
