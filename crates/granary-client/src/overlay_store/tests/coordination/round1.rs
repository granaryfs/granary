// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn coordination_round1_out_of_order_receipts_reclaim_across_restart() {
    let (scratch, io, mut client, mut authority) = serving();
    for n in 0..130 {
        let low = client
            .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
                true
            })
            .unwrap();
        client.dispatch(&low, &Tick(10)).unwrap();
        let low_answer = authority.send(&low);
        let high = client
            .prepare_registration(&root(client.writer_uuid(), 3), vec![], &Tick(11), |_, _| {
                true
            })
            .unwrap();
        client.dispatch(&high, &Tick(11)).unwrap();
        let high_answer = authority.send(&high);
        client
            .complete(
                &high,
                Ok(&high_answer),
                &Tick(12),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
        assert_eq!(
            client
                .snapshot()
                .pending
                .iter()
                .filter(|p| p.operation == Operation::Register)
                .count(),
            0,
            "out-of-order slots reclaimed at race {n}"
        );
        let revision = client.snapshot().revision;
        assert!(
            client
                .complete(
                    &low,
                    Ok(&reply(400, Some("bad-request"), None, vec![])),
                    &Tick(13),
                    &mut SeededRng::new(1),
                    0,
                    None
                )
                .is_err()
        );
        assert_eq!(
            client.snapshot().revision,
            revision,
            "reclaimed refusal does not persist"
        );
        assert!(
            client
                .complete(
                    &low,
                    Ok(&low_answer),
                    &Tick(13),
                    &mut SeededRng::new(1),
                    0,
                    None
                )
                .is_err(),
            "reclaimed acceptance cannot resurrect"
        );
    }
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 30);
    let transfer = client.prepare_succession(&Tick(20)).unwrap();
    client.dispatch(&transfer, &Tick(20)).unwrap();
    let answer = authority.send(&transfer);
    client
        .complete(
            &transfer,
            Ok(&answer),
            &Tick(21),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    open(&mut client, &io);
    register(&mut client, &mut authority, 4);
    assert_eq!(
        client.snapshot().phase,
        Phase::Serving,
        "reclaimed pipeline survives restart"
    );
}

#[test]
fn coordination_round1_terminal_acquire_refusals_allow_retry_after_restart() {
    for (status, token, refusal) in [
        (409, "intent-quota", "IntentOverQuota"),
        (409, "intent-epoch-exhausted", "IntentEpochExhausted"),
        (404, "unknown-target", "IntentNotImplemented"),
        (400, "bad-request", "IntentTerminalRefusal"),
        (403, "no-principal", "IntentTerminalRefusal"),
        (409, "intent-cursor-changed", "IntentCursorChanged"),
    ] {
        let scratch = Scratch::new();
        let io = SimIo::default();
        let mut client = start(&scratch, &io, 10);
        let request = client.prepare_acquire(0, &Tick(1)).unwrap();
        client.dispatch(&request, &Tick(1)).unwrap();
        let answer = reply(status, Some(token), None, vec![]);
        let result = client.complete(
            &request,
            Ok(&answer),
            &Tick(2),
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
            "terminal acquire returns to unowned: {token}"
        );
        drop(client);
        io.crash();
        let mut client = start(&scratch, &io, 30);
        acquire(&mut client, &mut Authority::default());
        assert_eq!(
            client.snapshot().phase,
            Phase::OwnedStart,
            "terminal acquire retry survives restart"
        );
    }
    // Changed carries a valid different row, unlike the bodyless refusals.
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut client = start(&scratch, &io, 10);
    let mut authority = Authority {
        row: Some(Receipt {
            writer: client.writer_uuid(),
            epoch: 1,
            instance: [99; 16],
            generation: 0,
            state: ReceiptState::Released,
        }),
        ..Authority::default()
    };
    let request = client.prepare_acquire(0, &Tick(1)).unwrap();
    client.dispatch(&request, &Tick(1)).unwrap();
    let changed = authority.send(&request);
    assert!(
        client
            .complete(
                &request,
                Ok(&changed),
                &Tick(2),
                &mut SeededRng::new(1),
                0,
                None
            )
            .is_err()
    );
    assert_eq!(
        client.snapshot().phase,
        Phase::Unowned,
        "changed acquire returns to unowned"
    );
}

#[test]
fn coordination_round1_local_transport_errors_retain_exact_acquire() {
    for error in [
        IntentTransportError::InvalidRequest,
        IntentTransportError::Backend,
    ] {
        let scratch = Scratch::new();
        let io = SimIo::default();
        let mut client = start(&scratch, &io, 10);
        let request = client.prepare_acquire(0, &Tick(1)).unwrap();
        client.dispatch(&request, &Tick(1)).unwrap();
        let result = client.complete(
            &request,
            Err(error),
            &Tick(2),
            &mut SeededRng::new(1),
            0,
            None,
        );
        assert!(
            matches!(result, Ok(crate::IntentCompletion::Unknown)),
            "no network evidence retains acquire: {result:?}"
        );
        let pending = &client.snapshot().pending[0];
        assert!(
            !pending.terminal && !pending.answered,
            "local refusal is not an answer"
        );
        let eligible = pending.eligible;
        drop(client);
        io.crash();
        let mut client = start(&scratch, &io, 30);
        let retained = client.retained_requests().pop().unwrap();
        assert_eq!(retained.bytes(), request.bytes());
        client.dispatch(&retained, &Tick(eligible)).unwrap();
        let answer = Authority::default().send(&retained);
        client
            .complete(
                &retained,
                Ok(&answer),
                &Tick(eligible + 1),
                &mut SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
    }
}

fn selection(client: &OverlayConfig, authority: &Authority) -> crate::SelectedRecovery {
    let row = authority.row.unwrap();
    let bytes = intent::encode_readback(
        authority.cursor,
        &[intent::ReadbackRow {
            writer: row.writer,
            epoch: row.epoch,
            generation: row.generation,
            root: &authority.root,
        }],
    )
    .unwrap();
    crate::SelectedRecovery::from_readback(
        client.scope.clone(),
        client.volume.clone(),
        row.writer,
        &reply(200, None, Some(intent::MEDIA_READBACK), bytes),
        |_, _| true,
    )
    .unwrap()
}
fn recovery_config(scratch: &Scratch) -> OverlayConfig {
    let mut client = config(&scratch.0);
    client.cap = 134_217_728;
    client.ownership_completion_reserve = REPLACEMENT_RESERVE;
    client
}

#[test]
fn coordination_round1_selected_takeover_superseded_fences_after_restart() {
    let (_s, _io, old, mut authority) = serving();
    let scratch = Scratch::new();
    let io = SimIo::default();
    let config = recovery_config(&scratch);
    let selected = selection(&config, &authority);
    let mut client = WritableStore::adopt_selected(
        Store::open(&scratch.0).unwrap(),
        config,
        io.clone(),
        &mut Entropy(30),
        FaultControl::default(),
        selected.acknowledge_displacement(),
    )
    .unwrap();
    assert!(client.snapshot().current.is_empty());
    let request = client.begin_selected_attempt(&Tick(10)).unwrap();
    client.dispatch(&request, &Tick(10)).unwrap();
    authority.row = Some(Receipt {
        epoch: authority.cursor + 1,
        instance: [99; 16],
        ..authority.row.unwrap()
    });
    let answer = authority.send(&request);
    let result = client.complete(
        &request,
        Ok(&answer),
        &Tick(11),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert!(
        matches!(result, Err(CoordinationError::Fenced { .. })),
        "selected takeover displacement persists fence: {result:?}"
    );
    assert_eq!(client.snapshot().phase, Phase::Fenced);
    assert!(
        matches!(
            client.recovery_rule().map(crate::RecoveryRule::admitted),
            Ok(Err(CoordinationError::Refused(
                "IntentSelectedWriterMissing"
            )))
        ),
        "a fenced carrier is reported by rule 0, never acted on"
    );
    drop(old);
    drop(client);
    io.crash();
    let mut client = start(&scratch, &io, 40);
    assert!(
        matches!(
            client.prepare_acquire(0, &Tick(20)),
            Err(CoordinationError::Fenced { .. })
        ),
        "selected fence survives restart"
    );
    assert!(
        client.retained_requests().is_empty(),
        "fenced takeover never retransmits"
    );
}

#[test]
fn coordination_round1_recovery_release_serves_then_names_selected_generation() {
    let (_s, _io, _old, mut authority) = serving();
    authority.row = Some(Receipt {
        generation: 5,
        ..authority.row.unwrap()
    });
    let scratch = Scratch::new();
    let io = SimIo::default();
    let config = recovery_config(&scratch);
    let selected = selection(&config, &authority);
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
    assert!(
        matches!(
            client.prepare_recovery_release(&Tick(10), crate::DEFAULT_RESOLUTION_BOUND),
            Err(CoordinationError::Refused("IntentOwnershipPending"))
        ),
        "no release before the grant is persisted"
    );
    client.dispatch(&request, &Tick(10)).unwrap();
    let answer = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let mut phases = vec![client.snapshot().phase];
    let release = client
        .prepare_recovery_release(&Tick(20), crate::DEFAULT_RESOLUTION_BOUND)
        .unwrap();
    phases.push(client.snapshot().phase);
    assert_eq!(
        intent::decode_release(release.bytes()).unwrap().generation,
        5,
        "release names the selected generation"
    );
    client.dispatch(&release, &Tick(20)).unwrap();
    let answer = authority.send(&release);
    client
        .complete(
            &release,
            Ok(&answer),
            &Tick(21),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    phases.push(client.snapshot().phase);
    // The phase table refuses owned start to releasing, so reaching
    // releasing proves serving was persisted between them.
    let row = authority.row.unwrap();
    assert_eq!(
        (phases, row.state, row.generation),
        (
            vec![Phase::OwnedStart, Phase::Releasing, Phase::Released],
            ReceiptState::Released,
            5
        )
    );
    assert_eq!(
        client.recovery_rule().unwrap(),
        crate::RecoveryRule::Nothing,
        "a released row owes nothing"
    );
}

#[test]
fn coordination_round1_recovery_owner_requires_this_instances_grant() {
    let name = |result: Result<(), CoordinationError>| match result {
        Ok(()) => None,
        Err(CoordinationError::Refused(name)) => Some(name),
        Err(error) => panic!("unexpected refusal: {error}"),
    };
    let (_s, _io, _old, mut authority) = serving();
    let scratch = Scratch::new();
    let io = SimIo::default();
    let config = recovery_config(&scratch);
    let selected = selection(&config, &authority);
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
    let pending = name(client.check_recovery_owner());
    client.dispatch(&request, &Tick(10)).unwrap();
    let answer = authority.send(&request);
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let granted = name(client.check_recovery_owner());
    let rule = client.recovery_rule().unwrap();
    drop(client);
    io.crash();
    // A new process mints a new instance; the persisted grant names the old one.
    let mut client = start(&scratch, &io, 40);
    let rerun = name(client.check_recovery_owner());
    let transfer = client.prepare_succession(&Tick(20)).unwrap();
    client.dispatch(&transfer, &Tick(20)).unwrap();
    let answer = authority.send(&transfer);
    client
        .complete(
            &transfer,
            Ok(&answer),
            &Tick(21),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    let succeeded = name(client.check_recovery_owner());
    assert_eq!(
        (pending, granted, rule, rerun, succeeded),
        (
            Some("IntentOwnershipPending"),
            None,
            crate::RecoveryRule::Classify,
            Some("IntentFreshInstanceRequired"),
            None
        ),
        "(handshake, granted, rule, re-run before succession, after succession)"
    );
}

#[test]
fn coordination_round1_adoption_raises_existing_writer_before_carrier() {
    let (_s, _io, _old, mut authority) = serving();
    authority.row = Some(Receipt {
        generation: 200,
        ..authority.row.unwrap()
    });
    for fail in [false, true] {
        let scratch = Scratch::new();
        let io = SimIo::default();
        let config = recovery_config(&scratch);
        let mut store = Store::open(&scratch.0).unwrap();
        let area = store
            .publication_root()
            .join("overlay")
            .join(config.scope.digest().unwrap())
            .join("v");
        // Establish just the matching writer, with a ceiling below selection.
        OverlayStore::establish_writer(
            &mut store,
            &config,
            &mut io.clone(),
            &mut Entropy(11),
            &FaultControl::default(),
        )
        .unwrap();
        let before = io.bytes(&area.join("writer"));
        assert_eq!(
            WriterRecord::decode(&before).unwrap().writer,
            authority.row.unwrap().writer
        );
        let mut disk = io.clone();
        disk.create(&area.join("writer.tmp")).unwrap();
        disk.write_at(&area.join("writer.tmp"), 0, b"stale")
            .unwrap();
        io.0.lock().unwrap().trace.clear();
        if fail {
            io.0.lock().unwrap().fail = Some("sync");
        }
        let selected = selection(&config, &authority);
        let result = WritableStore::adopt_selected(
            store,
            config,
            io.clone(),
            &mut Entropy(30),
            FaultControl::default(),
            selected.acknowledge_displacement(),
        );
        if fail {
            assert!(result.is_err(), "ceiling barrier failure refuses adoption");
            assert!(
                !io.0
                    .lock()
                    .unwrap()
                    .names
                    .contains_key(&area.join("ownership")),
                "failed ceiling never records selected G"
            );
        } else {
            assert!(
                result.is_ok(),
                "equal selected ceiling permits adoption: {result:?}"
            );
            let client = result.unwrap();
            assert!(
                WriterRecord::decode(&io.bytes(&area.join("writer")))
                    .unwrap()
                    .ceiling
                    >= client.snapshot().allocated,
                "existing selected writer ceiling covers allocated"
            );
            let trace = io.0.lock().unwrap().trace.clone();
            let writer_sync = trace
                .iter()
                .position(|(op, path)| op == "dir_sync" && path == &area)
                .unwrap();
            let carrier_write = trace
                .iter()
                .position(|(op, path)| op == "write" && path.ends_with("ownership.tmp"))
                .unwrap();
            assert!(
                writer_sync < carrier_write,
                "ceiling durable before selected carrier"
            );
            drop(client);
            io.crash();
            assert!(
                try_start(&scratch, &io, 40).is_ok(),
                "selected ceiling reopens"
            );
        }
    }
}

#[test]
fn coordination_round1_adoption_beside_evidence_has_no_writer_side_effect() {
    let (_s, _io, _old, authority) = serving();
    for evidence in ["ownership", "journal"] {
        let scratch = Scratch::new();
        let io = SimIo::default();
        let config = recovery_config(&scratch);
        let mut store = Store::open(&scratch.0).unwrap();
        let area = store
            .publication_root()
            .join("overlay")
            .join(config.scope.digest().unwrap())
            .join("v");
        OverlayStore::establish_writer(
            &mut store,
            &config,
            &mut io.clone(),
            &mut Entropy(11),
            &FaultControl::default(),
        )
        .unwrap();
        let mut disk = io.clone();
        if evidence == "ownership" {
            disk.remove(&area.join("writer")).unwrap();
        }
        disk.create(&area.join(evidence)).unwrap();
        io.0.lock().unwrap().trace.clear();
        let selected = selection(&config, &authority);
        let result = WritableStore::adopt_selected(
            store,
            config,
            io.clone(),
            &mut Entropy(30),
            FaultControl::default(),
            selected.acknowledge_displacement(),
        );
        assert!(result.is_err(), "beside evidence refuses adoption");
        assert!(
            !io.0
                .lock()
                .unwrap()
                .trace
                .iter()
                .any(|(op, _)| matches!(op.as_str(), "write" | "create" | "remove" | "rename")),
            "beside evidence checked before installing anything"
        );
    }
}

#[test]
fn coordination_round1_permission_requires_owned_start_grant() {
    let (_s, io, mut client, mut authority) = serving();
    let transfer = client.prepare_succession(&Tick(10)).unwrap();
    let mut h = header();
    h.writer = client.writer_uuid();
    assert!(
        client
            .open_overlay(h, vec![], &mut Source::default(), io.clone())
            .is_err(),
        "handshake replay refused before grant"
    );
    client.dispatch(&transfer, &Tick(10)).unwrap();
    let answer = authority.send(&transfer);
    client
        .complete(
            &transfer,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    open(&mut client, &io);
    register(&mut client, &mut authority, 2);
    let release = client
        .prepare_release(&Tick(20), crate::DEFAULT_RESOLUTION_BOUND, None)
        .unwrap();
    assert!(
        client
            .open_overlay(h, vec![], &mut Source::default(), io.clone())
            .is_err(),
        "releasing replay refused"
    );
    client.dispatch(&release, &Tick(20)).unwrap();
    let answer = authority.send(&release);
    client
        .complete(
            &release,
            Ok(&answer),
            &Tick(21),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert!(
        client
            .open_overlay(h, vec![], &mut Source::default(), io)
            .is_err(),
        "released replay refused"
    );
}

#[test]
fn coordination_round1_serving_completion_replaces_carrier_once() {
    let (_s, io, mut client, mut authority) = serving();
    let request = client
        .prepare_registration(&root(client.writer_uuid(), 2), vec![], &Tick(10), |_, _| {
            true
        })
        .unwrap();
    client.dispatch(&request, &Tick(10)).unwrap();
    let answer = authority.send(&request);
    io.0.lock().unwrap().trace.clear();
    client
        .complete(
            &request,
            Ok(&answer),
            &Tick(11),
            &mut SeededRng::new(1),
            0,
            None,
        )
        .unwrap();
    assert_eq!(
        io.0.lock()
            .unwrap()
            .trace
            .iter()
            .filter(|(op, path)| op == "rename" && path.ends_with("ownership.tmp"))
            .count(),
        1,
        "serving completion replaces carrier once"
    );
    assert!(
        client
            .snapshot()
            .pending
            .iter()
            .all(|p| p.operation != Operation::Register)
    );
    drop(client);
    io.crash();
}

#[test]
fn coordination_round1_accepted_receipt_defers_incomplete_publication() {
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
    let metrics = crate::metrics::tests::metrics();
    metrics.set_available(crate::MetricsGroup::Sync, true);
    client.set_metrics(metrics.clone());
    let request = client
        .prepare_registration(&root(client.writer_uuid(), 1), vec![], &Tick(3), |_, _| {
            true
        })
        .unwrap();
    client.dispatch(&request, &Tick(3)).unwrap();
    let answer = authority.send(&request);
    let result = client.complete(
        &request,
        Ok(&answer),
        &Tick(4),
        &mut SeededRng::new(1),
        0,
        None,
    );
    assert!(
        matches!(result, Ok(crate::IntentCompletion::Accepted(_))),
        "durable accepted outcome survives incomplete publication: {result:?}"
    );
    assert_eq!(
        client.snapshot().phase,
        Phase::OwnedStart,
        "incomplete publication defers serving"
    );
    let text = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        text.contains("granary_client_intent_registrations_total{result=\"ok\"} 1"),
        "accepted metric remains success"
    );
}

#[test]
fn coordination_round1_persistence_checks_phase_relation() {
    let (_s, io, mut client, _authority) = serving();
    io.0.lock().unwrap().trace.clear();
    let result = client.phase_for_test(Phase::Unowned);
    assert!(
        matches!(
            result,
            Err(CoordinationError::Codec(
                granary_core::overlay_ownership::Error("phase transition")
            ))
        ),
        "all phase persistence uses the transition relation: {result:?}"
    );
    assert_eq!(client.snapshot().phase, Phase::Serving);
    assert!(
        io.0.lock().unwrap().trace.is_empty(),
        "invalid phase never touches disk"
    );
}

#[test]
fn coordination_round1_release_default_expires_after_thirty_seconds() {
    let (_s, _io, mut client, _authority) = serving();
    client
        .prepare_release(&Tick(100), crate::DEFAULT_RESOLUTION_BOUND, None)
        .unwrap();
    assert_eq!(client.snapshot().pending.last().unwrap().expires, 30_100);
}

#[test]
fn coordination_round1_selected_ceiling_capacity_refuses_before_rewrite() {
    let (_s, _io, _old, mut authority) = serving();
    authority.row = Some(Receipt {
        generation: 200,
        ..authority.row.unwrap()
    });
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut config = recovery_config(&scratch);
    let mut store = Store::open(&scratch.0).unwrap();
    let area = store
        .publication_root()
        .join("overlay")
        .join(config.scope.digest().unwrap())
        .join("v");
    OverlayStore::establish_writer(
        &mut store,
        &config,
        &mut io.clone(),
        &mut Entropy(11),
        &FaultControl::default(),
    )
    .unwrap();
    let before = io.bytes(&area.join("writer"));
    config.cap = 1;
    let selected = selection(&config, &authority);
    let result = WritableStore::adopt_selected(
        store,
        config,
        io.clone(),
        &mut Entropy(30),
        FaultControl::default(),
        selected.acknowledge_displacement(),
    );
    assert!(result.is_err());
    assert_eq!(
        io.bytes(&area.join("writer")),
        before,
        "capacity refusal precedes selected ceiling rewrite"
    );
}
