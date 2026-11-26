// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::WritableAuthority;

/// An exhausted publication whose verified landing is durable, but whose
/// owner was displaced before registering the landing.
fn displaced(runtime: &tokio::runtime::Runtime, variant: bool, suffix: bool) -> LandingCut {
    let cut = landing_cut(runtime, false, suffix.then_some(b"suffix".as_slice()));
    let stored = super::archived::published(&cut.record, variant, false);
    let candidate = &cut.record.candidates[0];
    cut.remote
        .published
        .lock()
        .unwrap()
        .insert(candidate.seq, stored.clone());
    cut.io.mutate_recovered("journal", |bytes| {
        let scan = codec::scan_journal(bytes).unwrap();
        let boundary = scan.state.open_boundaries().next().unwrap();
        bytes.extend(
            codec::encode_record(
                &scan.header,
                scan.state.next_seq(),
                &Record::LandedCommit {
                    boundary_seq: boundary,
                    landed_root: GrainId::of(&stored),
                    landed_seq: candidate.seq,
                },
            )
            .unwrap(),
        );
    });
    cut.io.crash();
    let mut local = start(&cut.scratch, &cut.io, 160);
    local.phase_for_test(Phase::Fenced).unwrap();
    {
        let mut authority = cut.remote.authority.lock().unwrap();
        authority.cursor += 1;
        let row = authority.row.as_mut().unwrap();
        row.epoch += 1;
        row.instance = [99; 16];
        row.generation = 128;
    }
    assert_eq!(
        local.recovery_rule().unwrap(),
        RecoveryRule::LandedUnowned,
        "displaced landing premise"
    );
    cut
}

#[test]
fn landed_reselection_obtains_a_genuine_refresh_and_keeps_the_residual() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for (variant, projected, suffix) in [
        (false, false, true),
        (false, true, true),
        (true, false, true),
        (true, true, true),
        (false, false, false),
    ] {
        let cut = displaced(&runtime, variant, suffix);
        if projected {
            let content = cut
                .content
                .payloads
                .lock()
                .unwrap()
                .iter()
                .find_map(|(id, (size, grains))| {
                    let FileGrains::Inline(refs) = grains else {
                        return None;
                    };
                    (*size == 6 && refs.iter().any(|grain| grain.id == GrainId::of(b"sealed")))
                        .then_some(*id)
                })
                .unwrap();
            project_durable_boundaries(
                &cut.io,
                Some(codec::ProjectedSelection {
                    stage_id: 1,
                    content,
                    size: 6,
                }),
                None,
            );
        }
        let before = cut.remote.publication_sends.lock().unwrap().len();
        let result = boundary_command_with_ack(
            &cut.scratch,
            &cut.io,
            &cut.remote,
            &runtime,
            cut.writer,
            Some(cut.writer),
            None,
            FaultControl::default(),
        );
        let mut local = start(&cut.scratch, &cut.io, 161);
        let root = cut
            .remote
            .published
            .lock()
            .unwrap()
            .last_key_value()
            .unwrap()
            .1
            .clone();
        assert_eq!(
            (
                result.as_ref().map_err(ToString::to_string),
                local.recovery_rule().unwrap(),
                local.snapshot().phase,
                cut.remote.publication_sends.lock().unwrap().len() - before,
                runtime.block_on(super::super::selected::landed_names(&cut.remote, &root)),
                local.snapshot().allocated > 128,
            ),
            (
                Ok(&()),
                RecoveryRule::Nothing,
                Phase::Released,
                usize::from(suffix),
                vec![b"local".to_vec()],
                true
            ),
            "variant={variant}, projected={projected}, suffix={suffix}, cases={}: {result:?}",
            cases + 1
        );
        assert_eq!(
            cut_file(local.recovery_store(), &root, "local"),
            if suffix { b"suffix" } else { b"sealed" }
        );
        cases += 1;
    }
    assert_eq!(cases, 5);
}

#[test]
fn landed_reselection_is_admitted_by_the_store_before_dispatch() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cut = displaced(&runtime, false, true);
    let before = cut.io.recovered_bytes("journal").unwrap();
    let mut local = start(&cut.scratch, &cut.io, 162);
    let scope = local.snapshot().scope.clone();
    let volume = local.snapshot().volume.clone();
    let reply = runtime
        .block_on(cut.remote.writable_readback(&scope, &volume, &[0; 32]))
        .unwrap();
    let selection =
        crate::SelectedRecovery::from_readback(scope, volume, cut.writer, &reply, |_, _| true)
            .unwrap();
    let result = local.reselect(
        selection.acknowledge_takeover(cut.writer).unwrap(),
        cut.remote.time.as_ref(),
    );
    assert_eq!(
        (
            result.as_ref().map(|_| ()).map_err(ToString::to_string),
            local.snapshot().phase,
            cut.io.recovered_bytes("journal").unwrap() == before
        ),
        (Ok(()), Phase::Handshake, true),
        "direct admission: {result:?}"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "sibling and binmap controls retain the same exact selection across both retries"
)]
fn landed_reselection_preserves_a_newer_unsubsumed_selection_on_every_retry() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for body in [b"new acknowledged bytes".as_slice(), b"sealed"] {
        let cut = displaced(&runtime, false, true);
        // Prepare a sibling over the landing's parent so the ancestry walk runs.
        let (landed_seq, landed) = cut.remote.published.lock().unwrap().pop_last().unwrap();
        let selected = runtime.block_on(super::super::selected::one_file(
            &cut.remote,
            b"selected",
            body,
            cut.writer,
        ));
        cut.remote
            .published
            .lock()
            .unwrap()
            .insert(landed_seq, landed.clone());
        let sel = granary_core::root::decode_root(&selected).unwrap();
        let land = granary_core::root::decode_root(&landed).unwrap();
        assert_eq!(
            (
                sel.seq,
                sel.parent,
                sel.writer_uuid,
                sel.manifest_root == land.manifest_root,
                landed_seq > sel.seq - 1
            ),
            (land.seq, land.parent, land.writer_uuid, false, true),
            "premise: distinct sibling trees of one writer, with a nonempty walk"
        );
        {
            let mut authority = cut.remote.authority.lock().unwrap();
            authority.root = selected.clone();
            authority.row.as_mut().unwrap().state = ReceiptState::Live {
                prepared_root_id: GrainId::of(&selected),
            };
        }
        let before = cut.remote.publication_sends.lock().unwrap().len();
        let events = super::super::selected::Events::default();
        let _events = events.guard();
        let attempts = cut.remote.authority.lock().unwrap().sends.len();
        if body == b"sealed" {
            let objects = cut.remote.objects.read_objects(land.binmap_index).unwrap();
            assert_eq!(
                objects.get(&GrainId::of(body)).unwrap(),
                body,
                "premise: selected grains occur in the landing under another name"
            );
        }
        for acknowledgement in [Some(cut.writer), None] {
            let result = boundary_command_with_ack(
                &cut.scratch,
                &cut.io,
                &cut.remote,
                &runtime,
                cut.writer,
                acknowledgement,
                None,
                FaultControl::default(),
            );
            let mut local = start(&cut.scratch, &cut.io, 163);
            assert_eq!(
                (
                    result.err().map(|error| error.to_string()),
                    local.snapshot().root == selected
                        && cut.remote.authority.lock().unwrap().root == selected,
                    local.recovery_rule().unwrap(),
                    cut.remote.publication_sends.lock().unwrap().len()
                ),
                (
                    Some("intent refused: RecoveryJournalBlocked".into()),
                    true,
                    RecoveryRule::LandedUnrefreshed,
                    before
                ),
                "retry {cases}: the selected root must not be replaced by the older landing"
            );
            assert!(
                events
                    .recover()
                    .iter()
                    .any(|event| event
                        == "journal_blocked reason=selected-root-not-proved-published"),
                "events: {:?}",
                events.recover()
            );
            let authority = cut.remote.authority.lock().unwrap();
            assert_eq!(
                authority.row.as_ref().unwrap().state,
                ReceiptState::Live {
                    prepared_root_id: GrainId::of(&selected)
                }
            );
            assert!(
                !authority
                    .sends
                    .iter()
                    .skip(attempts)
                    .any(
                        |bytes| intent::decode_register(bytes, &sel.volume, |_, _| true).is_ok()
                            || intent::decode_release(bytes).is_ok()
                    ),
                "no refresh or release"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

#[test]
fn landed_reselection_requires_renewed_matching_consent() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for ending in ["no-ack", "wrong-ack", "absent", "released", "changed"] {
        let cut = displaced(&runtime, false, true);
        let journal = cut.io.recovered_bytes("journal").unwrap();
        match ending {
            "absent" => cut.remote.authority.lock().unwrap().row = None,
            "released" => {
                cut.remote
                    .authority
                    .lock()
                    .unwrap()
                    .row
                    .as_mut()
                    .unwrap()
                    .state = ReceiptState::Released;
            }
            "changed" => cut.remote.change_selection.store(true, Ordering::Relaxed),
            _ => (),
        }
        let ack = match ending {
            "no-ack" => None,
            "wrong-ack" => Some([9; 16]),
            _ => Some(cut.writer),
        };
        let sends = cut.remote.publication_sends.lock().unwrap().len();
        let attempts = cut.remote.attempts.lock().unwrap().len();
        let result = boundary_command_with_ack(
            &cut.scratch,
            &cut.io,
            &cut.remote,
            &runtime,
            cut.writer,
            ack,
            None,
            FaultControl::default(),
        );
        let expected = match ending {
            "no-ack" | "wrong-ack" => "intent refused: RecoveryLandedUnowned",
            "changed" => "IntentSelectionChanged",
            _ => "intent refused: IntentSelectedWriterMissing",
        };
        assert_eq!(
            (
                result.err().map(|e| e.to_string()),
                cut.io.recovered_bytes("journal").unwrap() == journal,
                cut.remote.publication_sends.lock().unwrap().len(),
                cut.remote.attempts.lock().unwrap().len()
            ),
            (Some(expected.into()), true, sends, attempts),
            "{ending}, cases={}",
            cases + 1
        );
        cases += 1;
    }
    assert_eq!(cases, 5);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "paired receipt and journal-witness cuts keep exact replay and grant assertions together"
)]
fn landed_reselection_refresh_recognition_survives_the_grant_and_restart() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for phase in ["landed_refresh", "before_replace"] {
        let cut = displaced(&runtime, false, true);
        let faults = FaultControl::default();
        faults.arm("sync.commit", phase, 1, FaultAction::Crash);
        let result = boundary_command_with_ack(
            &cut.scratch,
            &cut.io,
            &cut.remote,
            &runtime,
            cut.writer,
            Some(cut.writer),
            None,
            faults.clone(),
        );
        assert_eq!(
            (result.is_err(), faults.sync_fired().len()),
            (true, 1),
            "{phase}: {result:?}"
        );
        cut.io.crash();
        let mut local = start(&cut.scratch, &cut.io, 164);
        let stored = cut.remote.published.lock().unwrap()[&2].clone();
        assert_eq!(
            local.recovery_rule().unwrap(),
            if phase == "landed_refresh" {
                RecoveryRule::LandedUnrefreshed
            } else {
                RecoveryRule::LandedRefreshed
            }
        );
        if phase == "landed_refresh" {
            let request = local
                .retained_requests()
                .into_iter()
                .find(|request| request.operation() == Operation::Register)
                .unwrap();
            let registered =
                intent::decode_register(request.bytes(), &cut.record.volume, |_, _| true).unwrap();
            let current = intent::decode_receipt(&local.snapshot().current).unwrap();
            assert_eq!(
                (
                    registered.root == stored,
                    registered.epoch == current.epoch,
                    registered.instance == current.instance,
                    registered.generation > 128
                ),
                (true, true, true, true)
            );
        }
        if phase == "before_replace" {
            assert_eq!(
                (
                    local.snapshot().root == stored,
                    local.landed_refresh_registered(&stored, false).unwrap()
                ),
                (true, false)
            );
        }
        drop(local);
        let sends = cut.remote.authority.lock().unwrap().sends.len();
        let result = boundary_command(
            &cut.scratch,
            &cut.io,
            &cut.remote,
            &runtime,
            cut.writer,
            None,
            FaultControl::default(),
        );
        let mut local = start(&cut.scratch, &cut.io, 165);
        assert_eq!(
            (
                result.as_ref().map_err(ToString::to_string),
                local.recovery_rule().unwrap(),
                cut.remote
                    .authority
                    .lock()
                    .unwrap()
                    .sends
                    .iter()
                    .skip(sends)
                    .filter(
                        |bytes| intent::decode_register(bytes, &cut.record.volume, |_, _| true)
                            .is_ok()
                    )
                    .count()
            ),
            (
                Ok(&()),
                RecoveryRule::Nothing,
                if phase == "landed_refresh" { 2 } else { 1 }
            ),
            "{phase}, cases={}: {result:?}",
            cases + 1
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn landed_reselection_a_displaced_new_refresh_requires_another_acknowledgement() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for absent in [false, true] {
        let cut = displaced(&runtime, false, true);
        let faults = FaultControl::default();
        faults.arm("sync.commit", "landed_refresh", 1, FaultAction::Fail);
        let result = boundary_command_with_ack(
            &cut.scratch,
            &cut.io,
            &cut.remote,
            &runtime,
            cut.writer,
            Some(cut.writer),
            None,
            faults.clone(),
        );
        assert_eq!(
            (result.is_err(), faults.sync_fired().len()),
            (true, 1),
            "new refresh cut: {result:?}"
        );
        let sends = cut.remote.publication_sends.lock().unwrap().len();
        {
            let mut authority = cut.remote.authority.lock().unwrap();
            if absent {
                authority.row = None;
            } else {
                authority.cursor += 1;
                authority.row.as_mut().unwrap().epoch += 1;
            }
        }
        let result = boundary_command(
            &cut.scratch,
            &cut.io,
            &cut.remote,
            &runtime,
            cut.writer,
            None,
            FaultControl::default(),
        );
        let mut local = start(&cut.scratch, &cut.io, 166);
        assert_eq!(
            (
                result.err().map(|error| error.to_string()),
                local.snapshot().phase,
                local.recovery_rule().unwrap(),
                cut.remote.publication_sends.lock().unwrap().len()
            ),
            (
                Some("intent refused: RecoveryLandedUnowned".into()),
                Phase::Fenced,
                RecoveryRule::LandedUnowned,
                sends
            ),
            "absent={absent}, cases={}",
            cases + 1
        );
        drop(local);
        if !absent {
            let result = boundary_command_with_ack(
                &cut.scratch,
                &cut.io,
                &cut.remote,
                &runtime,
                cut.writer,
                Some(cut.writer),
                None,
                FaultControl::default(),
            );
            assert!(result.is_ok(), "renewed acknowledgement: {result:?}");
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn landed_reselection_does_not_refresh_when_selected_chain_reads_fail() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for fail_read in [false, true] {
        let cut = displaced(&runtime, false, true);
        if fail_read {
            *cut.remote.listing_fault.lock().unwrap() =
                Some(RootStoreError::Backend("selected head unavailable".into()));
        }
        let attempts = cut.remote.attempts.lock().unwrap().len();
        let result = boundary_command_with_ack(
            &cut.scratch,
            &cut.io,
            &cut.remote,
            &runtime,
            cut.writer,
            Some(cut.writer),
            None,
            FaultControl::default(),
        );
        let mut local = start(&cut.scratch, &cut.io, 167);
        if fail_read {
            assert_eq!(
                (
                    result.err().map(|error| error.to_string()),
                    local.recovery_rule().unwrap(),
                    cut.remote.attempts.lock().unwrap().len()
                ),
                (
                    Some("remote: store: selected head unavailable".into()),
                    RecoveryRule::LandedUnrefreshed,
                    attempts
                )
            );
        } else {
            assert_eq!(
                (
                    result.as_ref().map_err(ToString::to_string),
                    local.recovery_rule().unwrap()
                ),
                (Ok(&()), RecoveryRule::Nothing),
                "valid control: {result:?}"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn landing_with_an_empty_carrier_root_is_blocked_without_sending() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let events = super::super::selected::Events::default();
    let _events = events.guard();
    let fixture = runtime.block_on(cut_at("before_replace", false));
    let (scratch, io, remote, mut local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    local.set_carrier_root_for_test(Vec::new()).unwrap();
    local.phase_for_test(Phase::Releasing).unwrap();
    local.phase_for_test(Phase::Released).unwrap();
    assert_eq!(
        (
            local.recovery_rule().unwrap(),
            local.snapshot().root.is_empty(),
            local.recovery_released(),
        ),
        (RecoveryRule::LandedRefreshed, true, true),
        "empty-root landing premise: {:?}",
        local.snapshot()
    );
    drop(local);
    let sends = remote.authority.lock().unwrap().sends.len();
    let publications = remote.publication_sends.lock().unwrap().len();
    let result = boundary_command(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        FaultControl::default(),
    );
    assert_eq!(
        (
            result.err().map(|error| error.to_string()),
            remote.authority.lock().unwrap().sends.len() - sends,
            remote.publication_sends.lock().unwrap().len() - publications,
            events.recover().last().cloned(),
        ),
        (
            Some("intent refused: RecoveryJournalBlocked".into()),
            0,
            0,
            Some("journal_blocked reason=publication".into()),
        ),
        "local evidence failures must use the landing branch's blocked refusal"
    );
}

#[test]
fn landed_reselection_refuses_a_corrupt_selected_chain_before_registering() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cut = displaced(&runtime, false, true);
    let mut selected =
        granary_core::root::decode_root(&cut.remote.authority.lock().unwrap().root).unwrap();
    let volume = selected.volume.clone();
    selected.timestamp.secs += 1;
    let selected = super::super::rebase::signed(selected);
    {
        let mut authority = cut.remote.authority.lock().unwrap();
        authority.row.as_mut().unwrap().state = ReceiptState::Live {
            prepared_root_id: GrainId::of(&selected),
        };
        authority.root = selected;
    }
    // After the journal-base read, verify_base reads the head and its parent;
    // selected_relation then re-reads the head and fetches that parent again.
    let probes = cut.remote.probes.load(Ordering::Relaxed);
    cut.remote
        .corrupt_probe
        .store(probes + 5, Ordering::Relaxed);
    let registers = cut
        .remote
        .authority
        .lock()
        .unwrap()
        .sends
        .iter()
        .filter(|bytes| intent::decode_register(bytes, &volume, |_, _| true).is_ok())
        .count();
    let publications = cut.remote.publication_sends.lock().unwrap().len();
    let result = boundary_command_with_ack(
        &cut.scratch,
        &cut.io,
        &cut.remote,
        &runtime,
        cut.writer,
        Some(cut.writer),
        None,
        FaultControl::default(),
    );
    let mut local = start(&cut.scratch, &cut.io, 168);
    assert_eq!(
        (
            result.err().map(|error| error.to_string()),
            cut.remote
                .authority
                .lock()
                .unwrap()
                .sends
                .iter()
                .filter(|bytes| { intent::decode_register(bytes, &volume, |_, _| true).is_ok() })
                .count()
                - registers,
            cut.remote.publication_sends.lock().unwrap().len() - publications,
            local.recovery_rule().unwrap(),
        ),
        (
            Some("RecoveryRemoteIntegrity: prepared root ancestry".into()),
            0,
            0,
            RecoveryRule::LandedUnrefreshed,
        ),
        "a signed head with an unavailable parent must not authorize a refresh"
    );
}

#[test]
fn ordinary_finish_refuses_an_unproved_same_writer_sibling() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = runtime.block_on(Fixture::new());
    fixture.create("local", b"older acknowledged bytes");
    runtime.block_on(authenticate_registration(&fixture));
    published::settle_disk(&fixture.io);
    fixture.io.mutate_recovered("journal", |bytes| {
        let mut header = codec::scan_journal(bytes).unwrap().header;
        header.next_stage_id = 2;
        *bytes = codec::encode_journal(
            &header,
            &[Record::RecreateFile {
                at: None,
                exec: false,
                stage_id: 1,
                anchor: None,
            }],
        )
        .unwrap();
    });
    let writer = fixture.store.lock().unwrap().writer_uuid();
    let landed = runtime.block_on(super::super::selected::one_file(
        &fixture.remote,
        b"local",
        b"newer landed bytes",
        writer,
    ));
    fixture.remote.published.lock().unwrap().insert(2, landed);
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let mut local = open_owned_boundary(local, &io, &remote);
    assert!(
        local.finish_normalization_required().unwrap(),
        "premise: no-op history needs finish_clean"
    );
    assert!(
        !local.finish_publication_proved().unwrap(),
        "premise: selection is not published"
    );
    assert_eq!(
        local
            .coalesce_state(&SyncOptions::default(), TokioSyncRuntime.now())
            .unwrap(),
        crate::writable_store::sync_engine::CoalesceState::Clean,
        "premise: finish_clean is reached"
    );
    let selected = local.snapshot().root.clone();
    let before = remote.authority.lock().unwrap().sends.len();
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let events = super::super::selected::Events::default();
    let _events = events.guard();
    let result = crate::writable_start::shared_finish::finish_bound_store(
        crate::writable_start::shared_finish::FinishInputs {
            remote: remote.clone(),
            runtime: &runtime,
            key: &key,
            spare: SigningKey::from_seed(&[39; 32]).unwrap(),
            clock: remote.time.clone(),
            metrics: crate::ClientMetrics::new(&mut Entropy(80)),
            view_mode: crate::ViewMode::default(),
            deadline: TokioSyncRuntime.now() + Duration::from_secs(10),
            send_budget: None,
            landing: None,
            after_landing: || {},
            keys: TrustedKeys::new([*key.public_key()]).unwrap(),
            may_publish: true,
            selection_transport: None,
            refuse: |error, _| crate::WritableStartError::Coordination(error),
        },
        local,
        &mut Entropy(81),
        &mut SeededRng::new(2),
        |_, _, _, _| {},
        || Ok(()),
    );
    assert_eq!(
        (
            result.is_err(),
            events.recover(),
            remote.publication_sends.lock().unwrap().len(),
            remote.authority.lock().unwrap().root == selected
        ),
        (true, vec!["conflict path=<file>".into()], 0, true),
        "finish: {:?}",
        result.as_ref().err()
    );
    assert!(
        !remote
            .authority
            .lock()
            .unwrap()
            .sends
            .iter()
            .skip(before)
            .any(|bytes| intent::decode_release(bytes).is_ok())
    );
    drop(result);
    drop(start(&scratch, &io, 170));
}
