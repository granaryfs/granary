// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! An owned capture after its store's acknowledged registration.

use super::*;

fn owned_landing_cut(runtime: &tokio::runtime::Runtime, overwrite: bool) -> LandingCut {
    let fixture = runtime.block_on(Fixture::new());
    let stage = fixture.create("local", b"sealed");
    runtime
        .block_on(async {
            fixture
                .engine
                .sync(SyncTarget::Stage(stage), SyncOptions::default())
                .wait()
                .await
        })
        .unwrap();
    if overwrite {
        published::write(&fixture, stage, 0, b"newest");
    } else {
        fixture.create("extra", b"later unsynced write");
    }
    retained_landing_cut(runtime, fixture, stage, false, None)
}

fn recover_owned_landing(overwrite: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cut = owned_landing_cut(&runtime, overwrite);
    let local = start(&cut.scratch, &cut.io, 190);
    let selected = local.snapshot().root.clone();
    let landed = cut.record.candidates[0].root.clone();
    let sel = granary_core::root::decode_root(&selected).unwrap();
    let land = granary_core::root::decode_root(&landed).unwrap();
    assert_eq!(
        (
            sel.seq,
            sel.parent,
            sel.writer_uuid,
            sel.manifest_root == land.manifest_root
        ),
        (land.seq, land.parent, land.writer_uuid, false),
        "premise: own selected and landed trees are distinct siblings"
    );
    drop(local);
    let result = boundary_command(
        &cut.scratch,
        &cut.io,
        &cut.remote,
        &runtime,
        cut.writer,
        None,
        FaultControl::default(),
    )
    .map_err(|error| error.to_string());
    let mut after = start(&cut.scratch, &cut.io, 191);
    let installed = codec::scan_journal(&cut.io.recovered_bytes("journal").unwrap())
        .unwrap()
        .header;
    assert_eq!(
        (
            result,
            after.recovery_rule().unwrap(),
            after.snapshot().phase,
            (installed.base_root, installed.base_seq) == (GrainId::of(&landed), land.seq)
        ),
        (Ok(()), RecoveryRule::Nothing, Phase::Released, true),
        "own covered capture must finish without takeover"
    );
    assert_eq!(
        cut_file(after.recovery_store(), &landed, "local"),
        if overwrite { b"newest" } else { b"sealed" }
    );
    if !overwrite {
        assert_eq!(
            cut_file(after.recovery_store(), &landed, "extra"),
            b"later unsynced write"
        );
    }
}

#[test]
fn opus783_owned_landing_with_an_unsynced_extra_file_recovers() {
    recover_owned_landing(false);
}

#[test]
fn owned_landing_with_an_unsynced_overwrite_recovers() {
    recover_owned_landing(true);
}

#[test]
fn intentional_delete_after_sync() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = runtime.block_on(Fixture::new());
    let stage = fixture.create("file", b"acknowledged w");
    runtime
        .block_on(async {
            fixture
                .engine
                .sync(SyncTarget::Stage(stage), SyncOptions::default())
                .wait()
                .await
        })
        .unwrap();
    let prepared = fixture.remote.authority.lock().unwrap().root.clone();
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.namespace_record(Record::Delete {
                at: at("file"),
                kind: codec::DeleteKind::File {
                    stage_id: Some(stage),
                },
            })
            .map(|_| ())
        })
        .unwrap();
    let lane = runtime
        .block_on(
            fixture
                .engine
                .construct_commit(SyncOptions::default(), &mut Entropy(70)),
        )
        .unwrap();
    runtime.block_on(land_without_refresh(&fixture, &lane));
    assert!(
        !subsumed(&fixture.remote, &prepared),
        "without its journal, intentional deletion has no content witness"
    );
    let writer = fixture.store.lock().unwrap().writer_uuid();
    let (scratch, io, remote, local) = fixture.reload_carrier();
    drop(local);
    let result = boundary_command(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        FaultControl::default(),
    )
    .map_err(|error| error.to_string());
    let head = remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    assert_eq!(
        (
            result,
            runtime.block_on(super::super::selected::landed_names(&remote, &head)),
            remote.publication_sends.lock().unwrap().len(),
            remote.authority.lock().unwrap().row.as_ref().unwrap().state
        ),
        (Ok(()), vec![], 1, ReceiptState::Released),
        "the owned journal carries the intentional deletion through recovery"
    );
}

#[test]
fn owned_projected_landing_recovers_its_exact_registration() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = runtime.block_on(async {
        let fixture = Fixture::new().await;
        let local = fixture.create("local", b"sealed");
        fixture
            .engine
            .sync(SyncTarget::Stage(local), SyncOptions::default())
            .wait()
            .await
            .unwrap();
        let extra = fixture.create("extra", b"later published write");
        fixture.store.lock().unwrap().fault_control().arm(
            "sync.commit",
            "landed_readback",
            1,
            FaultAction::Fail,
        );
        let result = published::published(
            &fixture,
            SyncTarget::Stage(extra),
            70,
            SyncOptions::default(),
        )
        .await;
        assert_eq!(
            (
                result.err().map(|error| error.to_string()),
                durable_commit_state(&fixture)
            ),
            (
                Some("intent refused: SyncInjectedFault".into()),
                (Some(("complete", 1)), (true, false))
            ),
            "premise: the projected publication landed before its refresh"
        );
        fixture
    });
    let landed = fixture
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    assert_eq!(
        fixture.store.lock().unwrap().snapshot().root,
        landed,
        "premise: a projected sync registers its exact candidate before publication"
    );
    let writer = fixture.store.lock().unwrap().writer_uuid();
    let (scratch, io, remote, local) = fixture.reload_carrier();
    drop(local);
    let result = boundary_command(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        FaultControl::default(),
    )
    .map_err(|error| error.to_string());
    let mut local = start(&scratch, &io, 194);
    assert_eq!(
        (
            result,
            local.recovery_rule().unwrap(),
            local.snapshot().phase
        ),
        (Ok(()), RecoveryRule::Nothing, Phase::Released),
        "a projected capture includes earlier acknowledged registrations"
    );
    assert_eq!(
        cut_file(local.recovery_store(), &landed, "local"),
        b"sealed"
    );
    assert_eq!(
        cut_file(local.recovery_store(), &landed, "extra"),
        b"later published write"
    );
}

#[test]
fn an_earlier_local_registration_cannot_cover_a_foreign_landing_selection() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cut = owned_landing_cut(&runtime, false);
    let (seq, landed) = cut.remote.published.lock().unwrap().pop_last().unwrap();
    let selected = runtime.block_on(super::super::selected::one_file(
        &cut.remote,
        b"b",
        b"acknowledged on B",
        cut.writer,
    ));
    cut.remote.published.lock().unwrap().insert(seq, landed);
    let mut local = start(&cut.scratch, &cut.io, 197);
    local.phase_for_test(Phase::Fenced).unwrap();
    drop(local);
    {
        let mut authority = cut.remote.authority.lock().unwrap();
        authority.root = selected.clone();
        authority.cursor += 1;
        let row = authority.row.as_mut().unwrap();
        row.epoch += 1;
        row.instance = [99; 16];
        row.generation = 128;
        row.state = ReceiptState::Live {
            prepared_root_id: GrainId::of(&selected),
        };
    }
    let before = cut.remote.publication_sends.lock().unwrap().len();
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
        )
        .map_err(|error| error.to_string());
        let after = start(&cut.scratch, &cut.io, 198);
        let authority = cut.remote.authority.lock().unwrap();
        assert_eq!(
            (
                result,
                after.snapshot().root == selected,
                authority.root == selected,
                authority.row.unwrap().state,
                cut.remote.publication_sends.lock().unwrap().len()
            ),
            (
                Err("intent refused: RecoveryJournalBlocked".into()),
                true,
                true,
                ReceiptState::Live {
                    prepared_root_id: GrainId::of(&selected)
                },
                before
            )
        );
    }
}
