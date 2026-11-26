// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Dirty recovery must preserve a selection registered by another store.

use super::*;

fn fenced_selected_journal(
    runtime: &tokio::runtime::Runtime,
    name: &str,
    own_ack: bool,
) -> (Scratch, SimIo, Arc<Remote>, [u8; 16], Vec<u8>) {
    let fixture = runtime.block_on(Fixture::new());
    runtime.block_on(authenticate_registration(&fixture));
    if own_ack {
        let stage = fixture.create("old", b"own acknowledged bytes");
        runtime
            .block_on(async {
                fixture
                    .engine
                    .sync(SyncTarget::Stage(stage), SyncOptions::default())
                    .wait()
                    .await
            })
            .unwrap();
    }
    if !name.is_empty() {
        fixture.create(name, b"unsynced on A");
    }
    let writer = fixture.store.lock().unwrap().writer_uuid();
    let selected = runtime.block_on(super::super::selected::one_file(
        &fixture.remote,
        b"b",
        b"acknowledged on B",
        writer,
    ));
    {
        let mut authority = fixture.remote.authority.lock().unwrap();
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
    if name.is_empty() {
        let result = runtime.block_on(async {
            fixture
                .engine
                .sync(SyncTarget::Directory(None), SyncOptions::default())
                .wait()
                .await
        });
        assert!(
            matches!(result, Err(CoordinationError::Fenced { .. })),
            "{result:?}"
        );
    } else {
        fixture
            .store
            .lock()
            .unwrap()
            .phase_for_test(Phase::Fenced)
            .unwrap();
    }
    published::settle_disk(&fixture.io);
    let (scratch, io, remote, local) = fixture.reload_carrier();
    drop(local);
    (scratch, io, remote, writer, selected)
}

#[test]
fn dirty_reselection_keeps_the_foreign_selection_on_every_retry() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for (name, own_ack) in [("a2", false), ("b", false), ("a2", true), ("b", true)] {
        let (scratch, io, remote, writer, selected) =
            fenced_selected_journal(&runtime, name, own_ack);
        let before = remote.authority.lock().unwrap().sends.len();
        let events = super::super::selected::Events::default();
        let _events = events.guard();
        for ack in [Some(writer), None] {
            let result = boundary_command_with_ack(
                &scratch,
                &io,
                &remote,
                &runtime,
                writer,
                ack,
                None,
                FaultControl::default(),
            )
            .map_err(|error| error.to_string());
            let mut local = start(&scratch, &io, 193);
            let authority = remote.authority.lock().unwrap();
            assert_eq!(
                (
                    result,
                    local.recovery_rule().unwrap(),
                    local.snapshot().root == selected,
                    authority.root == selected,
                    authority.row.as_ref().unwrap().state,
                    remote.publication_sends.lock().unwrap().len(),
                    authority
                        .sends
                        .iter()
                        .skip(before)
                        .filter(|bytes| intent::decode_register(
                            bytes,
                            &local.snapshot().volume,
                            |_, _| true
                        )
                        .is_ok()
                            || intent::decode_release(bytes).is_ok())
                        .count()
                ),
                (
                    Err("intent refused: RecoveryJournalBlocked".into()),
                    RecoveryRule::DirtyJournal,
                    true,
                    true,
                    ReceiptState::Live {
                        prepared_root_id: GrainId::of(&selected)
                    },
                    0,
                    0
                ),
                "foreign dirty selection: name={name}, ack={ack:?}, own_ack={own_ack}, cases={cases}"
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
            cases += 1;
        }
    }
    assert_eq!(cases, 8);
}

#[test]
fn clean_reselection_publishes_the_foreign_selection_before_release() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (scratch, io, remote, writer, selected) = fenced_selected_journal(&runtime, "", false);
    let mut cases = 0;
    for acknowledgement in [Some(writer), None] {
        let result = boundary_command_with_ack(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            acknowledgement,
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
        let names = runtime.block_on(super::super::selected::landed_names(&remote, &head));
        assert_eq!(
            (
                result,
                head == selected,
                remote.authority.lock().unwrap().row.as_ref().unwrap().state,
                names
            ),
            (Ok(()), true, ReceiptState::Released, vec![b"b".to_vec()]),
            "clean selection attempt {cases}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}
