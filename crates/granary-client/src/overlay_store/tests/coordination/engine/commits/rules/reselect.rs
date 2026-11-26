// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::overlay_ownership::Phase;

#[expect(
    clippy::too_many_lines,
    reason = "one table preserves consent, phase, high-water and replay assertions across restarts"
)]
fn check_reselect(phases: &[Phase], endings: &[&str]) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for &phase in phases {
        for &ending in endings {
            let fixture = runtime.block_on(Fixture::new());
            fixture.create("local", b"sealed");
            runtime.block_on(authenticate_registration(&fixture));
            published::settle_disk(&fixture.io);
            if ending == "clean" {
                fixture.io.mutate_recovered("journal", |bytes| {
                    *bytes = codec::scan_journal(bytes).unwrap().header.encode().unwrap();
                });
            }
            let (scratch, io, remote, mut local) = fixture.reload_carrier();
            let writer = local.writer_uuid();
            if phase == Phase::Unowned {
                let request = local.prepare_succession(remote.time.as_ref()).unwrap();
                local.dispatch(&request, remote.time.as_ref()).unwrap();
                let answer = reply(400, Some("bad-request"), None, vec![]);
                assert!(
                    local
                        .complete(
                            &request,
                            Ok(&answer),
                            remote.time.as_ref(),
                            &mut SeededRng::new(1),
                            0,
                            None
                        )
                        .is_err()
                );
                assert_eq!(local.snapshot().phase, Phase::Unowned);
            }
            local.phase_for_test(phase).unwrap();
            let before = io.recovered_bytes("journal").unwrap();
            {
                let mut authority = remote.authority.lock().unwrap();
                authority.cursor += 1;
                let row = authority.row.as_mut().unwrap();
                row.epoch += 1;
                row.instance = [99; 16];
                if ending == "higher" {
                    row.generation = 128;
                }
                if ending == "released" {
                    row.state = ReceiptState::Released;
                }
            }
            drop(local);
            remote
                .change_selection
                .store(ending == "changed", Ordering::Relaxed);
            let ack = match ending {
                "wrong-ack" => Some([9; 16]),
                "no-ack" => None,
                _ => Some(writer),
            };
            let events = super::super::selected::Events::default();
            let _guard = events.guard();
            let faults = FaultControl::default();
            if ending == "cut" {
                faults.arm("intent.pending", "after_dir_sync", 1, FaultAction::Crash);
            }
            let mut result = boundary_command_with_ack(
                &scratch,
                &io,
                &remote,
                &runtime,
                writer,
                ack,
                None,
                faults.clone(),
            );
            if ending == "cut" {
                assert!(result.is_err());
                assert_eq!(faults.fired().len(), 1);
                io.crash();
                let local = start(&scratch, &io, 155);
                assert_eq!(local.snapshot().phase, Phase::Handshake);
                drop(local);
                result = boundary_command_with_ack(
                    &scratch,
                    &io,
                    &remote,
                    &runtime,
                    writer,
                    None,
                    None,
                    FaultControl::default(),
                );
                assert_eq!(remote.recovery_reads.load(Ordering::Relaxed), 1);
            }
            let mut local = start(&scratch, &io, 156);
            let observed = events.recover();
            if matches!(ending, "dirty" | "clean" | "higher" | "cut") {
                assert_eq!(
                    (
                        result.is_ok(),
                        local.recovery_rule().unwrap(),
                        local.snapshot().phase
                    ),
                    (true, RecoveryRule::Nothing, Phase::Released),
                    "{phase:?}/{ending}, cases={}, {result:?}: {observed:?}",
                    cases + 1
                );
                if ending == "higher" {
                    assert!(local.snapshot().allocated >= 128);
                }
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    if ending == "changed" {
                        "IntentSelectionChanged"
                    } else {
                        "intent refused: IntentSelectedWriterMissing"
                    },
                    "{phase:?}/{ending}"
                );
                assert!(observed.iter().any(|e| e.starts_with("selection_changed")));
                assert_eq!(io.recovered_bytes("journal").unwrap(), before);
                assert_eq!(remote.publication_sends.lock().unwrap().len(), 0);
                assert_eq!(
                    remote.recovery_sends.load(Ordering::Relaxed),
                    usize::from(ending == "changed") as u64
                );
            }
            cases += 1;
        }
    }
    assert_eq!(cases, phases.len() * endings.len());
}

#[test]
fn fenced_reselection_finishes_this_stores_dirty_journal() {
    check_reselect(&[Phase::Fenced], &["dirty"]);
}
#[test]
fn unowned_reselection_finishes_this_stores_dirty_journal() {
    check_reselect(&[Phase::Unowned], &["dirty"]);
}
#[test]
fn reselected_clean_store_reenters_publication_classification() {
    check_reselect(&[Phase::Fenced, Phase::Unowned], &["clean"]);
}
#[test]
fn reselected_higher_generation_raises_the_writer_ceiling() {
    check_reselect(&[Phase::Fenced, Phase::Unowned], &["higher"]);
}
#[test]
fn changed_reselection_stops_after_one_conditional_takeover() {
    check_reselect(&[Phase::Fenced, Phase::Unowned], &["changed"]);
}
#[test]
fn reselection_requires_a_live_row_and_renewed_matching_consent() {
    check_reselect(
        &[Phase::Fenced, Phase::Unowned],
        &["released", "wrong-ack", "no-ack"],
    );
}
#[test]
fn reselection_crash_resumes_the_retained_consent_without_a_readback() {
    check_reselect(&[Phase::Fenced, Phase::Unowned], &["cut"]);
}

#[test]
fn displaced_initial_adoption_reselects_with_its_original_fence_anchor() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = runtime.block_on(Fixture::new());
    let prepared = runtime.block_on(super::super::selected::one_file(
        &fixture.remote,
        b"selected",
        b"newer",
        super::super::selected::WRITER,
    ));
    let (scratch, _selection, authority) = super::super::selected::selection(&prepared);
    *fixture.remote.authority.lock().unwrap() = authority;
    fixture
        .remote
        .supersede_selection
        .store(true, Ordering::Relaxed);
    let io = SimIo::default();
    let first = boundary_command_with_ack(
        &scratch,
        &io,
        &fixture.remote,
        &runtime,
        super::super::selected::WRITER,
        Some(super::super::selected::WRITER),
        None,
        FaultControl::default(),
    );
    let fenced = start(&scratch, &io, 157).snapshot().clone();
    let second = boundary_command_with_ack(
        &scratch,
        &io,
        &fixture.remote,
        &runtime,
        super::super::selected::WRITER,
        Some(super::super::selected::WRITER),
        None,
        FaultControl::default(),
    );
    assert_eq!(
        (
            first.err().map(|error| error.to_string()),
            fenced.phase,
            fenced.current.is_empty(),
            second.map_err(|error| error.to_string()),
        ),
        (
            Some("IntentSelectionChanged".into()),
            Phase::Fenced,
            true,
            Ok(())
        )
    );
}

#[test]
fn reselection_readback_expires_before_renewed_consent_is_persisted() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let fixture = runtime.block_on(Fixture::new());
    fixture.create("local", b"sealed");
    runtime.block_on(authenticate_registration(&fixture));
    published::settle_disk(&fixture.io);
    let (scratch, io, remote, mut local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    local.phase_for_test(Phase::Fenced).unwrap();
    {
        let mut authority = remote.authority.lock().unwrap();
        authority.cursor += 1;
        let row = authority.row.as_mut().unwrap();
        row.epoch += 1;
        row.instance = [99; 16];
    }
    drop(local);
    let before = start(&scratch, &io, 158).snapshot().clone();
    remote.recovery_read_delay.store(31, Ordering::Relaxed);
    let events = super::super::selected::Events::default();
    let _guard = events.guard();
    let result = boundary_command_with_ack(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        Some(writer),
        None,
        FaultControl::default(),
    );
    assert_eq!(
        result.err().map(|error| error.to_string()),
        Some("intent refused: SyncDeadline".into())
    );
    let after = start(&scratch, &io, 159).snapshot().clone();
    assert_eq!(after, before);
    assert!(
        !events
            .recover()
            .iter()
            .any(|event| event.starts_with("selection_changed")),
        "a readback timeout is not a missing selection: {:?}",
        events.recover()
    );
}

#[test]
fn reselecting_a_newer_root_classifies_it_after_resuming_an_older_publication() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = exhausted_boundary(&runtime, PublishPlan::Timeout, PublishPlan::Timeout);
    let record = budget::saved(&fixture);
    let landed = record.candidates[0].clone();
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(landed.seq, landed.root);
    let selected_writer = fixture.store.lock().unwrap().writer_uuid();
    let selected = runtime.block_on(super::super::selected::one_file(
        &fixture.remote,
        b"selected",
        b"newer unpublished bytes",
        selected_writer,
    ));
    let root = fixture
        .store
        .lock()
        .unwrap()
        .recovery_store()
        .publication_root()
        .to_owned();
    let area = crate::overlay_store::area_path(&root, &record.scope, &record.volume).unwrap();
    let mut disk = fixture.io.clone();
    disk.remove(&area.join("journal")).unwrap();
    published::settle_disk(&disk);
    let (scratch, io, remote, mut local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    local.phase_for_test(Phase::Fenced).unwrap();
    {
        let mut authority = remote.authority.lock().unwrap();
        authority.cursor += 1;
        authority.root = selected.clone();
        let row = authority.row.as_mut().unwrap();
        row.epoch += 1;
        row.instance = [99; 16];
        row.state = ReceiptState::Live {
            prepared_root_id: GrainId::of(&selected),
        };
    }
    drop(local);
    let sends = remote.publication_sends.lock().unwrap().len();
    let result = boundary_command_with_ack(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        Some(writer),
        None,
        FaultControl::default(),
    );
    let published = remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    assert_eq!(
        (
            result.map_err(|error| error.to_string()),
            remote.publication_sends.lock().unwrap().len() - sends,
            runtime.block_on(super::super::selected::landed_names(&remote, &published)),
            remote.authority.lock().unwrap().row.unwrap().state,
        ),
        (
            Ok(()),
            1,
            vec![b"selected".to_vec()],
            ReceiptState::Released,
        ),
        "the completed older record cannot authorize release of the selected root"
    );
}
