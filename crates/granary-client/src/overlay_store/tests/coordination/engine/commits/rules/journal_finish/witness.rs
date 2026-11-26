// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Clone, Copy, Debug)]
enum LaterHead {
    Witness,
    Removal,
    Overwrite,
}

fn file_sync(
    runtime: &tokio::runtime::Runtime,
    other_first: bool,
    rewrite: Option<&[u8]>,
    receipt_crash: bool,
) -> (Fixture, GrainId) {
    let build = || {
        let fixture = runtime.block_on(Fixture::new());
        if other_first {
            fixture.create("unsynced", b"other work");
        }
        let stage = fixture.create("local", b"sealed");
        if !other_first && rewrite.is_none() {
            fixture.create("unsynced", b"other work");
        }
        (fixture, stage)
    };
    let after_capture = |fixture: &Fixture, stage| {
        if let Some(bytes) = rewrite {
            fixture.create("unsynced", b"other work");
            published::write(fixture, stage, 0, bytes);
        }
    };
    if receipt_crash {
        return crash_after_file_receipt(
            runtime,
            build,
            ("overlay.journal.append", "before", 2),
            after_capture,
        );
    }
    let (fixture, stage) = build();
    let witness = prepare_file(&fixture, runtime, stage);
    after_capture(&fixture, stage);
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    (fixture, witness)
}

fn prepare_file(fixture: &Fixture, runtime: &tokio::runtime::Runtime, stage: u64) -> GrainId {
    sync_file(fixture, runtime, stage);
    publish_registered(fixture)
}

fn publish_registered(fixture: &Fixture) -> GrainId {
    let prepared = fixture.remote.authority.lock().unwrap().root.clone();
    let seq = root::decode_root(&prepared).unwrap().seq;
    let witness = GrainId::of(&prepared);
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(seq, prepared);
    witness
}

fn sync_file(fixture: &Fixture, runtime: &tokio::runtime::Runtime, stage: u64) {
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

fn crash_after_file_receipt(
    runtime: &tokio::runtime::Runtime,
    build: impl FnOnce() -> (Fixture, u64),
    (point, phase, nth): (&'static str, &'static str, u64),
    after_capture: impl FnOnce(&Fixture, u64),
) -> (Fixture, GrainId) {
    let (fixture, stage) = build();
    let faults = fixture.store.lock().unwrap().fault_control();
    runtime.block_on(async {
        fixture.remote.hold_first.store(true, Ordering::Relaxed);
        let waiter = fixture
            .engine
            .sync(SyncTarget::Stage(stage), SyncOptions::default());
        fixture.remote.entered.notified().await;
        after_capture(&fixture, stage);
        // Materialization has finished and the completion fault can still be armed.
        persist_content(&fixture);
        published::settle_disk(&fixture.io);
        faults.arm(point, phase, nth, FaultAction::Crash);
        fixture.remote.release.notify_one();
        assert!(waiter.wait().await.is_err());
    });
    assert_eq!(faults.fired().len() + faults.sync_fired().len(), 1);
    let accepted = fixture.remote.authority.lock().unwrap().root.clone();
    let witness = GrainId::of(&accepted);
    let seq = root::decode_root(&accepted).unwrap().seq;
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(seq, accepted);
    (fixture, witness)
}

fn assert_unregistered_receipt(
    io: &SimIo,
    witness: GrainId,
) -> granary_core::overlay_journal::JournalScan {
    let (scan, records) = journal_generations(io);
    assert!(records.receipts.iter().any(|&(_, generation, root)| {
        root == witness && generation == scan.state.highest_generation()
    }));
    assert!(
        records
            .registrations
            .iter()
            .all(|&(_, root)| root != witness)
    );
    scan
}

#[derive(Clone, Copy, Debug)]
enum ReceiptLayout {
    MatchingSibling,
    DeletedSibling,
    Prefix,
    Projection,
}

fn receipt_workspace(
    runtime: &tokio::runtime::Runtime,
    layout: ReceiptLayout,
) -> (Fixture, u64, Option<u64>) {
    let fixture = runtime.block_on(Fixture::new());
    let sibling =
        matches!(layout, ReceiptLayout::MatchingSibling).then(|| fixture.create("a", b"aaaaaa"));
    if matches!(layout, ReceiptLayout::Projection) {
        fixture.create("u", b"unsync");
    }
    let local = fixture.create("local", b"sealed");
    if !matches!(layout, ReceiptLayout::Projection) {
        fixture.create("u", b"unsync");
    }
    if let Some(stage) = sibling {
        sync_file(&fixture, runtime, stage);
    }
    if matches!(layout, ReceiptLayout::DeletedSibling) {
        let stage = fixture.create("a", b"aaaaaa");
        sync_file(&fixture, runtime, stage);
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                t.namespace_record(Record::Delete {
                    at: crate::overlay_store::tests::incremental::loc("a"),
                    kind: granary_core::overlay_journal::DeleteKind::File {
                        stage_id: Some(stage),
                    },
                })
            })
            .unwrap();
    }
    (fixture, local, sibling)
}

#[test]
fn receipt_generation_survives_recovery_without_its_registration() {
    let runtime = suffix_runtime();
    let mut failures = Vec::new();
    for (layout, later_removal) in [
        (ReceiptLayout::MatchingSibling, false),
        (ReceiptLayout::DeletedSibling, false),
        (ReceiptLayout::Projection, false),
        (ReceiptLayout::MatchingSibling, true),
    ] {
        for fault in [
            ("overlay.journal.append", "before", 2),
            ("overlay.journal.post_sync", "after", 1),
            ("overlay.journal.post_sync", "before", 2),
        ] {
            let (fixture, witness) = crash_after_file_receipt(
                &runtime,
                || {
                    let (fixture, stage, _) = receipt_workspace(&runtime, layout);
                    (fixture, stage)
                },
                fault,
                |_, _| {},
            );
            let (seq, parent) = if later_removal {
                (4, publish_file(&fixture.remote, &runtime, b"a", b"aaaaaa"))
            } else {
                (3, witness)
            };
            let cut = SuffixRecovery::reopen(fixture);
            let before = assert_unregistered_receipt(&cut.io, witness);
            let result = cut.recover(&runtime, false, FaultControl::default());
            if !matches!(result, Ok(crate::RecoveryOutcome::JournalFinished { base_seq }) if base_seq == seq)
            {
                failures.push((layout, later_removal, fault, result));
                continue;
            }
            let files: &[(&str, &[u8])] = match (layout, later_removal) {
                (_, true) => &[("a", b"aaaaaa"), ("u", b"unsync")],
                (ReceiptLayout::MatchingSibling, false) => {
                    &[("a", b"aaaaaa"), ("local", b"sealed"), ("u", b"unsync")]
                }
                _ => &[("local", b"sealed"), ("u", b"unsync")],
            };
            assert_landed_files(&cut, seq, parent, files);
            let after = durable_journal(&cut.io);
            assert_eq!(after.state.next_stage_id(), before.state.next_stage_id());
            assert!(after.state.highest_generation() >= before.state.highest_generation());
            assert_settled(&cut, &runtime);
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

fn overwrite(remote: &Remote, runtime: &tokio::runtime::Runtime) -> GrainId {
    publish_file(remote, runtime, b"local", b"remote")
}

fn publish_file(
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    name: &[u8],
    bytes: &[u8],
) -> GrainId {
    publish_files(remote, runtime, &[(name, bytes)])
}

fn publish_files(
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    files: &[(&[u8], &[u8])],
) -> GrainId {
    let bytes = runtime.block_on(super::super::super::selected::files(
        remote, files, [99; 16],
    ));
    let id = GrainId::of(&bytes);
    let seq = root::decode_root(&bytes).unwrap().seq;
    remote.published.lock().unwrap().insert(seq, bytes);
    id
}

fn sibling_receipt_witness(
    runtime: &tokio::runtime::Runtime,
    receipt_crash: bool,
) -> (Fixture, GrainId, u64) {
    let (fixture, local, earlier) = receipt_workspace(runtime, ReceiptLayout::MatchingSibling);
    let sibling = root::decode_root(&fixture.remote.authority.lock().unwrap().root).unwrap();
    let (fixture, witness) = publish_receipt_witness(runtime, fixture, local, receipt_crash);
    let published = root::decode_root(&fixture.remote.published.lock().unwrap()[&2]).unwrap();
    assert_eq!(
        (sibling.seq, sibling.parent),
        (published.seq, published.parent)
    );
    assert_ne!(sibling.manifest_root, published.manifest_root);
    (fixture, witness, earlier.unwrap())
}

fn publish_receipt_witness(
    runtime: &tokio::runtime::Runtime,
    fixture: Fixture,
    local: u64,
    receipt_crash: bool,
) -> (Fixture, GrainId) {
    if receipt_crash {
        crash_after_file_receipt(
            runtime,
            || (fixture, local),
            ("overlay.journal.post_sync", "after", 1),
            |_, _| {},
        )
    } else {
        let witness = prepare_file(&fixture, runtime, local);
        persist_content(&fixture);
        published::settle_disk(&fixture.io);
        (fixture, witness)
    }
}

#[test]
fn sibling_receipt_follows_later_head() {
    let runtime = suffix_runtime();
    let mut failures = Vec::new();
    let later_trees: &[&[(&str, &[u8])]] = &[
        &[("local", b"sealed")],
        &[("a", b"remote"), ("local", b"sealed")],
        &[],
    ];
    for crash in [false, true] {
        for &later in later_trees {
            let (fixture, _, _) = sibling_receipt_witness(&runtime, crash);
            let files: Vec<_> = later
                .iter()
                .map(|&(name, bytes)| (name.as_bytes(), bytes))
                .collect();
            let head = publish_files(&fixture.remote, &runtime, &files);
            let cut = SuffixRecovery::reopen(fixture);
            let result = cut.recover(&runtime, false, FaultControl::default());
            if !matches!(
                result,
                Ok(crate::RecoveryOutcome::JournalFinished { base_seq: 4 })
            ) {
                failures.push((crash, later, result));
                continue;
            }
            let mut want = later.to_vec();
            want.push(("u", b"unsync"));
            assert_landed_files(&cut, 4, head, &want);
            assert_settled(&cut, &runtime);
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn sibling_receipt_preserves_same_size_edit() {
    let runtime = suffix_runtime();
    for overwrite in [false, true] {
        let (fixture, witness, stage) = sibling_receipt_witness(&runtime, false);
        published::write(&fixture, stage, 0, b"edited");
        persist_content(&fixture);
        published::settle_disk(&fixture.io);
        if overwrite {
            publish_files(
                &fixture.remote,
                &runtime,
                &[(b"a", b"remote"), (b"local", b"sealed")],
            );
        }
        let cut = SuffixRecovery::reopen(fixture);
        let result = cut.recover(&runtime, false, FaultControl::default());
        if overwrite {
            assert!(
                matches!(result, Err(crate::RecoveryCommandError::Conflict { .. })),
                "{result:?}"
            );
            assert_no_suffix_send_or_release(&cut.remote);
        } else {
            assert_eq!(
                result.unwrap(),
                crate::RecoveryOutcome::JournalFinished { base_seq: 3 }
            );
            assert_landed_files(
                &cut,
                3,
                witness,
                &[("a", b"edited"), ("local", b"sealed"), ("u", b"unsync")],
            );
            assert_settled(&cut, &runtime);
        }
    }
}

#[track_caller]
fn crash_after_witness_install(cut: &SuffixRecovery, runtime: &tokio::runtime::Runtime) {
    let faults = FaultControl::default();
    faults.arm("overlay.replace.dir_sync", "after", 1, FaultAction::Crash);
    let result = cut.recover(runtime, false, faults.clone());
    assert!(result.is_err(), "{result:?}");
    assert_eq!(
        faults.fired().len() + faults.sync_fired().len(),
        1,
        "{result:?}"
    );
    assert_no_suffix_send_or_release(&cut.remote);
    cut.io.crash();
}

#[test]
fn sibling_receipt_keeps_stage_referenced_by_suffix() {
    let runtime = suffix_runtime();
    let (fixture, witness, stage) = sibling_receipt_witness(&runtime, false);
    published::write(&fixture, stage, 0, b"aaaaaa");
    for exec in [true, false] {
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                t.namespace_record(Record::SetattrExec {
                    at: crate::overlay_store::tests::incremental::loc("a"),
                    exec,
                })
            })
            .unwrap();
    }
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    let cut = SuffixRecovery::reopen(fixture);
    crash_after_witness_install(&cut, &runtime);
    let journal = cut.io.recovered_bytes("journal").unwrap();
    let mut writes = Vec::new();
    let scan = granary_core::overlay_journal::scan_journal_with(&journal, |_, record| {
        if let Record::WriteExtent { stage_id, .. } = record {
            writes.push(*stage_id);
        }
    })
    .unwrap();
    assert_eq!(scan.header.base_root, witness);
    assert!(scan.state.stage(stage).is_some());
    assert!(writes.contains(&stage), "{writes:?}");
}

#[derive(Default)]
struct JournalGenerations {
    receipts: Vec<(u64, u64, GrainId)>,
    registrations: Vec<(u64, GrainId)>,
}

fn journal_generations(
    io: &SimIo,
) -> (
    granary_core::overlay_journal::JournalScan,
    JournalGenerations,
) {
    let journal = io.recovered_bytes("journal").unwrap();
    let mut records = JournalGenerations::default();
    let scan =
        granary_core::overlay_journal::scan_journal_with(&journal, |_, record| match record {
            Record::FileSynced {
                stage_id,
                generation,
                prepared_root,
                ..
            } => {
                records
                    .receipts
                    .push((*stage_id, *generation, *prepared_root));
            }
            Record::IntentRegistered {
                generation,
                prepared_root,
                ..
            } => {
                records.registrations.push((*generation, *prepared_root));
            }
            _ => {}
        })
        .unwrap();
    assert_eq!(scan.end, granary_core::overlay_journal::JournalEnd::Clean);
    (scan, records)
}

#[test]
fn receipt_registration_is_synthesized_only_when_a_generation_is_lost() {
    let runtime = suffix_runtime();
    for layout in [
        ReceiptLayout::MatchingSibling,
        ReceiptLayout::DeletedSibling,
        ReceiptLayout::Prefix,
        ReceiptLayout::Projection,
    ] {
        for crash in [true, false] {
            let (fixture, stage, _) = receipt_workspace(&runtime, layout);
            let (fixture, witness) = publish_receipt_witness(&runtime, fixture, stage, crash);
            let cut = SuffixRecovery::reopen(fixture);
            let (before, old) = journal_generations(&cut.io);
            let high = before.state.highest_generation();
            let earlier = matches!(
                layout,
                ReceiptLayout::MatchingSibling | ReceiptLayout::DeletedSibling
            );
            assert_eq!(old.receipts.len(), if earlier { 2 } else { 1 });
            assert_eq!(
                old.receipts
                    .last()
                    .map(|&(_, generation, root)| (generation, root)),
                Some((high, witness))
            );
            let mut registrations = Vec::new();
            if earlier {
                let (_, lower, sibling) = old.receipts[0];
                assert_ne!(sibling, witness);
                assert!(lower < high);
                assert!(old.registrations.contains(&(lower, sibling)));
                registrations.push((lower, sibling));
            }
            assert_eq!(old.registrations.contains(&(high, witness)), !crash);
            if !crash && !matches!(layout, ReceiptLayout::Projection) {
                registrations.push((high, witness));
            }
            let header = registrations
                .first()
                .map_or(high, |&(generation, _)| generation - 1);
            if earlier && crash {
                registrations.push((high, witness));
            }

            crash_after_witness_install(&cut, &runtime);
            let (image, installed) = journal_generations(&cut.io);
            assert_eq!(image.header.base_root, witness);
            assert_eq!(image.header.base_seq, 2);
            assert_eq!(image.header.receipt_generation, header);
            assert_eq!(image.state.highest_generation(), high);
            let retained = usize::from(matches!(layout, ReceiptLayout::DeletedSibling));
            assert_eq!(installed.receipts, old.receipts[..retained], "{layout:?}");
            assert_eq!(
                installed.registrations, registrations,
                "{layout:?} crash={crash}"
            );
            for &(stage, _, _) in &old.receipts[retained..] {
                assert!(image.state.stage(stage).is_none(), "{layout:?}");
            }
            assert_eq!(
                cut.recover(&runtime, false, FaultControl::default())
                    .unwrap(),
                crate::RecoveryOutcome::JournalFinished { base_seq: 3 }
            );
            let want: &[(&str, &[u8])] = if matches!(layout, ReceiptLayout::MatchingSibling) {
                &[("a", b"aaaaaa"), ("local", b"sealed"), ("u", b"unsync")]
            } else {
                &[("local", b"sealed"), ("u", b"unsync")]
            };
            assert_landed_files(&cut, 3, witness, want);
            assert_settled(&cut, &runtime);
        }
    }
}

fn move_head(
    fixture: &Fixture,
    runtime: &tokio::runtime::Runtime,
    witness: GrainId,
    later: LaterHead,
) -> (u64, GrainId, Option<&'static [u8]>) {
    match later {
        LaterHead::Witness => (3, witness, Some(b"sealed")),
        LaterHead::Removal => (4, publish_tree_from(&fixture.remote, runtime, 1), None),
        LaterHead::Overwrite => (4, overwrite(&fixture.remote, runtime), Some(b"remote")),
    }
}

fn assert_head(cut: &SuffixRecovery, seq: u64, parent: GrainId, file: Option<&[u8]>) {
    if let Some(file) = file {
        assert_landed_files(
            cut,
            seq,
            parent,
            &[("local", file), ("unsynced", b"other work")],
        );
    } else {
        assert_landed_files(cut, seq, parent, &[("unsynced", b"other work")]);
    }
}

fn assert_landed_files(cut: &SuffixRecovery, seq: u64, parent: GrainId, files: &[(&str, &[u8])]) {
    let (bytes, doc, objects) = cut.landed(seq, parent);
    let entries = crate::writable_store::capture::entries(&objects, doc.manifest_root, 1).unwrap();
    let names: Vec<_> = entries.iter().map(|entry| entry.name.as_bytes()).collect();
    assert_eq!(
        names,
        files
            .iter()
            .map(|(name, _)| name.as_bytes())
            .collect::<Vec<_>>()
    );
    for (name, file) in files {
        assert_eq!(cut_file(&objects, &bytes, name), *file, "{name}");
    }
}

fn assert_settled(cut: &SuffixRecovery, runtime: &tokio::runtime::Runtime) {
    assert_eq!(
        cut.remote.authority.lock().unwrap().row.unwrap().state,
        ReceiptState::Released
    );
    let before = cut.io.recovered_bytes("journal").unwrap();
    cut.io.crash();
    assert_eq!(
        cut.recover(runtime, false, FaultControl::default())
            .unwrap(),
        crate::RecoveryOutcome::NothingOwed
    );
    assert_eq!(cut.io.recovered_bytes("journal").unwrap(), before);
    assert_eq!(cut.remote.publication_sends.lock().unwrap().len(), 1);
}

#[derive(Clone, Copy)]
enum SuffixEdit {
    Keep,
    Create,
    Overwrite,
    Cancel,
}

type CrashCut = (&'static str, &'static str, u64, usize);

#[test]
fn newer_registration_preserves_later_deletion() {
    check_newer_registration(LaterHead::Removal, SuffixEdit::Keep, None, None);
}

#[test]
fn newer_registration_preserves_later_overwrite() {
    check_newer_registration(LaterHead::Overwrite, SuffixEdit::Keep, None, None);
}

#[test]
fn newer_registration_resumes_after_witness_install() {
    let crash = ("overlay.replace.dir_sync", "after", 2, 0);
    check_newer_registration(LaterHead::Removal, SuffixEdit::Keep, None, Some(crash));
}

#[test]
fn registered_selection_preserves_post_registration_work() {
    for later in [LaterHead::Witness, LaterHead::Removal, LaterHead::Overwrite] {
        for edit in [SuffixEdit::Create, SuffixEdit::Overwrite] {
            check_newer_registration(later, edit, None, None);
        }
    }
}

#[test]
fn registered_selection_proves_both_file_projections() {
    for older in [Some(false), Some(true)] {
        check_newer_registration(LaterHead::Removal, SuffixEdit::Overwrite, older, None);
    }
}

#[test]
fn registered_selection_suffix_crash_cuts() {
    for (older, point, phase, base, sends) in [
        (None, "overlay.replace.rename", "after", 1, 0),
        (None, "overlay.replace.dir_sync", "after", 2, 0),
        (None, "sync.commit", "before_replace", 2, 1),
        (Some(true), "overlay.replace.dir_sync", "after", 2, 0),
    ] {
        let fault = Some((point, phase, base, sends));
        check_newer_registration(LaterHead::Witness, SuffixEdit::Create, older, fault);
    }
}

#[track_caller]
fn check_newer_registration(
    later: LaterHead,
    edit: SuffixEdit,
    older_before_witness: Option<bool>,
    crash: Option<CrashCut>,
) {
    use crate::RecoveryOutcome::{JournalFinished, NothingOwed};

    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    if older_before_witness == Some(true) {
        fixture.create("older", b"dirty");
    }
    let stage = fixture.create("local", b"sealed");
    let witness = prepare_file(&fixture, &runtime, stage);
    if older_before_witness == Some(false) {
        fixture.create("older", b"dirty");
    }
    let suffix = fixture.create("u", b"other work");
    sync_file(&fixture, &runtime, suffix);
    let selected = fixture.remote.authority.lock().unwrap().root.clone();
    assert_ne!(GrainId::of(&selected), witness);
    let (seq, parent, file) = move_head(&fixture, &runtime, witness, later);
    let mut files: Vec<(&str, &[u8])> = file.into_iter().map(|file| ("local", file)).collect();
    files.extend(older_before_witness.map(|_| ("older", b"dirty".as_slice())));
    match edit {
        SuffixEdit::Keep => files.push(("u", b"other work")),
        SuffixEdit::Create => {
            fixture.create("v", b"later");
            files.extend([("u", b"other work".as_slice()), ("v", b"later".as_slice())]);
        }
        SuffixEdit::Overwrite => {
            published::write(&fixture, suffix, 0, b"other edit");
            files.push(("u", b"other edit"));
        }
        SuffixEdit::Cancel => delete_u(&fixture, suffix),
    }
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    let cut = SuffixRecovery::reopen(fixture);
    if let Some((point, phase, base, sends)) = crash {
        let (_, before) = journal_generations(&cut.io);
        let faults = FaultControl::default();
        faults.arm(point, phase, 1, FaultAction::Crash);
        assert!(cut.recover(&runtime, false, faults.clone()).is_err());
        assert_eq!(faults.fired().len() + faults.sync_fired().len(), 1);
        let (image, retained) = journal_generations(&cut.io);
        assert_eq!(image.header.base_seq, base);
        assert_eq!(cut.remote.publication_sends.lock().unwrap().len(), sends);
        cut.io.crash();
        if older_before_witness == Some(true) {
            let receipt = before
                .receipts
                .iter()
                .find(|(stage, _, root)| *stage == suffix && *root == GrainId::of(&selected))
                .unwrap_or_else(|| panic!("missing selected-stage receipt: {:?}", before.receipts));
            assert_eq!(
                (
                    retained.receipts.contains(receipt),
                    image.state.highest_generation()
                ),
                (true, receipt.1),
                "carried-stage receipts: {:?}",
                retained.receipts
            );
        }
        if matches!(edit, SuffixEdit::Keep) {
            assert_eq!(durable_journal(&cut.io).header.base_root, witness);
            assert_no_suffix_send_or_release(&cut.remote);
            assert_eq!(start(&cut.scratch, &cut.io, 168).snapshot().root, selected);
        }
    }
    let recover = || {
        cut.recover(&runtime, false, FaultControl::default())
            .unwrap()
    };
    if matches!(edit, SuffixEdit::Cancel) {
        assert_eq!(recover(), JournalFinished { base_seq: 2 });
        assert_eq!(durable_journal(&cut.io).header.base_root, witness);
        cut.io.crash();
        assert_eq!(recover(), NothingOwed);
        assert!(cut.remote.publication_sends.lock().unwrap().is_empty());
    } else {
        assert_eq!(recover(), JournalFinished { base_seq: seq });
        assert_landed_files(&cut, seq, parent, &files);
        assert_settled(&cut, &runtime);
    }
}

fn delete_u(fixture: &Fixture, stage: u64) {
    use granary_core::overlay_journal::DeleteKind;
    let at = crate::overlay_store::tests::incremental::loc("u");
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.namespace_record(Record::Delete {
                at,
                kind: DeleteKind::File {
                    stage_id: Some(stage),
                },
            })
        })
        .unwrap();
}

#[test]
fn registered_selection_refuses_an_admissible_slot() {
    check_forged_selection(true);
}

#[test]
fn registered_selection_refuses_a_tree_built_after_registration() {
    check_forged_selection(false);
}

fn check_forged_selection(admissible: bool) {
    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    let local = fixture.create("local", b"sealed");
    sync_file(&fixture, &runtime, local);
    let witness = fixture.remote.authority.lock().unwrap().root.clone();
    if admissible {
        publish_registered(&fixture);
    }
    let writer = fixture.store.lock().unwrap().writer_uuid();
    let selected = runtime.block_on(super::super::super::selected::files(
        &fixture.remote,
        &[(b"local", b"sealed"), (b"u", b"unsync")],
        writer,
    ));
    let u = admissible.then(|| fixture.create("u", b"unsync"));
    fixture.remote.published.lock().unwrap().insert(2, witness);
    register_bytes(
        &mut fixture.store.lock().unwrap(),
        &fixture.remote,
        &selected,
        fixture.remote.time.as_ref(),
    );
    if let Some(u) = u {
        delete_u(&fixture, u);
        fixture.create("v", b"later");
    } else {
        fixture.create("u", b"unsync");
    }
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    check_suffix_refusal(fixture, &runtime);
}

#[test]
fn registered_selection_refuses_a_receipt_after_registration() {
    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    let local = fixture.create("local", b"sealed");
    prepare_file(&fixture, &runtime, local);
    fixture.create("older", b"dirty");
    let u = fixture.create("u", b"unsync");
    sync_file(&fixture, &runtime, u);
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    fixture.io.mutate_recovered("journal", |bytes| {
        use granary_core::overlay_journal::{encode_journal, scan_journal_with};
        let mut records = Vec::new();
        let scan = scan_journal_with(bytes, |_, record| records.push(record.clone())).unwrap();
        let receipt = records.len() - 2;
        assert!(matches!(records[receipt], Record::FileSynced { stage_id, .. } if stage_id == u));
        assert!(matches!(
            records[receipt + 1],
            Record::IntentRegistered { .. }
        ));
        records.swap(receipt, receipt + 1);
        *bytes = encode_journal(&scan.header, &records).unwrap();
    });
    check_suffix_refusal(fixture, &runtime);
}

#[test]
fn registered_selection_cancels_back_to_published_witness() {
    for crash in [
        None,
        Some(("overlay.replace.rename", "after", 1, 0)),
        Some(("overlay.replace.dir_sync", "after", 2, 0)),
    ] {
        check_newer_registration(LaterHead::Witness, SuffixEdit::Cancel, None, crash);
    }
}

#[test]
fn newest_published_registration_is_the_witness() {
    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    let stage = fixture.create("local", b"sealed");
    prepare_file(&fixture, &runtime, stage);
    published::write(&fixture, stage, 0, b"edited");
    register_file(&fixture, &runtime, b"edited");
    publish_registered(&fixture);
    sync_file(&fixture, &runtime, stage);
    let suffix = fixture.create("unsynced", b"other work");
    sync_file(&fixture, &runtime, suffix);
    let parent = overwrite(&fixture.remote, &runtime);
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    let cut = SuffixRecovery::reopen(fixture);
    assert_eq!(
        cut.recover(&runtime, false, FaultControl::default())
            .unwrap(),
        crate::RecoveryOutcome::JournalFinished { base_seq: 5 }
    );
    assert_head(&cut, 5, parent, Some(b"remote"));
    assert_settled(&cut, &runtime);
}

#[test]
fn published_registration_without_a_cut_refuses_before_send() {
    check_registered_witness_refusal(b"forged", b"sealed");
}

#[test]
fn published_registration_requires_the_selected_manifest_to_match_replay() {
    check_registered_witness_refusal(b"sealed", b"forged");
}

fn check_registered_witness_refusal(witness: &[u8], selected: &[u8]) {
    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    register_file(&fixture, &runtime, witness);
    let witness = publish_registered(&fixture);
    fixture.create("local", b"sealed");
    register_file(&fixture, &runtime, selected);
    assert_eq!(fixture.registered().parent, Some(witness));
    publish_tree_from(&fixture.remote, &runtime, 1);
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    check_suffix_refusal(fixture, &runtime);
}

fn register_file(fixture: &Fixture, runtime: &tokio::runtime::Runtime, bytes: &[u8]) {
    let writer = fixture.store.lock().unwrap().writer_uuid();
    let prepared = runtime.block_on(super::super::super::selected::one_file(
        &fixture.remote,
        b"local",
        bytes,
        writer,
    ));
    register_bytes(
        &mut fixture.store.lock().unwrap(),
        &fixture.remote,
        &prepared,
        fixture.remote.time.as_ref(),
    );
}

#[test]
fn unpublished_registration_finishes_dirty_journal() {
    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    let stage = fixture.create("local", b"sealed");
    sync_file(&fixture, &runtime, stage);
    published::write(&fixture, stage, 0, b"edited");
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    let parent = fixture.base;
    let cut = SuffixRecovery::reopen(fixture);
    assert_eq!(
        cut.recover(&runtime, false, FaultControl::default())
            .unwrap(),
        crate::RecoveryOutcome::JournalFinished { base_seq: 2 }
    );
    assert_landed_files(&cut, 2, parent, &[("local", b"edited")]);
    assert_settled(&cut, &runtime);
}

#[test]
fn file_sync_witness_preserves_other_dirty_work() {
    let runtime = suffix_runtime();
    for other_first in [false, true] {
        for (later, crash) in [
            (LaterHead::Witness, false),
            (LaterHead::Removal, false),
            (LaterHead::Removal, true),
            (LaterHead::Overwrite, false),
        ] {
            let (fixture, witness) = file_sync(&runtime, other_first, None, crash);
            let (seq, parent, file) = move_head(&fixture, &runtime, witness, later);
            let cut = SuffixRecovery::reopen(fixture);
            assert_eq!(
                cut.recover(&runtime, false, FaultControl::default())
                    .map_err(|e| e.to_string()),
                Ok(crate::RecoveryOutcome::JournalFinished { base_seq: seq }),
                "{other_first:?} {later:?} receipt crash={crash}"
            );
            assert_head(&cut, seq, parent, file);
            assert_settled(&cut, &runtime);
        }
    }
}

#[test]
fn unchanged_witness_stage_follows_later_head() {
    let runtime = suffix_runtime();
    for crash in [false, true] {
        check_unchanged_witness_stage(&runtime, crash);
    }
}

fn check_unchanged_witness_stage(runtime: &tokio::runtime::Runtime, crash: bool) {
    for (rewrite, later, fault) in [
        (None, LaterHead::Removal, None),
        (
            None,
            LaterHead::Overwrite,
            Some(("overlay.replace.dir_sync", "after", 0)),
        ),
        (
            Some(b"sealed".as_slice()),
            LaterHead::Removal,
            Some(("sync.commit", "before_replace", 1)),
        ),
        (Some(b"sealed".as_slice()), LaterHead::Overwrite, None),
    ] {
        let other_first = matches!(fault, Some(("overlay.replace.dir_sync", ..)));
        let (fixture, witness) = file_sync(runtime, other_first, rewrite, crash);
        let (seq, parent, file) = move_head(&fixture, runtime, witness, later);
        let cut = SuffixRecovery::reopen(fixture);
        if let Some((point, phase, sends)) = fault {
            let before = durable_journal(&cut.io);
            let faults = FaultControl::default();
            faults.arm(point, phase, 1, FaultAction::Crash);
            assert!(cut.recover(runtime, false, faults.clone()).is_err());
            assert_eq!(faults.fired().len() + faults.sync_fired().len(), 1);
            assert_eq!(cut.remote.publication_sends.lock().unwrap().len(), sends);
            let after = durable_journal(&cut.io);
            assert_eq!(after.header.base_root, witness);
            assert_eq!(after.state.next_stage_id(), before.state.next_stage_id());
            assert!(after.state.highest_generation() >= before.state.highest_generation());
            cut.io.crash();
        }
        let result = cut.recover(runtime, false, FaultControl::default());
        if fault.is_some_and(|(_, _, sends)| sends == 1) {
            assert!(
                matches!(
                    result,
                    Ok(crate::RecoveryOutcome::JournalFinished { .. }
                        | crate::RecoveryOutcome::NothingOwed)
                ),
                "{result:?}"
            );
        } else {
            assert_eq!(
                result.map_err(|e| e.to_string()),
                Ok(crate::RecoveryOutcome::JournalFinished { base_seq: seq }),
                "rewrite={rewrite:?} later={later:?} receipt crash={crash}"
            );
        }
        assert_head(&cut, seq, parent, file);
        assert_settled(&cut, runtime);
    }
}

#[test]
fn same_size_witness_edit_against_remote_overwrite() {
    let runtime = suffix_runtime();
    let (fixture, _) = file_sync(&runtime, false, Some(b"edited"), false);
    overwrite(&fixture.remote, &runtime);
    let cut = SuffixRecovery::reopen(fixture);
    let result = cut.recover(&runtime, false, FaultControl::default());
    assert!(
        matches!(result, Err(crate::RecoveryCommandError::Conflict { .. })),
        "{result:?}"
    );
    assert_no_suffix_send_or_release(&cut.remote);
}

fn simple_suffix(runtime: &tokio::runtime::Runtime, carry: bool) -> (Fixture, GrainId) {
    let fixture = runtime.block_on(Fixture::new());
    let stage = fixture.create("local", b"sealed");
    let witness = prepare_file(&fixture, runtime, stage);
    if carry {
        published::write(&fixture, stage, 1, b"XX");
    } else {
        fixture.create("unsynced", b"other work");
    }
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    (fixture, witness)
}

/// The witness install's fault points, in [`WITNESS_CHUNKS`] slices with one
/// test each: every case recovers a durable fixture twice, and on Apple
/// targets each sync is a full-device flush (`F_FULLFSYNC`) whose cost grows
/// with every test flushing beside it, so one test holding every point
/// reached the ci profile's hard kill under a full parallel run.
const WITNESS_POINTS: [(&str, &str); 16] = [
    ("overlay.retire.mark_clear", "before"),
    ("overlay.retire.mark_clear", "after-sync"),
    ("overlay.carry.mark_clear", "before"),
    ("overlay.carry.mark_clear", "after-sync"),
    ("overlay.replace.quiesced", "before"),
    ("overlay.replace.build", "before"),
    ("overlay.replace.build", "partial"),
    ("overlay.replace.sync", "before"),
    ("overlay.replace.sync", "after"),
    ("overlay.replace.rename", "before"),
    ("overlay.replace.rename", "after"),
    ("overlay.replace.dir_sync", "before"),
    ("overlay.replace.dir_sync", "after"),
    ("overlay.replace.switched", "after"),
    ("overlay.retire.unlink", "before"),
    ("overlay.retire.unlink", "after-sync"),
];

/// The slices of [`WITNESS_POINTS`], one per test below.
const WITNESS_CHUNKS: [std::ops::Range<usize>; 4] = [0..4, 4..8, 8..12, 12..16];

#[test]
fn witness_chunks_cover_every_point_once() {
    let mut covered: Vec<usize> = WITNESS_CHUNKS.iter().cloned().flatten().collect();
    let listed = covered.len();
    covered.sort_unstable();
    covered.dedup();
    assert_eq!(
        (listed, covered),
        (
            WITNESS_POINTS.len(),
            (0..WITNESS_POINTS.len()).collect::<Vec<_>>()
        ),
        "every witness fault point must run in exactly one chunk"
    );
    let mut points = WITNESS_POINTS.to_vec();
    points.sort_unstable();
    points.dedup();
    assert_eq!(
        points.len(),
        WITNESS_POINTS.len(),
        "a witness fault point is listed twice"
    );
}

fn witness_install_chunk_converges(chunk: usize) {
    let runtime = suffix_runtime();
    for &(point, phase) in &WITNESS_POINTS[WITNESS_CHUNKS[chunk].clone()] {
        for (carry, crash) in [(false, true), (true, true), (false, false), (true, false)] {
            if point.starts_with("overlay.carry") && (!carry || !crash) {
                continue;
            }
            let case = (point, phase, carry, crash);
            let (fixture, witness) = simple_suffix(&runtime, carry);
            let cut = SuffixRecovery::reopen(fixture);
            let before = durable_journal(&cut.io);
            let faults = FaultControl::default();
            faults.arm(
                point,
                phase,
                1,
                if crash {
                    FaultAction::Crash
                } else {
                    FaultAction::Fail
                },
            );
            let first = cut.recover(&runtime, false, faults.clone());
            let fired = faults.fired().len() + faults.sync_fired().len();
            if first.is_err() {
                assert_eq!(fired, 1, "{case:?}");
                assert_ne!(
                    cut.remote.authority.lock().unwrap().row.unwrap().state,
                    ReceiptState::Released
                );
            } else {
                // When a mark is absent, clearing it emits no sync fault.
                assert_eq!(fired, 0, "{case:?}");
                assert!(point.contains("mark_clear"), "{case:?}");
            }
            if crash {
                cut.io.crash();
            }
            cut.recover(&runtime, false, FaultControl::default())
                .unwrap();
            let (head, _, objects) = cut.landed(3, witness);
            if carry {
                assert_eq!(cut_file(&objects, &head, "local"), b"sXXled", "{case:?}");
            } else {
                assert_head(&cut, 3, witness, Some(b"sealed"));
            }
            let after = durable_journal(&cut.io);
            assert_eq!(
                after.state.next_stage_id(),
                before.state.next_stage_id(),
                "{case:?}"
            );
            assert!(
                after.state.highest_generation() >= before.state.highest_generation(),
                "{case:?}"
            );
            assert!(cut.io.recovered_bytes("journal.next").is_none(), "{case:?}");
            assert_settled(&cut, &runtime);
        }
    }
}

#[test]
fn witness_install_faults_converge_1() {
    witness_install_chunk_converges(0);
}

#[test]
fn witness_install_faults_converge_2() {
    witness_install_chunk_converges(1);
}

#[test]
fn witness_install_faults_converge_3() {
    witness_install_chunk_converges(2);
}

#[test]
fn witness_install_faults_converge_4() {
    witness_install_chunk_converges(3);
}

#[test]
fn witness_install_reruns_against_moved_head() {
    let runtime = suffix_runtime();
    for (carry, later) in [
        (false, LaterHead::Removal),
        (false, LaterHead::Overwrite),
        (true, LaterHead::Removal),
        (true, LaterHead::Overwrite),
        (true, LaterHead::Witness),
    ] {
        let (fixture, _) = simple_suffix(&runtime, carry);
        let cut = SuffixRecovery::reopen(fixture);
        let faults = FaultControl::default();
        faults.arm("overlay.replace.dir_sync", "after", 1, FaultAction::Crash);
        assert!(cut.recover(&runtime, false, faults.clone()).is_err());
        assert_eq!(faults.sync_fired().len() + faults.fired().len(), 1);
        assert_eq!(durable_journal(&cut.io).header.base_seq, 2);
        assert_no_suffix_send_or_release(&cut.remote);
        let (head, file) = match later {
            LaterHead::Removal => (publish_tree_from(&cut.remote, &runtime, 1), None),
            LaterHead::Overwrite => (overwrite(&cut.remote, &runtime), Some(b"remote".as_slice())),
            LaterHead::Witness => (
                publish_tree_from(&cut.remote, &runtime, 2),
                Some(b"sXXled".as_slice()),
            ),
        };
        cut.io.crash();
        let result = cut.recover(&runtime, false, FaultControl::default());
        if carry && !matches!(later, LaterHead::Witness) {
            assert!(
                matches!(result, Err(crate::RecoveryCommandError::Conflict { .. })),
                "{later:?} {result:?}"
            );
            assert_no_suffix_send_or_release(&cut.remote);
            continue;
        }
        assert_eq!(
            result.unwrap(),
            crate::RecoveryOutcome::JournalFinished { base_seq: 4 }
        );
        if carry {
            let (root, _, objects) = cut.landed(4, head);
            assert_eq!(cut_file(&objects, &root, "local"), file.unwrap());
        } else {
            assert_head(&cut, 4, head, file);
        }
        assert_settled(&cut, &runtime);
    }
}

#[test]
fn witness_landing_reruns_below_a_newer_head() {
    let runtime = suffix_runtime();
    let (fixture, witness) = simple_suffix(&runtime, false);
    let cut = SuffixRecovery::reopen(fixture);
    let faults = FaultControl::default();
    faults.arm("sync.commit", "before_replace", 1, FaultAction::Crash);
    assert!(cut.recover(&runtime, false, faults.clone()).is_err());
    assert_eq!(faults.fired().len() + faults.sync_fired().len(), 1);
    assert_head(&cut, 3, witness, Some(b"sealed"));
    let next = publish_file(&cut.remote, &runtime, b"foreign", b"newer");
    cut.io.crash();
    cut.recover(&runtime, false, FaultControl::default())
        .unwrap();
    let head = cut.remote.published.lock().unwrap()[&4].clone();
    assert_eq!(GrainId::of(&head), next);
    assert_settled(&cut, &runtime);
}

#[test]
fn witness_relations_preserve_later_deletion() {
    let runtime = suffix_runtime();
    for relation in [
        LandedSelection::Exact,
        LandedSelection::EqualManifest,
        LandedSelection::Parent,
    ] {
        for registered in [false, true] {
            let (fixture, _) = landed_dirty(&runtime, relation, registered, true);
            let head = publish_tree_from(&fixture.remote, &runtime, 1);
            let cut = SuffixRecovery::reopen(fixture);
            assert_eq!(
                cut.recover(&runtime, !registered, FaultControl::default())
                    .unwrap(),
                crate::RecoveryOutcome::JournalFinished { base_seq: 4 },
                "{relation:?}/{registered}"
            );
            let (bytes, doc, objects) = cut.landed(4, head);
            let entries =
                crate::writable_store::capture::entries(&objects, doc.manifest_root, 1).unwrap();
            assert_eq!(
                entries
                    .iter()
                    .map(|e| e.name.as_bytes())
                    .collect::<Vec<_>>(),
                [b"suffix".as_slice()]
            );
            assert_eq!(cut_file(&objects, &bytes, "suffix"), b"unpublished");
            assert_settled(&cut, &runtime);
        }
    }
}

#[test]
fn unverifiable_witness_cut_blocks_recovery() {
    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    let stage = fixture.create("local", b"sealed");
    let id = prepare_file(&fixture, &runtime, stage);
    published::write(&fixture, stage, 0, b"edited");
    fixture.create("unsynced", b"other work");
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    let head = fixture.remote.published.lock().unwrap()[&2].clone();
    let doc = root::decode_root(&head).unwrap();
    let objects = fixture
        .remote
        .objects
        .read_objects(doc.binmap_index)
        .unwrap();
    let entries = crate::writable_store::capture::overlay_base_entries(
        &objects,
        doc.manifest_root,
        &|_, _| 0,
        &mut |_, _| Ok(()),
        &|| CoordinationError::Refused("SyncBase"),
    )
    .unwrap();
    let pin_files = fixture.content.payloads.lock().unwrap().clone();
    let witness = crate::recovery::DirtyWitness {
        selected: id,
        prepared: id,
        selection: None,
        tree: crate::recovery::WitnessTree {
            manifest: doc.manifest_root,
            entries,
            view: Arc::new(crate::writable_store::ViewContext {
                base_id: id,
                base_seq: 2,
                base_bytes: head,
                bins: Arc::from([]),
                entries: BTreeMap::new(),
                pin_files,
                pin_nodes: BTreeMap::new(),
            }),
        },
        event: crate::observe::RecoverEvent::Nothing,
    };
    fixture.store.lock().unwrap().close_mutations();
    let journal = fixture.io.recovered_bytes("journal").unwrap();
    let stages = durable_history(&fixture.io);
    for unavailable in [
        None,
        Some(Err(crate::OverlayError::ContentUnavailable)),
        Some(Err(crate::OverlayError::CaptureCoverageLost)),
        Some(Ok(Vec::new())),
    ] {
        let unavailable = std::cell::RefCell::new(unavailable);
        let fails = unavailable.borrow().is_some();
        let reads = std::cell::Cell::new(0);
        #[expect(
            clippy::redundant_closure_for_method_calls,
            reason = "the method item fixes the overlay borrow's lifetime"
        )]
        let snapshot = fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.recovery_prefix())
            .unwrap();
        let result = snapshot.prove(
            &witness,
            fixture.content.as_ref(),
            |_, _, offset, length| {
                reads.set(reads.get() + 1);
                unavailable.borrow_mut().take().unwrap_or_else(|| {
                    let offset = usize::try_from(offset).unwrap();
                    Ok(b"sealed"[offset..offset + length].to_vec())
                })
            },
            1_000_000,
            TokioSyncRuntime.now() + Duration::from_secs(5),
            &TokioSyncRuntime,
        );
        if fails {
            assert!(
                matches!(
                    result,
                    Err(CoordinationError::Refused("WritableRecoveryRequired"))
                ),
                "{result:?}"
            );
            assert_eq!(reads.get(), 1, "proof must stop at the unverifiable cursor");
        } else {
            assert!(result.is_ok(), "{result:?}");
            assert!(
                reads.get() > 1,
                "a verified mismatch permits checking earlier cursors"
            );
        }
        assert_eq!(fixture.io.recovered_bytes("journal").unwrap(), journal);
        assert_eq!(durable_history(&fixture.io), stages);
        assert_no_suffix_send_or_release(&fixture.remote);
    }
}

#[test]
fn scoped_witness_replays_each_stage_after_its_payload_cut() {
    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    let first = fixture.create("first", b"first!");
    sync_file(&fixture, &runtime, first);
    published::write(&fixture, first, 1, b"X");
    fixture.create("unsynced", b"other work");
    let second = fixture.create("local", b"sealed");
    let witness = prepare_file(&fixture, &runtime, second);
    published::write(&fixture, second, 1, b"YY");
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    let cut = SuffixRecovery::reopen(fixture);
    assert_eq!(
        cut.recover(&runtime, false, FaultControl::default())
            .unwrap(),
        crate::RecoveryOutcome::JournalFinished { base_seq: 3 }
    );
    let (bytes, doc, objects) = cut.landed(3, witness);
    assert_eq!(cut_file(&objects, &bytes, "first"), b"fXrst!");
    assert_eq!(cut_file(&objects, &bytes, "local"), b"sYYled");
    assert_eq!(cut_file(&objects, &bytes, "unsynced"), b"other work");
    assert_eq!(
        crate::writable_store::capture::entries(&objects, doc.manifest_root, 1)
            .unwrap()
            .len(),
        3
    );
    assert_settled(&cut, &runtime);
}

mod checkpoint;
