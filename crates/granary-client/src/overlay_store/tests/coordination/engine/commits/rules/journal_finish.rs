// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::root;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LandedSelection {
    Exact,
    Descendant,
    EqualManifest,
    Parent,
}

fn landed_dirty(
    runtime: &tokio::runtime::Runtime,
    relation: LandedSelection,
    registered: bool,
    suffix: bool,
) -> (Fixture, Vec<u8>) {
    let fixture = runtime.block_on(Fixture::new());
    let stage = fixture.create("local", b"sealed");
    let writer = fixture.store.lock().unwrap().writer_uuid();
    if !registered {
        let old = runtime.block_on(super::super::selected::one_file(
            &fixture.remote,
            b"old",
            b"earlier selection",
            writer,
        ));
        register_bytes(
            &mut fixture.store.lock().unwrap(),
            &fixture.remote,
            &old,
            fixture.remote.time.as_ref(),
        );
    }
    let prepared = if registered && relation != LandedSelection::Parent {
        runtime
            .block_on(async {
                fixture
                    .engine
                    .sync(SyncTarget::Stage(stage), SyncOptions::default())
                    .wait()
                    .await
            })
            .unwrap();
        fixture.remote.authority.lock().unwrap().root.clone()
    } else {
        runtime.block_on(super::super::selected::one_file(
            &fixture.remote,
            b"local",
            b"sealed",
            writer,
        ))
    };
    let mut doc = root::decode_root(&prepared).unwrap();
    assert_eq!((doc.seq, doc.parent), (2, Some(fixture.base)));
    let witness = if relation == LandedSelection::EqualManifest {
        doc.writer_uuid = [99; 16];
        super::super::rebase::signed(doc.clone())
    } else {
        prepared.clone()
    };
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(2, witness.clone());
    let selected = if relation == LandedSelection::Parent {
        doc.seq = 3;
        doc.parent = Some(GrainId::of(&witness));
        let selected = super::super::rebase::signed(doc);
        if registered {
            register_bytes(
                &mut fixture.store.lock().unwrap(),
                &fixture.remote,
                &selected,
                fixture.remote.time.as_ref(),
            );
        }
        selected
    } else {
        prepared
    };
    assert_eq!(
        selected == witness,
        matches!(
            relation,
            LandedSelection::Exact | LandedSelection::Descendant
        )
    );
    if suffix {
        fixture.create("suffix", b"unpublished");
    }
    persist_content(&fixture);
    if !registered {
        select_on_other_instance(&fixture, selected);
    }
    if relation == LandedSelection::Descendant {
        let head = runtime.block_on(super::super::selected::one_file(
            &fixture.remote,
            b"remote",
            b"later",
            [99; 16],
        ));
        assert_eq!(
            root::decode_root(&head).unwrap().parent,
            Some(GrainId::of(&witness))
        );
        fixture.remote.published.lock().unwrap().insert(3, head);
    }
    published::settle_disk(&fixture.io);
    (fixture, witness)
}

fn select_on_other_instance(fixture: &Fixture, selected: Vec<u8>) {
    let mut authority = fixture.remote.authority.lock().unwrap();
    authority.root = selected;
    let prepared_root_id = GrainId::of(&authority.root);
    authority.cursor += 1;
    let row = authority.row.as_mut().unwrap();
    row.epoch += 1;
    row.instance = [99; 16];
    row.generation = 128;
    row.state = ReceiptState::Live { prepared_root_id };
    drop(authority);
    fixture
        .store
        .lock()
        .unwrap()
        .phase_for_test(Phase::Fenced)
        .unwrap();
}

fn durable_journal(io: &SimIo) -> granary_core::overlay_journal::JournalScan {
    granary_core::overlay_journal::scan_journal(&io.recovered_bytes("journal").unwrap()).unwrap()
}

#[test]
fn dirty_registered_selection_already_landed() {
    check_landed_dirty(LandedSelection::Exact, true);
}

#[test]
fn dirty_unregistered_selection_already_landed() {
    check_landed_dirty(LandedSelection::Exact, false);
}

#[test]
fn dirty_selection_landed_below_head() {
    check_landed_dirty(LandedSelection::Descendant, true);
}

#[test]
fn dirty_selection_equal_to_another_signed_root() {
    check_landed_dirty(LandedSelection::EqualManifest, true);
}

#[test]
fn dirty_selection_equal_to_its_parent() {
    check_landed_dirty(LandedSelection::Parent, true);
}

fn check_landed_dirty(relation: LandedSelection, registered: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (fixture, witness) = landed_dirty(&runtime, relation, registered, false);
    let (scratch, io, remote, mut local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    let before = durable_journal(&io);
    let selected = remote.authority.lock().unwrap().root.clone();
    assert_eq!(
        local.recovery_rule().unwrap(),
        if registered {
            RecoveryRule::DirtyJournal
        } else {
            RecoveryRule::OwnershipLost
        }
    );
    let mut found = false;
    granary_core::overlay_journal::scan_journal_with(
        &io.recovered_bytes("journal").unwrap(),
        |_, record| {
            if let Record::IntentRegistered { prepared_root, .. } = record {
                found |= *prepared_root == GrainId::of(&selected);
            }
        },
    )
    .unwrap();
    assert_eq!(found, registered);
    drop(local);
    let before_requests = remote.authority.lock().unwrap().sends.len();
    let head = remote.published.lock().unwrap().clone();
    let (seq, id) = (
        root::decode_root(&witness).unwrap().seq,
        GrainId::of(&witness),
    );
    let result = recovery_outcome(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        (!registered).then_some(writer),
        None,
        FaultControl::default(),
    );
    assert_eq!(
        remote.publication_sends.lock().unwrap().len(),
        0,
        "{relation:?}, registered={registered}, {result:?}"
    );
    assert_eq!(
        result.map_err(|e| e.to_string()),
        Ok(crate::RecoveryOutcome::JournalFinished { base_seq: seq })
    );
    assert_eq!(*remote.published.lock().unwrap(), head);
    let authority = remote.authority.lock().unwrap();
    let volume = config(&scratch.0).volume;
    assert!(
        authority.sends[before_requests..]
            .iter()
            .all(|bytes| { intent::decode_register(bytes, &volume, |_, _| true).is_err() })
    );
    assert_eq!(authority.row.unwrap().state, ReceiptState::Released);
    drop(authority);
    let after = durable_journal(&io);
    assert_eq!(
        (
            after.header.base_seq,
            after.header.base_root,
            after.header.writer
        ),
        (seq, id, writer)
    );
    assert_eq!(after.state.next_seq(), 1);
    assert_eq!(after.header.next_stage_id, before.state.next_stage_id());
    assert!(after.header.receipt_generation >= before.state.highest_generation());
    assert!(durable_history(&io).1.is_empty());
    io.crash();
    let mut local = start(&scratch, &io, 167);
    assert!(local.recovery_released());
    assert_eq!(local.recovery_rule().unwrap(), RecoveryRule::Nothing);
    drop(local);
    let sends = remote.authority.lock().unwrap().sends.len();
    let rerun = recovery_outcome(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        None,
        FaultControl::default(),
    );
    assert_eq!(
        rerun.map_err(|e| e.to_string()),
        Ok(crate::RecoveryOutcome::NothingOwed)
    );
    assert_eq!(remote.publication_sends.lock().unwrap().len(), 0);
    assert_eq!(remote.authority.lock().unwrap().sends.len(), sends);
}

fn suffix_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

struct SuffixRecovery {
    scratch: Scratch,
    io: SimIo,
    remote: Arc<Remote>,
    writer: [u8; 16],
}

impl SuffixRecovery {
    fn reopen(fixture: Fixture) -> Self {
        let (scratch, io, remote, local) = fixture.reload_carrier();
        Self {
            scratch,
            io,
            remote,
            writer: local.writer_uuid(),
        }
    }

    fn recover(
        &self,
        runtime: &tokio::runtime::Runtime,
        take_over: bool,
        faults: FaultControl,
    ) -> Result<crate::RecoveryOutcome, crate::RecoveryCommandError> {
        recovery_outcome(
            &self.scratch,
            &self.io,
            &self.remote,
            runtime,
            self.writer,
            take_over.then_some(self.writer),
            None,
            faults,
        )
    }
    fn landed(
        &self,
        seq: u64,
        parent: GrainId,
    ) -> (
        Vec<u8>,
        root::RootDoc,
        crate::overlay_store::tests::sync_objects::Objects,
    ) {
        let head = self.remote.published.lock().unwrap()[&seq].clone();
        let doc = root::decode_root(&head).unwrap();
        assert_eq!(doc.parent, Some(parent));
        assert_eq!(
            self.remote.publication_sends.lock().unwrap().as_slice(),
            std::slice::from_ref(&head)
        );
        let objects = self.remote.objects.read_objects(doc.binmap_index).unwrap();
        (head, doc, objects)
    }
}

#[test]
fn dirty_selection_with_different_tree_publishes_once() {
    let runtime = suffix_runtime();
    for (relation, registered) in [
        (LandedSelection::Exact, true),
        (LandedSelection::Exact, false),
        (LandedSelection::EqualManifest, false),
        (LandedSelection::Parent, true),
        (LandedSelection::Parent, false),
    ] {
        let (fixture, witness) = landed_dirty(&runtime, relation, registered, true);
        let cut = SuffixRecovery::reopen(fixture);
        let result = cut.recover(&runtime, !registered, FaultControl::default());
        assert_eq!(
            result.map_err(|e| e.to_string()),
            Ok(crate::RecoveryOutcome::JournalFinished { base_seq: 3 }),
            "{relation:?}/{registered}"
        );
        let (head, _, objects) = cut.landed(3, GrainId::of(&witness));
        assert_eq!(cut_file(&objects, &head, "suffix"), b"unpublished");
        assert_eq!(
            durable_journal(&cut.io).header.base_root,
            GrainId::of(&head)
        );
    }
}

#[test]
fn dirty_selection_suffix_preserves_later_deletion() {
    check_dirty_selection_suffix_rebase(true);
}

#[test]
fn dirty_selection_suffix_keeps_file_retained_by_later_root() {
    check_dirty_selection_suffix_rebase(false);
}

fn check_dirty_selection_suffix_rebase(delete_file: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (fixture, prepared) = landed_dirty(&runtime, LandedSelection::Exact, true, false);
    assert_file(&fixture, &prepared, "local", b"sealed");

    let tree_seq = if delete_file { 1 } else { 2 };
    let head_id = publish_tree_from(&fixture.remote, &runtime, tree_seq);
    fixture.create("suffix", b"unpublished");
    published::settle_disk(&fixture.io);
    let base = fixture.base;
    let (scratch, io, remote, mut local) = fixture.reload_carrier();
    assert_eq!(local.recovery_rule().unwrap(), RecoveryRule::DirtyJournal);
    assert_eq!(local.snapshot().root, prepared);
    assert_eq!(durable_journal(&io).header.base_root, base);
    let writer = local.writer_uuid();
    drop(local);

    let result = recovery_outcome(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        None,
        FaultControl::default(),
    );
    assert_eq!(
        result.map_err(|e| e.to_string()),
        Ok(crate::RecoveryOutcome::JournalFinished { base_seq: 4 })
    );
    let published = remote.published.lock().unwrap();
    let (seq, recovered) = published.last_key_value().unwrap();
    assert_eq!(*seq, 4);
    assert_eq!(
        remote.publication_sends.lock().unwrap().as_slice(),
        std::slice::from_ref(recovered)
    );
    let doc = root::decode_root(recovered).unwrap();
    assert_eq!(doc.parent, Some(head_id));
    let objects = remote.objects.read_objects(doc.binmap_index).unwrap();
    assert_eq!(cut_file(&objects, recovered, "suffix"), b"unpublished");
    if delete_file {
        let entries =
            crate::writable_store::capture::entries(&objects, doc.manifest_root, 1).unwrap();
        assert!(
            entries
                .iter()
                .all(|entry| entry.name.as_bytes() != b"local"),
            "recovery resurrected `local`, which authority root 3 deleted"
        );
    } else {
        assert_eq!(cut_file(&objects, recovered, "local"), b"sealed");
    }
}

fn publish_tree_from(remote: &Remote, runtime: &tokio::runtime::Runtime, tree_seq: u64) -> GrainId {
    let tree = root::decode_root(&remote.published.lock().unwrap()[&tree_seq]).unwrap();
    let objects = remote.objects.read_objects(tree.binmap_index).unwrap();
    let head = runtime
        .block_on(crate::prepare_from_manifest(
            remote,
            &objects,
            tree.manifest_root,
            crate::HarvestStats::default(),
            &tree.volume,
            &SigningKey::from_seed(&[39; 32]).unwrap(),
            &granary_core::identity::WriterIdentity::from_bytes([99; 16]),
            tree.timestamp,
            crate::Policy { min_prefix_bits: 0 },
        ))
        .unwrap()
        .root_bytes;
    let doc = root::decode_root(&head).unwrap();

    let head_id = GrainId::of(&head);
    remote.published.lock().unwrap().insert(doc.seq, head);

    head_id
}

#[test]
fn dirty_suffix_same_stage_and_later_overwrite() {
    let runtime = suffix_runtime();
    for (same_stage, remote_change, expected) in [
        (true, "unchanged", Some(b"sXXled".as_slice())),
        (true, "removed", None),
        (true, "overwritten", None),
        (false, "overwritten", Some(b"remote".as_slice())),
    ] {
        let (fixture, _) = landed_dirty(&runtime, LandedSelection::Exact, true, false);
        if same_stage {
            let stage = durable_journal(&fixture.io).state.next_stage_id() - 1;
            published::write(&fixture, stage, 1, b"XX");
        } else {
            fixture.create("suffix", b"disjoint");
        }
        let head = match remote_change {
            "unchanged" => publish_tree_from(&fixture.remote, &runtime, 2),
            "removed" => publish_tree_from(&fixture.remote, &runtime, 1),
            _ => {
                let bytes = runtime.block_on(super::super::selected::one_file(
                    &fixture.remote,
                    b"local",
                    b"remote",
                    [99; 16],
                ));
                let id = GrainId::of(&bytes);
                fixture.remote.published.lock().unwrap().insert(3, bytes);
                id
            }
        };
        published::settle_disk(&fixture.io);
        let cut = SuffixRecovery::reopen(fixture);
        let result = cut.recover(&runtime, false, FaultControl::default());
        let case = format!("{same_stage}/{remote_change}");
        if let Some(expected) = expected {
            assert_eq!(
                result.map_err(|e| e.to_string()),
                Ok(crate::RecoveryOutcome::JournalFinished { base_seq: 4 }),
                "{case}"
            );
            let (root, _, objects) = cut.landed(4, head);
            assert_eq!(cut_file(&objects, &root, "local"), expected, "{case}");
            if !same_stage {
                assert_eq!(cut_file(&objects, &root, "suffix"), b"disjoint", "{case}");
            }
        } else {
            assert!(
                matches!(result, Err(crate::RecoveryCommandError::Conflict { .. })),
                "{case}: {result:?}"
            );
            assert_no_suffix_send_or_release(&cut.remote);
        }
    }
}

#[test]
fn dirty_suffix_removes_a_witness_file() {
    let runtime = suffix_runtime();
    let (fixture, witness) = landed_dirty(&runtime, LandedSelection::Exact, true, false);
    let stage = durable_journal(&fixture.io).state.next_stage_id() - 1;
    fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.namespace_record(Record::Delete {
                at: crate::overlay_store::tests::incremental::loc("local"),
                kind: granary_core::overlay_journal::DeleteKind::File {
                    stage_id: Some(stage),
                },
            })
        })
        .unwrap();
    published::settle_disk(&fixture.io);
    let cut = SuffixRecovery::reopen(fixture);
    let result = cut.recover(&runtime, false, FaultControl::default());
    assert_eq!(
        result.map_err(|e| e.to_string()),
        Ok(crate::RecoveryOutcome::JournalFinished { base_seq: 3 })
    );
    let (_, doc, objects) = cut.landed(3, GrainId::of(&witness));
    assert!(
        crate::writable_store::capture::entries(&objects, doc.manifest_root, 1)
            .unwrap()
            .is_empty()
    );
}

fn assert_no_suffix_send_or_release(remote: &Remote) {
    assert!(remote.publication_sends.lock().unwrap().is_empty());
    let authority = remote.authority.lock().unwrap();
    assert_ne!(authority.row.unwrap().state, ReceiptState::Released);
    assert!(
        authority
            .sends
            .iter()
            .all(|bytes| intent::decode_release(bytes).is_err())
    );
}

#[test]
fn dirty_suffix_refuses_unmatched_and_same_size_witnesses() {
    let runtime = suffix_runtime();
    for name in [b"other", b"local"] {
        let fixture = runtime.block_on(Fixture::new());
        fixture.create("local", b"sealed");
        let writer = fixture.store.lock().unwrap().writer_uuid();
        let witness = runtime.block_on(super::super::selected::one_file(
            &fixture.remote,
            name,
            b"forged",
            writer,
        ));
        register_bytes(
            &mut fixture.store.lock().unwrap(),
            &fixture.remote,
            &witness,
            fixture.remote.time.as_ref(),
        );
        fixture.remote.published.lock().unwrap().insert(2, witness);
        fixture.create("suffix", b"later");
        published::settle_disk(&fixture.io);
        check_suffix_refusal(fixture, &runtime);
    }
}

fn check_suffix_refusal(fixture: Fixture, runtime: &tokio::runtime::Runtime) {
    let cut = SuffixRecovery::reopen(fixture);
    let before = cut.io.recovered_bytes("journal").unwrap();
    let stages = durable_history(&cut.io);
    let result = cut.recover(runtime, false, FaultControl::default());
    assert_eq!(
        result.unwrap_err().to_string(),
        "intent refused: RecoveryJournalBlocked"
    );
    assert_eq!(cut.io.recovered_bytes("journal").unwrap(), before);
    assert_eq!(durable_history(&cut.io), stages);
    assert_no_suffix_send_or_release(&cut.remote);
}

#[test]
fn dirty_suffix_refuses_a_witness_older_than_its_base() {
    let runtime = suffix_runtime();
    let (fixture, _) = landed_dirty(&runtime, LandedSelection::Exact, true, true);
    let new_base = publish_tree_from(&fixture.remote, &runtime, 1);
    fixture.io.mutate_recovered("journal", |journal| {
        let mut records = Vec::new();
        let mut header =
            granary_core::overlay_journal::scan_journal_with(journal, |seq, record| {
                records.push((seq, record.clone()));
            })
            .unwrap()
            .header;
        header.base_root = new_base;
        header.base_seq = 3;
        *journal = header.encode().unwrap();
        for (seq, record) in records {
            journal.extend(
                granary_core::overlay_journal::encode_record(&header, seq, &record).unwrap(),
            );
        }
    });
    check_suffix_refusal(fixture, &runtime);
}

#[test]
fn dirty_suffix_refuses_a_witness_off_its_base_chain() {
    let runtime = suffix_runtime();
    let (fixture, witness) = landed_dirty(&runtime, LandedSelection::Exact, true, true);
    let mut fork = root::decode_root(&fixture.remote.published.lock().unwrap()[&1]).unwrap();
    fork.writer_uuid = [99; 16];
    let fork = super::super::rebase::signed(fork);
    let mut alternate = root::decode_root(&witness).unwrap();
    alternate.parent = Some(GrainId::of(&fork));
    let alternate = super::super::rebase::signed(alternate);
    register_bytes(
        &mut fixture.store.lock().unwrap(),
        &fixture.remote,
        &alternate,
        fixture.remote.time.as_ref(),
    );
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(2, alternate);
    let chain = fixture.remote.published.clone();
    fixture.remote.post_listing_probe.set(Arc::new(move || {
        chain.lock().unwrap().insert(1, fork.clone());
    }));
    published::settle_disk(&fixture.io);
    check_suffix_refusal(fixture, &runtime);
}

#[test]
fn dirty_selection_requires_chain_evidence_and_takeover_consent() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for case in ["missing", "corrupt", "no-consent"] {
        let consent_missing = case == "no-consent";
        let (fixture, _) = landed_dirty(
            &runtime,
            LandedSelection::Descendant,
            !consent_missing,
            true,
        );
        if !consent_missing {
            let mut published = fixture.remote.published.lock().unwrap();
            published.remove(&2).unwrap();
            if case == "corrupt" {
                published.insert(2, b"corrupt root".to_vec());
            }
        }
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        let before = io.recovered_bytes("journal").unwrap();
        let stages = durable_history(&io);
        let result = recovery_outcome(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            None,
            FaultControl::default(),
        );
        let error = result.unwrap_err().to_string();
        let expected = match case {
            "missing" => "ancestor missing",
            "corrupt" => "root ancestry mismatch",
            _ => "IntentSelectedWriterMissing",
        };
        assert!(error.contains(expected), "{case}: {error}");
        assert_eq!(io.recovered_bytes("journal").unwrap(), before, "{case}");
        assert_eq!(durable_history(&io), stages, "{case}");
        assert_eq!(remote.publication_sends.lock().unwrap().len(), 0, "{case}");
        assert!(
            remote
                .authority
                .lock()
                .unwrap()
                .sends
                .iter()
                .all(|bytes| intent::decode_release(bytes).is_err()),
            "{case}"
        );
    }
}

#[test]
fn landed_dirty_journal_switch_and_release_crash_cuts() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (point, phase, seq, released) in [
        ("overlay.replace.rename", "after", 1, false),
        ("overlay.replace.dir_sync", "after", 2, false),
        ("recover.release", "prepared", 2, false),
        ("recover.release", "confirmed", 2, true),
    ] {
        let (fixture, witness) =
            landed_dirty(&runtime, LandedSelection::EqualManifest, true, false);
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        let faults = FaultControl::default();
        faults.arm(point, phase, 1, FaultAction::Crash);
        let result = recovery_outcome(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            None,
            faults.clone(),
        );
        assert_eq!(
            remote.authority.lock().unwrap().row.unwrap().state == ReceiptState::Released,
            released,
            "{point}/{phase}: authority released before the journal was durable"
        );
        assert!(result.is_err(), "{point}/{phase}: {result:?}");
        assert_eq!(faults.fired().len(), 1, "{point}/{phase}: {result:?}");
        assert_eq!(
            remote.publication_sends.lock().unwrap().len(),
            0,
            "{point}/{phase}"
        );
        assert_eq!(durable_journal(&io).header.base_seq, seq, "{point}/{phase}");
        io.crash();
        let result = recovery_outcome(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            None,
            FaultControl::default(),
        );
        assert!(result.is_ok(), "{point}/{phase}: {result:?}");
        let after = durable_journal(&io);
        assert_eq!(
            (after.header.base_root, after.state.next_seq()),
            (GrainId::of(&witness), 1),
            "{point}/{phase}"
        );
        assert_eq!(
            remote.publication_sends.lock().unwrap().len(),
            0,
            "{point}/{phase}"
        );
        let local = start(&scratch, &io, 168);
        assert!(local.recovery_released(), "{point}/{phase}");
    }
}

#[test]
fn dirty_suffix_journal_switch_and_release_crash_cuts() {
    let runtime = suffix_runtime();
    for (point, phase, base_seq, sends) in [
        ("overlay.replace.build", "partial", 1, 0),
        ("overlay.replace.sync", "after", 1, 0),
        ("overlay.replace.rename", "after", 1, 0),
        ("overlay.replace.dir_sync", "after", 2, 0),
        ("sync.commit", "before_replace", 2, 1),
        ("recover.release", "prepared", 3, 1),
        ("recover.release", "confirmed", 3, 1),
    ] {
        let (fixture, witness) = landed_dirty(&runtime, LandedSelection::Exact, true, false);
        let stage = durable_journal(&fixture.io).state.next_stage_id() - 1;
        published::write(&fixture, stage, 1, b"XX");
        published::settle_disk(&fixture.io);
        let cut = SuffixRecovery::reopen(fixture);
        let before = durable_journal(&cut.io);
        let faults = FaultControl::default();
        faults.arm(point, phase, 1, FaultAction::Crash);
        let result = cut.recover(&runtime, false, faults.clone());
        let case = format!("{point}/{phase}");
        assert!(result.is_err(), "{case}: {result:?}");
        assert_eq!(
            faults.fired().len() + faults.sync_fired().len(),
            1,
            "{case}"
        );
        assert_eq!(
            cut.remote.publication_sends.lock().unwrap().len(),
            sends,
            "{case}"
        );
        let crashed = durable_journal(&cut.io);
        assert_eq!(crashed.header.base_seq, base_seq, "{case}");
        assert_eq!(crashed.header.writer, before.header.writer, "{case}");
        assert_eq!(
            crashed.state.next_stage_id(),
            before.state.next_stage_id(),
            "{case}"
        );
        assert!(
            crashed.state.highest_generation() >= before.state.highest_generation(),
            "{case}"
        );
        if point == "overlay.replace.build" || point == "overlay.replace.sync" {
            // A live temp name may reach disk even without our directory sync.
            let next = cut
                .io
                .tree()
                .into_keys()
                .find(|path| path.ends_with("journal.next"))
                .unwrap();
            cut.io
                .clone()
                .sync_directory(next.parent().unwrap())
                .unwrap();
            assert!(cut.io.recovered_bytes("journal.next").is_some(), "{case}");
        }
        cut.io.crash();
        assert!(
            cut.recover(&runtime, false, FaultControl::default())
                .is_ok(),
            "{case}"
        );
        assert!(cut.io.recovered_bytes("journal.next").is_none(), "{case}");
        let (landed, doc, objects) = cut.landed(3, GrainId::of(&witness));
        assert_eq!(cut_file(&objects, &landed, "local"), b"sXXled", "{case}");
        let mut store = start(&cut.scratch, &cut.io, 168);
        assert!(store.recovery_released(), "{case}");
        let clean = durable_journal(&cut.io);
        assert_eq!(clean.header.base_root, GrainId::of(&landed), "{case}");
        assert!(
            clean.state.highest_generation() >= before.state.highest_generation(),
            "{case}"
        );
        let entries = crate::writable_store::capture::overlay_base_entries(
            &objects,
            doc.manifest_root,
            &|_, _| 0,
            &mut |_, _| Ok(()),
            &|| CoordinationError::Refused("SyncBase"),
        )
        .unwrap();
        store
            .open_released_overlay_local(clean.header, entries, cut.io.clone())
            .unwrap();
        assert!(store.finish_publication_proved().unwrap(), "{case}");
        drop(store);
        cut.io.crash();
        assert_eq!(
            cut.recover(&runtime, false, FaultControl::default())
                .unwrap(),
            crate::RecoveryOutcome::NothingOwed,
            "{case}"
        );
        assert_eq!(
            cut.remote.publication_sends.lock().unwrap().as_slice(),
            std::slice::from_ref(&landed),
            "{case}"
        );
    }
}

type DurableHistory = (
    std::collections::BTreeSet<std::path::PathBuf>,
    Vec<(std::path::PathBuf, u64, (Vec<u8>, Vec<u8>))>,
);

fn durable_history(io: &SimIo) -> DurableHistory {
    let model = io.0.lock().unwrap();
    let directories = model
        .durable_directories
        .iter()
        .filter(|path| path.components().any(|part| part.as_os_str() == "overlay"))
        .cloned()
        .collect();
    let files = model
        .durable_names
        .iter()
        .filter(|(path, _)| {
            path.parent()
                .is_some_and(|parent| parent.ends_with("staging"))
        })
        .map(|(path, id)| (path.clone(), *id, model.files[id].clone()))
        .collect();
    (directories, files)
}

fn restore_history(io: &SimIo, history: &DurableHistory, dirty: bool) -> u64 {
    let header =
        granary_core::overlay_journal::scan_journal(&io.recovered_bytes("journal").unwrap())
            .unwrap()
            .header;
    let stage = header.next_stage_id.checked_sub(1).unwrap();
    let grains =
        granary_core::manifest::FileGrains::Inline(vec![granary_core::manifest::GrainRef {
            id: GrainId::of(b"sealed"),
            unpacked_len: 6,
        }]);
    let base_content =
        GrainId::of(&granary_core::manifest::node::file_payload(6, &grains).unwrap());
    let mut model = io.0.lock().unwrap();
    model.directories.extend(history.0.iter().cloned());
    model.durable_directories.extend(history.0.iter().cloned());
    for (path, id, bytes) in &history.1 {
        let path = path.with_file_name(format!("{stage:016x}"));
        let mut bytes = bytes.clone();
        for image in [&mut bytes.0, &mut bytes.1] {
            let mut stage_header =
                granary_core::overlay_journal::StagingHeader::decode(&image[..160]).unwrap();
            stage_header.stage_id = stage;
            image[..160].copy_from_slice(&stage_header.encode().unwrap());
        }
        model.names.insert(path.clone(), *id);
        model.durable_names.insert(path, *id);
        model.files.insert(*id, bytes);
    }
    drop(model);
    io.mutate_recovered("journal", |bytes| {
        let mut records = vec![
            Record::StageBind {
                at: at("local"),
                cause: granary_core::overlay_journal::BindCause::Rebind,
                stage_id: stage,
                staged_size: 6,
                base_content,
            },
            Record::Truncate {
                stage_id: stage,
                new_size: 6,
            },
        ];
        if dirty {
            records.push(Record::WriteExtent {
                stage_id: stage,
                offset: 0,
                length: 6,
                check: granary_core::overlay_journal::extent_check(stage, 0, b"sealed"),
            });
        }
        *bytes = granary_core::overlay_journal::encode_journal(&header, &records).unwrap();
    });
    stage
}

/// Archive provenance cannot authorize or exclude recovery of the actual journal.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one paired table keeps durable premises, actions and overall outcomes together"
)]
fn settled_and_plain_dirty_journals_finish_without_archive_provenance() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for case in [
        "plain",
        "no-write",
        "never-landed",
        "archive-fenced",
        "archive-unfenced",
        "unsubmitted",
        "landed",
        "variant",
    ] {
        let (scratch, io, remote, writer, expected, sends) = if matches!(case, "landed" | "variant")
        {
            let cut = landing_cut(&runtime, false, Some(b"suffix"));
            if case == "variant" {
                let bytes = super::archived::published(&cut.record, true, false);
                cut.remote
                    .published
                    .lock()
                    .unwrap()
                    .insert(cut.record.candidates[0].seq, bytes);
            }
            (
                cut.scratch,
                cut.io,
                cut.remote,
                cut.writer,
                b"suffix".as_slice(),
                9,
            )
        } else {
            let fixture = if case == "plain" {
                let fixture = runtime.block_on(Fixture::new());
                fixture.create("local", b"sealed");
                runtime.block_on(authenticate_registration(&fixture));
                published::settle_disk(&fixture.io);
                fixture
            } else if case == "unsubmitted" {
                runtime.block_on(cut_at("boundary_recorded", true))
            } else if case == "archive-unfenced" {
                runtime.block_on(cut_at("before_submit", false))
            } else {
                let plan = if case == "never-landed" {
                    PublishPlan::Timeout
                } else {
                    PublishPlan::RateLimited
                };
                exhausted_boundary(&runtime, plan, plan)
            };
            if case == "never-landed" {
                let record = budget::saved(&fixture);
                let bytes = runtime.block_on(super::super::selected::one_file(
                    &fixture.remote,
                    b"remote",
                    b"foreign",
                    [99; 16],
                ));
                fixture
                    .remote
                    .published
                    .lock()
                    .unwrap()
                    .insert(record.candidates[0].seq, bytes);
            }
            let prior = fixture.remote.publication_sends.lock().unwrap().len();
            let (scratch, io, remote, mut local) = fixture.reload_carrier();
            if case.starts_with("archive-") {
                let record = local
                    .publication_transaction(|j| {
                        j.load(&config(&scratch.0).scope, &config(&scratch.0).volume)
                    })
                    .unwrap()
                    .unwrap();
                abandon_boundary(&mut local, &record);
            }
            let writer = local.writer_uuid();
            let before = super::archived::evidence(&io);
            let early = local.check_recovery_owner().unwrap_err().to_string();
            assert_eq!(
                (early, super::archived::evidence(&io) == before),
                (
                    "intent refused: IntentFreshInstanceRequired".to_owned(),
                    true
                ),
                "case={case}"
            );
            drop(local);
            (scratch, io, remote, writer, b"sealed".as_slice(), prior + 1)
        };
        let events = super::super::selected::Events::default();
        let _guard = events.guard();
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        );
        if case == "archive-unfenced" {
            let observed = events.recover();
            assert!(
                observed
                    .iter()
                    .any(|event| event == "fence_settled how=released"),
                "a proved non-landing archive is not a conflict strip: {observed:?}"
            );
            assert!(
                !observed
                    .iter()
                    .any(|event| event == "fence_settled how=stripped")
            );
        }
        let mut reopened = start(&scratch, &io, 151);
        let area = crate::overlay_store::area_path(
            &scratch.0,
            &config(&scratch.0).scope,
            &config(&scratch.0).volume,
        )
        .unwrap();
        let (header, clean) = crate::overlay_store::journal_condition(&mut io.clone(), &area)
            .unwrap()
            .unwrap();
        let root = remote
            .published
            .lock()
            .unwrap()
            .last_key_value()
            .unwrap()
            .1
            .clone();
        let doc = granary_core::root::decode_root(&root).unwrap();
        let objects = remote.objects.read_objects(doc.binmap_index).unwrap();
        assert_eq!(
            (
                result.as_ref().map_err(ToString::to_string).err(),
                if result.is_ok() {
                    cut_file(&objects, &root, "local")
                } else {
                    Vec::new()
                },
                header.base_root == GrainId::of(&root),
                clean,
                reopened.snapshot().phase,
                reopened.recovery_rule().unwrap(),
                events
                    .recover()
                    .iter()
                    .any(|event| event.starts_with("journal_finished")),
                remote.publication_sends.lock().unwrap().len()
            ),
            (
                None,
                expected.to_vec(),
                true,
                true,
                granary_core::overlay_ownership::Phase::Released,
                RecoveryRule::Nothing,
                true,
                sends
            ),
            "case={case}, cases={}, result={result:?}, events={:?}",
            cases + 1,
            events.recover()
        );
        cases += 1;
    }
    assert_eq!(cases, 8);
}

#[test]
fn in_flight_nonconflicting_boundary_refuses_unresolved_without_resend() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = runtime.block_on(Fixture::new());
    fixture.create("local", b"sealed");
    runtime.block_on(authenticate_registration(&fixture));
    let lane = runtime
        .block_on(
            fixture
                .engine
                .construct_commit(SyncOptions::default(), &mut Entropy(70)),
        )
        .unwrap();
    persist_content(&fixture);
    mark_boundary_attempt(&fixture, &lane);
    let record = budget::saved(&fixture);
    let head = fixture
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    assert!(granary_core::root::decode_root(&head).unwrap().seq < record.candidates[0].seq);
    super::conflict::check_unresolved(&runtime, fixture);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the pair checks lane identity at dispatch and durable bytes, completion and release together"
)]
fn conflict_free_never_landed_and_never_sent_finish_with_distinct_settlement() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for unanswered in [true, false] {
        let fixture = runtime.block_on(Fixture::new());
        fixture.create("local", b"sealed");
        runtime.block_on(authenticate_registration(&fixture));
        let lane = runtime
            .block_on(
                fixture
                    .engine
                    .construct_commit(SyncOptions::default(), &mut Entropy(70)),
            )
            .unwrap();
        published::settle_disk(&fixture.io);
        runtime.block_on(super::super::rebase::foreign_head(&fixture, "remote"));
        persist_content(&fixture);
        if unanswered {
            mark_boundary_attempt(&fixture, &lane);
        }
        let record = budget::saved(&fixture);
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        let events = super::super::selected::Events::default();
        let _guard = events.guard();
        let sends = remote.publication_sends.lock().unwrap().len();
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        );
        assert!(
            result.is_ok(),
            "unanswered={unanswered}: {result:?}: {:?}",
            events.recover()
        );
        assert_eq!(remote.publication_sends.lock().unwrap().len(), sends + 1);
        if unanswered {
            assert!(
                !remote.publication_sends.lock().unwrap()[sends..]
                    .iter()
                    .any(|root| record
                        .candidates
                        .iter()
                        .any(|candidate| candidate.root == *root))
            );
        }
        let mut reopened = start(&scratch, &io, 160);
        let completed = reopened
            .publication_transaction(|j| j.load(&record.scope, &record.volume))
            .unwrap()
            .unwrap();
        assert!(completed.is_complete());
        assert_eq!(
            completed.publication_id == record.publication_id,
            !unanswered,
            "never-sent first dispatch keeps the lane; proved non-landing publishes the rebuilt work"
        );
        assert_eq!(
            reopened
                .publication_transaction(|j| j.archived(
                    &record.scope.digest().unwrap(),
                    &record.volume,
                    record.publication_id
                ))
                .unwrap(),
            unanswered
        );
        let root = remote
            .published
            .lock()
            .unwrap()
            .last_key_value()
            .unwrap()
            .1
            .clone();
        let doc = granary_core::root::decode_root(&root).unwrap();
        let objects = remote.objects.read_objects(doc.binmap_index).unwrap();
        assert_eq!(cut_file(&objects, &root, "local"), b"sealed");
        let area =
            crate::overlay_store::area_path(&scratch.0, &record.scope, &record.volume).unwrap();
        let (header, clean) = crate::overlay_store::journal_condition(&mut io.clone(), &area)
            .unwrap()
            .unwrap();
        let observed = events.recover();
        assert_eq!(
            (
                header.base_root,
                clean,
                reopened.snapshot().phase,
                reopened.recovery_rule().unwrap(),
                observed.iter().any(|e| e.starts_with("journal_finished"))
            ),
            (
                GrainId::of(&root),
                true,
                granary_core::overlay_ownership::Phase::Released,
                RecoveryRule::Nothing,
                true
            )
        );
        assert!(
            !observed.iter().any(|e| e.starts_with("conflict")
                || e.starts_with("resent")
                || e == "fence_settled how=stripped"),
            "{observed:?}"
        );
    }
}

#[test]
fn resumed_nonboundary_publication_continues_into_the_dirty_journal_finish() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = exhausted_boundary(&runtime, PublishPlan::Timeout, PublishPlan::Timeout);
    let record = budget::saved(&fixture);
    let base_seq = granary_core::root::decode_root(&record.frozen.initial_root)
        .unwrap()
        .seq;
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(base_seq, record.frozen.initial_root.clone());
    fixture.io.mutate_recovered("journal", |bytes| {
        let mut header = granary_core::overlay_journal::scan_journal(bytes)
            .unwrap()
            .header;
        header.base_root = GrainId::of(&record.frozen.initial_root);
        header.base_seq = base_seq;
        *bytes = granary_core::overlay_journal::encode_journal(
            &header,
            &[Record::SetattrExec {
                at: at("local"),
                exec: true,
            }],
        )
        .unwrap();
    });
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    let mut premise = start(&scratch, &io, 161);
    assert_eq!(
        premise.recovery_rule().unwrap(),
        RecoveryRule::ResumeRecovery
    );
    drop(premise);
    let events = super::super::selected::Events::default();
    let _guard = events.guard();

    let result = boundary_command(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        FaultControl::default(),
    );
    let mut reopened = start(&scratch, &io, 162);
    assert_eq!(result.map_err(|error| error.to_string()), Ok(()));
    assert_eq!(
        (
            reopened.snapshot().phase,
            reopened.recovery_rule().unwrap(),
            events
                .recover()
                .iter()
                .any(|event| event.starts_with("journal_finished")),
        ),
        (
            granary_core::overlay_ownership::Phase::Released,
            RecoveryRule::Nothing,
            true,
        )
    );
}

/// A durable release is reused only when replay proves the restored history
/// already represented by its published root.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one paired row keeps the released receipt, semantic replay, refusal and byte preservation together"
)]
fn released_carrier_reuses_its_durable_receipt_only_for_clean_history() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    let mut rows = Vec::new();
    for semantically_dirty in [false, true] {
        let fixture = runtime.block_on(Fixture::new());
        fixture.create("local", b"sealed");
        runtime.block_on(authenticate_registration(&fixture));
        published::settle_disk(&fixture.io);
        let history = durable_history(&fixture.io);
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        )
        .unwrap();
        let stage = restore_history(&io, &history, semantically_dirty);
        if semantically_dirty {
            forge_live_stage(&io, stage);
        }
        io.crash();
        let premise = start(&scratch, &io, 149);
        let area = crate::overlay_store::area_path(
            &scratch.0,
            &config(&scratch.0).scope,
            &config(&scratch.0).volume,
        )
        .unwrap();
        let header = crate::overlay_store::journal_condition(&mut io.clone(), &area)
            .unwrap()
            .unwrap()
            .0;
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
                premise.snapshot().phase,
                header.base_root,
                header.base_seq,
                premise.snapshot().root.is_empty(),
            ),
            (
                granary_core::overlay_ownership::Phase::Released,
                GrainId::of(&published),
                2,
                true,
            ),
            "semantically_dirty={semantically_dirty}: released current-base premise"
        );
        drop(premise);
        let before = super::archived::evidence(&io);
        let sends = remote.recovery_sends.load(Ordering::Relaxed);
        let events = super::super::selected::Events::default();
        let _guard = events.guard();
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        );
        let observed = events.recover();
        let mut reopened = start(&scratch, &io, 150);
        let after = super::archived::evidence(&io);
        rows.push((
            semantically_dirty,
            (
                result.map_err(|error| error.to_string()),
                remote.recovery_sends.load(Ordering::Relaxed) - sends,
                reopened.snapshot().phase,
                reopened.recovery_rule().unwrap(),
                observed
                    .iter()
                    .any(|event| event.starts_with("journal_finished")),
                observed
                    .iter()
                    .any(|event| event == "journal_blocked reason=publication"),
                !semantically_dirty || after == before,
            ),
            observed,
        ));
        cases += 1;
    }
    assert_eq!(
        (rows, cases),
        (
            vec![
                (
                    false,
                    (
                        Ok(()),
                        0,
                        granary_core::overlay_ownership::Phase::Released,
                        RecoveryRule::Nothing,
                        true,
                        false,
                        true,
                    ),
                    vec!["journal_finished base_seq=2".to_owned()],
                ),
                (
                    true,
                    (
                        Err("intent refused: RecoveryJournalBlocked".to_owned()),
                        0,
                        granary_core::overlay_ownership::Phase::Released,
                        RecoveryRule::DirtyJournal,
                        false,
                        true,
                        true,
                    ),
                    vec!["journal_blocked reason=publication".to_owned()],
                ),
            ],
            2
        ),
        "(semantically dirty, outcome, sends, phase, rule, events, bytes), cases"
    );
}

/// A successful action cannot hide a rejected residual commit in the same run.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one paired table keeps durable premises, actions and overall outcomes together"
)]
fn completed_settlement_and_install_do_not_hide_unfinished_remainder() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for installed in [false, true] {
        let (scratch, io, remote, writer) = if installed {
            let cut = landing_cut(&runtime, false, Some(b"suffix"));
            (cut.scratch, cut.io, cut.remote, cut.writer)
        } else {
            let fixture =
                exhausted_boundary(&runtime, PublishPlan::RateLimited, PublishPlan::RateLimited);
            let (scratch, io, remote, local) = fixture.reload_carrier();
            let writer = local.writer_uuid();
            drop(local);
            (scratch, io, remote, writer)
        };
        remote
            .publication_plan
            .lock()
            .unwrap()
            .push_back(PublishPlan::Reject);
        let events = super::super::selected::Events::default();
        let _guard = events.guard();
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        );
        let local = start(&scratch, &io, 152);
        let observed = events.recover();
        let retained = super::archived::evidence(&io)
            .into_iter()
            .filter(|(path, _)| path.parent().is_some_and(|p| p.ends_with("staging")))
            .map(|(_, (_, durable))| durable.get(160..).unwrap_or_default().to_vec())
            .collect::<Vec<_>>();
        let expected = if installed {
            b"suffix".as_slice()
        } else {
            b"sealed".as_slice()
        };
        assert_eq!(
            (
                result.is_err(),
                result
                    .as_ref()
                    .err()
                    .is_some_and(|e| !e.to_string().contains("RecoveryConflict")),
                observed.iter().any(|e| e
                    == if installed {
                        "fence_settled how=landed"
                    } else {
                        "fence_settled how=released"
                    }),
                observed.iter().any(|e| e.starts_with("journal_blocked")),
                observed.iter().any(|e| e.starts_with("journal_finished")),
                local.snapshot().phase == granary_core::overlay_ownership::Phase::Released,
                retained
            ),
            (
                true,
                true,
                true,
                true,
                false,
                false,
                vec![expected.to_vec()]
            ),
            "installed={installed}, cases={}, {result:?}, {observed:?}",
            cases + 1
        );
        drop(local);
        let restored = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            FaultControl::default(),
        );
        assert!(
            restored.is_ok(),
            "installed={installed}: restored service: {restored:?}"
        );
        cases += 1;
    }
    let mut controls = Vec::new();
    let mut expected_controls = Vec::new();
    for (phase, why) in [
        ("journal", "replay"),
        ("publication", "publication"),
        ("obligations", "obligations"),
        ("engine", "obligations"),
        ("release", "release"),
        ("read", "replay"),
        ("retained", "publication"),
        ("capacity", "limit"),
        ("sequence", "limit"),
    ] {
        let fixture =
            exhausted_boundary(&runtime, PublishPlan::RateLimited, PublishPlan::RateLimited);
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        let faults = FaultControl::default();
        faults.arm(
            "recover.postcondition",
            phase,
            1,
            if phase == "read" {
                FaultAction::Block
            } else {
                FaultAction::Fail
            },
        );
        let peer = if phase == "read" {
            let watch = faults.clone();
            let disk = io.clone();
            Some(std::thread::spawn(move || {
                let _resume = published::ResumeOnDrop(&watch);
                for _ in 0..5000 {
                    if !watch.fired().is_empty() {
                        disk.0.lock().unwrap().fail = Some("read");
                        return;
                    }
                    crate::overlay_test_support::block_for_test(Duration::from_millis(1));
                }
                panic!("final read seam did not fire");
            }))
        } else {
            None
        };
        let events = super::super::selected::Events::default();
        let _guard = events.guard();
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            &runtime,
            writer,
            None,
            faults.clone(),
        );
        if let Some(peer) = peer {
            peer.join().unwrap();
        }
        let observed = events.recover();
        controls.push((
            phase,
            (
                result.is_err(),
                faults.fired().len(),
                observed
                    .iter()
                    .any(|e| e == &format!("journal_blocked reason={why}")),
                observed.iter().any(|e| e.starts_with("journal_finished")),
            ),
        ));
        expected_controls.push((phase, (true, 1, true, false)));
        if phase == "read" {
            assert!(
                result
                    .as_ref()
                    .err()
                    .is_some_and(|e| e.to_string().contains("model injected I/O")),
                "{result:?}"
            );
        }
        cases += 1;
    }
    assert_eq!(
        controls, expected_controls,
        "final postconditions, cases={cases}"
    );
    assert_eq!(cases, 11);
}

/// An unchanged conflicting head repeats its verified collision; an ordinary
/// publication rejection has no collision evidence and keeps its fence name.
#[test]
fn same_head_conflict_refuses_without_release_or_finished_event() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for kind in ["conflict", "disjoint", "generic-fence"] {
        let fixture = exhausted_boundary(&runtime, PublishPlan::Timeout, PublishPlan::Timeout);
        let record = budget::saved(&fixture);
        let bytes = runtime.block_on(super::super::selected::one_file(
            &fixture.remote,
            if kind == "conflict" {
                b"local"
            } else {
                b"remote"
            },
            b"foreign",
            [99; 16],
        ));
        fixture
            .remote
            .published
            .lock()
            .unwrap()
            .insert(record.candidates[0].seq, bytes);
        if kind == "generic-fence" {
            fixture
                .remote
                .publication_plan
                .lock()
                .unwrap()
                .push_back(PublishPlan::Reject);
        }
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
        for attempt in 0..if kind == "conflict" { 2 } else { 1 } {
            let events = super::super::selected::Events::default();
            let _guard = events.guard();
            let result = boundary_command(
                &scratch,
                &io,
                &remote,
                &runtime,
                writer,
                None,
                FaultControl::default(),
            );
            let local = start(&scratch, &io, 153);
            let observed = events.recover();
            let collision = result
                .as_ref()
                .err()
                .is_some_and(|e| e.to_string() == "intent refused: RecoveryConflict");
            let inventory = result
                .as_ref()
                .err()
                .and_then(crate::RecoveryCommandError::conflict_inventory)
                .is_some();
            assert_eq!(
                (
                    result.is_ok(),
                    collision,
                    inventory,
                    observed.iter().any(|e| e == "conflict path=<file>"),
                    observed.iter().any(|e| e.starts_with("journal_finished")),
                    local.snapshot().phase == granary_core::overlay_ownership::Phase::Released
                ),
                (
                    kind == "disjoint",
                    kind == "conflict",
                    false,
                    kind == "conflict",
                    kind == "disjoint",
                    kind == "disjoint"
                ),
                "kind={kind}, attempt={attempt}, cases={}, {result:?}, {observed:?}",
                cases + 1
            );
            if kind == "generic-fence" {
                assert!(
                    matches!(
                        result,
                        Err(crate::RecoveryCommandError::Coordination(
                            CoordinationError::Fenced { .. }
                                | CoordinationError::CommitFenced { .. }
                        ))
                    ),
                    "{result:?}"
                );
            }
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

mod witness;
