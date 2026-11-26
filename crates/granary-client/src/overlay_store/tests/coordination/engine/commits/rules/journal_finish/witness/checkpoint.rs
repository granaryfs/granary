// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A recovered whole-prefix replacement keeps each stage's last acknowledged
//! checkpoint: a `file-synced` after the proved cut is dropped only while no
//! kept receipt or replay rollback of its stage lies between the cut and it.

use super::*;

/// Every `file-synced` of `stage` in the durable journal, as
/// `(content, generation)` in journal order.
fn receipts(io: &SimIo, stage: u64) -> Vec<(GrainId, u64)> {
    let journal = io.recovered_bytes("journal").unwrap();
    let mut out = Vec::new();
    granary_core::overlay_journal::scan_journal_with(&journal, |_, record| {
        if let Record::FileSynced {
            stage_id,
            content,
            generation,
            ..
        } = record
            && *stage_id == stage
        {
            out.push((*content, *generation));
        }
    })
    .unwrap();
    out
}

/// The durable journal's records as `seq:kind`, with the stage a stage
/// record names.
fn frames(io: &SimIo) -> Vec<String> {
    let journal = io.recovered_bytes("journal").unwrap();
    let mut out = Vec::new();
    granary_core::overlay_journal::scan_journal_with(&journal, |seq, record| {
        let text = format!("{record:?}");
        let kind = text.split([' ', '{', '(']).next().unwrap_or("");
        let stage = match record {
            Record::WriteExtent { stage_id, .. }
            | Record::Truncate { stage_id, .. }
            | Record::StageRollback { stage_id, .. }
            | Record::StageBind { stage_id, .. }
            | Record::FileSynced { stage_id, .. } => format!(" {stage_id}"),
            _ => String::new(),
        };
        out.push(format!("{seq}:{kind}{stage}"));
    })
    .unwrap();
    out
}

/// `stage`'s checkpoint after folding the durable journal, as replay folds
/// it: the last `file-synced`, else the last `stage-rollback` anchor, else the
/// bind's base content, as `(content, size)`.
fn checkpoint(io: &SimIo, stage: u64) -> Option<(Option<GrainId>, u64)> {
    let journal = io.recovered_bytes("journal").unwrap();
    let (mut mark, mut rollback, mut bind) = (None, None, None);
    granary_core::overlay_journal::scan_journal_with(&journal, |_, record| match record {
        Record::FileSynced {
            stage_id,
            synced_size,
            content,
            ..
        } if *stage_id == stage => mark = Some((Some(*content), *synced_size)),
        Record::StageRollback {
            stage_id, anchor, ..
        } if *stage_id == stage => {
            rollback = Some(anchor.map_or((None, 0), |a| (Some(a.content), a.size)));
        }
        Record::StageBind {
            stage_id,
            staged_size,
            base_content,
            ..
        } if *stage_id == stage => bind = Some((Some(*base_content), *staged_size)),
        _ => {}
    })
    .unwrap();
    mark.or(rollback).or(bind)
}

/// Publish the authority's registered root exactly on its parent through the
/// exact-root recovery publisher, as a disk-loss takeover does, and return it.
fn publish_witness(fixture: &Fixture, runtime: &tokio::runtime::Runtime) -> GrainId {
    let prepared = fixture.remote.authority.lock().unwrap().root.clone();
    runtime.block_on(recover_without_local_store(
        &fixture.remote,
        prepared.clone(),
    ));
    let seq = root::decode_root(&prepared).unwrap().seq;
    assert_eq!(
        fixture.remote.published.lock().unwrap().get(&seq),
        Some(&prepared),
        "premise: the registered root is published exactly"
    );
    // The suffix rows count only the recovery's own sends.
    fixture.remote.publication_sends.lock().unwrap().clear();
    GrainId::of(&prepared)
}

/// Dirty `f` past its acknowledged C1, crash the recovery right after it
/// installs the replacement, and return the recovery with the witness.
fn recover_dirty(
    fixture: Fixture,
    runtime: &tokio::runtime::Runtime,
    f: u64,
    witness: GrainId,
) -> SuffixRecovery {
    published::write(&fixture, f, 0, b"CCCC");
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    let cut = SuffixRecovery::reopen(fixture);
    crash_after_witness_install(&cut, runtime);
    let journal = cut.io.recovered_bytes("journal").unwrap();
    let scan = granary_core::overlay_journal::scan_journal(&journal).unwrap();
    assert_eq!(
        scan.header.base_root, witness,
        "premise: the witness installed"
    );
    cut
}

/// Lose `f`'s unacknowledged C3 bytes, finish the recovery, and return the
/// landed bytes of `f`: replay rolls `f` back to its checkpoint first.
fn land_after_losing_c3(
    cut: &SuffixRecovery,
    runtime: &tokio::runtime::Runtime,
    f: u64,
    witness: GrainId,
) -> Vec<u8> {
    cut.io.mutate_recovered(&format!("{f:016x}"), |body| {
        body[granary_core::overlay_journal::STAGING_HEADER_LEN..][..4].copy_from_slice(b"ZZZZ");
    });
    cut.io.crash();
    // The witness is published at seq 2; the finished journal lands above it.
    let seq = 3;
    assert_eq!(
        cut.recover(runtime, false, FaultControl::default())
            .map_err(|e| e.to_string()),
        Ok(crate::RecoveryOutcome::JournalFinished { base_seq: seq })
    );
    let (bytes, _, objects) = cut.landed(seq, witness);
    assert_eq!(cut_file(&objects, &bytes, "other"), b"unsynced");
    cut_file(&objects, &bytes, "f")
}

/// `f` holds C1 at the cut. Each detour rewrites it and fsyncs it; an
/// unsynced create after the first, or after the cut when there is none,
/// moves the tree off the witness. Then `f` is rewritten to C1 and fsynced:
/// that root is the published witness.
fn detours_then_c1(
    runtime: &tokio::runtime::Runtime,
    detours: &[&[u8]],
) -> (Fixture, u64, GrainId, (GrainId, u64)) {
    let fixture = runtime.block_on(Fixture::new());
    let f = fixture.create("f", b"AAAA");
    for (index, bytes) in detours.iter().enumerate() {
        published::write(&fixture, f, 0, bytes);
        sync_file(&fixture, runtime, f);
        if index == 0 {
            fixture.create("other", b"unsynced");
        }
    }
    if detours.is_empty() {
        fixture.create("other", b"unsynced");
    }
    published::write(&fixture, f, 0, b"AAAA");
    sync_file(&fixture, runtime, f);
    let witness = publish_witness(&fixture, runtime);
    let all = receipts(&fixture.io, f);
    let acknowledged = *all.last().unwrap();
    assert_eq!(all.len(), detours.len() + 1);
    assert!(all[..detours.len()].iter().all(|r| r.0 != acknowledged.0));
    (fixture, f, witness, acknowledged)
}

/// A receipt kept after the cut is followed by the matching C1 receipt: the
/// C1 receipt stays the last checkpoint, and a later loss of unacknowledged
/// bytes restores C1.
#[test]
fn recovered_suffix_keeps_a_matching_receipt_after_a_kept_one() {
    let runtime = suffix_runtime();
    let (fixture, f, witness, acknowledged) = detours_then_c1(&runtime, &[b"BBBB"]);
    let cut = recover_dirty(fixture, &runtime, f, witness);
    assert_eq!(
        receipts(&cut.io, f).last(),
        Some(&acknowledged),
        "the image's last checkpoint of f: {:?}",
        frames(&cut.io)
    );
    assert_eq!(land_after_losing_c3(&cut, &runtime, f, witness), b"AAAA");
    assert_settled(&cut, &runtime);
}

/// Two kept receipts before the matching one: the first closes the stage.
#[test]
fn recovered_suffix_keeps_a_matching_receipt_after_two_kept_ones() {
    let runtime = suffix_runtime();
    let (fixture, f, witness, acknowledged) = detours_then_c1(&runtime, &[b"BBBB", b"DDDD"]);
    let cut = recover_dirty(fixture, &runtime, f, witness);
    assert_eq!(
        receipts(&cut.io, f).last(),
        Some(&acknowledged),
        "the image's last checkpoint of f: {:?}",
        frames(&cut.io)
    );
    assert_eq!(land_after_losing_c3(&cut, &runtime, f, witness), b"AAAA");
    assert_settled(&cut, &runtime);
}

/// The exact image of the kept-then-matching shape: the prelude bind, the
/// kept C2 receipt with its registration, and the C1 receipt after the
/// rewrite that it acknowledges.
#[test]
fn recovered_suffix_frames_for_a_kept_then_matching_receipt() {
    let runtime = suffix_runtime();
    let (fixture, f, witness, _) = detours_then_c1(&runtime, &[b"BBBB"]);
    let cut = recover_dirty(fixture, &runtime, f, witness);
    assert_eq!(
        frames(&cut.io),
        [
            "1:StageBind 1",
            "2:WriteExtent 1",
            "3:FileSynced 1",
            "4:IntentRegistered",
            "5:Create",
            "6:WriteExtent 2",
            "7:WriteExtent 1",
            "8:FileSynced 1",
            "9:IntentRegistered",
            "10:WriteExtent 1",
        ]
    );
}

/// The C2 receipt's capture precedes the cut but its record follows it, so
/// the C1 receipt after it must stay.
#[test]
fn recovered_suffix_keeps_a_matching_receipt_after_a_late_earlier_capture() {
    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    let f = fixture.create("f", b"BBBB");
    runtime.block_on(async {
        fixture.remote.hold_first.store(true, Ordering::Relaxed);
        let waiter = fixture
            .engine
            .sync(SyncTarget::Stage(f), SyncOptions::default());
        fixture.remote.entered.notified().await;
        published::write(&fixture, f, 0, b"AAAA");
        fixture.create("other", b"unsynced");
        fixture.remote.release.notify_one();
        waiter.wait().await.unwrap();
    });
    sync_file(&fixture, &runtime, f);
    let witness = publish_witness(&fixture, &runtime);
    let all = receipts(&fixture.io, f);
    assert_eq!(all.len(), 2);
    assert_ne!(all[0].0, all[1].0);
    let cut = recover_dirty(fixture, &runtime, f, witness);
    assert_eq!(
        receipts(&cut.io, f).last(),
        Some(&all[1]),
        "the image's last checkpoint of f: {:?}",
        frames(&cut.io)
    );
    assert_eq!(land_after_losing_c3(&cut, &runtime, f, witness), b"AAAA");
}

/// `f` is fsynced at X, then holds C1 at the cut. Replay rolls the lost C1
/// bytes back to X after the cut; C1 is rewritten and fsynced (the witness).
/// The matching receipt after the rollback stays, or the image's checkpoint
/// would be the rollback's X.
#[test]
fn recovered_suffix_keeps_a_matching_receipt_after_a_rollback() {
    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    let f = fixture.create("f", b"XXXX");
    sync_file(&fixture, &runtime, f);
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    let stage = format!("{f:016x}");
    let synced = fixture.io.recovered_bytes(&stage).unwrap();
    published::write(&fixture, f, 0, b"AAAA");
    fixture.create("other", b"unsynced");
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    fixture
        .io
        .mutate_recovered(&stage, |body| body.clone_from(&synced));
    let fixture = runtime.block_on(fixture.try_restart_over(vec![])).unwrap();
    assert_eq!(
        (
            published::local_file(&fixture, "f"),
            frames(&fixture.io)
                .iter()
                .filter(|frame| frame.contains(":StageRollback "))
                .count()
        ),
        (Some(b"XXXX".to_vec()), 1),
        "premise: replay rolled the lost C1 bytes back to X"
    );
    published::write(&fixture, f, 0, b"AAAA");
    sync_file(&fixture, &runtime, f);
    let witness = publish_witness(&fixture, &runtime);
    let acknowledged = *receipts(&fixture.io, f).last().unwrap();
    let cut = recover_dirty(fixture, &runtime, f, witness);
    assert_eq!(
        receipts(&cut.io, f).last(),
        Some(&acknowledged),
        "the image's last checkpoint of f: {:?}",
        frames(&cut.io)
    );
    assert_eq!(land_after_losing_c3(&cut, &runtime, f, witness), b"AAAA");
}

/// With no checkpoint record of `f` between the cut and its matching
/// receipt, the image absorbs the receipt into the prelude bind, keeps its
/// registration, and retires `f` after a write away and back.
#[test]
fn recovered_suffix_absorbs_a_matching_receipt_after_the_cut() {
    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    let f = fixture.create("f", b"AAAA");
    fixture.create("other", b"unsynced");
    sync_file(&fixture, &runtime, f);
    let witness = publish_witness(&fixture, &runtime);
    published::write(&fixture, f, 0, b"XXXX");
    published::write(&fixture, f, 0, b"AAAA");
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    let cut = SuffixRecovery::reopen(fixture);
    crash_after_witness_install(&cut, &runtime);
    let (scan, records) = journal_generations(&cut.io);
    assert_eq!(scan.header.base_root, witness);
    assert_eq!(
        (
            receipts(&cut.io, f),
            records.registrations.iter().any(|&(_, r)| r == witness),
            scan.state.stage(f).is_some(),
        ),
        (Vec::new(), true, false),
        "{:?}",
        frames(&cut.io)
    );
}

/// The projected path keeps its own admission: a covered stage written away
/// and back before its own receipt still recovers.
#[test]
fn projected_recovery_keeps_its_receipt_admission() {
    let runtime = suffix_runtime();
    let fixture = runtime.block_on(Fixture::new());
    fixture.create("other", b"unsynced");
    let f = fixture.create("f", b"AAAA");
    published::write(&fixture, f, 0, b"XXXX");
    published::write(&fixture, f, 0, b"AAAA");
    sync_file(&fixture, &runtime, f);
    let witness = publish_witness(&fixture, &runtime);
    let recreated = |io: &SimIo| {
        frames(io)
            .iter()
            .filter(|frame| frame.ends_with(":RecreateFile"))
            .count()
    };
    assert_eq!(recreated(&fixture.io), 0);
    let cut = recover_dirty(fixture, &runtime, f, witness);
    // Only the projected residual writes `recreate-file`; a whole-prefix
    // image copies the source's records, which have none.
    assert_eq!(recreated(&cut.io), 1, "{:?}", frames(&cut.io));
    // The witness is published at seq 2; the finished journal lands above it.
    let seq = 3;
    assert_eq!(
        cut.recover(&runtime, false, FaultControl::default())
            .map_err(|e| e.to_string()),
        Ok(crate::RecoveryOutcome::JournalFinished { base_seq: seq })
    );
    assert_landed_files(
        &cut,
        seq,
        witness,
        &[("f", b"CCCC"), ("other", b"unsynced")],
    );
    assert_settled(&cut, &runtime);
}

/// The matching receipt right after the cut is absorbed although a replay
/// rollback of `f` follows it. Replay anchors the rollback on the stage's
/// checkpoint, that receipt's mark, so the image's rollback baseline and the
/// source's mark name the same content.
#[test]
fn recovered_suffix_absorbs_a_matching_receipt_before_a_rollback() {
    let runtime = suffix_runtime();
    let (fixture, f, witness, acknowledged) = detours_then_c1(&runtime, &[]);
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    let stage = format!("{f:016x}");
    let synced = fixture.io.recovered_bytes(&stage).unwrap();
    published::write(&fixture, f, 0, b"EEEE");
    // Touch f's path, so the image carries f rather than retiring it.
    for exec in [true, false] {
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                t.namespace_record(Record::SetattrExec {
                    at: crate::overlay_store::tests::incremental::loc("f"),
                    exec,
                })
            })
            .unwrap();
    }
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    // The unacknowledged EEEE is lost: recovery's replay rolls f back first.
    fixture
        .io
        .mutate_recovered(&stage, |body| body.clone_from(&synced));
    let cut = SuffixRecovery::reopen(fixture);
    crash_after_witness_install(&cut, &runtime);
    let image = frames(&cut.io);
    assert_eq!(
        (
            receipts(&cut.io, f),
            image
                .iter()
                .filter(|frame| frame.ends_with(&format!(":StageRollback {f}")))
                .count(),
            checkpoint(&cut.io, f),
        ),
        (Vec::new(), 1, Some((Some(acknowledged.0), 4))),
        "{image:?}"
    );
    assert_eq!(
        cut.recover(&runtime, false, FaultControl::default())
            .map_err(|e| e.to_string()),
        Ok(crate::RecoveryOutcome::JournalFinished { base_seq: 3 })
    );
    assert_landed_files(&cut, 3, witness, &[("f", b"AAAA"), ("other", b"unsynced")]);
    assert_settled(&cut, &runtime);
}

/// A carried stage whose only receipt after the cut is absorbed: the image
/// has no mark for it, and its checkpoint is the prelude bind at the cut
/// content, which is the acknowledged content the staging header mirrors.
#[test]
fn recovered_suffix_absorbs_the_receipt_of_a_carried_stage() {
    let runtime = suffix_runtime();
    let (fixture, f, witness, acknowledged) = detours_then_c1(&runtime, &[]);
    let cut = recover_dirty(fixture, &runtime, f, witness);
    let header = cut.io.recovered_bytes(&format!("{f:016x}")).unwrap();
    let header = granary_core::overlay_journal::StagingHeader::decode(
        &header[..granary_core::overlay_journal::STAGING_HEADER_LEN],
    )
    .unwrap();
    let granary_core::overlay_journal::MarkState::Present(mark) = header.mark else {
        panic!("premise: the header mirrors the acknowledged mark: {header:?}");
    };
    assert_eq!(
        (
            receipts(&cut.io, f),
            checkpoint(&cut.io, f),
            (mark.content, mark.synced_size),
        ),
        (
            Vec::new(),
            Some((Some(acknowledged.0), 4)),
            (acknowledged.0, 4)
        ),
        "{:?}",
        frames(&cut.io)
    );
}

/// Run recovery over `fixture` as a mount start does, crash right after the
/// replacement installs, remount, and fsync `f` again: a write lands after
/// that fsync's capture, its staging-header mark write tears in a crash (so
/// the fsync is never acknowledged), and the write never reaches the staging
/// body. Returns what the remount serves for `f` before and after.
fn torn_mark_after_install(fixture: Fixture, f: u64) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let runtime = suffix_runtime();
    published::write(&fixture, f, 0, b"CCCC");
    persist_content(&fixture);
    published::settle_disk(&fixture.io);
    let writer = fixture.store.lock().unwrap().writer_uuid();
    let Fixture {
        _scratch: scratch,
        io,
        store,
        engine,
        remote,
        metrics,
        content,
        ..
    } = fixture;
    drop(engine);
    drop(Arc::into_inner(store).unwrap().into_inner().unwrap());
    io.crash();
    let faults = FaultControl::default();
    faults.arm("overlay.replace.dir_sync", "after", 1, FaultAction::Crash);
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
    assert!(result.is_err(), "{result:?}");
    assert_eq!(faults.fired().len() + faults.sync_fired().len(), 1);
    let fixture = runtime
        .block_on(remount(scratch, io, remote, metrics, content))
        .unwrap();
    let served = published::local_file(&fixture, "f");
    let faults = fixture.store.lock().unwrap().fault_control();
    runtime.block_on(async {
        fixture.remote.hold_first.store(true, Ordering::Relaxed);
        let waiter = fixture
            .engine
            .sync(SyncTarget::Stage(f), SyncOptions::default());
        fixture.remote.entered.notified().await;
        published::write(&fixture, f, 0, b"EEEE");
        persist_content(&fixture);
        published::settle_disk(&fixture.io);
        faults.arm("overlay.mark.write", "partial", 1, FaultAction::Crash);
        fixture.remote.release.notify_one();
        assert!(waiter.wait().await.is_err());
    });
    assert_eq!(faults.fired().len() + faults.sync_fired().len(), 1);
    // The torn half-block reached the disk; the unsynced EEEE did not.
    published::settle_disk(&fixture.io);
    let stage = format!("{f:016x}");
    fixture.io.mutate_recovered(&stage, |body| {
        body[granary_core::overlay_journal::STAGING_HEADER_LEN..][..4].copy_from_slice(b"CCCC");
    });
    let header = fixture.io.recovered_bytes(&stage).unwrap();
    assert_eq!(
        granary_core::overlay_journal::StagingHeader::decode(
            &header[..granary_core::overlay_journal::STAGING_HEADER_LEN]
        )
        .map(|header| header.mark),
        Ok(granary_core::overlay_journal::MarkState::Damaged),
        "premise: the mark write tore"
    );
    let Fixture {
        _scratch: scratch,
        io,
        store,
        engine,
        remote,
        metrics,
        content,
        ..
    } = fixture;
    drop(engine);
    drop(Arc::into_inner(store).unwrap().into_inner().unwrap());
    let after = runtime
        .block_on(remount(scratch, io, remote, metrics, content))
        .unwrap();
    (served, published::local_file(&after, "f"))
}

/// Open a mount over the authority's last published root on this disk, as
/// `Fixture::try_restart_at` does, from a fixture's parts.
async fn remount(
    scratch: Scratch,
    io: SimIo,
    remote: Arc<Remote>,
    metrics: ClientMetrics,
    content: Arc<Content>,
) -> Result<Fixture, CoordinationError> {
    let (base_seq, base_bytes) = {
        let published = remote.published.lock().unwrap();
        let (seq, bytes) = published.last_key_value().unwrap();
        (*seq, bytes.clone())
    };
    let doc = granary_core::root::decode_root(&base_bytes).unwrap();
    let entries = crate::writable_store::capture::overlay_base_entries(
        content.as_ref(),
        doc.manifest_root,
        &|_, _| 0,
        &mut |_, _| Ok(()),
        &|| CoordinationError::Refused("test reopen"),
    )
    .unwrap();
    let base = GrainId::of(&base_bytes);
    io.crash();
    let mut local = start(&scratch, &io, 140);
    local.set_metrics(metrics.clone());
    assert!(local.landed_replay()?.is_none());
    let succession_at = 2_000_002;
    let transfer = local.prepare_succession(&Tick(succession_at))?;
    local.dispatch(&transfer, &Tick(succession_at))?;
    let answer = remote.authority.lock().unwrap().send(&transfer);
    local.complete(
        &transfer,
        Ok(&answer),
        &Tick(succession_at + 1),
        &mut SeededRng::new(1),
        0,
        None,
    )?;
    let mut h = header();
    h.writer = local.writer_uuid();
    h.base_root = base;
    h.base_seq = base_seq;
    local.open_overlay(h, entries, &mut ContentReader(content.clone()), io.clone())?;
    for capture in local.reopened_captures()? {
        local.fail_reopened_capture(&capture)?;
    }
    register(&mut local, &mut remote.authority.lock().unwrap(), 2);
    let store = Arc::new(Mutex::new(local));
    let trusted =
        TrustedKeys::new([*SigningKey::from_seed(&[39; 32]).unwrap().public_key()]).unwrap();
    let engine = SyncEngine::with_runtime(
        store.clone(),
        remote.clone(),
        content.clone(),
        remote.time.clone(),
        remote.time.clone(),
        SigningKey::from_seed(&[39; 32]).unwrap(),
        trusted,
        base_bytes,
        metrics.clone(),
        Arc::new(TrackedRuntime(content.clone())),
    )
    .await?;
    Ok(Fixture {
        _scratch: scratch,
        io,
        store,
        engine,
        remote,
        metrics,
        base,
        content,
    })
}

/// With the kept C2 receipt before the matching C1 one, a torn mark write
/// after the remount leaves replay only the journal's checkpoint to roll `f`
/// back to: it must be the acknowledged C1, not the older C2.
#[test]
fn torn_mark_after_recovery_rolls_back_to_the_acknowledged_fsync() {
    let runtime = suffix_runtime();
    let (fixture, f, _, _) = detours_then_c1(&runtime, &[b"BBBB"]);
    assert_eq!(
        torn_mark_after_install(fixture, f),
        (Some(b"CCCC".to_vec()), Some(b"AAAA".to_vec()))
    );
}

/// The same fault with no detour: the absorbed receipt's stage rolls back
/// to the prelude bind, the acknowledged C1.
#[test]
fn torn_mark_after_recovery_without_a_kept_receipt() {
    let runtime = suffix_runtime();
    let (fixture, f, _, _) = detours_then_c1(&runtime, &[]);
    assert_eq!(
        torn_mark_after_install(fixture, f),
        (Some(b"CCCC".to_vec()), Some(b"AAAA".to_vec()))
    );
}
