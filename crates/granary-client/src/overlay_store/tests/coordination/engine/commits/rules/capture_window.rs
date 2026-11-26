// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A write between a stage fsync's capture and its journal record can be in a
//! whole-tree boundary without being in the synced mark.

use super::*;
use granary_core::overlay_journal::{JournalEnd, extent_check, scan_journal_with};

#[derive(Clone, Copy, Debug)]
enum Boundary {
    None,
    Constructed,
    LandedOwed,
    Installed,
}

#[derive(Debug, PartialEq, Eq)]
enum Reopen {
    Opened(Option<String>, usize),
    Refused(String),
}

/// Join the captured extent to the numbered root and file read from the
/// modeled publication peer. The identities are the journal's retained
/// publication id and the submission's modeled request operation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn captured_write_extent_reaches_its_numbered_publication() {
    const BEFORE: &[u8] = b"first write";
    const AFTER: &[u8] = b"later write";
    let f = Fixture::new().await;
    let stage = f.create("write", b"");
    published::write(&f, stage, 0, BEFORE);

    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "captured", 1, FaultAction::Block);
    let resume = published::ResumeOnDrop(&faults);
    let mut secure = Entropy(70);
    let mut constructing = Box::pin(
        f.engine
            .construct_commit(SyncOptions::default(), &mut secure),
    );
    let mut entered = Box::pin(fired(&faults, "sync.commit", "captured"));
    std::future::poll_fn(|cx| {
        assert!(constructing.as_mut().poll(cx).is_pending());
        entered.as_mut().poll(cx)
    })
    .await;
    published::write(&f, stage, 0, AFTER);
    drop(resume);
    let lane = constructing.await.unwrap();

    // Read before driving the commit, which can replace and renumber the journal.
    let journal = f.io.recovered_bytes("journal").unwrap();
    let mut writes = Vec::new();
    let mut boundaries = Vec::new();
    let scan = scan_journal_with(&journal, |seq, record| match *record {
        Record::WriteExtent {
            stage_id,
            offset,
            length,
            check,
        } if stage_id == stage => writes.push((seq, offset, length, check)),
        Record::CommitBoundary {
            candidate,
            through_seq,
            publication_id,
        } => boundaries.push((seq, through_seq, candidate, publication_id)),
        _ => {}
    })
    .unwrap();
    assert_eq!(scan.end, JournalEnd::Clean);
    let &[(before_seq, ..), (after_seq, ..)] = writes.as_slice() else {
        panic!("expected exactly two recorded writes for stage {stage}, got {writes:?}");
    };
    let expected_write = |seq, bytes: &[u8]| {
        (
            seq,
            0,
            u64::try_from(bytes.len()).unwrap(),
            extent_check(stage, 0, bytes),
        )
    };
    assert_eq!(
        writes,
        [
            expected_write(before_seq, BEFORE),
            expected_write(after_seq, AFTER)
        ]
    );
    let &[(boundary_seq, cutoff, candidate, publication_id)] = boundaries.as_slice() else {
        panic!("expected one whole-tree boundary, got {boundaries:?}");
    };
    assert_eq!(boundary_seq, lane.boundary_seq());
    assert!(
        before_seq <= cutoff && cutoff < after_seq && after_seq < boundary_seq,
        "expected the overwrite after capture and before append: {before_seq}, {cutoff}, {after_seq}, {boundary_seq}"
    );

    let retained = rebase::load(&f);
    let operation = retained.current.unwrap().operation;
    assert_ne!(operation, publication_id);
    assert_eq!(publication_id, retained.publication_id);
    assert_eq!(candidate, GrainId::of(&retained.frozen.initial_root));
    let result = budget::drive(&f, &lane, &mut Delay).await;
    assert_eq!(result.handle.publication_id, publication_id);
    let PublicationOutcome::Landed(landed) = result.outcome else {
        panic!(
            "expected the captured commit to land, got {:?}",
            result.outcome
        );
    };
    assert_eq!((landed.seq, landed.id), (2, candidate));
    let published = f.remote.published.lock().unwrap()[&landed.seq].clone();
    assert_eq!(GrainId::of(&published), candidate);
    assert_eq!(published, landed.root);
    assert_eq!(
        f.remote.publication_sends.lock().unwrap().as_slice(),
        std::slice::from_ref(&published)
    );
    assert_eq!(
        f.remote.publication_operations.lock().unwrap().as_slice(),
        &[operation.to_vec()]
    );
    let root = granary_core::root::decode_root(&published).unwrap();
    let remote_objects = f.remote.objects.read_objects(root.binmap_index).unwrap();
    assert_eq!(cut_file(&remote_objects, &published, "write"), BEFORE);
}

async fn sync_and_write(f: &Fixture, stage: u64, offset: u64, held: bool, row: &str) {
    f.remote.hold_first.store(held, Ordering::Relaxed);
    let sync = f
        .engine
        .sync(SyncTarget::Stage(stage), SyncOptions::default());
    if held {
        f.remote.entered.notified().await;
        published::write(f, stage, offset, b"WWWW");
        f.remote.release.notify_one();
    }
    sync.wait()
        .await
        .unwrap_or_else(|error| panic!("{row}: fsync failed: {error}"));
    if !held {
        published::write(f, stage, offset, b"WWWW");
    }

    published::settle_disk(&f.io);
    let journal = f.io.recovered_bytes("journal").unwrap();
    let (mut write, mut mark) = (None, None);
    scan_journal_with(&journal, |seq, record| match *record {
        Record::WriteExtent {
            stage_id,
            offset: at,
            length: 4,
            ..
        } if stage_id == stage && at == offset => write = Some(seq),
        Record::FileSynced {
            stage_id,
            content,
            synced_size,
            ..
        } if stage_id == stage => {
            let bytes = f
                .content
                .read_content(content, 0, usize::try_from(synced_size).unwrap());
            mark = Some((seq, bytes.unwrap()));
        }
        _ => {}
    })
    .unwrap();
    assert!(
        matches!((&write, &mark), (Some(write), Some((synced, bytes)))
            if (write < synced) == held && bytes == b"y-data-1"),
        "{row}: expected the write {} the file-synced for y-data-1, got write {write:?}, mark {mark:?}",
        if held { "before" } else { "after" },
    );
}

/// Land the commit at the authority and stop at its readback seam: the landing
/// is journaled, its refresh and replacement are not.
async fn land_before_refresh(f: &Fixture, lane: &crate::RetainedCommit, row: &str) {
    let published = f.remote.published.lock().unwrap().len();
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "landed_readback", 1, FaultAction::Block);
    let (mut secure, mut delay) = (Entropy(80), Delay);
    let mut driving = Box::pin(f.engine.drive_commit(
        lane,
        &mut secure,
        &mut delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ));
    let mut entered = Box::pin(fired(&faults, "sync.commit", "landed_readback"));
    std::future::poll_fn(|cx| {
        assert!(
            driving.as_mut().poll(cx).is_pending(),
            "{row}: the commit finished before its readback seam"
        );
        entered.as_mut().poll(cx)
    })
    .await;
    drop(driving);
    faults.resume();
    let journal = f.io.recovered_bytes("journal").unwrap();
    let (mut landed, mut refreshed) = (false, false);
    scan_journal_with(&journal, |_, record| match record {
        Record::LandedCommit { .. } => landed = true,
        Record::IntentRegistered {
            cause: granary_core::overlay_journal::IntentCause::LandedRefresh,
            ..
        } if landed => refreshed = true,
        _ => {}
    })
    .unwrap();
    assert_eq!(
        (f.remote.published.lock().unwrap().len(), landed, refreshed),
        (published + 1, true, false),
        "{row}: the readback seam must hold a journaled landing and no refresh after it"
    );
}

/// Journal the row's commit boundary over y, in the state the row names.
async fn make_boundary(f: &Fixture, boundary: Boundary, offset: u64, row: &str) {
    match boundary {
        Boundary::None => {}
        Boundary::Constructed | Boundary::LandedOwed => {
            let sends = f.remote.publication_sends.lock().unwrap().len();
            let lane = f
                .engine
                .construct_commit(SyncOptions::default(), &mut Entropy(70))
                .await
                .unwrap_or_else(|error| panic!("{row}: constructing the boundary failed: {error}"));
            if matches!(boundary, Boundary::LandedOwed) {
                land_before_refresh(f, &lane, row).await;
            } else {
                assert_eq!(
                    (
                        f.remote.publication_sends.lock().unwrap().len(),
                        durable_commit_state(f).0,
                        durable_commit_state(f).1.0,
                    ),
                    (sends, Some(("ready", 1)), false),
                    "{row}: construction must leave a durable unsent candidate",
                );
            }
        }
        Boundary::Installed => published::commit_all(f, 70).await,
    }
    if matches!(boundary, Boundary::LandedOwed | Boundary::Installed) {
        let captured: &[u8] = if offset == 8 {
            b"y-data-1WWWW"
        } else {
            b"y-daWWWW"
        };
        assert_eq!(
            published::head_file(f, "y").as_deref(),
            Some(captured),
            "{row}: landed bytes"
        );
    }
}

async fn reopen_after_cut(
    row: &str,
    start_published: bool,
    offset: u64,
    boundary: Boundary,
    held: bool,
    lose_body: bool,
) -> Reopen {
    let f = Fixture::new().await;
    let y = if start_published {
        f.create("y", b"y-base-0");
        published::commit_all(&f, 60).await;
        try_persist_content(&f)
            .unwrap_or_else(|error| panic!("{row}: persisting the published base failed: {error}"));
        let y = torn_operation::copy_up_y(&f);
        published::write(&f, y, 0, b"y-data-1");
        y
    } else {
        f.create("y", b"y-data-1")
    };
    sync_and_write(&f, y, offset, held, row).await;
    published::hold(&f, "y");
    make_boundary(&f, boundary, offset, row).await;

    let io = f.io.clone();
    let stage = format!("{y:016x}");
    published::settle_disk(&io);
    let body = io.recovered_bytes(&stage).unwrap();
    published::write(&f, y, 0, b"ZZ");
    try_persist_content(&f)
        .unwrap_or_else(|error| panic!("{row}: persisting content failed: {error}"));
    published::settle_disk(&io);
    if lose_body {
        io.mutate_recovered(&stage, |durable| durable.clone_from(&body));
    }
    let journal = io.recovered_bytes("journal").unwrap();
    let staging = io.recovered_bytes(&stage).unwrap();
    // Reopen over the journal's own base, as a mount does before it installs
    // an owed landing.
    let base_seq = JournalHeader::decode(journal.get(..117).unwrap())
        .unwrap()
        .base_seq;
    let base_root = f.remote.published.lock().unwrap()[&base_seq].clone();
    let reopened = match boundary {
        Boundary::Installed => f.try_restart_at_head().await,
        _ if base_seq == 1 => f.try_restart_over(vec![]).await,
        _ => f.try_restart_at_published(base_seq, base_root, false).await,
    };
    match reopened {
        Ok(f) => {
            // The reopened mount finishes any recovered commit before it serves.
            if let Ok(lane) = f.engine.recover_commit(SyncOptions::default()) {
                let (mut secure, mut delay) = (Entropy(90), Delay);
                let _ = Box::pin(f.engine.drive_commit(
                    &lane,
                    &mut secure,
                    &mut delay,
                    RecoveryIntent::ExplicitRecovery,
                    SyncOptions::default(),
                ))
                .await;
            }
            let mut rollbacks = 0;
            scan_journal_with(&io.recovered_bytes("journal").unwrap(), |_, record| {
                if matches!(record, Record::StageRollback { .. }) {
                    rollbacks += 1;
                }
            })
            .unwrap();
            let bytes =
                published::local_file(&f, "y").map(|bytes| String::from_utf8(bytes).unwrap());
            Reopen::Opened(bytes, rollbacks)
        }
        Err(error) => {
            assert_eq!(
                (io.recovered_bytes("journal"), io.recovered_bytes(&stage)),
                (Some(journal), Some(staging)),
                "{row}: refusal changed the journal or staging bytes",
            );
            Reopen::Refused(error.to_string())
        }
    }
}

async fn check_held_write(offset: u64) {
    let mut outcomes = Vec::new();
    let mut expected = Vec::new();
    for start_published in [false, true] {
        for boundary in [Boundary::LandedOwed, Boundary::Constructed] {
            let row = format!("write at {offset}, published base {start_published}, {boundary:?}");
            let got = reopen_after_cut(&row, start_published, offset, boundary, true, true).await;
            outcomes.push((row.clone(), got));
            expected.push((
                row,
                Reopen::Refused("overlay refused: live extent mismatch".to_owned()),
            ));
        }
    }
    assert_eq!(
        (outcomes.len(), outcomes),
        (4, expected),
        "write at {offset} during fsync must refuse after a boundary"
    );
}

#[tokio::test]
async fn append_between_capture_and_record() {
    check_held_write(8).await;
}

#[tokio::test]
async fn overwrite_between_capture_and_record() {
    check_held_write(4).await;
}

#[tokio::test]
async fn no_boundary_rolls_back() {
    let row = "no boundary, lost write";
    assert_eq!(
        reopen_after_cut(row, false, 8, Boundary::None, true, true).await,
        Reopen::Opened(Some("y-data-1".to_owned()), 1),
        "{row}",
    );
}

#[tokio::test]
async fn installed_boundary_recovers_its_bytes() {
    let row = "installed boundary, lost write";
    assert_eq!(
        reopen_after_cut(row, false, 8, Boundary::Installed, true, true).await,
        Reopen::Opened(Some("y-data-1WWWW".to_owned()), 1),
        "{row}",
    );
}

#[tokio::test]
async fn durable_body_reopens_without_rollback() {
    let row = "landed boundary, durable write";
    assert_eq!(
        reopen_after_cut(row, false, 8, Boundary::LandedOwed, true, false).await,
        Reopen::Opened(Some("ZZdata-1WWWW".to_owned()), 0),
        "{row}",
    );
}

#[tokio::test]
async fn append_after_fsync_also_refuses() {
    let row = "append after fsync, landed boundary, lost write";
    assert_eq!(
        reopen_after_cut(row, false, 8, Boundary::LandedOwed, false, true).await,
        Reopen::Refused("overlay refused: live extent mismatch".to_owned()),
        "{row}",
    );
}
