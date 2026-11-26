// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

const ACKNOWLEDGED: &[u8] = b"original";
const LOST: &[u8] = b"scramble";
const MISMATCH: &str = "overlay refused: live extent mismatch";

fn synced_stage() -> (Fixture, u64) {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, ACKNOWLEDGED);
    f.sync(id, 1);
    (f, id)
}

/// The seq just below the stage's first write: a boundary there captured none
/// of its bytes.
fn before_first_write(f: &Fixture) -> u64 {
    let mut first = None;
    codec::scan_journal_with(&f.io.bytes(&f.overlay.journal_path()), |seq, record| {
        if matches!(record, Record::WriteExtent { .. }) {
            first.get_or_insert(seq);
        }
    })
    .unwrap();
    first.unwrap() - 1
}

fn corrupt_extent(f: &mut Fixture, id: u64) {
    let path = f.overlay.stage_path(id);
    f.io.write_at(&path, 160, LOST).unwrap();
    f.io.sync(&path).unwrap();
    f.io.sync(&f.overlay.journal_path()).unwrap();
    f.io.crash();
}

#[test]
fn reopen_settles_failed_rollback_switch_before_acknowledging_work() {
    let mut rows = Vec::new();
    for phase in ["dir_sync", "after_rename"] {
        let (mut f, id) = synced_stage();
        f.write(id, b"buffered");
        corrupt_extent(&mut f, id);
        let faults = FaultControl::default();
        faults.arm("overlay.journal.rollback", phase, 1, FaultAction::Fail);
        let failed = f.reopen_with_faults(faults.clone());
        assert_eq!(
            (
                matches!(failed, Err(OverlayError::Io(_))),
                faults.fired().len()
            ),
            (true, 1),
            "{phase}: first open {failed:?}, faults {:?}",
            faults.fired()
        );
        f.reopen()
            .unwrap_or_else(|error| panic!("{phase}: retry: {error}"));
        f.write(id, b"accepted");
        f.sync(id, 2);
        f.io.crash();
        let read = f
            .reopen()
            .and_then(|()| f.overlay.read_stage(&mut f.store, &f.owner, id, 0, 8));
        rows.push((phase, read.map_err(|error| error.to_string())));
    }
    assert_eq!(
        rows,
        [
            ("dir_sync", Ok(b"accepted".to_vec())),
            ("after_rename", Ok(b"accepted".to_vec())),
        ],
        "acknowledged write after a failed rollback switch"
    );
}

#[test]
fn open_barrier_failure_preserves_visible_and_durable_bytes() {
    let mut rows = Vec::new();
    for phase in ["area", "staging", "journal"] {
        let (mut f, id) = synced_stage();
        f.write(id, b"buffered");
        corrupt_extent(&mut f, id);
        let before = f.io.tree();
        let faults = FaultControl::default();
        faults.arm("overlay.open.barrier", phase, 1, FaultAction::Fail);
        let failed = f.reopen_with_faults(faults.clone());
        let visible_unchanged = f.io.tree() == before;
        f.io.crash();
        let durable_unchanged = f.io.tree() == before;
        let retry = f.reopen();
        rows.push((
            phase,
            failed.map_err(|error| error.to_string()),
            faults.fired().len(),
            visible_unchanged,
            durable_unchanged,
            retry.map_err(|error| error.to_string()),
        ));
    }
    assert_eq!(
        rows,
        ["area", "staging", "journal"].map(|phase| (
            phase,
            Err(OverlayError::Io(std::io::Error::other("overlay injected fault")).to_string()),
            1,
            true,
            true,
            Ok(()),
        )),
        "failed barrier must leave evidence alone before replay"
    );
}

#[test]
fn reopen_settles_failed_writer_switch_before_acknowledging_work() {
    let (mut f, id) = synced_stage();
    let faults = f.overlay.fault_control();
    faults.arm("overlay.writer", "dir_sync", 1, FaultAction::Fail);
    let failed = f.overlay.raise_ceiling(&mut f.store, 200);
    assert_eq!(
        (
            matches!(failed, Err(OverlayError::Io(_))),
            faults.fired().len()
        ),
        (true, 1),
        "writer switch: {failed:?}, faults {:?}",
        faults.fired()
    );
    f.reopen().unwrap();
    f.write(id, b"accepted");
    f.sync(id, 101);
    f.io.crash();
    let read = f
        .reopen()
        .and_then(|()| f.overlay.read_stage(&mut f.store, &f.owner, id, 0, 8));
    assert_eq!(
        read.map_err(|error| error.to_string()).as_deref(),
        Ok(&b"accepted"[..])
    );
}

#[test]
fn reopen_settles_staging_after_failed_create() {
    let (mut f, id) = synced_stage();
    let faults = f.overlay.fault_control();
    faults.arm("overlay.stage.dir_sync", "before", 1, FaultAction::Fail);
    let failed = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("g"), false);
    assert_eq!(
        (
            matches!(failed, Err(OverlayError::Io(_))),
            faults.fired().len()
        ),
        (true, 1),
        "stage create: {failed:?}, faults {:?}",
        faults.fired()
    );
    let start = f.io.0.lock().unwrap().trace.len();
    f.reopen().unwrap();
    let writer = f.overlay.area.join("writer");
    let staging = f.overlay.area.join("staging");
    let settled_before_writer = f.io.0.lock().unwrap().trace[start..]
        .iter()
        .take_while(|(op, path)| op != "length" || path != &writer)
        .any(|(op, path)| op == "dir_sync" && path == &staging);
    f.write(id, b"accepted");
    f.sync(id, 2);
    f.io.crash();
    f.reopen().unwrap();
    let read = f.overlay.read_stage(&mut f.store, &f.owner, id, 0, 8);
    assert_eq!(
        (
            settled_before_writer,
            read.map_err(|error| error.to_string())
        ),
        (true, Ok(b"accepted".to_vec())),
        "staging settles before writer evidence even when the unbound file can be swept"
    );
}

#[test]
fn in_process_recovery_settles_journal_after_failed_sync() {
    let (mut f, id) = synced_stage();
    f.write(id, b"buffered");
    f.io.sync(&f.overlay.stage_path(id)).unwrap();
    let path = f.overlay.journal_path();
    let live = f.io.bytes(&path);
    f.io.0.lock().unwrap().fail = Some("sync");
    let failed = f.io.sync(&path);
    assert!(
        failed.is_err() && f.io.recovered_bytes("journal").as_deref() != Some(&live),
        "journal sync {failed:?}, durable {:?}",
        f.io.recovered_bytes("journal").map(|bytes| bytes.len())
    );
    f.overlay
        .recover(&mut f.store, &f.owner, &mut f.source)
        .unwrap();
    f.io.crash();
    assert_eq!(
        (f.io.bytes(&path).len(), f.io.bytes(&path) == live),
        (live.len(), true),
        "in-process replay must settle bytes it admits"
    );
}

#[test]
fn rollback_accepts_an_older_header_with_the_same_checkpoint() {
    let (mut f, id) = synced_stage();
    let path = f.overlay.stage_path(id);
    let older = f.io.bytes(&path)[..codec::STAGING_HEADER_LEN].to_vec();
    f.sync(id, 2);
    f.io.write_at(&path, 0, &older).unwrap();
    f.write(id, b"buffered");
    corrupt_extent(&mut f, id);
    let result = f
        .reopen()
        .and_then(|()| f.overlay.read_stage(&mut f.store, &f.owner, id, 0, 8));
    assert_eq!(
        (
            result.map_err(|error| error.to_string()),
            rollback_count(&f.io.bytes(&f.overlay.journal_path()))
        ),
        (Ok(ACKNOWLEDGED.to_vec()), 1),
        "header generation can lag when its payload agrees"
    );
}

#[test]
fn in_process_rollback_invalidates_unmaterialized_captures() {
    let (mut f, id) = synced_stage();
    f.write(id, b"buffered");
    let other = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("other"), false)
        .unwrap();
    f.write(other, b"other");
    f.io.sync(&f.overlay.stage_path(other)).unwrap();
    f.io.sync_directory(&f.overlay.area.join("staging"))
        .unwrap();
    let unaffected = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(other))
        .unwrap();
    let captured = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    let eager = f.overlay.capture(&mut f.store, &f.owner, id).unwrap();
    corrupt_extent(&mut f, id);
    f.overlay
        .recover(&mut f.store, &f.owner, &mut f.source)
        .unwrap();

    let stale = f
        .overlay
        .captured_range(&mut f.store, &f.owner, &captured, 0, 0);
    let flush = f
        .overlay
        .flush_sync_boundary(&mut f.store, &f.owner, &captured);
    let eager_status = f.overlay.validate_capture(&eager);
    let read = f
        .overlay
        .read_stage(&mut f.store, &f.owner, id, 0, ACKNOWLEDGED.len());
    assert_eq!(
        (
            stale.as_ref().err().map(ToString::to_string).as_deref(),
            flush.as_ref().err().map(ToString::to_string).as_deref(),
            eager_status
                .as_ref()
                .err()
                .map(ToString::to_string)
                .as_deref(),
            read.unwrap().as_slice(),
            f.overlay.summary().rolled_back_stages,
        ),
        (
            Some("capture coverage lost (EIO)"),
            Some("capture coverage lost (EIO)"),
            Some("capture coverage lost (EIO)"),
            ACKNOWLEDGED,
            1
        ),
        "old range: {stale:?}"
    );
    assert_eq!(
        snapshot::materialize(&mut f, &unaffected, &unaffected.files()[0]).concat(),
        b"other"
    );
    f.overlay.release_sync_boundary(&captured).unwrap();
    f.overlay.complete_failed_capture(&eager).unwrap();
    f.overlay.release_sync_boundary(&unaffected).unwrap();
}

#[test]
fn in_process_tail_cut_invalidates_captures_of_the_cut_stage() {
    let (mut f, id) = synced_stage();
    let path = f.overlay.stage_path(id);
    let old_body = f.io.bytes(&path);
    let journal = f.overlay.journal_path();
    let keep = f.io.bytes(&journal).len();
    f.write(id, b"buffered");
    let captured = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    assert_eq!(
        snapshot::materialize(&mut f, &captured, &captured.files()[0]).concat(),
        b"buffered"
    );
    f.io.mutate(&path, |bytes| *bytes = old_body);
    f.io.mutate(&journal, |bytes| bytes.truncate(keep + 1));
    let scan = codec::scan_journal(&f.io.bytes(&journal)).unwrap();
    assert_eq!(
        (scan.end, scan.valid_len),
        (codec::JournalEnd::Torn(codec::TornCause::ShortLength), keep)
    );
    f.overlay
        .recover(&mut f.store, &f.owner, &mut f.source)
        .unwrap();

    let stale = f
        .overlay
        .captured_range(&mut f.store, &f.owner, &captured, 0, 0);
    let new = f
        .overlay
        .seal_sync(&mut f.store, &f.owner, SyncTarget::Stage(id))
        .unwrap();
    assert_eq!(
        (
            stale.as_ref().err().map(ToString::to_string).as_deref(),
            snapshot::materialize(&mut f, &new, &new.files()[0])
                .concat()
                .as_slice(),
            f.overlay.summary().rolled_back_stages,
            f.io.bytes(&journal).len(),
        ),
        (Some("capture coverage lost (EIO)"), ACKNOWLEDGED, 0, keep),
        "old range: {stale:?}"
    );
    f.overlay.release_sync_boundary(&captured).unwrap();
    f.overlay.release_sync_boundary(&new).unwrap();
}

fn boundary(f: &mut Fixture, projected: bool, through_seq: u64) {
    let candidate = grain(2);
    let publication_id = [1; 16];
    f.overlay
        .append(&if projected {
            Record::ProjectedBoundary {
                candidate,
                through_seq,
                publication_id,
                selection: None,
            }
        } else {
            Record::CommitBoundary {
                candidate,
                through_seq,
                publication_id,
            }
        })
        .unwrap();
}

fn assert_replay_refusal_preserves_tree(f: &mut Fixture) {
    let before = f.io.tree();
    let cursor = f.io.0.lock().unwrap().trace.len();
    let result = f.reopen().map_err(|error| error.to_string());
    let persistence = f.persistence_since(cursor);
    assert_eq!(
        (
            result.as_ref().err().map(String::as_str),
            persistence.as_slice(),
            f.io.tree() == before
        ),
        (Some(MISMATCH), f.open_barriers().as_slice(), true),
        "replay outcome {result:?}, persistence {persistence:?}"
    );
}

fn boundary_cutoff(projected: bool, captured: bool) {
    let (mut f, id) = synced_stage();
    let synced = f.overlay.summary().records;
    f.write(id, b"buffered");
    let extent = f.overlay.summary().records;
    let through = if captured {
        extent
    } else {
        before_first_write(&f)
    };
    assert_eq!(extent, synced + 1, "extent={extent}, synced={synced}");
    boundary(&mut f, projected, through);
    corrupt_extent(&mut f, id);
    if captured {
        assert_replay_refusal_preserves_tree(&mut f);
    } else {
        f.reopen()
            .unwrap_or_else(|error| panic!("E={extent}, S={synced}, B={through}: {error}"));
        assert_eq!(
            (
                &f.io.bytes(&f.overlay.stage_path(id))[160..],
                rollback_count(&f.io.bytes(&f.overlay.journal_path())),
                f.overlay.readiness()
            ),
            (ACKNOWLEDGED, 1, OverlayReadiness::PendingRecovery)
        );
    }
}

#[test]
fn rollback_refuses_extent_at_commit_boundary() {
    boundary_cutoff(false, true);
}

#[test]
fn rollback_restores_extent_above_sync_after_commit_boundary_below_stage() {
    boundary_cutoff(false, false);
}

#[test]
fn rollback_refuses_extent_at_projected_boundary() {
    boundary_cutoff(true, true);
}

#[test]
fn rollback_restores_extent_above_sync_after_projected_boundary_below_stage() {
    boundary_cutoff(true, false);
}

/// A boundary that captured the stage's synced bytes refuses a rollback of a
/// later write: the mark is the file at its fsync's capture, which is not
/// recorded, so a write the boundary holds could be newer than the mark.
fn boundary_over_synced_bytes(projected: bool) {
    let (mut f, id) = synced_stage();
    let synced = f.overlay.summary().records;
    f.write(id, b"buffered");
    boundary(&mut f, projected, synced);
    corrupt_extent(&mut f, id);
    assert_replay_refusal_preserves_tree(&mut f);
}

#[test]
fn rollback_refuses_after_commit_boundary_over_synced_bytes() {
    boundary_over_synced_bytes(false);
}

#[test]
fn rollback_refuses_after_projected_boundary_over_synced_bytes() {
    boundary_over_synced_bytes(true);
}

#[test]
fn rollback_refuses_extent_just_below_sync() {
    let (mut f, id) = synced_stage();
    let mut seen = (0, 0);
    codec::scan_journal_with(
        &f.io.bytes(&f.overlay.journal_path()),
        |seq, record| match record {
            Record::WriteExtent { .. } => seen.0 = seq,
            Record::FileSynced { .. } => seen.1 = seq,
            _ => {}
        },
    )
    .unwrap();
    assert_eq!(seen, (2, 3), "extent and sync sequences: {seen:?}");
    corrupt_extent(&mut f, id);
    assert_replay_refusal_preserves_tree(&mut f);
}

#[test]
fn rollback_refuses_captured_payload_after_sync_even_if_its_check_is_retired() {
    let (mut f, id) = synced_stage();
    let synced = f.overlay.summary().records;
    f.write(id, b"captured");
    let captured = f.overlay.summary().records;
    boundary(&mut f, false, captured);
    f.write(id, b"buffered");
    let live = f.overlay.summary().records;
    assert_eq!((captured, live), (synced + 1, synced + 3));
    corrupt_extent(&mut f, id);
    assert_replay_refusal_preserves_tree(&mut f);
}

#[test]
fn rollback_refuses_captured_truncate_with_no_captured_live_extent() {
    let (mut f, id) = synced_stage();
    f.overlay.truncate(&mut f.store, &f.owner, id, 2).unwrap();
    let through = f.overlay.summary().records;
    boundary(&mut f, true, through);
    f.write(id, b"buffered");
    corrupt_extent(&mut f, id);
    assert_replay_refusal_preserves_tree(&mut f);
}

#[test]
fn rollback_refuses_captured_earlier_rollback() {
    let (mut f, id) = synced_stage();
    f.write(id, b"buffered");
    corrupt_extent(&mut f, id);
    f.reopen().unwrap();
    let through = f.overlay.summary().records;
    boundary(&mut f, true, through);
    f.write(id, b"buffered");
    corrupt_extent(&mut f, id);
    assert_replay_refusal_preserves_tree(&mut f);
}

#[test]
fn rollback_refuses_a_disagreeing_newer_header_mark() {
    let (mut f, id) = synced_stage();
    f.write(id, b"buffered");
    let path = f.overlay.stage_path(id);
    let mut header = StagingHeader::decode(&f.io.bytes(&path)[..160]).unwrap();
    let MarkState::Present(mut mark) = header.mark else {
        panic!("expected a synced fixture: {header:?}");
    };
    assert_eq!(mark.generation, 1);
    mark.generation = 2;
    mark.content = GrainId::of(LOST);
    header.mark = MarkState::Present(mark);
    f.io.write_at(&path, 0, &header.encode().unwrap()).unwrap();
    corrupt_extent(&mut f, id);
    assert_replay_refusal_preserves_tree(&mut f);
}

#[test]
fn rollback_checkpoint_survives_a_newer_header_only_mark() {
    let (mut f, id) = synced_stage();
    f.write(id, b"buffered");
    corrupt_extent(&mut f, id);
    f.reopen().unwrap();

    // Persist a newer mirror without its journal record, as at the mark barrier.
    let path = f.overlay.stage_path(id);
    let mut header =
        StagingHeader::decode(&f.io.bytes(&path)[..codec::STAGING_HEADER_LEN]).unwrap();
    let content = GrainId::of(LOST);
    f.source.0.insert(content, LOST.to_vec());
    header.mark = MarkState::Present(SyncedMark {
        synced_size: LOST.len() as u64,
        content,
        generation: 2,
    });
    f.io.write_at(&path, 0, &header.encode().unwrap()).unwrap();
    f.io.sync(&path).unwrap();
    f.io.crash();
    f.reopen().unwrap();

    let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
    assert_eq!(
        (
            capture.entries().first().map(|entry| &entry.kind),
            &f.io.bytes(&path)[codec::STAGING_HEADER_LEN..],
            f.overlay.summary().rolled_back_stages,
        ),
        (
            Some(&OverlayKind::File {
                content: Some(GrainId::of(ACKNOWLEDGED))
            }),
            ACKNOWLEDGED,
            1,
        ),
        "a header-only mark leaves the restored checkpoint, body and report in place"
    );
}

#[test]
fn rollback_plans_all_stages_before_installing_any_repair() {
    let mut f = Fixture::new();
    let first = f.create();
    f.write(first, b"buffered");
    let last = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("last"), false)
        .unwrap();
    f.write(last, ACKNOWLEDGED);
    f.sync(last, 1);
    corrupt_extent(&mut f, first);
    corrupt_extent(&mut f, last);
    assert_replay_refusal_preserves_tree(&mut f);
}

fn log_reopen(
    f: &mut Fixture,
    faults: FaultControl,
    paths: observe::LogPaths,
) -> (Result<(), OverlayError>, String) {
    let log = LogBytes::default();
    let subscriber = observe::closed_subscriber_with_paths(
        observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("info"),
        log.clone(),
        paths,
        observe::BundleHistory::default(),
    );
    let outcome = tracing::subscriber::with_default(subscriber, || f.reopen_with_faults(faults));
    let bytes = log.0.lock().unwrap().clone();
    (outcome, String::from_utf8(bytes).unwrap())
}

fn stage_reports(log: &str) -> Vec<&str> {
    log.lines()
        .filter(|line| line.contains("\"event\":\"overlay.stage_rolled_back\""))
        .collect()
}

#[test]
fn rollback_with_open_commit_boundary_reports_pending() {
    let (mut f, id) = synced_stage();
    let through = before_first_write(&f);
    f.write(id, b"buffered");
    boundary(&mut f, false, through);
    corrupt_extent(&mut f, id);

    let (result, log) = log_reopen(&mut f, FaultControl::default(), observe::LogPaths::Full);
    result.unwrap();
    assert_eq!(
        (
            f.overlay.readiness(),
            log.lines()
                .any(|line| line.contains("\"event\":\"overlay.recovery\"")
                    && line.contains("\"outcome\":\"pending\"")
                    && line.contains("\"rolled_back_stages\":1")
                    && line.contains("\"rolled_back_bytes\":8"))
        ),
        (OverlayReadiness::PendingRecovery, true),
        "{log}"
    );
}

fn rollback_cut(name: &'static str, phase: &'static str, switched: bool, durable_stage: bool) {
    let (mut f, id) = synced_stage();
    f.write(id, b"buffered");
    corrupt_extent(&mut f, id);
    let journal = f.overlay.journal_path();
    let stage = f.overlay.stage_path(id);
    let original = f.io.bytes(&journal);
    let scan = codec::scan_journal(&original).unwrap();
    let seq = scan.state.next_seq();
    let expected = [
        original.clone(),
        codec::encode_record(
            &scan.header,
            seq,
            &Record::StageRollback {
                stage_id: id,
                old_size: 8,
                anchor: Some(codec::RecreateAnchor {
                    content: GrainId::of(ACKNOWLEDGED),
                    size: 8,
                }),
                discarded_bytes: 8,
            },
        )
        .unwrap(),
    ]
    .concat();
    let faults = FaultControl::default();
    faults.arm(name, phase, 1, FaultAction::Crash);
    let (result, log) = log_reopen(&mut f, faults.clone(), observe::LogPaths::Redacted);
    let fired = faults.fired();
    assert_eq!(
        (
            matches!(result, Err(OverlayError::InjectedCrash)),
            fired.len(),
            stage_reports(&log).len()
        ),
        (true, 1, 0),
        "{name}/{phase}: result {result:?}, fired {fired:?}, log {log}"
    );
    assert_eq!((fired[0].name, fired[0].phase), (name, phase));
    if phase == "partial" {
        assert_eq!(&f.io.bytes(&stage)[160..], b"origmble");
    }
    f.io.crash();
    assert_eq!(
        (f.io.bytes(&journal), &f.io.bytes(&stage)[160..]),
        (
            if switched { expected.clone() } else { original },
            if durable_stage { ACKNOWLEDGED } else { LOST }
        ),
        "{name}/{phase}: durable journal and staging body at the cut"
    );
    for (policy, path) in [
        (observe::LogPaths::Redacted, "<file>"),
        (observe::LogPaths::Full, "f"),
    ] {
        let (result, log) = log_reopen(&mut f, FaultControl::default(), policy);
        result.unwrap_or_else(|error| panic!("{name}/{phase}: recovery {error}"));
        let reports = stage_reports(&log);
        let summary = f.overlay.summary();
        assert_eq!(
            (
                f.io.bytes(&journal),
                &f.io.bytes(&stage)[160..],
                rollback_count(&f.io.bytes(&journal)),
                summary.rolled_back_stages,
                summary.rolled_back_bytes,
                reports.len()
            ),
            (expected.clone(), ACKNOWLEDGED, 1, 1, 8, 1)
        );
        for field in [
            "\"level\":\"WARN\"".to_owned(),
            format!("\"rollback_seq\":{seq}"),
            format!("\"stage_id\":{id}"),
            format!("\"path\":\"{path}\""),
            "\"old_size\":8".to_owned(),
            "\"restored_size\":8".to_owned(),
            "\"discarded_bytes\":8".to_owned(),
        ] {
            assert!(
                reports[0].contains(&field),
                "missing {field}: {}",
                reports[0]
            );
        }
        assert!(
            log.lines()
                .any(|line| line.contains("\"event\":\"overlay.recovery\"")
                    && line.contains("\"outcome\":\"repaired\"")
                    && line.contains("\"rolled_back_stages\":1")
                    && line.contains("\"rolled_back_bytes\":8")),
            "{log}"
        );
        f.io.crash();
    }
}

#[test]
fn rollback_cut_before_journal_rename() {
    rollback_cut("overlay.journal.rollback", "rename", false, false);
}

#[test]
fn rollback_cut_after_journal_rename_before_directory_sync() {
    rollback_cut("overlay.journal.rollback", "after_rename", false, false);
}

#[test]
fn rollback_cut_after_durable_journal_switch() {
    rollback_cut("overlay.journal.rollback", "after_dir_sync", true, false);
}

#[test]
fn rollback_cut_during_stage_materialization() {
    rollback_cut("overlay.stage.write", "partial", true, false);
}

#[test]
fn rollback_cut_before_stage_fsync() {
    rollback_cut("overlay.stage.sync", "before", true, false);
}

#[test]
fn rollback_cut_after_staging_durability_before_report() {
    rollback_cut("overlay.stage.rollback_report", "before", true, true);
}

#[test]
fn rollback_keeps_the_admitted_prefix_and_records_each_stage_in_order() {
    let mut f = Fixture::new();
    let first = f.create();
    f.write(first, b"buffered");
    f.overlay
        .write(&mut f.store, &f.owner, first, 8, b"live")
        .unwrap();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Delete {
                at: at("f"),
                kind: codec::DeleteKind::File {
                    stage_id: Some(first),
                },
            },
        )
        .unwrap();
    let second = f
        .overlay
        .create_file(&mut f.store, &f.owner, at("second"), false)
        .unwrap();
    f.write(second, b"buffered");
    corrupt_extent(&mut f, first);
    corrupt_extent(&mut f, second);
    let journal = f.overlay.journal_path();
    let prefix = f.io.bytes(&journal);
    f.io.write_at(&journal, prefix.len() as u64, &[0, 0])
        .unwrap();
    f.io.sync(&journal).unwrap();
    let (result, log) = log_reopen(&mut f, FaultControl::default(), observe::LogPaths::Full);
    result.unwrap();
    let repaired = f.io.bytes(&journal);
    assert!(repaired.starts_with(&prefix));
    let mut rollbacks = Vec::new();
    codec::scan_journal_with(&repaired, |_, record| {
        if let Record::StageRollback {
            stage_id,
            old_size,
            anchor,
            discarded_bytes,
        } = record
        {
            rollbacks.push((*stage_id, *old_size, *anchor, *discarded_bytes));
        }
    })
    .unwrap();
    assert_eq!(rollbacks, [(first, 12, None, 12), (second, 8, None, 8)]);
    let reports = stage_reports(&log);
    assert_eq!(reports.len(), 2, "{log}");
    assert!(!reports[0].contains("\"path\""), "{log}");
    assert!(reports[1].contains("\"path\":\"second\""), "{log}");
    f.io.crash();
    f.reopen().unwrap();
    assert_eq!(
        (
            f.io.bytes(&journal),
            f.overlay.summary().rolled_back_stages,
            f.overlay.summary().rolled_back_bytes
        ),
        (repaired, 2, 20)
    );
}

#[test]
fn rollback_does_not_convert_an_extent_read_error_into_a_payload_failure() {
    let (mut f, id) = synced_stage();
    f.write(id, b"buffered");
    corrupt_extent(&mut f, id);
    let before = f.io.tree();
    f.io.0.lock().unwrap().read_error_at = Some(160);
    let result = f.reopen();
    assert_eq!(
        (result.unwrap_err().to_string(), f.io.tree() == before),
        ("overlay I/O: model injected read error".to_owned(), true)
    );
}

#[test]
fn rollback_report_clears_after_a_later_write() {
    let (mut f, id) = synced_stage();
    f.write(id, b"buffered");
    corrupt_extent(&mut f, id);
    f.reopen().unwrap();
    assert_eq!(f.overlay.summary().rolled_back_stages, 1);
    f.write(id, b"accepted");
    f.io.sync(&f.overlay.journal_path()).unwrap();
    f.io.sync(&f.overlay.stage_path(id)).unwrap();
    f.io.crash();
    let (result, log) = log_reopen(&mut f, FaultControl::default(), observe::LogPaths::Full);
    result.unwrap();
    assert_eq!(
        (
            stage_reports(&log).len(),
            f.overlay.summary().rolled_back_stages,
            &f.io.bytes(&f.overlay.stage_path(id))[160..],
            rollback_count(&f.io.bytes(&f.overlay.journal_path()))
        ),
        (0, 0, b"accepted".as_slice(), 1)
    );
}
