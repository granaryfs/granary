// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::PublicationJournal as _;

fn boundary(runtime: &tokio::runtime::Runtime, mode: &str) -> Fixture {
    let fixture = if mode == "answered" {
        terminal_boundary(runtime)
    } else {
        let fixture = runtime.block_on(Fixture::new());
        fixture.create("local", b"sealed");
        if mode == "multiple" {
            fixture.create("other", b"second");
        }
        runtime.block_on(authenticate_registration(&fixture));
        fixture
    };
    let lane = (mode != "answered").then(|| {
        runtime
            .block_on(
                fixture
                    .engine
                    .construct_commit(SyncOptions::default(), &mut Entropy(70)),
            )
            .unwrap()
    });
    fixture.create("suffix", b"remaining");
    published::settle_disk(&fixture.io);
    runtime.block_on(super::super::rebase::foreign_heads(
        &fixture,
        if mode == "multiple" {
            &["local", "other"]
        } else {
            &["local"]
        },
    ));
    persist_content(&fixture);
    if mode == "unanswered" {
        mark_boundary_attempt(&fixture, lane.as_ref().unwrap());
    }
    fixture
}

#[expect(
    clippy::too_many_lines,
    reason = "one restart checks settlement, exact event counts, journal paths and staged bytes together"
)]
fn check_conflict(mode: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cases = 0;
    for mode in [mode] {
        let local_reports = crate::local_report::local_capture();
        let local_baseline = local_reports.len();
        let fixture = boundary(&runtime, mode);
        let record = budget::saved(&fixture);
        let sends = fixture.remote.publication_sends.lock().unwrap().len();
        let (scratch, io, remote, local) = fixture.reload_carrier();
        let writer = local.writer_uuid();
        drop(local);
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
        let mut local = start(&scratch, &io, 151);
        let archived = local
            .publication_transaction(|j| {
                j.archived(
                    &record.scope.digest().unwrap(),
                    &record.volume,
                    record.publication_id,
                )
            })
            .unwrap();
        let observed = events.recover();
        assert_eq!(
            (
                result.as_ref().err().map(ToString::to_string),
                result
                    .as_ref()
                    .err()
                    .and_then(crate::RecoveryCommandError::conflict_inventory)
                    .is_some(),
                archived,
                observed.iter().any(|e| e == "fence_settled how=stripped"),
                observed.iter().any(|e| e == "conflict path=<file>"),
                observed
                    .iter()
                    .any(|e| e == "journal_blocked reason=publication"),
                observed.iter().any(|e| e.starts_with("journal_finished")),
                local.snapshot().phase == granary_core::overlay_ownership::Phase::Released,
                remote.publication_sends.lock().unwrap().len(),
            ),
            (
                Some("intent refused: RecoveryConflict".into()),
                false,
                true,
                true,
                true,
                true,
                false,
                false,
                sends
            ),
            "mode={mode}, cases={}, {result:?}: {observed:?}",
            cases + 1
        );
        assert_eq!(
            observed
                .iter()
                .filter(|e| *e == "conflict path=<file>")
                .count(),
            if mode == "multiple" { 2 } else { 1 },
            "{observed:?}"
        );
        if mode == "multiple" {
            let reports = local_reports.since(local_baseline);
            for path in ["local", "other"] {
                assert!(
                    reports
                        .iter()
                        .any(|report| report.contains(&format!("conflict path=\"{path}\""))),
                    "missing {path:?} from typed local reports: {reports:?}"
                );
            }
        }
        let bytes = io.recovered_bytes("journal").unwrap();
        let mut paths = Vec::new();
        codec::scan_journal_with(&bytes, |_, record| {
            if let Record::StageBind { at, .. } | Record::Create { at, .. } = record {
                paths.push(at.clone());
            }
        })
        .unwrap();
        assert!(paths.contains(&at("local")), "prefix: {paths:?}");
        assert!(paths.contains(&at("suffix")), "suffix: {paths:?}");
        for (name, expected) in [
            ("local", b"sealed".as_slice()),
            ("suffix", b"remaining".as_slice()),
        ] {
            let mut stage = None;
            codec::scan_journal_with(&bytes, |_, record| {
                if let Record::Create {
                    at: location,
                    kind: granary_core::overlay_journal::CreateKind::File { stage_id, .. },
                } = record
                    && *location == at(name)
                {
                    stage = Some(*stage_id);
                }
            })
            .unwrap();
            let mut staged_bytes = 0u64;
            codec::scan_journal_with(&bytes, |_, record| {
                if let Record::WriteExtent {
                    stage_id, length, ..
                } = record
                    && Some(*stage_id) == stage
                {
                    staged_bytes += length;
                }
            })
            .unwrap();
            assert!(
                staged_bytes >= expected.len() as u64,
                "{name}: staged byte count {staged_bytes}"
            );
            let file = io
                .recovered_bytes(&format!("{:016x}", stage.unwrap()))
                .unwrap();
            assert!(file.ends_with(expected), "{name}: {file:?}");
        }
        cases += 1;
    }
    assert_eq!(cases, 1);
}

#[test]
fn answered_conflict_archives_strips_and_preserves_work() {
    check_conflict("answered");
}
#[test]
fn never_sent_conflict_archives_strips_and_preserves_work() {
    check_conflict("never-sent");
}
#[test]
fn unanswered_conflict_probes_before_strip_and_preserves_work() {
    check_conflict("unanswered");
}

#[test]
fn multiple_conflicts_report_every_path_once() {
    check_conflict("multiple");
}

#[expect(
    clippy::too_many_lines,
    reason = "one row checks the collision premise, probe completion and landed install together"
)]
fn check_landed(variant: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = boundary(&runtime, "never-sent");
    let lane = fixture
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap();
    mark_boundary_attempt(&fixture, &lane);
    let record = budget::saved(&fixture);
    let stored = super::archived::published(&record, variant, false);
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(record.candidates[0].seq, stored.clone());
    let head = runtime.block_on(super::super::rebase::foreign_head(&fixture, "local"));
    let head_seq = granary_core::root::decode_root(&head).unwrap().seq;
    assert!(head_seq > record.candidates[0].seq);
    persist_content(&fixture);
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let keys = TrustedKeys::new([*key.public_key()]).unwrap();
    let reports = crate::local_report::local_capture();
    {
        // A merge before the probe would report `local`: the head is strictly
        // past the landing and carries a foreign edit to the lane's changed path.
        let baseline = reports.len();
        let events = super::super::selected::Events::default();
        let _guard = events.guard();
        let mut local = fixture.store.lock().unwrap();
        let mut secure = Entropy(71);
        let mut journal = crate::RecoveryJournal::new(&mut local, &*fixture.remote, &keys)
            .report_conflicts_with(&mut secure);
        let error = runtime
            .block_on(journal.rebase_manifest(
                &record.frozen,
                Some(GrainId::of(&head)),
                head_seq + 1,
            ))
            .unwrap_err();
        assert_eq!(error.kind, crate::PublicationStoreErrorKind::Conflict);
        assert_eq!(events.recover(), ["conflict path=<file>"]);
        assert!(
            reports
                .since(baseline)
                .iter()
                .any(|r| r.contains("conflict path=\"local\""))
        );
    }
    let baseline = reports.len();
    let sends = fixture.remote.publication_sends.lock().unwrap().len();
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    let events = super::super::selected::Events::default();
    let _guard = events.guard();
    crate::recovery::landing_hooks_for_test(crate::recovery::LandingHooks {
        witness_failure: true,
        ..Default::default()
    });
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
        result.unwrap_err().to_string(),
        "remote: store: injected landing witness failure"
    );
    let mut local = start(&scratch, &io, 154);
    let observed = events.recover();
    assert_eq!(
        observed
            .iter()
            .filter(|e| e.starts_with("conflict"))
            .count(),
        0,
        "at probe completion: {observed:?}"
    );
    assert!(
        !reports
            .since(baseline)
            .iter()
            .any(|r| r.contains("conflict path="))
    );
    let completed = local
        .publication_transaction(|j| j.load(&record.scope, &record.volume))
        .unwrap()
        .unwrap();
    assert!(
        matches!(completed.phase, granary_core::retained_submission::Phase::Complete(ref done) if done.id == record.candidates[0].id && done.root == record.candidates[0].root)
    );
    let mut landed = None;
    codec::scan_journal_with(&io.recovered_bytes("journal").unwrap(), |_, record| {
        if let Record::LandedCommit { landed_root, .. } = record {
            landed = Some(*landed_root);
        }
    })
    .unwrap();
    assert_eq!(landed, Some(GrainId::of(&stored)));
    drop(local);
    let result = boundary_command(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        FaultControl::default(),
    );
    assert!(result.is_ok(), "{result:?}: {:?}", events.recover());
    let mut reopened = start(&scratch, &io, 155);
    assert_eq!(
        reopened.snapshot().phase,
        granary_core::overlay_ownership::Phase::Released
    );
    assert_eq!(reopened.recovery_rule().unwrap(), RecoveryRule::Nothing);
    let observed = events.recover();
    assert!(
        !observed
            .iter()
            .any(|e| e.starts_with("conflict") || e == "fence_settled how=stripped"),
        "{observed:?}"
    );
    assert!(
        !reports
            .since(baseline)
            .iter()
            .any(|r| r.contains("conflict path="))
    );
    assert!(observed.iter().any(|e| e.starts_with("journal_finished")));
    let sent = remote.publication_sends.lock().unwrap();
    assert_eq!(sent.len(), sends + 1);
    assert!(
        !sent[sends..]
            .iter()
            .any(|root| record.candidates.iter().any(|c| c.root == *root))
    );
}

#[test]
fn landed_exact_skips_conflict_reports_before_probe_and_install() {
    check_landed(false);
}

#[test]
fn landed_prefix_skips_conflict_reports_before_probe_and_install() {
    check_landed(true);
}

pub(super) fn check_unresolved(runtime: &tokio::runtime::Runtime, fixture: Fixture) {
    let record = budget::saved(&fixture);
    let seq = record.candidates.last().unwrap().seq;
    let sends = fixture.remote.publication_sends.lock().unwrap().len();
    let reports = crate::local_report::local_capture();
    let baseline = reports.len();
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    for attempt in 0..2 {
        let events = super::super::selected::Events::default();
        let _guard = events.guard();
        let result = boundary_command(
            &scratch,
            &io,
            &remote,
            runtime,
            writer,
            None,
            FaultControl::default(),
        );
        let mut reopened = start(&scratch, &io, 156);
        let observed = events.recover();
        assert_eq!(
            (
                result.as_ref().err().map(ToString::to_string),
                observed
                    .iter()
                    .any(|e| e == &format!("unresolved seq={seq}")),
                observed
                    .iter()
                    .any(|e| e == "journal_blocked reason=publication"),
                observed.iter().any(|e| e.starts_with("conflict")
                    || e.starts_with("fence_settled")
                    || e.starts_with("journal_finished")),
                reports
                    .since(baseline)
                    .iter()
                    .any(|r| r.contains("conflict path=")),
                remote.publication_sends.lock().unwrap().len()
            ),
            (
                Some("intent refused: RecoveryUnresolved".into()),
                true,
                true,
                false,
                false,
                sends
            ),
            "attempt={attempt}: {observed:?}"
        );
        assert_ne!(
            reopened.snapshot().phase,
            granary_core::overlay_ownership::Phase::Released
        );
        let mut boundary = None;
        let mut landed = false;
        codec::scan_journal_with(
            &io.recovered_bytes("journal").unwrap(),
            |_, item| match item {
                Record::CommitBoundary { publication_id, .. } => boundary = Some(*publication_id),
                Record::LandedCommit { .. } => landed = true,
                _ => {}
            },
        )
        .unwrap();
        assert_eq!((boundary, landed), (Some(record.publication_id), false));
        let retained = reopened
            .publication_transaction(|j| j.load(&record.scope, &record.volume))
            .unwrap()
            .unwrap();
        let mut expected = record.clone();
        expected.generation = retained.generation;
        assert_eq!(retained, expected);
        let scan = codec::scan_journal(&io.recovered_bytes("journal").unwrap()).unwrap();
        let progress = scan.state.commit_progress(&record.publication_id).unwrap();
        assert_eq!(
            progress.attempts,
            record
                .candidates
                .iter()
                .map(|c| c.evidence.started)
                .sum::<u64>()
        );
        assert!(
            !reopened
                .publication_transaction(|j| j.archived(
                    &record.scope.digest().unwrap(),
                    &record.volume,
                    record.publication_id
                ))
                .unwrap()
        );
        drop(reopened);
        io.crash();
    }
}

#[test]
fn unresolved_conflict_does_not_report_or_strip_before_proof() {
    use granary_core::retained_submission::{Phase, Role};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = boundary(&runtime, "unanswered");
    let mut record = budget::saved(&fixture);
    let mut next = record.candidates[0].clone();
    record.candidates[0].role = Role::History;
    let head = fixture
        .remote
        .published
        .lock()
        .unwrap()
        .last_key_value()
        .unwrap()
        .1
        .clone();
    let mut doc = granary_core::root::decode_root(&next.root).unwrap();
    doc.seq += 1;
    doc.parent = Some(GrainId::of(&head));
    next.root = super::super::rebase::signed(doc);
    next.id = GrainId::of(&next.root);
    next.seq += 1;
    next.number += 1;
    record.phase = Phase::AwaitingAnswer {
        candidate: next.number,
        attempt: 1,
    };
    record.candidates.push(next);
    let generation = record.generation;
    record.generation += 1;
    let lane = fixture
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap();
    {
        let mut local = fixture.store.lock().unwrap();
        local
            .publication_transaction(|j| j.replace(generation, &record))
            .unwrap();
        local
            .overlay_transaction(|t| {
                t.record_commit_attempt(lane.boundary_seq(), record.publication_id, 2)
            })
            .unwrap();
    }
    check_unresolved(&runtime, fixture);
}

#[test]
fn unanswered_conflict_reports_after_proof_before_archive_and_strip() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = boundary(&runtime, "unanswered");
    let record = budget::saved(&fixture);
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    let events = super::super::selected::Events::default();
    let _guard = events.guard();
    let reports = crate::local_report::local_capture();
    let baseline = reports.len();
    let proof_reads = Arc::new(AtomicU64::new(0));
    let observed_reads = proof_reads.clone();
    let event_view = events.clone();
    let report_view = reports.clone();
    remote.post_listing_probe.set(Arc::new(move || {
        observed_reads.fetch_add(1, Ordering::Relaxed);
        assert!(
            !event_view
                .recover()
                .iter()
                .any(|event| event.starts_with("conflict")),
            "conflict event preceded the non-landing proof read"
        );
        assert!(
            !report_view
                .since(baseline)
                .iter()
                .any(|report| report.contains("conflict path=")),
            "typed conflict report preceded the non-landing proof read"
        );
    }));
    let faults = FaultControl::default();
    faults.arm("recover.archive", "synced", 1, FaultAction::Crash);
    let result = boundary_command(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        faults.clone(),
    );
    assert!(result.is_err());
    assert_eq!(faults.fired().len(), 1);
    assert_eq!(proof_reads.load(Ordering::Relaxed), 2);
    let observed = events.recover();
    assert_eq!(
        observed
            .iter()
            .filter(|e| *e == "conflict path=<file>")
            .count(),
        1,
        "{observed:?}"
    );
    assert_eq!(
        reports
            .since(baseline)
            .iter()
            .filter(|r| r.contains("conflict path=\"local\""))
            .count(),
        1
    );
    assert!(
        !observed
            .iter()
            .any(|e| e.starts_with("fence_settled") || e.starts_with("journal_finished"))
    );
    let mut reopened = start(&scratch, &io, 157);
    assert_eq!(
        reopened.recovery_rule().unwrap(),
        RecoveryRule::BoundaryArchived
    );
    assert!(
        codec::scan_journal(&io.recovered_bytes("journal").unwrap())
            .unwrap()
            .state
            .commit_progress(&record.publication_id)
            .is_some()
    );
    assert_eq!(remote.publication_sends.lock().unwrap().len(), 0);
}

#[test]
fn conflict_archive_cut_restarts_through_the_unfenced_strip() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = boundary(&runtime, "never-sent");
    let record = budget::saved(&fixture);
    let (scratch, io, remote, local) = fixture.reload_carrier();
    let writer = local.writer_uuid();
    drop(local);
    let faults = FaultControl::default();
    faults.arm("recover.archive", "synced", 1, FaultAction::Crash);
    let result = boundary_command(
        &scratch,
        &io,
        &remote,
        &runtime,
        writer,
        None,
        faults.clone(),
    );
    assert!(result.is_err());
    assert_eq!(faults.fired().len(), 1, "{result:?}");
    let mut local = start(&scratch, &io, 152);
    assert_eq!(
        local.recovery_rule().unwrap(),
        RecoveryRule::BoundaryArchived
    );
    let progress = codec::scan_journal(&io.recovered_bytes("journal").unwrap()).unwrap();
    assert!(
        !progress
            .state
            .commit_progress(&record.publication_id)
            .unwrap()
            .fenced
    );
    drop(local);
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
    assert_eq!(
        result.unwrap_err().to_string(),
        "intent refused: RecoveryConflict"
    );
    assert!(
        events
            .recover()
            .iter()
            .any(|e| e == "fence_settled how=stripped")
    );
    assert!(
        io.recovered_bytes("0000000000000002")
            .unwrap()
            .ends_with(b"remaining")
    );
    assert_eq!(remote.publication_sends.lock().unwrap().len(), 0);
}
