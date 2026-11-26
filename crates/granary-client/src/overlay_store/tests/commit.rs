// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use codec::CommitProgress;

fn boundary(f: &mut Fixture, publication: u8) -> u64 {
    let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
    f.overlay
        .record_boundary(
            &mut f.store,
            &f.owner,
            capture,
            grain(publication),
            [publication; 16],
        )
        .unwrap()
}
fn charge(f: &mut Fixture, boundary: u64, publication: u8, attempt: u64) {
    f.overlay
        .record_commit_attempt(&mut f.store, &f.owner, boundary, [publication; 16], attempt)
        .unwrap();
}
fn fence(f: &mut Fixture, boundary: u64, publication: u8) {
    f.overlay
        .record_commit_fence(&mut f.store, &f.owner, boundary, [publication; 16])
        .unwrap();
}
fn progress(f: &mut Fixture, publication: u8) -> Option<CommitProgress> {
    f.overlay
        .commit_progress(&mut f.store, &f.owner, [publication; 16])
        .unwrap()
}
fn expected(attempts: u64, fenced: bool) -> CommitProgress {
    CommitProgress { attempts, fenced }
}

#[test]
fn commit_progress_restart_recovers_charges_and_fence_without_namespace_service() {
    let mut f = Fixture::new();
    let b = boundary(&mut f, 7);
    for n in 1..=8 {
        charge(&mut f, b, 7, n);
    }
    fence(&mut f, b, 7);
    f.io.crash();
    f.reopen().unwrap();
    assert_eq!(
        (
            f.overlay.readiness(),
            progress(&mut f, 7),
            progress(&mut f, 8)
        ),
        (
            OverlayReadiness::PendingRecovery,
            Some(expected(8, true)),
            None
        )
    );
    assert!(f.overlay.entries(&mut f.store, &f.owner).is_err());
}

#[test]
fn commit_progress_append_has_distinct_pre_and_post_sync_barriers() {
    let mut f = Fixture::new();
    let b = boundary(&mut f, 7);
    for fenced in [false, true] {
        f.io.0.lock().unwrap().trace.clear();
        if fenced {
            fence(&mut f, b, 7);
        } else {
            charge(&mut f, b, 7, 1);
        }
        let path = f.overlay.journal_path();
        let operations =
            f.io.0
                .lock()
                .unwrap()
                .trace
                .iter()
                .filter(|(op, p)| *p == path && matches!(op.as_str(), "write" | "sync"))
                .map(|(op, _)| op.clone())
                .collect::<Vec<_>>();
        assert_eq!(
            (operations, progress(&mut f, 7)),
            (
                vec!["sync".to_owned(), "write".to_owned(), "sync".to_owned()],
                Some(expected(1, fenced))
            )
        );
    }
}

#[test]
fn commit_progress_rejects_bad_binding_before_io_and_poison_preserves_evidence() {
    let mut f = Fixture::new();
    let b = boundary(&mut f, 7);
    for publication in [8, 7] {
        let before = f.io.bytes(&f.overlay.journal_path());
        let result =
            f.overlay
                .record_commit_attempt(&mut f.store, &f.owner, b, [publication; 16], 2);
        assert_eq!(
            (
                result.map_err(|e| e.to_string()),
                f.io.bytes(&f.overlay.journal_path())
            ),
            (
                Err("overlay refused: journal value rule".to_owned()),
                before
            )
        );
    }
    f.overlay
        .faults
        .arm("overlay.journal.post_sync", "before", 1, FaultAction::Fail);
    let result = f
        .overlay
        .record_commit_attempt(&mut f.store, &f.owner, b, [7; 16], 1);
    assert!(result.is_err(), "injected post-sync failure: {result:?}");
    assert_eq!(f.overlay.readiness(), OverlayReadiness::Poisoned);
    assert!(
        f.overlay
            .commit_progress(&mut f.store, &f.owner, [7; 16])
            .is_err()
    );
}

#[test]
fn commit_progress_reserve_finishes_at_full_capacity() {
    let mut f = Fixture::new();
    f.overlay.config.ownership_completion_reserve = 0;
    let b = boundary(&mut f, 7);
    let length = f.overlay.journal.lock().unwrap().length;
    f.overlay.config.cap = f.overlay.charge().unwrap() + f.overlay.reserve(length, 0).unwrap();
    let cap = f.overlay.config.cap;
    for n in 1..=8 {
        let result = f
            .overlay
            .record_commit_attempt(&mut f.store, &f.owner, b, [7; 16], n);
        assert_eq!(
            result.map(|_| ()).map_err(|e| e.to_string()),
            Ok(()),
            "reserved attempt {n}"
        );
    }
    let before = f.io.bytes(&f.overlay.journal_path());
    let unreserved = f
        .overlay
        .record_commit_attempt(&mut f.store, &f.owner, b, [7; 16], 9);
    assert_eq!(
        (
            unreserved.map_err(|error| error.to_string()),
            f.io.bytes(&f.overlay.journal_path())
        ),
        (Err("overlay cap exhausted (ENOSPC)".to_owned()), before),
        "unreserved attempt must not consume landing headroom"
    );
    let fenced = f
        .overlay
        .record_commit_fence(&mut f.store, &f.owner, b, [7; 16]);
    assert_eq!(
        fenced.map(|_| ()).map_err(|error| error.to_string()),
        Ok(()),
        "reserved fence"
    );
    let before = f.io.bytes(&f.overlay.journal_path());
    let repeated = f
        .overlay
        .record_commit_fence(&mut f.store, &f.owner, b, [7; 16]);
    assert_eq!(
        (
            repeated.map_err(|error| error.to_string()),
            f.io.bytes(&f.overlay.journal_path())
        ),
        (Err("overlay cap exhausted (ENOSPC)".to_owned()), before),
        "repeated fence must not consume landing headroom"
    );
    let proof = LandedProof {
        boundary_seq: b,
        landed_root: grain(7),
        landed_seq: 2,
        captured_entries: vec![],
        entries: vec![],
    };
    let landed = f.overlay.record_landed(&mut f.store, &f.owner, &proof);
    assert_eq!(
        landed.map(|_| ()).map_err(|e| e.to_string()),
        Ok(()),
        "reserved landing"
    );
    let refresh = f.overlay.record_intent_registered(
        &mut f.store,
        &f.owner,
        20,
        grain(7),
        codec::IntentCause::LandedRefresh,
    );
    assert_eq!(
        refresh.map(|_| ()).map_err(|e| e.to_string()),
        Ok(()),
        "reserved refresh"
    );
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    assert_eq!(
        (progress(&mut f, 7), f.overlay.charge().unwrap() <= cap),
        (None, true)
    );
}

#[test]
fn commit_progress_additional_records_use_ordinary_capacity_without_retry_policy() {
    let mut f = Fixture::new();
    let b = boundary(&mut f, 7);
    for n in 1..=9 {
        charge(&mut f, b, 7, n);
    }
    fence(&mut f, b, 7);
    fence(&mut f, b, 7);
    f.io.crash();
    f.reopen().unwrap();
    assert_eq!(progress(&mut f, 7), Some(expected(9, true)));
}

#[test]
fn commit_progress_replacement_keeps_in_doubt_and_drops_landed_evidence() {
    let mut f = Fixture::new();
    let completed = boundary(&mut f, 7);
    charge(&mut f, completed, 7, 1);
    fence(&mut f, completed, 7);
    let proof = LandedProof {
        boundary_seq: completed,
        landed_root: grain(7),
        landed_seq: 2,
        captured_entries: vec![],
        entries: vec![],
    };
    f.overlay
        .record_landed(&mut f.store, &f.owner, &proof)
        .unwrap();
    f.overlay
        .record_intent_registered(
            &mut f.store,
            &f.owner,
            20,
            grain(7),
            codec::IntentCause::LandedRefresh,
        )
        .unwrap();
    let pending = boundary(&mut f, 8);
    charge(&mut f, pending, 8, 1);
    charge(&mut f, pending, 8, 2);
    fence(&mut f, pending, 8);
    assert_eq!(
        (progress(&mut f, 7), progress(&mut f, 8)),
        (None, Some(expected(2, true)))
    );
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    let commits = f.overlay.recovery_commits(&mut f.store, &f.owner).unwrap();
    let [
        RecoveryCommit::Boundary {
            index,
            publication_id,
            ..
        },
    ] = commits.as_slice()
    else {
        panic!("surviving boundary: {commits:?}");
    };
    assert_eq!(
        (
            *index != pending,
            *publication_id,
            progress(&mut f, 7),
            progress(&mut f, 8)
        ),
        (true, [8; 16], None, Some(expected(2, true)))
    );
    f.io.crash();
    f.reopen().unwrap();
    assert_eq!(
        (progress(&mut f, 7), progress(&mut f, 8)),
        (None, Some(expected(2, true)))
    );
}

#[test]
fn commit_progress_rejected_replacement_refuses_other_boundaries() {
    let mut f = Fixture::new();
    let rejected = boundary(&mut f, 7);
    boundary(&mut f, 8);
    let before = f.io.bytes(&f.overlay.journal_path());
    let result = f
        .overlay
        .replace_rejected(&mut f.store, &f.owner, rejected, [7; 16]);
    assert_eq!(
        (
            result.map_err(|error| error.to_string()),
            f.io.bytes(&f.overlay.journal_path()) == before,
            progress(&mut f, 7),
            progress(&mut f, 8)
        ),
        (
            Err("overlay refused: rejection boundary binding".to_owned()),
            true,
            Some(expected(0, false)),
            Some(expected(0, false))
        )
    );
}

#[test]
fn commit_progress_replacement_refuses_an_in_doubt_prefix_boundary() {
    let mut f = Fixture::new();
    let pending = boundary(&mut f, 8);
    charge(&mut f, pending, 8, 1);
    fence(&mut f, pending, 8);
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let before = f.io.bytes(&f.overlay.journal_path());
    let result = f.overlay.replace_landed(&mut f.store, &f.owner, proof);
    assert_eq!(
        (
            result.map_err(|error| error.to_string()),
            f.io.bytes(&f.overlay.journal_path()) == before,
            progress(&mut f, 8)
        ),
        (
            Err("overlay refused: replacement pending prefix boundary".to_owned()),
            true,
            Some(expected(1, true))
        )
    );
}

#[test]
fn commit_progress_read_requires_completed_replay() {
    let mut f = Fixture::new();
    let b = boundary(&mut f, 7);
    charge(&mut f, b, 7, 1);
    f.overlay.replayed = false;
    let result = f.overlay.commit_progress(&mut f.store, &f.owner, [7; 16]);
    assert!(
        matches!(result, Err(OverlayError::PendingReconciliation)),
        "unreplayed journal: {result:?}"
    );
    f.overlay.replayed = true;
    assert_eq!(progress(&mut f, 7), Some(expected(1, false)));
}

#[test]
fn commit_progress_rejection_without_no_write_proof_preserves_charged_records() {
    let mut f = Fixture::new();
    let b = boundary(&mut f, 7);
    charge(&mut f, b, 7, 1);
    let before = f.io.bytes(&f.overlay.journal_path());
    let result = f
        .overlay
        .replace_rejected(&mut f.store, &f.owner, b, [7; 16]);
    assert_eq!(
        (
            result.map_err(|error| error.to_string()),
            f.io.bytes(&f.overlay.journal_path()) == before,
            progress(&mut f, 7)
        ),
        (
            Err("overlay refused: rejection attempt evidence".to_owned()),
            true,
            Some(expected(1, false))
        )
    );
}

fn proved_submission() -> granary_core::retained_submission::Submission {
    use granary_core::retained_submission as retained;
    let mut record = retained::decode(include_bytes!(
        "../../../../granary-core/tests/vectors/retained-submission/ready.bin"
    ))
    .unwrap();
    assert_eq!(record.candidates.len(), 1, "retained fixture: {record:?}");
    record.last_response = None;
    let evidence = &mut record.candidates[0].evidence;
    *evidence = retained::Evidence::default();
    let attempt = evidence.start().unwrap();
    evidence.answer(attempt, true, false).unwrap();
    retained::decode(&retained::encode(&record).unwrap()).unwrap()
}

fn retained_boundary(
    f: &mut Fixture,
    record: &granary_core::retained_submission::Submission,
    candidate: GrainId,
) -> u64 {
    let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
    f.overlay
        .record_boundary(
            &mut f.store,
            &f.owner,
            capture,
            candidate,
            record.publication_id,
        )
        .unwrap()
}

#[test]
fn commit_progress_rejection_with_saved_no_write_proof_strips_charges() {
    let record = proved_submission();
    let proof = crate::NoWriteProof::from_submission(&record, 1).expect("saved no-write answers");
    let mut f = Fixture::new();
    let b = retained_boundary(&mut f, &record, GrainId::of(&record.frozen.initial_root));
    f.overlay
        .record_commit_attempt(&mut f.store, &f.owner, b, record.publication_id, 1)
        .unwrap();
    f.overlay
        .replace_rejected_with_proof(
            &mut f.store,
            &f.owner,
            b,
            record.publication_id,
            Some(crate::RejectionProof::NoWrite(proof)),
        )
        .unwrap();
    f.io.crash();
    f.reopen().unwrap();
    assert_eq!(
        (
            f.overlay.recovery_commits(&mut f.store, &f.owner).unwrap(),
            f.overlay
                .commit_progress(&mut f.store, &f.owner, record.publication_id)
                .unwrap()
        ),
        (vec![], None)
    );
}

#[test]
fn fenced_rejection_requires_bound_proof_and_preserves_dirty_work_across_restart() {
    let mut cases = 0;
    for (proof_attempts, allowed, refusal) in [
        (8, false, Some("overlay refused: rejection fenced")),
        (7, true, Some("overlay refused: rejection boundary binding")),
        (8, true, None),
    ] {
        let record = proved_submission();
        let mut f = Fixture::new();
        let stage = f.create();
        f.write(stage, b"sealed");
        let b = retained_boundary(&mut f, &record, GrainId::of(&record.frozen.initial_root));
        f.write(stage, b"suffix");
        f.io.sync(&f.overlay.stage_path(stage)).unwrap();
        for attempt in 1..=8 {
            f.overlay
                .record_commit_attempt(&mut f.store, &f.owner, b, record.publication_id, attempt)
                .unwrap();
        }
        f.overlay
            .record_commit_fence(&mut f.store, &f.owner, b, record.publication_id)
            .unwrap();
        let before = f.io.bytes(&f.overlay.journal_path());
        let proof = crate::NoWriteProof::from_submission(&record, proof_attempts).unwrap();
        let result = if allowed {
            f.overlay.replace_rejected_fenced(
                &mut f.store,
                &f.owner,
                b,
                record.publication_id,
                crate::RejectionProof::NoWrite(proof),
            )
        } else {
            f.overlay.replace_rejected_with_proof(
                &mut f.store,
                &f.owner,
                b,
                record.publication_id,
                Some(crate::RejectionProof::NoWrite(proof)),
            )
        };
        assert_eq!(
            (
                result.err().map(|e| e.to_string()),
                f.io.bytes(&f.overlay.journal_path()) == before
            ),
            (refusal.map(str::to_owned), refusal.is_some()),
            "attempts={proof_attempts}, allowed={allowed}"
        );
        f.io.crash();
        f.reopen().unwrap();
        let progress = f
            .overlay
            .commit_progress(&mut f.store, &f.owner, record.publication_id)
            .unwrap();
        assert_eq!(progress, refusal.map(|_| expected(8, true)));
        if refusal.is_none() {
            assert_eq!(
                f.overlay
                    .read_stage(&mut f.store, &f.owner, stage, 0, 6)
                    .unwrap(),
                b"suffix"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn commit_progress_rejection_refuses_a_proof_after_the_attempt_count_moves() {
    let mut count = 0;
    for moved in [false, true] {
        let record = proved_submission();
        let mut f = Fixture::new();
        let b = retained_boundary(&mut f, &record, GrainId::of(&record.frozen.initial_root));
        f.overlay
            .record_commit_attempt(&mut f.store, &f.owner, b, record.publication_id, 1)
            .unwrap();
        let proof = crate::NoWriteProof::from_submission(&record, 1).unwrap();
        if moved {
            f.overlay
                .record_commit_attempt(&mut f.store, &f.owner, b, record.publication_id, 2)
                .unwrap();
        }
        let before = f.io.bytes(&f.overlay.journal_path());
        let result = f.overlay.replace_rejected_with_proof(
            &mut f.store,
            &f.owner,
            b,
            record.publication_id,
            Some(crate::RejectionProof::NoWrite(proof)),
        );
        if moved {
            assert_eq!(
                (
                    result.map_err(|e| e.to_string()),
                    f.io.bytes(&f.overlay.journal_path()) == before
                ),
                (
                    Err("overlay refused: rejection boundary binding".to_owned()),
                    true
                )
            );
        } else {
            assert!(result.is_ok(), "unchanged attempt count: {result:?}");
        }
        count += 1;
    }
    assert_eq!(count, 2);
}

#[test]
fn commit_progress_no_write_proof_requires_valid_incomplete_and_all_candidate_answers() {
    use granary_core::retained_submission as retained;
    let record = proved_submission();
    assert!(crate::NoWriteProof::from_submission(&record, 1).is_some());
    let mut unknown = record.clone();
    let mut history = unknown.candidates[0].clone();
    history.number += 1;
    history.role = retained::Role::History;
    history.evidence = retained::Evidence {
        started: 1,
        ..retained::Evidence::default()
    };
    unknown.candidates.push(history);
    let valid = retained::validate(&unknown);
    assert!(valid.is_ok(), "uncertain history fixture: {valid:?}");
    assert!(
        crate::NoWriteProof::from_submission(&unknown, 1).is_none(),
        "uncertain history admitted"
    );
    let mut invalid = record.clone();
    invalid.candidates[0].evidence.last_answered_attempt = 0;
    assert!(
        crate::NoWriteProof::from_submission(&invalid, 1).is_none(),
        "invalid counters admitted"
    );
    let mut complete = record.clone();
    complete.current = None;
    let candidate = &complete.candidates[0];
    complete.phase = retained::Phase::Complete(retained::Completion {
        seq: candidate.seq,
        id: candidate.id,
        root: candidate.root.clone(),
        receipt: None,
    });
    let valid = retained::validate(&complete);
    assert!(valid.is_ok(), "completed fixture: {valid:?}");
    assert!(
        crate::NoWriteProof::from_submission(&complete, 1).is_none(),
        "completion admitted as no-write"
    );
}

#[test]
fn commit_progress_rejection_preserves_fences_even_with_no_write_proof() {
    let record = proved_submission();
    let mut count = 0;
    for attempts in [0, 1] {
        let proof = crate::NoWriteProof::from_submission(&record, attempts)
            .expect("saved no-write answers");
        let mut f = Fixture::new();
        let b = retained_boundary(&mut f, &record, GrainId::of(&record.frozen.initial_root));
        if attempts != 0 {
            f.overlay
                .record_commit_attempt(&mut f.store, &f.owner, b, record.publication_id, 1)
                .unwrap();
        }
        f.overlay
            .record_commit_fence(&mut f.store, &f.owner, b, record.publication_id)
            .unwrap();
        let before = f.io.bytes(&f.overlay.journal_path());
        let result = f.overlay.replace_rejected_with_proof(
            &mut f.store,
            &f.owner,
            b,
            record.publication_id,
            Some(crate::RejectionProof::NoWrite(proof)),
        );
        assert_eq!(
            (
                result.map_err(|error| error.to_string()),
                f.io.bytes(&f.overlay.journal_path()) == before,
                f.overlay
                    .commit_progress(&mut f.store, &f.owner, record.publication_id)
                    .unwrap()
            ),
            (
                Err("overlay refused: rejection fenced".to_owned()),
                true,
                Some(expected(attempts, true))
            )
        );
        count += 1;
    }
    assert_eq!(count, 2);
}

#[test]
fn commit_progress_rejection_binds_no_write_proof_to_publication_and_candidate() {
    let record = proved_submission();
    let mut count = 0;
    for wrong_publication in [false, true] {
        let mut different = record.clone();
        if wrong_publication {
            different.publication_id = [99; 16];
        }
        let candidate = if wrong_publication {
            GrainId::of(&record.frozen.initial_root)
        } else {
            grain(99)
        };
        let proof =
            crate::NoWriteProof::from_submission(&record, 1).expect("saved no-write answers");
        let mut f = Fixture::new();
        let b = retained_boundary(&mut f, &different, candidate);
        f.overlay
            .record_commit_attempt(&mut f.store, &f.owner, b, different.publication_id, 1)
            .unwrap();
        let before = f.io.bytes(&f.overlay.journal_path());
        let result = f.overlay.replace_rejected_with_proof(
            &mut f.store,
            &f.owner,
            b,
            different.publication_id,
            Some(crate::RejectionProof::NoWrite(proof)),
        );
        assert_eq!(
            (
                result.map_err(|error| error.to_string()),
                f.io.bytes(&f.overlay.journal_path()) == before
            ),
            (
                Err("overlay refused: rejection boundary binding".to_owned()),
                true
            ),
            "wrong publication={wrong_publication}"
        );
        count += 1;
    }
    assert_eq!(count, 2);
}

#[test]
fn commit_progress_rejected_replacement_refuses_another_landing() {
    let mut f = Fixture::new();
    let rejected = boundary(&mut f, 7);
    let landed = boundary(&mut f, 8);
    let proof = LandedProof {
        boundary_seq: landed,
        landed_root: grain(8),
        landed_seq: 2,
        captured_entries: vec![],
        entries: vec![],
    };
    f.overlay
        .record_landed(&mut f.store, &f.owner, &proof)
        .unwrap();
    let before = f.io.bytes(&f.overlay.journal_path());
    let result = f
        .overlay
        .replace_rejected(&mut f.store, &f.owner, rejected, [7; 16]);
    assert_eq!(
        (
            result.map_err(|error| error.to_string()),
            f.io.bytes(&f.overlay.journal_path()) == before
        ),
        (
            Err("overlay refused: rejection boundary binding".to_owned()),
            true
        )
    );
}

#[test]
fn commit_progress_replacement_refuses_suffix_evidence_for_a_closed_prefix_boundary() {
    let mut count = 0;
    for evidence in ["attempt", "fence", "landing"] {
        let mut f = Fixture::new();
        let first = boundary(&mut f, 7);
        let second = boundary(&mut f, 8);
        match evidence {
            "attempt" => charge(&mut f, first, 7, 1),
            "fence" => fence(&mut f, first, 7),
            _ => {}
        }
        let first = LandedProof {
            boundary_seq: first,
            landed_root: grain(7),
            landed_seq: 2,
            captured_entries: vec![],
            entries: vec![],
        };
        f.overlay
            .record_landed(&mut f.store, &f.owner, &first)
            .unwrap();
        let second = LandedProof {
            boundary_seq: second,
            landed_root: grain(8),
            landed_seq: 3,
            captured_entries: vec![],
            entries: vec![],
        };
        f.overlay
            .record_landed(&mut f.store, &f.owner, &second)
            .unwrap();
        f.overlay
            .record_intent_registered(
                &mut f.store,
                &f.owner,
                20,
                grain(8),
                codec::IntentCause::LandedRefresh,
            )
            .unwrap();
        let before = f.io.bytes(&f.overlay.journal_path());
        let result = f.overlay.replace_landed(&mut f.store, &f.owner, second);
        assert_eq!(
            (
                result.map_err(|error| error.to_string()),
                f.io.bytes(&f.overlay.journal_path()) == before
            ),
            (
                Err("overlay refused: landing refers to absorbed boundary".to_owned()),
                true
            ),
            "{evidence}"
        );
        count += 1;
    }
    assert_eq!(count, 3);
}

#[test]
fn commit_fence_report_uses_cached_summary_when_the_area_is_unreadable() {
    for unreadable in [true, false] {
        let mut f = Fixture::new();
        let id = f.create();
        f.write(id, b"retained");
        let summary = f.overlay.summary();
        let mut records = 0;
        codec::scan_journal_with(&f.io.bytes(&f.overlay.journal_path()), |_, _| records += 1)
            .unwrap();
        assert_eq!(
            (summary.records, records > 0),
            (records, true),
            "{summary:?}: counted {records}"
        );
        assert!(
            summary.charged_bytes > 0 && summary.records > 0,
            "{summary:?}"
        );
        let log = LogBytes::default();
        let guard = tracing::subscriber::set_default(observe::subscriber(
            observe::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            log.clone(),
        ));
        f.io.0.lock().unwrap().trace.clear();
        if unreadable {
            f.io.0.lock().unwrap().fail = Some("entries");
        }
        f.overlay
            .report_commit_fenced(observe::FailureClass::Conflict);
        drop(guard);
        let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            (
                text.lines()
                    .filter(|l| l.contains("\"event\":\"overlay.refused\""))
                    .count(),
                f.io.0.lock().unwrap().trace.len()
            ),
            (1, 0),
            "unreadable={unreadable}: {text}"
        );
        assert!(
            text.contains(&format!("\"bytes\":{}}}", summary.charged_bytes)),
            "{text}"
        );
        assert!(
            text.contains(&format!("\"record_index\":{records},")),
            "{text}"
        );
    }
}

fn projected(
    f: &mut Fixture,
    through_seq: u64,
    selection: Option<codec::ProjectedSelection>,
) -> u64 {
    f.overlay
        .append(&Record::ProjectedBoundary {
            candidate: grain(9),
            through_seq,
            publication_id: [9; 16],
            selection,
        })
        .unwrap()
}

#[test]
fn projected_boundary_is_open_commit_evidence_after_restart() {
    let mut f = Fixture::new();
    // An empty file: the crash below keeps no unsynced staging bytes.
    let id = f.create();
    let selection = Some(codec::ProjectedSelection {
        stage_id: id,
        content: grain(4),
        size: 0,
    });
    f.io.0.lock().unwrap().trace.clear();
    let through = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
    let b = projected(&mut f, through, selection);
    let path = f.overlay.journal_path();
    let barriers =
        f.io.0
            .lock()
            .unwrap()
            .trace
            .iter()
            .filter(|(op, p)| *p == path && matches!(op.as_str(), "write" | "sync"))
            .map(|(op, _)| op.clone())
            .collect::<Vec<_>>();
    for n in 1..=8 {
        charge(&mut f, b, 9, n);
    }
    fence(&mut f, b, 9);
    f.io.crash();
    f.reopen().unwrap();
    let commits = f.overlay.recovery_commits(&mut f.store, &f.owner).unwrap();
    let entries = f
        .overlay
        .commit_entries(b, [9; 16])
        .map_err(|e| e.to_string());
    assert_eq!(
        (
            barriers,
            f.overlay.readiness(),
            commits,
            progress(&mut f, 9),
            entries
        ),
        (
            vec!["sync".to_owned(), "write".to_owned(), "sync".to_owned()],
            OverlayReadiness::PendingRecovery,
            vec![RecoveryCommit::Boundary {
                index: b,
                candidate: grain(9),
                through_seq: through,
                publication_id: [9; 16],
                selection: BoundarySelection::Projected(selection),
            }],
            Some(expected(8, true)),
            Err("overlay refused: commit prefix binding".to_owned())
        )
    );
    assert!(f.overlay.entries(&mut f.store, &f.owner).is_err());
}

#[test]
fn projected_boundary_replacement_remaps_its_cursor_and_rebinds_its_selection() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"landed");
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    let selection = Some(codec::ProjectedSelection {
        stage_id: id,
        content: grain(4),
        size: 6,
    });
    let through = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
    let pending = projected(&mut f, through, selection);
    charge(&mut f, pending, 9, 1);
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    let mut observed = Vec::new();
    for reopen in [false, true] {
        if reopen {
            f.io.crash();
            f.reopen().unwrap();
        }
        let bytes = f.io.bytes(&f.overlay.journal_path());
        let mut records = Vec::new();
        codec::scan_journal_with(&bytes, |seq, record| records.push((seq, record.clone())))
            .unwrap();
        observed.push((
            records,
            f.overlay.recovery_commits(&mut f.store, &f.owner).unwrap(),
            progress(&mut f, 9),
        ));
    }
    let rebind = |(_, record): &(u64, Record)| matches!(record, Record::StageBind { cause: codec::BindCause::Rebind, stage_id, .. } if *stage_id == id);
    let (records, commits, charged) = &observed[0];
    assert_eq!(
        (
            records.first().is_some_and(rebind),
            records
                .iter()
                .map(|(seq, record)| (*seq, record.kind()))
                .collect::<Vec<_>>(),
            commits.as_slice(),
            *charged,
        ),
        (
            true,
            vec![(1, 2), (2, 10), (3, 15), (4, 13)],
            &[RecoveryCommit::Boundary {
                index: 3,
                candidate: grain(9),
                through_seq: 2,
                publication_id: [9; 16],
                selection: BoundarySelection::Projected(selection),
            }][..],
            Some(expected(1, false)),
        )
    );
    assert_eq!(observed[1], observed[0], "reopened replacement");
}

#[test]
fn projected_boundary_rejected_replacement_refuses_it_as_target_or_suffix() {
    let mut count = 0;
    for target_is_projected in [false, true] {
        let mut f = Fixture::new();
        let ordinary = boundary(&mut f, 7);
        let through = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
        let projected = projected(&mut f, through, None);
        let (target, publication) = if target_is_projected {
            (projected, [9; 16])
        } else {
            (ordinary, [7; 16])
        };
        let before = f.io.bytes(&f.overlay.journal_path());
        let result = f
            .overlay
            .replace_rejected(&mut f.store, &f.owner, target, publication);
        assert_eq!(
            (
                result.map_err(|error| error.to_string()),
                f.io.bytes(&f.overlay.journal_path()) == before,
                progress(&mut f, 7),
                progress(&mut f, 9)
            ),
            (
                Err("overlay refused: rejection boundary binding".to_owned()),
                true,
                Some(expected(0, false)),
                Some(expected(0, false))
            ),
            "projected target: {target_is_projected}"
        );
        count += 1;
    }
    assert_eq!(count, 2);
}

#[test]
fn projected_boundary_reopen_holds_service_without_splitting_dirty_spans() {
    let mut observed = Vec::new();
    for projected_kind in [false, true] {
        let mut f = Fixture::new();
        f.create();
        let b = if projected_kind {
            let through = f.overlay.journal.lock().unwrap().state.next_seq() - 1;
            projected(&mut f, through, None)
        } else {
            boundary(&mut f, 9)
        };
        f.io.crash();
        f.reopen().unwrap();
        observed.push((
            b,
            f.overlay.readiness(),
            f.overlay.last_boundary_seq,
            f.overlay.dirty_split_seq,
        ));
    }
    assert_eq!(
        observed,
        [
            (2, OverlayReadiness::PendingRecovery, 2, 2),
            (2, OverlayReadiness::PendingRecovery, 0, 0)
        ]
    );
}
