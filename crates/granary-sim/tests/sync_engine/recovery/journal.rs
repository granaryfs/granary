// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::super::support::journal::Journal;
use super::*;
use granary_client::{FaultAction, FaultControl, RecoveryOutcome};

#[expect(
    clippy::too_many_lines,
    reason = "one restart fixture preserves the real capture, publication and durable handoff sequence"
)]
fn fixture(seed: u64, mode: &str) -> Journal {
    let fixture = Fixture::new();
    let stage = fixture.create("local", b"sealed");
    assert!(fixture.sync(seed, stage).0.is_ok());
    super::super::support::journal::persist_content(&fixture);
    if mode == "plain" {
        return Journal::new(fixture);
    }
    let faults = fixture.store.lock().unwrap().fault_control();
    if mode == "unsubmitted" {
        faults.arm("sync.commit", "boundary_recorded", 1, FaultAction::Fail);
    }
    let lane = fixture
        .runtime
        .run(
            seed,
            100_000,
            fixture.engine.construct_commit(
                SyncOptions::default(),
                &mut SeededSecureRandom::for_incarnation(seed, 70),
            ),
        )
        .unwrap()
        .0;
    if mode == "unsubmitted" {
        assert!(lane.is_err(), "unsubmitted cut: {lane:?}");
        return Journal::new(fixture);
    }
    let lane = lane.unwrap();
    if matches!(mode, "landed" | "variant" | "mount-refresh") {
        fixture.create("suffix", b"remaining");
    }
    if matches!(mode, "conflict-answered" | "conflict-never-sent") {
        fixture.create("suffix", b"remaining");
        let foreign = super::prepare(&fixture, seed + 1, &[("local", b"foreign")], FOREIGN);
        fixture.publish_root(foreign);
        if mode == "conflict-answered" {
            let mut local = fixture.store.lock().unwrap();
            let scope = local.snapshot().scope.clone();
            let volume = local.snapshot().volume.clone();
            let mut record = local
                .publication_transaction(|j| j.load(&scope, &volume))
                .unwrap()
                .unwrap();
            let generation = record.generation;
            let candidate = record.candidates.first_mut().unwrap();
            let attempt = candidate.evidence.start().unwrap();
            candidate.evidence.answer(attempt, true, false).unwrap();
            record.last_response = Some(granary_core::retained_submission::LastResponse {
                candidate: candidate.number,
                attempt,
                status: 409,
                token: b"stale-base".to_vec(),
                answer: vec![],
            });
            record.generation += 1;
            local
                .publication_transaction(|j| j.replace(generation, &record))
                .unwrap();
        }
        return Journal::new(fixture);
    }
    let record = {
        let mut local = fixture.store.lock().unwrap();
        let scope = local.snapshot().scope.clone();
        let volume = local.snapshot().volume.clone();
        local
            .publication_transaction(|j| j.observe(&scope, &volume))
            .unwrap()
            .unwrap()
    };
    if mode == "mount-refresh" {
        faults.arm("sync.commit", "landed_refresh", 1, FaultAction::Fail);
    } else {
        fixture
            .remote
            .publication_plan
            .lock()
            .unwrap()
            .extend((0..8).map(|_| {
                if mode == "no-write" {
                    PublishPlan::RateLimited
                } else {
                    PublishPlan::Timeout
                }
            }));
    }
    let result = fixture
        .runtime
        .run(
            seed,
            100_000,
            Box::pin(fixture.engine.drive_commit(
                &lane,
                &mut SeededSecureRandom::for_incarnation(seed, 71),
                &mut Delay,
                RecoveryIntent::Continue,
                SyncOptions::default(),
            )),
        )
        .unwrap()
        .0;
    if mode == "mount-refresh" {
        assert_eq!(
            result.err().map(|error| error.to_string()),
            Some("intent refused: SyncInjectedFault".into())
        );
        return Journal::new(fixture);
    }
    let result = result.unwrap();
    assert_eq!(
        result.outcome,
        PublicationOutcome::Exhausted,
        "mode={mode}: {result:?}"
    );
    if matches!(mode, "landed" | "variant") {
        let mut bytes = record.candidates.first().unwrap().root.clone();
        if mode == "variant" {
            let mut doc = granary_core::root::decode_root(&bytes).unwrap();
            doc.sigs.push(RootSig {
                key_id: [98; 32],
                sig: [0; 64],
            });
            bytes = granary_core::root::encode_root(&doc).unwrap();
        }
        fixture.publish_root(bytes);
    }
    if matches!(mode, "conflict" | "disjoint" | "generic-fence") {
        let foreign = super::prepare(
            &fixture,
            seed + 1,
            &[(
                if mode == "conflict" {
                    "local"
                } else {
                    "remote"
                },
                b"foreign",
            )],
            FOREIGN,
        );
        fixture.publish_root(foreign);
        if mode == "generic-fence" {
            fixture
                .remote
                .publication_plan
                .lock()
                .unwrap()
                .push_back(PublishPlan::Reject);
        }
    }
    Journal::new(fixture)
}

#[test]
fn settled_and_plain_dirty_journals_finish_without_archive_provenance() {
    let mut cases = 0;
    for seed in [1, 42] {
        for mode in ["plain", "no-write", "unsubmitted", "landed", "variant"] {
            let journal = fixture(seed, mode);
            let capture = super::super::commit_faults::Capture::default();
            let _guard = tracing::subscriber::set_default(granary_client::subscriber(
                granary_client::LogFormat::Json,
                tracing_subscriber::EnvFilter::new("trace"),
                capture.clone(),
            ));
            let result = journal.run(1, FaultControl::default(), false);
            let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            assert_eq!(
                (
                    matches!(result, Ok(RecoveryOutcome::JournalFinished { .. })),
                    journal.classifier(),
                    journal.released(),
                    if result.is_ok() {
                        journal.file("local")
                    } else {
                        Vec::new()
                    },
                    journal.remote.publication_sends.lock().unwrap().len(),
                    text.contains("recover.journal_finished")
                ),
                (
                    true,
                    RecoveryRule::Nothing,
                    true,
                    b"sealed".to_vec(),
                    if matches!(mode, "plain" | "unsubmitted") {
                        1
                    } else {
                        9
                    },
                    true
                ),
                "seed={seed}, mode={mode}, cases={}, {result:?}: {text}",
                cases + 1
            );
            if matches!(mode, "landed" | "variant") {
                assert_eq!(journal.file("suffix"), b"remaining");
            }
            cases += 1;
        }
    }
    assert_eq!(cases, 10);
}

#[test]
fn completed_settlement_and_install_do_not_hide_unfinished_remainder() {
    let mut cases = 0;
    for mode in ["no-write", "landed", "variant"] {
        let journal = fixture(42, mode);
        let faults = FaultControl::default();
        faults.arm("sync.commit", "before_submit", 1, FaultAction::Fail);
        let capture = super::super::commit_faults::Capture::default();
        let _guard = tracing::subscriber::set_default(granary_client::subscriber(
            granary_client::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            capture.clone(),
        ));
        let result = journal.run(1, faults.clone(), false);
        let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            (
                result.is_err(),
                faults.sync_fired().len(),
                journal.released(),
                text.contains("recover.fence_settled"),
                text.contains("recover.journal_blocked"),
                text.contains("recover.journal_finished")
            ),
            (true, 1, false, true, true, false),
            "mode={mode}, cases={}, {result:?}: {text}",
            cases + 1
        );
        let result = journal.run(2, FaultControl::default(), false);
        assert_eq!(
            (result.is_ok(), journal.released(), journal.file("local")),
            (true, true, b"sealed".to_vec()),
            "mode={mode}: {result:?}"
        );
        if matches!(mode, "landed" | "variant") {
            assert_eq!(journal.file("suffix"), b"remaining");
        }
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn normalization_and_release_crash_cuts_rederive_completion() {
    let mut cases = 0;
    for (name, phase) in [
        ("sync.commit", "before_replace"),
        ("recover.release", "before"),
        ("recover.release", "prepared"),
        ("recover.release", "confirmed"),
    ] {
        let journal = fixture(42, "landed");
        let faults = FaultControl::default();
        faults.arm(name, phase, 1, FaultAction::Crash);
        let cut = journal.run(1, faults.clone(), false);
        assert_eq!(
            (
                cut.is_err(),
                faults.fired().len() + faults.sync_fired().len()
            ),
            (true, 1),
            "{name}/{phase}, cases={}, {cut:?}",
            cases + 1
        );
        let sends = journal.remote.publication_sends.lock().unwrap().len();
        let result = journal.run(2, FaultControl::default(), false);
        assert_eq!(
            (
                result.is_ok(),
                journal.released(),
                if result.is_ok() {
                    journal.file("suffix")
                } else {
                    Vec::new()
                },
                journal.remote.publication_sends.lock().unwrap().len()
            ),
            (
                true,
                true,
                b"remaining".to_vec(),
                if name == "sync.commit" {
                    sends + 1
                } else {
                    sends
                }
            ),
            "{name}/{phase}: {result:?}"
        );
        let result = journal.run(3, FaultControl::default(), false);
        assert_eq!(
            (
                result.is_ok(),
                journal.remote.publication_sends.lock().unwrap().len()
            ),
            (true, 9),
            "released rerun {name}/{phase}: {result:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn same_head_conflict_refuses_without_release_or_finished_event() {
    let mut cases = 0;
    for mode in ["conflict", "disjoint", "generic-fence"] {
        let journal = fixture(42, mode);
        for attempt in 1..=if mode == "conflict" { 2 } else { 1 } {
            let capture = super::super::commit_faults::Capture::default();
            let _guard = tracing::subscriber::set_default(granary_client::subscriber(
                granary_client::LogFormat::Json,
                tracing_subscriber::EnvFilter::new("trace"),
                capture.clone(),
            ));
            let result = journal.run(attempt, FaultControl::default(), false);
            let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            assert_eq!(
                (
                    result.is_ok(),
                    result
                        .as_ref()
                        .err()
                        .is_some_and(|e| e == "intent refused: RecoveryConflict"),
                    journal.released(),
                    text.contains("recover.conflict"),
                    text.contains("recover.journal_finished")
                ),
                (
                    mode == "disjoint",
                    mode == "conflict",
                    mode == "disjoint",
                    mode == "conflict",
                    mode == "disjoint"
                ),
                "mode={mode}, attempt={attempt}, cases={}, {result:?}: {text}",
                cases + 1
            );
            if mode == "generic-fence" {
                assert!(
                    result
                        .as_ref()
                        .err()
                        .is_some_and(|error| (error.starts_with("commit publication ")
                            && error.ends_with(" fenced (ESTALE)"))
                            || error.starts_with("intent fenced (ESTALE)")),
                    "{result:?}"
                );
            }
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

#[test]
fn conflict_strip_preserves_post_boundary_work_without_publishing() {
    let mut cases = 0;
    for seed in [1, 42, 43] {
        for mode in ["conflict-answered", "conflict-never-sent"] {
            let journal = fixture(seed, mode);
            let capture = super::super::commit_faults::Capture::default();
            let _guard = tracing::subscriber::set_default(granary_client::subscriber(
                granary_client::LogFormat::Json,
                tracing_subscriber::EnvFilter::new("trace"),
                capture.clone(),
            ));
            let sends = journal.remote.publication_sends.lock().unwrap().len();
            let result = journal.run(1, FaultControl::default(), false);
            let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            assert_eq!(
                (
                    result,
                    journal.released(),
                    text.contains("\"how\":\"stripped\""),
                    text.contains("recover.conflict"),
                    text.contains("recover.journal_finished"),
                    journal.remote.publication_sends.lock().unwrap().len()
                ),
                (
                    Err("intent refused: RecoveryConflict".into()),
                    false,
                    true,
                    true,
                    false,
                    sends
                ),
                "seed={seed}, mode={mode}, cases={}, {text}",
                cases + 1
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 6);
}

#[test]
fn landed_reselection_refreshes_only_after_renewed_acknowledgement() {
    let mut cases = 0;
    for seed in [1, 42, 43] {
        let journal = fixture(seed, "mount-refresh");
        journal.displace();
        let sends = journal.remote.publication_sends.lock().unwrap().len();
        let refused = journal.run(2, FaultControl::default(), false);
        assert_eq!(
            (
                refused.err(),
                journal.classifier(),
                journal.remote.publication_sends.lock().unwrap().len()
            ),
            (
                Some("intent refused: RecoveryLandedUnowned".into()),
                RecoveryRule::LandedUnowned,
                sends
            ),
            "seed={seed}, cases={}",
            cases + 1
        );
        let result = journal.run(3, FaultControl::default(), true);
        assert_eq!(
            (
                result.is_ok(),
                journal.classifier(),
                journal.released(),
                if result.is_ok() {
                    journal.file("suffix")
                } else {
                    Vec::new()
                },
                journal.remote.publication_sends.lock().unwrap().len()
            ),
            (
                true,
                RecoveryRule::Nothing,
                true,
                b"remaining".to_vec(),
                sends + 1
            ),
            "seed={seed}, cases={}: {result:?}",
            cases + 1
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}
