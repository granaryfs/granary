// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn counter(f: &Fixture, series: &str) -> u64 {
    f.metrics()
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{series} ")))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "paired retry observations include the durable restart and exact emitted attempt"
)]
async fn commit_reporting_counts_started_transient_and_disjoint_rebase_retries() {
    let mut cases = 0;
    for (label, answer, reason, restart) in [
        (
            "transient answer",
            PublishPlan::RateLimited,
            "transient",
            false,
        ),
        (
            "disjoint rebase",
            PublishPlan::StaleForeign,
            "conflict",
            false,
        ),
        (
            "resumed disjoint rebase",
            PublishPlan::StaleForeign,
            "conflict",
            true,
        ),
    ] {
        let f = Fixture::new().await;
        f.create("local", b"sealed");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([answer, PublishPlan::Land]);
        let (f, lane) = if restart {
            let faults = f.store.lock().unwrap().fault_control();
            faults.arm("sync.commit", "before_submit", 2, FaultAction::Fail);
            let interrupted = Box::pin(f.engine.drive_commit(
                &lane,
                &mut Entropy(80),
                &mut Delay,
                RecoveryIntent::Continue,
                SyncOptions::default(),
            ))
            .await;
            assert_eq!(
                (
                    interrupted.as_ref().err().map(ToString::to_string),
                    f.remote.publication_sends.lock().unwrap().len(),
                    counter(
                        &f,
                        "granary_client_commit_retries_total{reason=\"conflict\"}"
                    )
                ),
                (
                    Some(
                        "publication journal: journal: intent refused: SyncInjectedFault"
                            .to_owned()
                    ),
                    1,
                    0
                ),
                "{label}: {interrupted:?}"
            );
            let f = f.restart().await;
            let lane = f.engine.recover_commit(SyncOptions::default()).unwrap();
            (f, lane)
        } else {
            (f, lane)
        };
        let log = TimingLog::default();
        let guard = tracing::subscriber::set_default(crate::observe::subscriber(
            crate::observe::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            log.clone(),
        ));
        let result = budget::drive(&f, &lane, &mut Delay).await;
        drop(guard);
        let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        let retries: Vec<_> = text
            .lines()
            .filter(|line| line.contains("\"event\":\"op.retry\""))
            .collect();
        assert_eq!(
            (
                matches!(result.outcome, PublicationOutcome::Landed(_)),
                f.remote.publication_sends.lock().unwrap().len(),
                counter(
                    &f,
                    &format!("granary_client_commit_retries_total{{reason=\"{reason}\"}}")
                ),
                retries.len()
            ),
            (true, 2, 1, 1),
            "{label}: {text}"
        );
        assert_eq!(
            (
                retries[0].contains("\"attempt\":2"),
                retries[0].contains(&format!("\"reason\":\"{reason}\""))
            ),
            (true, true),
            "{label}: {text}"
        );
        assert_eq!(
            counter(&f, "granary_client_rebase_conflicts_total"),
            0,
            "{label}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[tokio::test]
async fn commit_reporting_omits_retry_when_next_attempt_save_is_refused() {
    let f = Fixture::new().await;
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::RateLimited, PublishPlan::Land]);
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "before_submit", 2, FaultAction::Fail);
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let result = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            result.as_ref().err().map(ToString::to_string),
            f.remote.publication_sends.lock().unwrap().len(),
            counter(
                &f,
                "granary_client_commit_retries_total{reason=\"transient\"}"
            ),
            text.lines()
                .filter(|line| line.contains("\"event\":\"op.retry\""))
                .count()
        ),
        (
            Some("publication journal: journal: intent refused: SyncInjectedFault".to_owned()),
            1,
            0,
            0
        ),
        "second attempt-save cut: {result:?}; {text}"
    );
    budget::drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (
            f.remote.publication_sends.lock().unwrap().len(),
            counter(
                &f,
                "granary_client_commit_retries_total{reason=\"transient\"}"
            )
        ),
        (2, 1)
    );
}

#[tokio::test]
async fn commit_reporting_counts_overlapping_rebase_once() {
    let f = Fixture::new().await;
    f.create("private-name", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    rebase::foreign_head(&f, "private-name").await;
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::StaleCurrent, PublishPlan::Land]);
    let result = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    assert_eq!(
        (
            matches!(result, Err(CoordinationError::Fenced { .. })),
            f.remote.publication_sends.lock().unwrap().len(),
            counter(&f, "granary_client_rebase_conflicts_total"),
            counter(
                &f,
                "granary_client_commit_retries_total{reason=\"conflict\"}"
            )
        ),
        (true, 0, 1, 0),
        "overlapping rebase: {result:?}"
    );
}

#[tokio::test]
async fn commit_reporting_does_not_treat_a_provider_conflict_as_overlapping_names() {
    let f = Fixture::new().await;
    f.create("local", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    rebase::foreign_head(&f, "remote").await;
    f.content.put_conflict.store(true, Ordering::Relaxed);
    let result = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    assert_eq!(
        (
            matches!(result, Err(CoordinationError::Fenced { .. })),
            f.remote.publication_sends.lock().unwrap().len(),
            counter(&f, "granary_client_rebase_conflicts_total")
        ),
        (true, 0, 0),
        "provider conflict without overlapping names: {result:?}"
    );
}

#[tokio::test]
async fn commit_reporting_does_not_count_candidate_recomputation_as_a_rebase_attempt() {
    let f = Fixture::new().await;
    f.create("local", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let head = rebase::foreign_head(&f, "local").await;
    let mut record = rebase::load(&f);
    let mut doc = granary_core::root::decode_root(&record.frozen.initial_root).unwrap();
    doc.seq = 3;
    doc.parent = Some(GrainId::of(&head));
    let mut candidate = record.candidates[0].clone();
    record.candidates[0].role = granary_core::retained_submission::Role::History;
    candidate.number = 2;
    candidate.seq = doc.seq;
    candidate.root = rebase::signed(doc);
    candidate.id = GrainId::of(&candidate.root);
    record.candidates.push(candidate);
    let generation = record.generation;
    record.generation += 1;
    let error = f
        .engine
        .replace_commit_record(&lane, generation, &record)
        .await
        .unwrap_err();
    assert_eq!(
        (
            error.kind,
            error.reason.as_str(),
            counter(&f, "granary_client_rebase_conflicts_total")
        ),
        (
            crate::PublicationStoreErrorKind::Conflict,
            "overlay namespace conflict",
            0
        )
    );
    f.store
        .lock()
        .unwrap()
        .publication_transaction(|j| j.replace(generation, &record))
        .unwrap();
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let result = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            matches!(result, Err(CoordinationError::Fenced { .. })),
            counter(&f, "granary_client_rebase_conflicts_total"),
            text.lines()
                .filter(|line| line.contains("\"event\":\"op.conflict\"")
                    && line.contains("\"path\":\"<file>\""))
                .count()
        ),
        (true, 0, 1),
        "recomputation fence: {result:?}: {text}"
    );
}

#[tokio::test]
async fn commit_reporting_stale_base_retry_keeps_conflict_after_unavailable_rebase() {
    let f = Fixture::new().await;
    f.create("local", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::StaleParentUnavailable, PublishPlan::Land]);
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let first = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ))
    .await;
    assert_eq!(
        (
            first.as_ref().err().map(crate::sync::failure_class),
            f.remote.publication_sends.lock().unwrap().len(),
            counter(
                &f,
                "granary_client_commit_retries_total{reason=\"unavailable\"}"
            )
        ),
        (Some(crate::FailureClass::Unavailable), 1, 0),
        "{first:?}: {}",
        f.metrics()
    );
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "before_submit", 1, FaultAction::Fail);
    let failed = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ))
    .await;
    assert_eq!(
        (
            failed.err().map(|e| e.to_string()),
            f.remote.publication_sends.lock().unwrap().len(),
            counter(
                &f,
                "granary_client_commit_retries_total{reason=\"unavailable\"}"
            )
        ),
        (
            Some("publication journal: journal: intent refused: SyncInjectedFault".to_owned()),
            1,
            0
        )
    );
    let done = budget::drive(&f, &lane, &mut Delay).await;
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            matches!(done.outcome, PublicationOutcome::Landed(_)),
            f.remote.publication_sends.lock().unwrap().len(),
            counter(
                &f,
                "granary_client_commit_retries_total{reason=\"unavailable\"}"
            ),
            counter(
                &f,
                "granary_client_commit_retries_total{reason=\"conflict\"}"
            ),
            text.lines()
                .filter(|l| l.contains("\"event\":\"op.retry\"")
                    && l.contains("\"reason\":\"conflict\"")
                    && l.contains("\"attempt\":2"))
                .count()
        ),
        (true, 2, 0, 1, 1),
        "{text}\n{}",
        f.metrics()
    );
}

#[tokio::test]
async fn commit_reporting_stale_base_retry_keeps_conflict_after_unavailable_verification() {
    let f = Fixture::new().await;
    f.create("local", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::StaleForeign, PublishPlan::Land]);
    f.store.lock().unwrap().fault_control().arm(
        "sync.commit",
        "before_submit",
        2,
        FaultAction::Fail,
    );
    let first = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ))
    .await;
    assert_eq!(
        (
            first.err().map(|e| e.to_string()),
            f.remote.publication_sends.lock().unwrap().len()
        ),
        (
            Some("publication journal: journal: intent refused: SyncInjectedFault".to_owned()),
            1
        )
    );
    f.remote.offline.store(true, Ordering::Relaxed);
    let unavailable = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(81),
        &mut Delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ))
    .await;
    assert_eq!(
        (
            unavailable.as_ref().err().map(ToString::to_string),
            f.remote.publication_sends.lock().unwrap().len(),
            counter(
                &f,
                "granary_client_commit_retries_total{reason=\"unavailable\"}"
            )
        ),
        (
            Some("intent refused: SyncCommitRebaseUnavailable".to_owned()),
            1,
            0
        ),
        "{unavailable:?}"
    );
    f.remote.offline.store(false, Ordering::Relaxed);
    let done = budget::drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (
            matches!(done.outcome, PublicationOutcome::Landed(_)),
            f.remote.publication_sends.lock().unwrap().len(),
            counter(
                &f,
                "granary_client_commit_retries_total{reason=\"unavailable\"}"
            ),
            counter(
                &f,
                "granary_client_commit_retries_total{reason=\"conflict\"}"
            )
        ),
        (true, 2, 0, 1),
        "{}",
        f.metrics()
    );
}
