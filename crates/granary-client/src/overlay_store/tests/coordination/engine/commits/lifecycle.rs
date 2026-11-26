// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

use super::reporting::counter;

struct MeasuredDelay {
    time: Arc<Time>,
    waits: usize,
}
impl RecoveryDelay for MeasuredDelay {
    fn jitter(&mut self, _: Duration) -> Duration {
        Duration::ZERO
    }
    fn wait(&mut self, _: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.waits += 1;
        self.time.ticks.store(20, Ordering::Relaxed);
        self.time.wall.store(100_000, Ordering::Relaxed);
        Box::pin(async {})
    }
}

#[tokio::test]
async fn commit_lifecycle_measures_only_drive_and_counts_one_terminal_after_retries() {
    let f = Fixture::new().await;
    f.create("file", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    // Construction and waiting precede the measured attempt.
    f.remote.time.ticks.store(10, Ordering::Relaxed);
    f.remote.time.wall.store(1_000, Ordering::Relaxed);
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::RateLimited, PublishPlan::Land]);
    let mut delay = MeasuredDelay {
        time: f.remote.time.clone(),
        waits: 0,
    };
    let done = budget::drive(&f, &lane, &mut delay).await;
    assert_eq!(
        (
            matches!(done.outcome, PublicationOutcome::Landed(_)),
            f.remote.publication_sends.lock().unwrap().len(),
            counter(&f, "granary_client_commits_total{result=\"ok\"}"),
            counter(
                &f,
                "granary_client_commit_duration_seconds_count{result=\"ok\"}"
            ),
            f.metrics()
                .contains("granary_client_commit_duration_seconds_sum{result=\"ok\"} 0.025000\n")
        ),
        (true, 2, 1, 1, true),
        "{}",
        f.metrics()
    );
    assert_eq!(delay.waits, 1, "retry wait count: {}", delay.waits);
    let again = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    assert!(
        again.is_err(),
        "retired lane unexpectedly resumed: {again:?}"
    );
    assert_eq!(
        counter(&f, "granary_client_commits_total{result=\"ok\"}"),
        1
    );
}

#[tokio::test]
async fn commit_lifecycle_omits_unavailable_and_reversed_timing_without_losing_terminal_count() {
    let mut cases = 0;
    for (label, ticks, start_unavailable, unavailable) in [
        ("start unavailable", 10, true, false),
        ("elapsed unavailable", 10, false, true),
        ("clock reversed", 40, false, false),
    ] {
        let f = Fixture::new().await;
        f.create("file", b"sealed");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        f.remote.time.ticks.store(ticks, Ordering::Relaxed);
        f.remote
            .time
            .start_unavailable
            .store(start_unavailable, Ordering::Relaxed);
        f.remote
            .time
            .unavailable
            .store(unavailable, Ordering::Relaxed);
        let done = budget::drive(&f, &lane, &mut Delay).await;
        assert_eq!(
            (
                matches!(done.outcome, PublicationOutcome::Landed(_)),
                counter(&f, "granary_client_commits_total{result=\"ok\"}"),
                counter(
                    &f,
                    "granary_client_commit_duration_seconds_count{result=\"ok\"}"
                )
            ),
            (true, 1, 0),
            "{label}: {}",
            f.metrics()
        );
        assert_eq!(
            (
                counter(&f, "granary_client_metrics_available{group=\"commit\"}"),
                counter(&f, "granary_client_metrics_overflow{metric=\"M06\"}")
            ),
            (1, 1),
            "{label}: {}",
            f.metrics()
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one report compares the terminal tuple, exact accounting and every staged byte"
)]
async fn commit_lifecycle_reports_exhaustion_and_retained_prefix_and_suffix_work() {
    let f = Fixture::new().await;
    f.create("prefix", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    f.create("suffix", b"retained");
    let journal_path =
        f.io.0
            .lock()
            .unwrap()
            .names
            .keys()
            .find(|p| p.file_name().is_some_and(|n| n == "journal"))
            .unwrap()
            .clone();
    let journal_before = f.io.bytes(&journal_path);
    let stage_paths: Vec<_> =
        f.io.0
            .lock()
            .unwrap()
            .names
            .keys()
            .filter(|p| p.components().any(|n| n.as_os_str() == "staging"))
            .cloned()
            .collect();
    let stages: Vec<_> = stage_paths
        .into_iter()
        .map(|p| {
            let bytes = f.io.bytes(&p);
            (p, bytes)
        })
        .collect();
    let before = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| Ok(t.summary()))
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::RateLimited; 8]);
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let done = budget::drive(&f, &lane, &mut Delay).await;
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let records: Vec<_> = text.lines().collect();
    let report: Vec<_> = records
        .iter()
        .filter(|r| r.contains("\"event\":\"overlay.refused\""))
        .collect();
    assert_eq!(
        (
            done.outcome,
            counter(&f, "granary_client_commits_total{result=\"exhausted\"}"),
            report.len()
        ),
        (PublicationOutcome::Exhausted, 1, 1),
        "{text}"
    );
    let report = report[0];
    let journal_after = f.io.bytes(&journal_path);
    let expected_bytes = before.charged_bytes + (journal_after.len() - journal_before.len()) as u64;
    let reported_bytes = report
        .split("\"bytes\":")
        .nth(1)
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.parse::<u64>().ok());
    assert_eq!(
        (
            report.contains("\"class\":\"refused\""),
            report.contains("\"files\":2,"),
            reported_bytes,
            report.contains(&format!("\"record_index\":{},", before.records + 9))
        ),
        (true, true, Some(expected_bytes), true),
        "{text}"
    );
    assert!(
        journal_after.starts_with(&journal_before),
        "sealed journal was discarded"
    );
    assert_eq!(stages.len(), 2);
    for (path, bytes) in stages {
        assert_eq!(f.io.bytes(&path), bytes, "retained stage {path:?}");
    }
    assert!(before.charged_bytes > 0 && before.records > 0, "{before:?}");
    assert!(
        records
            .iter()
            .any(|r| r.contains("\"event\":\"op.failed\"") && r.contains("\"class\":\"refused\"")),
        "{text}"
    );
    assert!(
        matches!(
            f.store
                .lock()
                .unwrap()
                .overlay_transaction(|t| t.create_file(at("refused"), false)),
            Err(CoordinationError::CommitFenced { .. } | CoordinationError::Fenced { .. })
        ),
        "fence missing"
    );
}

#[tokio::test]
async fn commit_lifecycle_conflict_has_redacted_path_and_terminal_metric() {
    let mut cases = 0;
    for policy in [crate::LogPaths::Redacted, crate::LogPaths::Full] {
        let f = Fixture::new().await;
        f.create("private-name", b"sealed");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        rebase::foreign_head(&f, "private-name").await;
        let log = TimingLog::default();
        let history = crate::BundleHistory::default();
        let guard = tracing::subscriber::set_default(crate::observe::closed_subscriber_with_paths(
            crate::observe::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            log.clone(),
            policy,
            history.clone(),
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
        let records: Vec<_> = text.lines().collect();
        let conflict: Vec<_> = records
            .iter()
            .filter(|r| r.contains("\"event\":\"op.conflict\""))
            .collect();
        assert_eq!(
            (
                matches!(result, Err(CoordinationError::Fenced { .. })),
                counter(&f, "granary_client_commits_total{result=\"conflict\"}"),
                counter(&f, "granary_client_rebase_conflicts_total"),
                conflict.len()
            ),
            (true, 1, 1, 1),
            "{result:?}: {text}"
        );
        let correlation = r#""op":"cor-4848484848484848""#;
        assert!(
            conflict[0].matches("\"name\":\"op\"").count() == 1
                && conflict[0].contains(correlation),
            "{text}"
        );
        let full = policy == crate::LogPaths::Full;
        assert_eq!(
            (
                conflict[0].contains("\"path\":\"<file>\""),
                text.contains("private-name")
            ),
            (!full, full),
            "{policy:?}: {text}"
        );
        let snapshot = history.snapshot();
        let bundle = snapshot
            .records()
            .iter()
            .map(|record| String::from_utf8_lossy(record.as_bytes()))
            .collect::<String>();
        assert_eq!(
            (
                bundle.contains("private-name"),
                bundle.contains("\"path\":\"<file>\"")
            ),
            (false, true),
            "{bundle}"
        );
        assert!(
            records.iter().any(|r| r.contains("\"event\":\"op.failed\"")
                && r.contains("\"class\":\"conflict\"")
                && r.contains(correlation)),
            "{text}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn commit_lifecycle_cancellation_and_resumption_have_one_local_terminal_observation() {
    let f = Fixture::new().await;
    f.create("file", b"sealed");
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
    f.remote.time.ticks.store(10, Ordering::Relaxed);
    let entered = Arc::new(Notify::new());
    let mut delay = HeldDelay {
        calls: 0,
        at: 1,
        entered: entered.clone(),
    };
    let mut entropy = Entropy(80);
    let mut driving = Box::pin(f.engine.drive_commit(
        &lane,
        &mut entropy,
        &mut delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ));
    let mut answer = Box::pin(entered.notified());
    std::future::poll_fn(|cx| {
        assert!(
            driving.as_mut().poll(cx).is_pending(),
            "driver finished before backoff"
        );
        answer.as_mut().poll(cx)
    })
    .await;
    drop(driving);
    assert_eq!(
        (
            f.remote.publication_sends.lock().unwrap().len(),
            counter(&f, "granary_client_commits_total{result=\"cancelled\"}")
        ),
        (1, 0)
    );
    f.remote.time.ticks.store(20, Ordering::Relaxed);
    let done = budget::drive(&f, &lane.clone(), &mut Delay).await;
    assert_eq!(
        (
            matches!(done.outcome, PublicationOutcome::Landed(_)),
            counter(&f, "granary_client_commits_total{result=\"cancelled\"}"),
            counter(&f, "granary_client_commits_total{result=\"ok\"}"),
            f.metrics()
                .contains("granary_client_commit_duration_seconds_sum{result=\"ok\"} 0.025000\n")
        ),
        (true, 0, 1, true),
        "{}",
        f.metrics()
    );
}

#[tokio::test]
async fn commit_lifecycle_recovered_attempt_cannot_sample_only_the_tail() {
    let f = Fixture::new().await;
    f.create("file", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let faults = f.store.lock().unwrap().fault_control();
    faults.arm("sync.commit", "before_submit", 1, FaultAction::Fail);
    let failed = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    assert_eq!(
        (
            failed.err().map(|e| e.to_string()),
            counter(&f, "granary_client_commits_total{result=\"failed\"}")
        ),
        (
            Some("publication journal: journal: intent refused: SyncInjectedFault".to_owned()),
            0
        )
    );
    let f = f.restart().await;
    let lane = f.engine.recover_commit(SyncOptions::default()).unwrap();
    let done = budget::drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (
            matches!(done.outcome, PublicationOutcome::Landed(_)),
            counter(&f, "granary_client_commits_total{result=\"ok\"}"),
            counter(
                &f,
                "granary_client_commit_duration_seconds_count{result=\"ok\"}"
            )
        ),
        (true, 1, 0)
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "paired terminal and open outcomes share the operation and counter assertions"
)]
async fn commit_lifecycle_classifies_refusal_and_unresolved_without_a_false_success() {
    let mut cases = 0;
    for (label, plan, expected, result, count, class) in [
        (
            "terminal refusal",
            PublishPlan::Reject,
            PublicationOutcome::Refused,
            "failed",
            1,
            "refused",
        ),
        (
            "unresolved probe",
            PublishPlan::Accepted,
            PublicationOutcome::Unresolved,
            "unknown",
            0,
            "unavailable",
        ),
        (
            "backend integrity error",
            PublishPlan::Malformed,
            PublicationOutcome::BackendError,
            "failed",
            0,
            "corrupt",
        ),
    ] {
        let f = Fixture::new().await;
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        if result == "unknown" {
            use granary_core::retained_submission::{Phase, Probe, ProbeReason};
            let mut record = rebase::load(&f);
            record.candidates[0].evidence.start().unwrap();
            record.phase = Phase::Unresolved(Probe {
                cycle: record.generation,
                seq: record.candidates[0].seq,
                reason: ProbeReason::Transport,
            });
            let generation = record.generation;
            record.generation += 1;
            f.store
                .lock()
                .unwrap()
                .publication_transaction(|j| j.replace(generation, &record))
                .unwrap();
        } else {
            f.remote.publication_plan.lock().unwrap().push_back(plan);
        }
        let log = TimingLog::default();
        let guard = tracing::subscriber::set_default(crate::observe::subscriber(
            crate::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            log.clone(),
        ));
        let done = Box::pin(f.engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await
        .unwrap();
        drop(guard);
        let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            (
                text.lines()
                    .filter(|l| l.contains("\"event\":\"op.begin\",\"kind\":\"commit\""))
                    .count(),
                text.lines()
                    .filter(|l| l.contains("\"event\":\"op.end\",\"kind\":\"commit\""))
                    .count(),
                text.lines()
                    .filter(
                        |l| l.contains("\"event\":\"op.failed\",\"kind\":\"commit\"")
                            && l.contains(&format!("\"class\":\"{class}\""))
                    )
                    .count()
            ),
            (1, 1, 1),
            "{label}: {text}"
        );
        assert!(
            text.lines()
                .filter(|l| l.contains("\"kind\":\"commit\""))
                .all(|l| l.matches("\"name\":\"op\"").count() == 1),
            "{label}: {text}"
        );
        assert_eq!(
            (
                done.outcome,
                counter(
                    &f,
                    &format!("granary_client_commits_total{{result=\"{result}\"}}")
                ),
                counter(&f, "granary_client_commits_total{result=\"ok\"}")
            ),
            (expected, count, 0),
            "{label}: {}",
            f.metrics()
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

/// The wire identity sent by the coordinator is named by `op.publish_bound`
/// under the commit's id, once per distinct operation identity. The wrong
/// implementations this catches: no emission, an emission per send, an emission
/// per candidate across a rebase, emitting only the first identity across epoch
/// recovery, an emission naming a different identity than the wire's, and an
/// emission outside the commit's span.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one drive loop exercises four publication schedules and verifies correlation spans"
)]
async fn commit_lifecycle_binds_the_wire_identity_once_under_the_commit_id() {
    fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        line.split(key)
            .nth(1)
            .and_then(|rest| rest.split_once('"'))
            .map(|(val, _)| val)
    }
    let mut cases = 0;
    for (label, rebased, plan, sends, expect_distinct_identities) in [
        ("single send", false, vec![PublishPlan::Land], 1, false),
        (
            "resend after a transient answer",
            false,
            vec![PublishPlan::RateLimited, PublishPlan::Land],
            2,
            false,
        ),
        (
            "rebased candidate",
            true,
            vec![PublishPlan::StaleForeign, PublishPlan::Land],
            2,
            false,
        ),
        (
            "epoch recovery sends a distinct identity",
            false,
            vec![
                PublishPlan::EpochMismatch(granary_core::authlog::Epoch::from_bytes([4; 16])),
                PublishPlan::Land,
            ],
            2,
            true,
        ),
    ] {
        let f = Fixture::new().await;
        f.create("file", b"sealed");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let record = rebase::load(&f);
        let drawn = super::budget::publication_hex(record.current.unwrap().operation);
        f.remote.publication_plan.lock().unwrap().extend(plan);
        let log = TimingLog::default();
        let guard = tracing::subscriber::set_default(crate::observe::subscriber(
            crate::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            log.clone(),
        ));
        let done = budget::drive(&f, &lane, &mut Delay).await;
        drop(guard);
        let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        let event = |name: &str| -> Vec<&str> {
            text.lines()
                .filter(|l| l.contains(&format!("\"event\":\"{name}\"")))
                .collect()
        };
        let wire: Vec<_> = f
            .remote
            .publication_operations
            .lock()
            .unwrap()
            .iter()
            .map(|operation| {
                let bytes: [u8; 16] = operation.as_slice().try_into().unwrap();
                super::budget::publication_hex(bytes)
            })
            .collect();
        let bound = event("op.publish_bound");
        let publication_sends = f.remote.publication_sends.lock().unwrap().clone();
        let rebase_occurred = publication_sends.len() > 1
            && publication_sends[0] == record.frozen.initial_root
            && publication_sends[1] != record.frozen.initial_root;
        let expected_wire = if expect_distinct_identities {
            vec![drawn.clone(), wire.get(1).cloned().unwrap_or_default()]
        } else {
            vec![drawn.clone(); sends]
        };
        let expected_bound: Vec<Option<&str>> = if expect_distinct_identities {
            wire.iter().map(|w| Some(w.as_str())).collect()
        } else {
            vec![Some(drawn.as_str())]
        };
        assert_eq!(
            (
                matches!(done.outcome, PublicationOutcome::Landed(_)),
                if rebased { rebase_occurred } else { true },
                wire.clone(),
                bound
                    .iter()
                    .map(|l| field(l, "\"publish_operation\":\""))
                    .collect::<Vec<_>>(),
            ),
            (true, true, expected_wire, expected_bound,),
            "{label}: {text}"
        );
        if expect_distinct_identities {
            assert_ne!(
                wire[0], wire[1],
                "{label}: epoch recovery must mint a new identity"
            );
        }
        let span_id = |lines: &[&str]| -> Vec<Option<String>> {
            lines
                .iter()
                .map(|l| field(l, "\"op\":\"").map(str::to_owned))
                .collect()
        };
        assert_eq!(
            (
                span_id(&bound),
                span_id(&event("op.begin")),
                span_id(&event("op.end")),
            ),
            (
                vec![Some("cor-4848484848484848".to_owned()); bound.len()],
                vec![Some("cor-4848484848484848".to_owned())],
                vec![Some("cor-4848484848484848".to_owned())],
            ),
            "{label}: {text}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[tokio::test]
async fn commit_lifecycle_missing_correlation_entropy_reports_without_changing_the_fence() {
    struct Dry(usize);
    impl granary_core::secure_random::SecureRandom for Dry {
        fn fill(
            &mut self,
            out: &mut [u8],
        ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
            if self.0 >= out.len() {
                self.0 -= out.len();
                out.fill(70);
                Ok(())
            } else {
                Err(granary_core::secure_random::EntropyUnavailable)
            }
        }
    }
    let f = Fixture::new().await;
    f.create("private-name", b"sealed");
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Dry(32))
        .await
        .unwrap();
    rebase::foreign_head(&f, "private-name").await;
    let result = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Dry(0),
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
            text.lines()
                .filter(|line| line.contains("\"event\":\"op.failed\"")
                    && line.contains("\"kind\":\"commit\"")
                    && line.contains("\"class\":\"unavailable\""))
                .count(),
            text.lines()
                .filter(|line| line.contains("\"event\":\"op.conflict\"")
                    && line.contains("\"path\":\"<file>\""))
                .count(),
            text.contains("private-name"),
            text.lines()
                .filter(|line| line.contains(
                    "\"event\":\"op.failed\",\"kind\":\"session\",\"class\":\"unavailable\""
                ))
                .count()
        ),
        (true, 0, 1, false, 1),
        "{result:?}: {text}"
    );
}

#[tokio::test]
async fn commit_lifecycle_recovered_lane_missing_correlation_entropy_reports_and_drives_without_an_id()
 {
    struct Dry;
    impl granary_core::secure_random::SecureRandom for Dry {
        fn fill(
            &mut self,
            _: &mut [u8],
        ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
            Err(granary_core::secure_random::EntropyUnavailable)
        }
    }
    let f = Fixture::new().await;
    f.create("private-name", b"sealed");
    f.engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let restarted = f.restart().await;
    let lane = restarted
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap();
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let result = Box::pin(restarted.engine.drive_commit(
        &lane,
        &mut Dry,
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let commit = |event: &str| -> Vec<bool> {
        text.lines()
            .filter(|line| line.contains(&format!("\"event\":\"{event}\",\"kind\":\"commit\"")))
            .map(|line| line.contains("\"op\":"))
            .collect()
    };
    assert_eq!(
        (
            matches!(&result, Ok(done) if matches!(done.outcome, PublicationOutcome::Landed(_))),
            text.lines()
                .filter(|line| line.contains(
                    "\"event\":\"op.failed\",\"kind\":\"session\",\"class\":\"unavailable\""
                ))
                .count(),
            commit("op.begin"),
            commit("op.end"),
        ),
        (true, 1, vec![false], vec![false],),
        "{result:?}: {text}"
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one report compares every commit event, waited for or abandoned"
)]
async fn commit_lifecycle_permanent_refusal_is_loud_and_prevents_a_new_commit_loop() {
    let f = Fixture::new().await;
    f.create("file", b"retained");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    f.remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::Reject; 4]);
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let done = budget::drive(&f, &lane, &mut Delay).await;
    assert_eq!(done.outcome, PublicationOutcome::Refused, "{done:?}");
    let mut refused = 0;
    for attempt in 0..3 {
        let next = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(71 + attempt))
            .await;
        match next {
            Err(CoordinationError::Fenced { .. }) => refused += 1,
            Ok(next) => {
                budget::drive(&f, &next, &mut Delay).await;
            }
            Err(error) => panic!("unexpected refusal before new commit: {error}"),
        }
    }
    // A caller that stops waiting once construction is supervised still
    // gets the construction's failure reported.
    let mut abandoned = Box::pin(
        f.engine
            .construct_commit(SyncOptions::default(), &mut Entropy(74)),
    );
    std::future::poll_fn(|cx| {
        assert!(
            abandoned.as_mut().poll(cx).is_pending(),
            "construction finished before its caller stopped waiting"
        );
        std::task::Poll::Ready(())
    })
    .await;
    drop(abandoned);
    let failures = || {
        String::from_utf8_lossy(&log.0.lock().unwrap())
            .matches("\"event\":\"op.failed\",\"kind\":\"commit\"")
            .count()
    };
    let mut timer = std::pin::pin!(TokioSyncRuntime.sleep(Duration::from_secs(3)));
    std::future::poll_fn(|cx| {
        if failures() == 5 || timer.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(());
        }
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    })
    .await;
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (refused, f.remote.publication_sends.lock().unwrap().len()),
        (3, 1),
        "{text}"
    );
    let events: Vec<_> = text
        .lines()
        .filter_map(|line| {
            ["op.begin", "op.failed", "op.end"]
                .into_iter()
                .find(|event| line.contains(&format!("\"event\":\"{event}\",\"kind\":\"commit\"")))
        })
        .collect();
    // Each refused construction reports its failure under the id it drew
    // after its two identity draws: `Entropy(71 + attempt)` yields the
    // correlation bytes `73 + attempt`, the abandoned one's included.
    let construction_failures: Vec<_> = text
        .lines()
        .skip_while(|line| !line.contains("\"event\":\"op.end\""))
        .filter(|line| line.contains("\"event\":\"op.failed\",\"kind\":\"commit\""))
        .map(|line| {
            let (_, rest) = line.split_once("\"op\":\"")?;
            rest.split('"').next().map(str::to_owned)
        })
        .collect();
    assert_eq!(
        (events, construction_failures),
        (
            vec![
                "op.begin",
                "op.failed",
                "op.end",
                "op.failed",
                "op.failed",
                "op.failed",
                "op.failed"
            ],
            [0x49_u8, 0x4a, 0x4b, 0x4c]
                .into_iter()
                .map(|byte| Some(
                    crate::CorrelationId::draw(&mut Entropy(byte))
                        .unwrap()
                        .to_string()
                ))
                .collect::<Vec<_>>(),
        ),
        "{text}"
    );
    assert!(text.contains("\"class\":\"refused\""), "{text}");
}

#[tokio::test]
async fn commit_lifecycle_repeated_fence_reports_once() {
    let f = Fixture::new().await;
    f.create("private-name", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    rebase::foreign_head(&f, "private-name").await;
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    for _ in 0..3 {
        let result = Box::pin(f.engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await;
        assert!(
            matches!(result, Err(CoordinationError::Fenced { .. })),
            "{result:?}"
        );
    }
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            text.lines()
                .filter(|l| l.contains("\"event\":\"op.failed\",\"kind\":\"commit\""))
                .count(),
            text.lines()
                .filter(|l| l.contains("\"event\":\"op.conflict\""))
                .count(),
            text.lines()
                .filter(|l| l.contains("\"event\":\"overlay.refused\""))
                .count()
        ),
        (1, 1, 1),
        "{text}"
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one interleaving owns both blocking merges and their cancellation cleanup"
)]
async fn commit_lifecycle_cancelled_merge_cannot_report_its_path_in_the_next_drive() {
    struct Release(Arc<(Mutex<bool>, std::sync::Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0.0.lock().unwrap() = true;
            self.0.1.notify_one();
        }
    }
    let f = Fixture::new().await;
    f.create("private-name", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    rebase::foreign_head(&f, "private-name").await;
    let entered = Arc::new(Notify::new());
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let _release = Release(release.clone());
    *f.content.pause.lock().unwrap() = Some((entered.clone(), release.clone()));
    let mut entropy = Entropy(80);
    let mut delay = Delay;
    let mut first = Box::pin(f.engine.drive_commit(
        &lane,
        &mut entropy,
        &mut delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ));
    let mut paused = Box::pin(entered.notified());
    let mut timer = std::pin::pin!(TokioSyncRuntime.sleep(Duration::from_secs(3)));
    std::future::poll_fn(|cx| {
        assert!(
            timer.as_mut().poll(cx).is_pending(),
            "first merge did not pause"
        );
        let got = first.as_mut().poll(cx);
        assert!(
            got.is_pending(),
            "first drive ended before merge pause: {got:?}"
        );
        paused.as_mut().poll(cx)
    })
    .await;
    drop(first);
    rebase::foreign_head(&f, "remote").await;
    f.create("remote", b"suffix");
    let second_entered = Arc::new(Notify::new());
    let second_release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let _second_release = Release(second_release.clone());
    *f.content.pause.lock().unwrap() = Some((second_entered.clone(), second_release.clone()));
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::closed_subscriber_with_paths(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
        crate::LogPaths::Full,
        crate::BundleHistory::default(),
    ));
    let mut entropy = Entropy(81);
    let mut delay = Delay;
    let mut second = Box::pin(f.engine.drive_commit(
        &lane,
        &mut entropy,
        &mut delay,
        RecoveryIntent::ExplicitRecovery,
        SyncOptions::default(),
    ));
    let mut paused = Box::pin(second_entered.notified());
    let mut timer = std::pin::pin!(TokioSyncRuntime.sleep(Duration::from_secs(3)));
    std::future::poll_fn(|cx| {
        assert!(
            timer.as_mut().poll(cx).is_pending(),
            "second merge did not pause"
        );
        let got = second.as_mut().poll(cx);
        assert!(
            got.is_pending(),
            "second drive ended before merge pause: {got:?}"
        );
        paused.as_mut().poll(cx)
    })
    .await;
    let completed = f.content.blocking_completed.load(Ordering::Acquire);
    *release.0.lock().unwrap() = true;
    release.1.notify_one();
    let content = f.content.clone();
    TokioSyncRuntime
        .timeout_at(
            TokioSyncRuntime.now() + Duration::from_secs(2),
            async move {
                while content.blocking_completed.load(Ordering::Acquire) == completed {
                    content.blocking_finished.notified().await;
                }
            },
        )
        .await
        .expect("cancelled merge did not finish");
    assert_eq!(
        counter(&f, "granary_client_rebase_conflicts_total"),
        1,
        "{}",
        f.metrics()
    );
    *second_release.0.lock().unwrap() = true;
    second_release.1.notify_one();
    let result = second.await;
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            matches!(result, Err(CoordinationError::Fenced { .. })),
            text.lines()
                .filter(|l| l.contains("\"event\":\"op.conflict\"")
                    && l.contains("\"path\":\"private-name\""))
                .count(),
            text.lines()
                .filter(|l| l.contains("\"event\":\"op.conflict\"")
                    && l.contains("\"path\":\"remote\""))
                .count()
        ),
        (true, 0, 1),
        "{result:?}: {text}"
    );
}

#[tokio::test]
async fn commit_lifecycle_deadline_then_landing_keeps_the_first_attempt_token() {
    let f = Fixture::new().await;
    f.create("file", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    f.remote.time.ticks.store(10, Ordering::Relaxed);
    f.remote.publication_plan.lock().unwrap().extend([
        PublishPlan::LandAfterDelay(Duration::from_secs(1)),
        PublishPlan::Land,
    ]);
    let first = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions {
            resolution_bound: Duration::from_millis(50),
            ..SyncOptions::default()
        },
    ))
    .await;
    assert_eq!(
        (
            first.err().map(|e| e.to_string()),
            counter(&f, "granary_client_commits_total{result=\"failed\"}")
        ),
        (Some("intent refused: SyncDeadline".to_owned()), 0)
    );
    f.remote.time.ticks.store(20, Ordering::Relaxed);
    let done = budget::drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (
            matches!(done.outcome, PublicationOutcome::Landed(_)),
            counter(&f, "granary_client_commits_total{result=\"ok\"}"),
            f.metrics()
                .contains("granary_client_commit_duration_seconds_sum{result=\"ok\"} 0.025000\n")
        ),
        (true, 1, true),
        "{}",
        f.metrics()
    );
}

#[tokio::test]
async fn commit_lifecycle_journal_failure_emits_a_classified_operation_pair_without_termination() {
    let f = Fixture::new().await;
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    f.store.lock().unwrap().fault_control().arm(
        "sync.commit",
        "before_submit",
        1,
        FaultAction::Fail,
    );
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
            result.err().map(|e| crate::sync::failure_class(&e)),
            counter(&f, "granary_client_commits_total{result=\"failed\"}"),
            text.lines()
                .filter(
                    |l| l.contains("\"event\":\"op.failed\",\"kind\":\"commit\",\"class\":\"io\"")
                )
                .count(),
            text.lines()
                .filter(|l| l.contains("\"event\":\"op.begin\",\"kind\":\"commit\""))
                .count(),
            text.lines()
                .filter(|l| l.contains("\"event\":\"op.end\",\"kind\":\"commit\""))
                .count()
        ),
        (Some(crate::FailureClass::Io), 0, 1, 1, 1),
        "{text}"
    );
}

#[tokio::test]
async fn commit_lifecycle_preflight_refusal_does_not_consume_the_terminal_observation() {
    let f = Fixture::new().await;
    f.create("file", b"sealed");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    f.content.unavailable.store(true, Ordering::Relaxed);
    let first = Box::pin(f.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await;
    assert_eq!(
        (
            first.as_ref().err().map(crate::sync::failure_class),
            counter(&f, "granary_client_commits_total{result=\"failed\"}")
        ),
        (Some(crate::FailureClass::Corrupt), 0),
        "{first:?}: {}",
        f.metrics()
    );
    f.content.unavailable.store(false, Ordering::Relaxed);
    let done = budget::drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (
            matches!(done.outcome, PublicationOutcome::Landed(_)),
            counter(&f, "granary_client_commits_total{result=\"ok\"}")
        ),
        (true, 1),
        "{}",
        f.metrics()
    );
}

#[tokio::test]
async fn coalesce_commit_waits_for_last_close_and_quiesce_delay_without_inline_commit() {
    use granary_core::manifest::Name;
    let f = Fixture::new().await;
    let stage = f.create("file", b"open");
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.open_stage(&[Name::new(b"file".to_vec()).unwrap()]))
        .unwrap();
    let store = f.store.clone();
    let remote = f.remote.clone();
    let writer = TokioSyncRuntime.spawn(async move {
        TokioSyncRuntime.sleep(Duration::from_millis(40)).await;
        let sends_while_open = remote.publication_sends.lock().unwrap().len();
        store
            .lock()
            .unwrap()
            .overlay_transaction(|t| {
                t.write(stage, 0, b"closed")?;
                t.close_stage(stage)
            })
            .unwrap();
        let sends_on_close = remote.publication_sends.lock().unwrap().len();
        TokioSyncRuntime.sleep(Duration::from_millis(10)).await;
        let sends_before_quiesce = remote.publication_sends.lock().unwrap().len();
        (sends_while_open, sends_on_close, sends_before_quiesce)
    });
    let options = SyncOptions {
        quiesce_delay: Duration::from_millis(30),
        max_coalesce_delay: Duration::from_secs(5),
        ..SyncOptions::default()
    };
    let done = Box::pin(f.engine.coalesce_commit(options, &mut Entropy(70)))
        .await
        .unwrap();
    let (sends_while_open, sends_on_close, sends_before_quiesce) = writer.await.unwrap();
    let sends_total = f.remote.publication_sends.lock().unwrap().len();
    let state_after = f
        .store
        .lock()
        .unwrap()
        .coalesce_state(&options, TokioSyncRuntime.now())
        .unwrap();
    assert_eq!(
        (
            sends_while_open,
            sends_on_close,
            sends_before_quiesce,
            sends_total,
            matches!(done.outcome, PublicationOutcome::Landed(_)),
            state_after,
        ),
        (
            0,
            0,
            0,
            1,
            true,
            crate::writable_store::sync_engine::CoalesceState::Clean,
        ),
        "portable coalesce_commit must wait for close and quiesce_delay so the post-close write lands in the single commit: open={sends_while_open}, close={sends_on_close}, before={sends_before_quiesce}, total={sends_total}, state_after={state_after:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::redundant_closure_for_method_calls,
    reason = "the transaction facade requires a higher-ranked lifetime; a method pointer does not compile"
)]
async fn capture_window_write_survives_landing_and_commits_on_coalesce_wake() {
    use crate::writable_store::sync_engine::CoalesceState;
    let f = Fixture::new().await;
    let s = &f.store;
    let stage = f.create("file", b"sealed bytes");
    let write = |bytes: &[u8]| {
        s.lock()
            .unwrap()
            .overlay_transaction(|t| t.write(stage, 0, bytes).map(|_| ()))
            .unwrap();
    };
    let coalesce = |opts: &SyncOptions, now| s.lock().unwrap().coalesce_state(opts, now).unwrap();
    let after_first_write = TokioSyncRuntime.now();
    s.lock()
        .unwrap()
        .overlay_transaction(|t| t.capture_boundary())
        .unwrap();
    TokioSyncRuntime.sleep(Duration::from_millis(20)).await;
    write(b"second bytes");
    s.lock()
        .unwrap()
        .overlay_transaction(|t| t.capture_boundary())
        .unwrap();
    let max_age_probe = SyncOptions {
        quiesce_delay: Duration::from_secs(30),
        max_coalesce_delay: Duration::from_secs(5),
        ..SyncOptions::default()
    };
    let state_after_abandoned = coalesce(&max_age_probe, TokioSyncRuntime.now());
    assert!(
        matches!(
            state_after_abandoned,
            CoalesceState::WaitUntil(Some(deadline))
                if deadline <= after_first_write + Duration::from_secs(5)
        ),
        "abandoned captures must keep the pre-capture span visible with its original first_at: {state_after_abandoned:?}"
    );
    let faults = s.lock().unwrap().fault_control();
    faults.arm("sync.commit", "captured", 1, FaultAction::Block);
    let mut constructing = Box::pin(
        f.engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70)),
    );
    let mut entered = Box::pin(fired(&faults, "sync.commit", "captured"));
    std::future::poll_fn(|cx| {
        assert!(constructing.as_mut().poll(cx).is_pending());
        entered.as_mut().poll(cx)
    })
    .await;
    TokioSyncRuntime.sleep(Duration::from_millis(30)).await;
    let before_window_write = TokioSyncRuntime.now();
    write(b"window bytes");
    let after_window_write = TokioSyncRuntime.now();
    faults.resume();
    let lane = constructing.await.unwrap();
    TokioSyncRuntime.sleep(Duration::from_millis(20)).await;
    write(b"steady bytes");
    let first = budget::drive(&f, &lane, &mut Delay).await;
    let probe_at = before_window_write + Duration::from_secs(5) - Duration::from_millis(5);
    let state_at_pre_capture_max_age = coalesce(&max_age_probe, probe_at);
    let options = SyncOptions {
        quiesce_delay: Duration::from_millis(20),
        max_coalesce_delay: Duration::from_secs(5),
        ..SyncOptions::default()
    };
    let state_after_first = coalesce(&options, TokioSyncRuntime.now());
    assert_ne!(
        state_after_first,
        CoalesceState::Clean,
        "capture-window write must remain dirty after landing: {state_after_first:?}"
    );
    assert!(
        matches!(
            state_at_pre_capture_max_age,
            CoalesceState::WaitUntil(Some(deadline))
                if deadline >= before_window_write + Duration::from_secs(5)
                    && deadline <= after_window_write + Duration::from_secs(5)
        ),
        "after landing, max-age must be measured from the first post-capture write (in [{:?}, {:?}]), not from the committed pre-capture write ({:?}): {state_at_pre_capture_max_age:?}",
        before_window_write + Duration::from_secs(5),
        after_window_write + Duration::from_secs(5),
        after_first_write + Duration::from_secs(5),
    );
    let second = Box::pin(f.engine.coalesce_commit(options, &mut Entropy(90)))
        .await
        .unwrap();
    let state_after_second = coalesce(&options, TokioSyncRuntime.now());
    let PublicationOutcome::Landed(done) = &second.outcome else {
        panic!("expected landed window commit, got {:?}", second.outcome);
    };
    assert_file(&f, &done.root, "file", b"steady bytes");
    assert_eq!(
        (
            matches!(first.outcome, PublicationOutcome::Landed(_)),
            f.remote.publication_sends.lock().unwrap().len(),
            state_after_second,
        ),
        (true, 2, CoalesceState::Clean),
        "window write must commit on the coalescer wake after landing"
    );
}

#[tokio::test]
async fn landed_commit_with_held_stage_handle_restarts_clean() {
    use crate::writable_store::sync_engine::CoalesceState;
    use granary_core::manifest::Name;
    let f = Fixture::new().await;
    let payload = b"held across landing";
    let _stage = f.create("file", payload);
    let path = vec![Name::new(b"file".to_vec()).unwrap()];
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.open_stage(&path))
        .unwrap();
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let done = budget::drive(&f, &lane, &mut Delay).await;
    let PublicationOutcome::Landed(landed) = &done.outcome else {
        panic!("expected landed commit, got {:?}", done.outcome);
    };
    let doc = granary_core::root::decode_root(&landed.root).unwrap();
    let manifest_entries =
        crate::writable_store::capture::entries(f.content.as_ref(), doc.manifest_root, 1).unwrap();
    let EntryKind::File { size, grains, .. } = &manifest_entries[0].kind else {
        panic!("file missing");
    };
    let content = GrainId::of(&manifest::node::file_payload(*size, grains).unwrap());
    let base_entry = OverlayEntry {
        path: path.clone(),
        inode: 2,
        kind: OverlayKind::File {
            content: Some(content),
        },
        stage_id: None,
        size: *size,
        exec: false,
    };
    let mut h = header();
    h.writer = f.store.lock().unwrap().writer_uuid();
    h.base_root = landed.id;
    h.base_seq = landed.seq;
    f.store
        .lock()
        .unwrap()
        .open_overlay(
            h,
            vec![base_entry.clone()],
            &mut super::ContentReader(f.content.clone()),
            f.io.clone(),
        )
        .unwrap();
    let state_after_restart = f
        .store
        .lock()
        .unwrap()
        .coalesce_state(&SyncOptions::default(), TokioSyncRuntime.now())
        .unwrap();
    let reopened_stage = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            let s = t.open_stage(&path)?;
            t.truncate(s, *size)?;
            t.close_stage(s)?;
            Ok(s)
        })
        .unwrap();
    let state_after_same_size_truncate = f
        .store
        .lock()
        .unwrap()
        .coalesce_state(&SyncOptions::default(), TokioSyncRuntime.now())
        .unwrap();
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(reopened_stage, *size + 1))
        .unwrap();
    let state_after_real_truncate = f
        .store
        .lock()
        .unwrap()
        .coalesce_state(&SyncOptions::default(), TokioSyncRuntime.now())
        .unwrap();
    assert_eq!(
        (
            state_after_restart,
            state_after_same_size_truncate,
            state_after_real_truncate != CoalesceState::Clean,
        ),
        (CoalesceState::Clean, CoalesceState::Clean, true),
        "synthetic landing truncate on replay and live same-size truncate must stay Clean, while size-changing truncate marks overlay dirty: restart={state_after_restart:?}, same_size={state_after_same_size_truncate:?}, real={state_after_real_truncate:?}"
    );
}

#[tokio::test]
async fn commit_construction_and_drive_share_one_correlation_id_while_recovery_draws_fresh() {
    use granary_core::secure_random::{EntropyUnavailable, SecureRandom};

    struct Sequence(Vec<Option<u8>>);
    impl SecureRandom for Sequence {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
            if self.0.is_empty() {
                return Err(EntropyUnavailable);
            }
            let byte = self.0.remove(0).ok_or(EntropyUnavailable)?;
            dest.fill(byte);
            Ok(())
        }
    }

    let f = Fixture::new().await;
    f.create("file-one", b"first");
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let mut construct_rng = Sequence(vec![Some(0x11), Some(0x22), Some(0x33)]);
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut construct_rng)
        .await
        .unwrap();
    let mut drive_rng = Sequence(vec![]);
    Box::pin(f.engine.drive_commit(
        &lane,
        &mut drive_rng,
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let expected_first = crate::CorrelationId::draw(&mut Entropy(0x33))
        .unwrap()
        .to_string();
    let count_op = |event: &str| {
        text.lines()
            .filter(|l| l.contains(event) && l.contains(&expected_first))
            .count()
    };
    assert_eq!(
        (
            count_op("\"event\":\"op.begin\""),
            count_op("\"event\":\"op.end\""),
            count_op("\"event\":\"op.publish_bound\""),
        ),
        (1, 1, 1),
        "{text}"
    );

    // Recovered commit (`lane.recovered == true`, no `operation_id` on `RetainedCommit`) draws from `secure`.
    let r = Fixture::new().await;
    r.create("file-recovered", b"recovered");
    let retained = r
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(0x44))
        .await
        .unwrap();
    let restarted = r.restart().await;
    let recovered_lane = restarted
        .engine
        .recover_commit(SyncOptions::default())
        .unwrap();
    let rec_log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        rec_log.clone(),
    ));
    Box::pin(restarted.engine.drive_commit(
        &recovered_lane,
        &mut Entropy(0x55),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap();
    drop(guard);
    let _ = retained;
    let rec_text = String::from_utf8(rec_log.0.lock().unwrap().clone()).unwrap();
    let expected_recovered = crate::CorrelationId::draw(&mut Entropy(0x55))
        .unwrap()
        .to_string();
    assert!(
        rec_text
            .lines()
            .any(|l| l.contains("\"event\":\"op.begin\"")
                && l.contains("\"kind\":\"commit\"")
                && l.contains(&expected_recovered)),
        "{rec_text}"
    );
}
