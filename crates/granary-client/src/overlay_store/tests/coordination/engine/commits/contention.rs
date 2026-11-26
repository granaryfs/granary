// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

use super::reporting::counter;

#[tokio::test]
async fn contention_terminal_window_distinguishes_boundary_and_below_with_one_rising_event() {
    let mut cases = 0;
    for (label, successes, flagged) in [("at threshold", 3, true), ("below threshold", 4, false)] {
        let f = Fixture::new().await;
        let log = TimingLog::default();
        let guard = tracing::subscriber::set_default(crate::observe::subscriber(
            crate::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            log.clone(),
        ));
        for n in 0..successes {
            f.create(&format!("file-{n}"), b"sealed");
            let lane = f
                .engine
                .construct_commit(SyncOptions::default(), &mut Entropy(70 + n))
                .await
                .unwrap();
            let done = budget::drive(&f, &lane, &mut Delay).await;
            assert!(
                matches!(done.outcome, PublicationOutcome::Landed(_)),
                "{label}: {done:?}"
            );
            if n < 3 {
                assert!(
                    !f.metrics().contains("granary_client_contention_flag"),
                    "premature decision: {}",
                    f.metrics()
                );
            }
        }
        f.create("last", b"sealed");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(90))
            .await
            .unwrap();
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .extend([PublishPlan::RateLimited; 8]);
        let done = budget::drive(&f, &lane, &mut Delay).await;
        assert_eq!(
            (
                done.outcome,
                counter(&f, "granary_client_commits_total{result=\"exhausted\"}")
            ),
            (PublicationOutcome::Exhausted, 1),
            "{label}: {}",
            f.metrics()
        );
        assert!(
            f.metrics().contains(&format!(
                "granary_client_contention_flag {}\n",
                u8::from(flagged)
            )),
            "{label}: {}",
            f.metrics()
        );
        let _ = Box::pin(f.engine.drive_commit(
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
            text.lines()
                .filter(|l| l.contains("\"event\":\"commit.contention\""))
                .count(),
            usize::from(flagged),
            "{label}: {text}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn contention_landed_disjoint_rebase_only_increments_denominator() {
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
    let done = budget::drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (
            matches!(done.outcome, PublicationOutcome::Landed(_)),
            counter(
                &f,
                "granary_client_commit_retries_total{reason=\"conflict\"}"
            )
        ),
        (true, 1),
        "{done:?}: {}",
        f.metrics()
    );
    for n in 0..3 {
        f.create(&format!("later-{n}"), b"sealed");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(90 + n))
            .await
            .unwrap();
        let done = budget::drive(&f, &lane, &mut Delay).await;
        assert!(
            matches!(done.outcome, PublicationOutcome::Landed(_)),
            "{done:?}"
        );
    }
    assert_eq!(
        (
            counter(&f, "granary_client_commits_total{result=\"ok\"}"),
            f.metrics().contains("granary_client_contention_flag 0\n")
        ),
        (4, true),
        "{}",
        f.metrics()
    );
}

#[tokio::test]
async fn contention_restart_discards_process_window_and_metric_decision() {
    let f = Fixture::new().await;
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    for _ in 0..4 {
        f.store
            .lock()
            .unwrap()
            .observe_commit(crate::CommitResult::Exhausted);
    }
    assert!(
        f.metrics().contains("granary_client_contention_flag 1\n"),
        "{}",
        f.metrics()
    );
    drop(lane);
    let f = f.restart().await;
    assert!(
        !f.metrics().contains("granary_client_contention_flag"),
        "{}",
        f.metrics()
    );
    for _ in 0..3 {
        f.store
            .lock()
            .unwrap()
            .observe_commit(crate::CommitResult::Ok);
    }
    assert!(
        !f.metrics().contains("granary_client_contention_flag"),
        "{}",
        f.metrics()
    );
    f.store
        .lock()
        .unwrap()
        .observe_commit(crate::CommitResult::Ok);
    assert!(
        f.metrics().contains("granary_client_contention_flag 0\n"),
        "{}",
        f.metrics()
    );
}

#[tokio::test]
async fn rejected_commit_release_failure_preserves_sticky_fence() {
    let mut cases = 0;
    for corrupt_charge in [false, true] {
        let f = Fixture::new().await;
        f.create("local", b"sealed");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        if corrupt_charge {
            let mut local = f.store.lock().unwrap();
            local.release_engine_graph(lane.charge()).unwrap();
        }
        f.remote
            .publication_plan
            .lock()
            .unwrap()
            .push_back(PublishPlan::Reject);
        let done = Box::pin(f.engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await;
        assert_eq!(
            done.as_ref().err().map(ToString::to_string),
            corrupt_charge.then(|| "overlay refused: engine graph underflow".to_owned()),
            "{done:?}"
        );
        let write = f
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.create_file(at("later"), false));
        assert!(
            matches!(write, Err(CoordinationError::Fenced { .. })),
            "release failure={corrupt_charge}: {write:?}"
        );
        assert_eq!(
            (
                counter(&f, "granary_client_commits_total{result=\"failed\"}"),
                counter(&f, "granary_client_commits_total{result=\"conflict\"}")
            ),
            (1, 0),
            "release failure={corrupt_charge}: {}",
            f.metrics()
        );
        let _ = Box::pin(f.engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await;
        assert_eq!(
            (
                counter(&f, "granary_client_commits_total{result=\"failed\"}"),
                counter(&f, "granary_client_commits_total{result=\"conflict\"}")
            ),
            (1, 0),
            "repeated refused lane: {}",
            f.metrics()
        );
        for _ in 0..3 {
            f.store
                .lock()
                .unwrap()
                .observe_commit(crate::CommitResult::Ok);
        }
        assert!(
            f.metrics().contains("granary_client_contention_flag 0\n"),
            "{}",
            f.metrics()
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn contention_counts_same_path_fence_but_not_ownership_fence() {
    let mut cases = 0;
    for same_path in [true, false] {
        let f = Fixture::new().await;
        f.create("local", b"sealed");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        for _ in 0..3 {
            f.store
                .lock()
                .unwrap()
                .observe_commit(crate::CommitResult::Ok);
        }
        if same_path {
            rebase::foreign_head(&f, "local").await;
        } else {
            f.store
                .lock()
                .unwrap()
                .phase_for_test(granary_core::overlay_ownership::Phase::Fenced)
                .unwrap();
        }
        let done = Box::pin(f.engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await;
        assert_eq!(
            (
                matches!(done, Err(CoordinationError::Fenced { .. })),
                counter(&f, "granary_client_commits_total{result=\"conflict\"}"),
                f.metrics().contains(&format!(
                    "granary_client_contention_flag {}\n",
                    u8::from(same_path)
                ))
            ),
            (true, u64::from(same_path), true),
            "same path={same_path}: {done:?}\n{}",
            f.metrics()
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn contention_counts_same_path_conflict_but_not_commit_boundary_fence() {
    let mut cases = 0;
    for same_path in [true, false] {
        let f = Fixture::new().await;
        f.create("local", b"sealed");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let publication = budget::saved(&f).publication_id;
        for _ in 0..3 {
            f.store
                .lock()
                .unwrap()
                .observe_commit(crate::CommitResult::Ok);
        }
        if same_path {
            rebase::foreign_head(&f, "local").await;
        } else {
            f.store
                .lock()
                .unwrap()
                .overlay_transaction(|t| t.record_commit_fence(lane.boundary_seq(), publication))
                .unwrap();
        }
        let done = Box::pin(f.engine.drive_commit(
            &lane,
            &mut Entropy(80),
            &mut Delay,
            RecoveryIntent::Continue,
            SyncOptions::default(),
        ))
        .await;
        assert_eq!(
            (
                match &done {
                    Err(CoordinationError::Fenced { .. }) => same_path,
                    Err(CoordinationError::CommitFenced { publication: p }) => {
                        !same_path && *p == publication
                    }
                    _ => false,
                },
                counter(&f, "granary_client_commits_total{result=\"conflict\"}"),
                f.metrics().contains(&format!(
                    "granary_client_contention_flag {}\n",
                    u8::from(same_path)
                ))
            ),
            (true, u64::from(same_path), true),
            "same path={same_path}: {done:?}\n{}",
            f.metrics()
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn contention_ownership_fence_after_exhaustion_or_refusal_has_no_conflict_sample() {
    let mut cases = 0;
    for (label, plan, prior) in [
        ("exhausted lane", PublishPlan::RateLimited, "exhausted"),
        ("refused lane", PublishPlan::Reject, "failed"),
    ] {
        let f = Fixture::new().await;
        f.create("local", b"sealed");
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        f.remote.publication_plan.lock().unwrap().extend([plan; 8]);
        let done = budget::drive(&f, &lane, &mut Delay).await;
        assert_eq!(
            (
                done.outcome,
                counter(
                    &f,
                    &format!("granary_client_commits_total{{result=\"{prior}\"}}")
                )
            ),
            (
                if prior == "exhausted" {
                    PublicationOutcome::Exhausted
                } else {
                    PublicationOutcome::Refused
                },
                1
            ),
            "{label}: {}",
            f.metrics()
        );
        f.store
            .lock()
            .unwrap()
            .phase_for_test(granary_core::overlay_ownership::Phase::Fenced)
            .unwrap();
        // A new observation sees the ownership fence with the mount's sticky fence still set.
        let observed = f
            .engine
            .finish_commit_observation_for_test(&lane, &mut Entropy(81), true);
        assert_eq!(
            (
                observed,
                counter(&f, "granary_client_commits_total{result=\"conflict\"}")
            ),
            (true, 0),
            "{label}: {}",
            f.metrics()
        );
        for _ in 0..2 {
            f.store
                .lock()
                .unwrap()
                .observe_commit(crate::CommitResult::Ok);
        }
        assert!(
            f.metrics().contains(&format!(
                "granary_client_contention_flag {}\n",
                u8::from(prior == "exhausted")
            )),
            "{label}: {}",
            f.metrics()
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn contention_store_poison_is_reported_before_observation_is_latched() {
    let mut cases = 0;
    for poisoned in [false, true] {
        let f = Fixture::new().await;
        let lane = f
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        if poisoned {
            let store = f.store.clone();
            let injected = std::thread::spawn(move || {
                let _guard = store.lock().unwrap();
                panic!("injected store poison");
            })
            .join();
            assert!(injected.is_err(), "store poison result: {injected:?}");
        }
        let log = TimingLog::default();
        let guard = tracing::subscriber::set_default(crate::observe::subscriber(
            crate::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            log.clone(),
        ));
        let observed = f
            .engine
            .finish_commit_observation_for_test(&lane, &mut Entropy(80), false);
        drop(guard);
        let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            (
                observed,
                counter(&f, "granary_client_commits_total{result=\"failed\"}"),
                text.lines()
                    .filter(|line| line.contains("\"event\":\"op.failed\"")
                        && line.contains("\"kind\":\"commit\"")
                        && line.contains("\"class\":\"refused\""))
                    .count()
            ),
            (!poisoned, u64::from(!poisoned), 1),
            "poisoned={poisoned}: {text}\n{}",
            f.metrics()
        );
        f.store.clear_poison();
        assert!(
            f.engine
                .finish_commit_observation_for_test(&lane, &mut Entropy(81), false)
        );
        assert_eq!(
            counter(&f, "granary_client_commits_total{result=\"failed\"}"),
            1,
            "poisoned={poisoned}: {}",
            f.metrics()
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn contention_recorder_installation_does_not_advertise_sync_before_attachment() {
    let scratch = Scratch::new();
    let io = SimIo::default();
    let mut local = start(&scratch, &io, 120);
    let metrics = ClientMetrics::new(&mut Entropy(91));
    local.set_metrics(metrics.clone());
    let exported = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert_eq!(
        (
            exported.contains("granary_client_metrics_available{group=\"sync\"} 0\n"),
            exported.contains("granary_client_metrics_available{group=\"commit\"} 0\n"),
            exported.contains("granary_client_metrics_available{group=\"contention\"} 0\n")
        ),
        (true, true, true),
        "{exported}"
    );
    let f = Fixture::new().await;
    assert_eq!(
        (
            counter(&f, "granary_client_metrics_available{group=\"sync\"}"),
            counter(&f, "granary_client_metrics_available{group=\"commit\"}"),
            counter(&f, "granary_client_metrics_available{group=\"contention\"}")
        ),
        (1, 1, 0),
        "{}",
        f.metrics()
    );

    let rejected_metrics = ClientMetrics::new(&mut Entropy(92));
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    let trusted = TrustedKeys::new([*key.public_key()]).unwrap();
    let base = f.remote.published.lock().unwrap().get(&1).unwrap().clone();
    let rejected = SyncEngine::with_runtime(
        f.store.clone(),
        f.remote.clone(),
        f.content.clone(),
        f.remote.time.clone(),
        f.remote.time.clone(),
        key,
        trusted,
        base,
        rejected_metrics.clone(),
        Arc::new(TrackedRuntime(f.content.clone())),
    )
    .await;
    let exported = rejected_metrics
        .snapshot()
        .unwrap()
        .render_prometheus()
        .unwrap();
    assert_eq!(
        (
            rejected.err().map(|error| error.to_string()),
            exported.contains("granary_client_metrics_available{group=\"sync\"} 0\n"),
            exported.contains("granary_client_metrics_available{group=\"commit\"} 0\n"),
            exported.contains("granary_client_metrics_available{group=\"contention\"} 0\n")
        ),
        (
            Some("intent refused: SyncEngineAlreadyAttached".to_owned()),
            true,
            true,
            true
        ),
        "rejected attachment: {exported}"
    );
}
