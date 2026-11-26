// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::writable_store::sync_engine::CoalesceState;

async fn acceptance_payload_refusal(full: bool, workspace: u64, spill: bool) {
    let mut cases = 0;
    for bound in [workspace, if spill { 1_048_576 } else { 32_768 }] {
        let (f, boundary) = construction_boundary(if spill { "spill" } else { "small" }).await;
        let result = f
            .engine
            .accept_boundary_for_test(&boundary, bound, full)
            .await
            .err()
            .map(|error| (error.to_string(), crate::sync::failure_class(&error)));
        assert_eq!(
            (result, f.engine.last_spend().get("other").copied()),
            (
                if bound == workspace {
                    Some((
                        "intent refused: SyncWorkspaceExhausted".into(),
                        crate::FailureClass::Refused,
                    ))
                } else {
                    None
                },
                Some(if spill {
                    266_240
                } else if bound == workspace {
                    2048
                } else {
                    4096
                })
            ),
            "full={full}, spill={spill}, bound={bound}, spend={:?}",
            f.engine.last_spend()
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn sync_payload_workspace_refusal_is_named() {
    acceptance_payload_refusal(false, 14_784, false).await;
}

#[tokio::test]
async fn commit_payload_workspace_refusal_is_named() {
    acceptance_payload_refusal(true, 16_384, false).await;
}

#[tokio::test]
async fn manifest_spill_workspace_refusal_is_named() {
    acceptance_payload_refusal(false, 360_448, true).await;
}

async fn construction_boundary(shape: &str) -> (Fixture, SyncBoundary) {
    let (f, target) = match shape {
        "spill" | "orphan" => {
            let (f, stage) = spilled_file(129).await;
            (f, SyncTarget::Stage(stage))
        }
        "small" | "directory" => {
            let f = Fixture::new().await;
            f.create("payload", b"captured");
            if shape == "directory" {
                f.store
                    .lock()
                    .unwrap()
                    .overlay_transaction(|t| {
                        t.namespace_record(Record::Create {
                            at: at("directory"),
                            kind: codec::CreateKind::Dir,
                        })?;
                        let stage = t.create_file(
                            crate::overlay_store::tests::incremental::loc("directory/child"),
                            false,
                        )?;
                        t.write(stage, 0, b"nested")
                    })
                    .unwrap();
            }
            (f, SyncTarget::Tree)
        }
        _ => panic!("unknown construction fixture: {shape}"),
    };
    let boundary = match (shape, target) {
        ("orphan", SyncTarget::Stage(stage)) => orphan_boundary(&f, stage),
        (_, target) => f
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.seal_sync(target))
            .unwrap(),
    };
    (f, boundary)
}

fn orphan_boundary(f: &Fixture, stage: u64) -> SyncBoundary {
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            t.open_stage(&path("spill"))?;
            t.namespace_record(Record::Delete {
                at: at("spill"),
                kind: codec::DeleteKind::File {
                    stage_id: Some(stage),
                },
            })?;
            t.seal_sync(SyncTarget::Stage(stage))
        })
        .unwrap()
}

#[tokio::test]
async fn construction_workspace_breakpoints_preserve_refusal_class() {
    let mut cases = 0;
    let mut expected_cases = 0;
    for shape in ["small", "spill", "directory", "orphan"] {
        let (f, boundary) = construction_boundary(shape).await;
        assert_eq!(
            (
                boundary.files().len(),
                boundary.files().iter().any(|file| file.entry().is_none()),
            ),
            (if shape == "directory" { 2 } else { 1 }, shape == "orphan"),
            "shape={shape}, files={:?}",
            boundary.files()
        );
        let (result, charges) = f
            .engine
            .accept_boundary_with_budgets_for_test(&boundary, [1_048_576; 2])
            .await;
        assert!(
            result.is_ok(),
            "shape={shape}, result={result:?}, charges={charges:?}"
        );
        assert!(
            charges
                .iter()
                .all(|phase| !phase.is_empty() && phase.iter().all(|&charge| charge >= 1024)),
            "shape={shape}, charges={charges:?}"
        );
        if matches!(shape, "spill" | "orphan") {
            assert!(
                charges[1].contains(&133_120),
                "shape={shape}, charges={charges:?}"
            );
        }
        let full = charges.each_ref().map(|phase| phase.iter().sum::<u64>());
        let (f, boundary) = construction_boundary(shape).await;
        let (result, observed) = f
            .engine
            .accept_boundary_with_budgets_for_test(&boundary, full)
            .await;
        assert_eq!(
            (result.err().map(|error| error.to_string()), observed),
            (None, charges.clone()),
            "shape={shape}, full={full:?}"
        );
        for (phase, trace) in charges.iter().enumerate() {
            let breakpoints = trace.iter().scan(0_u64, |total, &charge| {
                *total += charge;
                Some(*total)
            });
            expected_cases += trace.len() + 1;
            for (limit, prefix) in std::iter::once((0, 1)).chain(
                breakpoints
                    .enumerate()
                    .map(|(index, total)| (total - 1, index + 1)),
            ) {
                let mut limits = full;
                limits[phase] = limit;
                let (f, boundary) = construction_boundary(shape).await;
                let (result, observed) = f
                    .engine
                    .accept_boundary_with_budgets_for_test(&boundary, limits)
                    .await;
                let error = result
                    .err()
                    .map(|error| (error.to_string(), crate::sync::failure_class(&error)));
                assert_eq!(
                    (error, observed[phase].clone()),
                    (
                        Some((
                            "intent refused: SyncWorkspaceExhausted".into(),
                            crate::FailureClass::Refused
                        )),
                        trace.iter().take(prefix).copied().collect::<Vec<_>>(),
                    ),
                    "shape={shape}, phase={phase}, limits={limits:?}, observed={observed:?}"
                );
                cases += 1;
            }
        }
        eprintln!("shape={shape}, charges={charges:?}, full={full:?}");
    }
    assert_eq!((cases, cases > 0), (expected_cases, true));
    eprintln!("breakpoint refusal cases={cases}, full-budget successes=8");
}

#[tokio::test]
async fn orphan_acceptance_workspace_refusal_is_named() {
    let mut cases = 0;
    for (workspace, get_bytes) in [(524_288, 179_872), (655_360, 269_808), (1_048_576, 540_672)] {
        let (f, stage) = spilled_file(300).await;
        let boundary = orphan_boundary(&f, stage);
        assert_eq!(
            (
                boundary.files().len(),
                boundary
                    .files()
                    .first()
                    .is_some_and(|file| file.entry().is_none())
            ),
            (1, true),
            "{:?}",
            boundary.files()
        );
        let result = f
            .engine
            .accept_boundary_for_test(&boundary, workspace, false)
            .await
            .err()
            .map(|error| (error.to_string(), crate::sync::failure_class(&error)));
        assert_eq!(
            (result, f.engine.last_spend().get("get").copied()),
            (
                if workspace < 1_048_576 {
                    Some((
                        "intent refused: SyncWorkspaceExhausted".into(),
                        crate::FailureClass::Refused,
                    ))
                } else {
                    None
                },
                Some(get_bytes)
            ),
            "workspace={workspace}, spend={:?}",
            f.engine.last_spend()
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

async fn fresh_file_lands(mib: usize) {
    let f = Fixture::new().await;
    let mut rng = SeededRng::new(773);
    let mut bytes = vec![0_u8; mib * 1_048_576];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    f.create("fresh", &bytes);
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    assert_eq!(f.engine.workspace_held_for_test(), 1_073_741_824);
    let result = budget::drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (
            matches!(result.outcome, PublicationOutcome::Landed(_)),
            f.engine.workspace_held_for_test()
        ),
        (true, 0)
    );
    assert_file(&f, &f.remote.published.lock().unwrap()[&2], "fresh", &bytes);
}

#[tokio::test]
async fn fresh_one_mib_lands_at_defaults() {
    fresh_file_lands(1).await;
}

#[tokio::test]
async fn fresh_eight_mib_lands_at_defaults() {
    fresh_file_lands(8).await;
}

#[tokio::test]
async fn fresh_thirty_two_mib_lands_at_defaults() {
    fresh_file_lands(32).await;
}

#[tokio::test]
async fn projected_seal_pressure_requests_a_commit_while_the_tree_still_fits() {
    let f = Fixture::new().await;
    f.create("pressure", &vec![7; 32 * 1_048_576]);
    let state = coalesce(&f, TokioSyncRuntime.now());
    let requested = summary(&f).commit_requested;
    let sealed = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.seal_sync(SyncTarget::Tree));
    assert_eq!(
        (
            requested,
            matches!(state, CoalesceState::Ready),
            sealed.is_ok()
        ),
        (true, true, true),
        "summary={:?}, seal_error={:?}",
        summary(&f),
        sealed.as_ref().err()
    );
}

#[tokio::test]
async fn detached_charged_stage_requests_a_commit() {
    let f = Fixture::new().await;
    reopen_capped(&f, 220_000_000);
    let (before_delete, after_delete) = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| {
            let scratch = t.create_file(
                crate::overlay_store::tests::incremental::loc("scratch"),
                false,
            )?;
            t.truncate(scratch, 165_000_000)?;
            let before_delete = t.summary();
            t.namespace_record(Record::Delete {
                at: at("scratch"),
                kind: codec::DeleteKind::File {
                    stage_id: Some(scratch),
                },
            })?;
            Ok((before_delete, t.summary()))
        })
        .unwrap();
    assert_eq!(
        (
            before_delete.commit_requested,
            after_delete.commit_requested,
            after_delete.orphan_bytes,
        ),
        (true, true, 165_000_160),
        "before_delete={before_delete:?}, after_delete={after_delete:?}"
    );
}

#[tokio::test]
async fn eager_trigger_prices_both_graphs_and_has_a_working_floor() {
    let f = Fixture::new().await;
    f.create("buffer", &vec![7; 65_536]);
    let (before, seal_charge) = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| Ok((t.summary(), t.projected_tree_seal_charge_for_test()?)))
        .unwrap();
    let projected = before
        .charged_bytes
        .saturating_add(before.reserved_bytes)
        .saturating_add(before.captured_bytes)
        .saturating_add(seal_charge);
    let old_projection = before
        .charged_bytes
        .saturating_mul(2)
        .saturating_add(before.reserved_bytes)
        .saturating_add(before.captured_bytes);
    let graph_cap = (old_projection / 3 + 1).saturating_mul(4);
    let graph_threshold = (graph_cap / 4).saturating_mul(3);
    assert!(
        old_projection < graph_threshold && graph_threshold <= projected,
        "old={old_projection}, threshold={graph_threshold}, projected={projected}"
    );
    reopen_capped(&f, graph_cap);
    let _ = coalesce(&f, TokioSyncRuntime.now());
    assert!(
        summary(&f).commit_requested,
        "the capture and commit graphs did not contribute to the trigger"
    );

    let minimum = (projected / 3 + 1).saturating_mul(4);
    reopen_capped(&f, minimum - 1);
    let _ = coalesce(&f, TokioSyncRuntime.now());
    let below = summary(&f).commit_requested;
    reopen_capped(&f, minimum);
    let _ = coalesce(&f, TokioSyncRuntime.now());
    let at = summary(&f).commit_requested;
    assert_eq!(
        (below, at, projected <= minimum),
        (true, false, true),
        "projected={projected}, minimum={minimum}"
    );
    eprintln!("one-buffer projected seal={projected}, minimum cap={minimum}");
}

#[tokio::test]
async fn full_overlay_commit_reports_named_capacity_bytes_and_not_io() {
    let f = Fixture::new().await;
    let bytes = vec![7; 4 * 1_048_576];
    for index in 0..23 {
        f.create(&format!("full-{index:02}"), &bytes);
    }
    let before = summary(&f);
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let error = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap_err();
    drop(guard);
    let events = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let capacity = events
        .lines()
        .find(|line| line.contains("overlay.cap_exhausted"));
    let overlay_failures = events
        .lines()
        .filter(|line| {
            line.contains("\"event\":\"op.failed\"") && line.contains("\"kind\":\"overlay_write\"")
        })
        .count();
    assert_eq!(
        (
            error.to_string(),
            crate::sync::failure_class(&error),
            capacity.is_some(),
            events.contains("\"class\":\"io\""),
            overlay_failures,
            before.charged_bytes > 0,
        ),
        (
            "overlay refused: OverlayCapacityExhausted".to_owned(),
            crate::FailureClass::Refused,
            true,
            false,
            1,
            true,
        ),
        "before={before:?}, capacity={capacity:?}, events={events}"
    );
    let capacity = capacity.unwrap();
    assert!(
        capacity.contains(
            "\"reason\":\"OverlayCapacityExhausted\",\"cap\":134217728,\"charged\":96624009,\"reserved\":33814682,\"captured\":34180,\"needed\":98685463"
        ),
        "wrong capacity fields: {capacity}"
    );
}

#[tokio::test]
async fn ninety_two_mib_tree_lands_with_the_operator_exit_allowances() {
    let f = Fixture::over_capped(Basis::empty().await, 268_435_456)
        .await
        .unwrap();
    let bytes = vec![7; 4 * 1_048_576];
    for index in 0..23 {
        f.create(&format!("wedged-{index:02}"), &bytes);
    }
    let options = SyncOptions {
        workspace_bytes: 4_294_967_296,
        ..SyncOptions::default()
    };
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap();
    let result = budget::drive(&f, &lane, &mut Delay).await;
    assert_eq!(
        (
            matches!(result.outcome, PublicationOutcome::Landed(_)),
            f.engine.workspace_held_for_test(),
        ),
        (true, 0),
        "{result:?}"
    );
}

#[tokio::test]
async fn workspace_diagnostics_are_once_per_attempt() {
    let f = Fixture::new().await;
    f.create("reports", b"captured");
    let boundary = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.seal_sync(SyncTarget::Tree))
        .unwrap();
    let reports = crate::local_report::local_capture();
    let baseline = reports.len();
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let errors = f.engine.repeated_workspace_charges_for_test(&boundary);
    drop(guard);
    let events = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            errors,
            reports
                .since(baseline)
                .iter()
                .filter(|s| s.contains("SyncWorkspaceExhausted"))
                .count(),
            events
                .lines()
                .filter(|s| s.contains("sync.workspace_exhausted"))
                .count()
        ),
        (
            vec!["intent refused: SyncWorkspaceExhausted".to_owned(); 2],
            1,
            1
        ),
        "{events}"
    );
    f.store
        .lock()
        .unwrap()
        .fail_sync_preparation(&boundary)
        .unwrap();
}

#[tokio::test]
async fn named_capacity_refusal_hands_the_wait_to_the_coalescer() {
    for failed in [false, true] {
        let f = Fixture::new().await;
        f.create("capacity", b"dirty");
        *f.content.jitter_word.lock().unwrap() = Some(u64::MAX);
        if failed {
            f.io.0.lock().unwrap().fail = Some("length");
        }
        let pause = f
            .engine
            .live_refusal_pause_for_test(&CoordinationError::Overlay(OverlayError::Refused(
                "OverlayCapacityExhausted",
            )));
        assert_eq!(
            (
                pause,
                f.engine.live_pauses_for_test(),
                f.io.0.lock().unwrap().fail
            ),
            (
                Some(Duration::from_millis(40)),
                vec![(
                    Duration::from_millis(40),
                    if failed {
                        Duration::from_millis(40)
                    } else {
                        Duration::ZERO
                    }
                )],
                None
            ),
            "failed={failed}"
        );
    }
}

#[tokio::test]
async fn workspace_refusal_names_the_path_backs_off_and_lands_the_repaired_boundary() {
    let reports = crate::local_report::local_capture();
    let baseline = reports.len();
    let f = Fixture::new().await;
    f.create("a-small", b"unrelated");
    let stage = f.create("workspace\nfile", &vec![7; 2_097_152]);
    let options = SyncOptions {
        workspace_bytes: 8_388_608,
        ..SyncOptions::default()
    };
    let error = f
        .engine
        .construct_commit(options, &mut Entropy(70))
        .await
        .unwrap_err();
    let now = TokioSyncRuntime.now();
    let backoff = coalesce(&f, now + Duration::from_secs(1));
    let report = reports.since(baseline).into_iter().find(|line| {
        line.contains("SyncWorkspaceExhausted") && line.contains("workspace\\x0afile")
    });
    // A nonzero stall draw makes capacity's suppression observable.
    *f.content.jitter_word.lock().unwrap() = Some(u64::MAX);
    assert_eq!(
        (
            error.to_string(),
            crate::sync::failure_class(&error),
            crate::sync_mount_error(&error),
            f.engine.live_refusal_pause_for_test(&error),
            f.engine.live_pauses_for_test(),
            matches!(backoff, CoalesceState::WaitUntil(Some(at)) if at > now + Duration::from_secs(500)),
            f.engine.workspace_held_for_test(),
            report.is_some()
        ),
        (
            "intent refused: SyncWorkspaceExhausted".into(),
            crate::FailureClass::Refused,
            granary_fuse::MountSyncError::Backend(granary_fuse::MountError::NoSpace),
            Some(Duration::from_millis(40)),
            vec![(Duration::from_millis(40), Duration::ZERO)],
            true,
            0,
            true
        ),
        "report={report:?}, backoff={backoff:?}"
    );
    *f.content.jitter_word.lock().unwrap() = None;
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.truncate(stage, 0))
        .unwrap();
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(71))
        .await
        .unwrap();
    let result = budget::drive(&f, &lane, &mut Delay).await;
    let PublicationOutcome::Landed(done) = result.outcome else {
        panic!("boundary did not land");
    };
    assert_file(&f, &done.root, "workspace\nfile", b"");
    assert_file(&f, &done.root, "a-small", b"unrelated");
    assert_eq!(f.engine.workspace_held_for_test(), 0);
}

#[tokio::test]
async fn larger_workspace_lands_a_dirty_file_and_its_later_delta_uses_the_default() {
    let f = Fixture::over_capped(Basis::empty().await, 268_435_456)
        .await
        .unwrap();
    let mut rng = SeededRng::new(773);
    let mut bytes = vec![0_u8; 67_108_864];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    let stage = f.create("large", &bytes);
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.open_stage(&path("large")))
        .unwrap();
    let refused = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap_err();
    assert_eq!(
        (refused.to_string(), f.engine.workspace_held_for_test()),
        ("intent refused: SyncWorkspaceExhausted".into(), 0)
    );
    let options = SyncOptions {
        workspace_bytes: 2_147_483_648,
        ..SyncOptions::default()
    };
    let lane = f
        .engine
        .construct_commit(options, &mut Entropy(71))
        .await
        .unwrap();
    let first = budget::drive(&f, &lane, &mut Delay).await;
    assert!(
        matches!(first.outcome, PublicationOutcome::Landed(_)),
        "{first:?}"
    );
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(stage, 33_554_432, b"delta"))
        .unwrap();
    bytes[33_554_432..33_554_437].copy_from_slice(b"delta");
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(72))
        .await
        .unwrap();
    let second = budget::drive(&f, &lane, &mut Delay).await;
    let PublicationOutcome::Landed(done) = second.outcome else {
        panic!("delta did not land");
    };
    assert_file(&f, &done.root, "large", &bytes);
    assert_eq!(
        (
            f.engine.last_spend().values().sum::<u64>() < 134_217_728,
            f.engine.workspace_held_for_test()
        ),
        (true, 0)
    );
}

#[tokio::test]
async fn construction_leases_balance_cancellation_error_and_restart() {
    let f = Fixture::new().await;
    f.create("lease", b"retained");
    for _ in 0..3 {
        let capture = f.engine.begin_commit(SyncOptions::default()).await.unwrap();
        assert_eq!(f.engine.workspace_held_for_test(), 1_073_741_824);
        f.engine.discard_commit(capture).unwrap();
        assert_eq!(f.engine.workspace_held_for_test(), 0);
    }
    f.content.put_conflict.store(true, Ordering::Release);
    let error = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap_err();
    assert_eq!(
        (error.to_string(), f.engine.workspace_held_for_test()),
        ("overlay namespace conflict".into(), 0)
    );
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(71))
        .await
        .unwrap();
    assert_eq!(f.engine.workspace_held_for_test(), 1_073_741_824);
    drop(lane);
    let f = f.restart().await;
    assert_eq!(f.engine.workspace_held_for_test(), 0);
    let lane = f.engine.recover_commit(SyncOptions::default()).unwrap();
    assert_eq!(f.engine.workspace_held_for_test(), 1_073_741_824);
    budget::drive(&f, &lane, &mut Delay).await;
    assert_eq!(f.engine.workspace_held_for_test(), 0);
}

fn path(name: &str) -> Vec<Name> {
    vec![Name::new(name.as_bytes().to_vec()).unwrap()]
}

fn summary(f: &Fixture) -> crate::OverlaySummary {
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| Ok(t.summary()))
        .unwrap()
}

fn coalesce(f: &Fixture, now: tokio::time::Instant) -> CoalesceState {
    f.store
        .lock()
        .unwrap()
        .coalesce_state(&SyncOptions::default(), now)
        .unwrap()
}

/// Reopens the overlay under `cap`; a reopen is where a cap changes.
fn reopen_capped(f: &Fixture, cap: u64) {
    let mut local = f.store.lock().unwrap();
    let mut h = header();
    h.writer = local.writer_uuid();
    h.base_root = f.base;
    local.cap_for_test(cap);
    local
        .open_overlay(h, vec![], &mut Source::default(), f.io.clone())
        .unwrap();
}

/// Three dirty files reopened one byte under their measured total, then two
/// of them opened: Ready, dirty, holding handles and owing room above the cap.
async fn above_the_cap() -> (Fixture, [u64; 2], u64) {
    let f = Fixture::new().await;
    let names = ["held", "also-held"];
    for name in names {
        f.create(name, b"held bytes");
    }
    f.create("dirty", b"dirty bytes");
    let s = summary(&f);
    let total = s.charged_bytes + s.reserved_bytes + s.captured_bytes;
    reopen_capped(&f, total - 1);
    let held = names.map(|name| {
        f.store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.open_stage(&path(name)))
            .unwrap()
    });
    (f, held, total)
}

async fn refused_commit(f: &Fixture) -> Result<(), String> {
    f.engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

#[tokio::test]
async fn a_commit_above_the_cap_refuses_without_poisoning_and_reads_still_serve() {
    let (f, held, _) = above_the_cap().await;
    let before = summary(&f);
    let first = refused_commit(&f).await;
    // A lane left behind would refuse the second attempt as in flight.
    let second = refused_commit(&f).await;
    let after = summary(&f);
    let read = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.read_stage(held[0], 0, 10))
        .map_err(|e| format!("{e:?}"));
    assert_eq!(
        (
            before.owed.owed > 0,
            first,
            second,
            (after.records, after.charged_bytes),
            read,
            f.remote.publication_sends.lock().unwrap().len(),
        ),
        (
            true,
            Err("Overlay(Refused(\"OverlayCapacityExhausted\"))".into()),
            Err("Overlay(Refused(\"OverlayCapacityExhausted\"))".into()),
            (before.records, before.charged_bytes),
            Ok(b"held bytes".to_vec()),
            0,
        ),
        "before {before:?}, after {after:?}"
    );
}

const BACKOFF: Duration = Duration::from_mins(10);

#[tokio::test]
async fn above_the_cap_a_refused_commit_waits_out_its_backoff() {
    let (f, _, _) = above_the_cap().await;
    let first_attempt = coalesce(&f, TokioSyncRuntime.now());
    let refused = refused_commit(&f).await;
    let seen = TokioSyncRuntime.now();
    let after_refusal = coalesce(&f, seen);
    // Quiescence cannot fire with handles open; the maximum age has expired
    // and the commit request stands, yet the backoff holds.
    let before_backoff = coalesce(&f, seen + BACKOFF - Duration::from_secs(1));
    let after_backoff = coalesce(&f, seen + BACKOFF);
    assert_eq!(
        (
            first_attempt,
            refused,
            after_refusal,
            before_backoff,
            after_backoff
        ),
        (
            CoalesceState::Ready,
            Err("Overlay(Refused(\"OverlayCapacityExhausted\"))".into()),
            CoalesceState::WaitUntil(Some(seen + BACKOFF)),
            CoalesceState::WaitUntil(Some(seen + BACKOFF)),
            CoalesceState::Ready,
        )
    );
}

#[tokio::test]
async fn above_the_cap_a_handle_close_ends_the_backoff_with_a_wake() {
    let (f, held, _) = above_the_cap().await;
    let refused = refused_commit(&f).await;
    let after_refusal = coalesce(&f, TokioSyncRuntime.now());
    let wake = f.store.lock().unwrap().coalesce_wake.clone();
    let mut notified = std::pin::pin!(wake.notified());
    notified.as_mut().enable();
    // One of two handles closes: no last-close wake, the overlay is still
    // above the cap, and the refused commit is worth one more attempt.
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.close_stage(held[0]))
        .unwrap();
    let signalled =
        std::future::poll_fn(|cx| std::task::Poll::Ready(notified.as_mut().poll(cx).is_ready()))
            .await;
    let after_close = coalesce(&f, TokioSyncRuntime.now());
    let still_owed = summary(&f).owed.owed > 0;
    assert_eq!(
        (
            refused,
            matches!(after_refusal, CoalesceState::WaitUntil(Some(_))),
            signalled,
            after_close,
            still_owed
        ),
        (
            Err("Overlay(Refused(\"OverlayCapacityExhausted\"))".into()),
            true,
            true,
            CoalesceState::Ready,
            true,
        ),
        "{after_refusal:?}"
    );
}

#[tokio::test]
async fn a_cap_raised_after_a_refused_commit_makes_it_eligible_and_it_commits() {
    let (f, _, total) = above_the_cap().await;
    let refused = refused_commit(&f).await;
    let now = TokioSyncRuntime.now();
    let suppressed = coalesce(&f, now);
    reopen_capped(&f, total * 2);
    let raised = coalesce(&f, now + Duration::from_mins(1));
    let committed = refused_commit(&f).await;
    assert_eq!(
        (refused, suppressed, raised, committed),
        (
            Err("Overlay(Refused(\"OverlayCapacityExhausted\"))".into()),
            CoalesceState::WaitUntil(Some(now + BACKOFF)),
            CoalesceState::Ready,
            Ok(()),
        )
    );
}

#[tokio::test]
async fn a_commit_whose_capture_fits_but_whose_boundary_record_does_not_backs_off() {
    let f = Fixture::new().await;
    f.create("dirty", b"dirty bytes");
    let s = summary(&f);
    // Room for the capture and its graph charge, plus room that writes in
    // the capture window fill before the durable boundary is recorded.
    reopen_capped(
        &f,
        s.charged_bytes + s.reserved_bytes + s.captured_bytes + 65_536,
    );
    let faults = f.store.lock().unwrap().fault_control();
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
    let filler = f.create("filler", b"");
    let (mut offset, mut size) = (0_u64, 65_536_usize);
    while size > 0 {
        let wrote = f
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.write(filler, offset, &vec![7; size]).map(|_| ()));
        match wrote {
            Ok(()) => offset += size as u64,
            Err(CoordinationError::Overlay(OverlayError::NoSpace)) => size /= 2,
            Err(error) => panic!("filler write: {error:?}"),
        }
    }
    faults.resume();
    let refused = constructing.await.map(|_| ()).map_err(|e| format!("{e:?}"));
    let now = TokioSyncRuntime.now();
    let state = coalesce(&f, now + Duration::from_mins(1));
    assert_eq!(
        (refused, summary(&f).owed.owed, state),
        (
            Err("Overlay(Refused(\"OverlayCapacityExhausted\"))".into()),
            0,
            CoalesceState::WaitUntil(Some(now + Duration::from_mins(1) + BACKOFF)),
        ),
        "filled {offset} bytes"
    );
}

#[tokio::test]
async fn a_write_refusal_does_not_supply_capacity_bytes_to_a_workspace_refusal() {
    let f = Fixture::new().await;
    let stage = f.create("full", b"bytes");
    let before = summary(&f);
    reopen_capped(
        &f,
        before.charged_bytes + before.reserved_bytes + before.captured_bytes,
    );
    let write = f
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(stage, 5, b"x"));
    assert!(
        matches!(
            write,
            Err(CoordinationError::Overlay(OverlayError::NoSpace))
        ),
        "write refusal premise: {write:?}"
    );
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let pause = f
        .engine
        .live_refusal_pause_for_test(&CoordinationError::Refused("SyncWorkspaceExhausted"));
    drop(guard);
    let events = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (pause, events.contains("overlay.cap_exhausted")),
        (Some(Duration::from_millis(40)), false),
        "{events}"
    );
}

#[tokio::test]
async fn a_landed_file_held_open_does_not_keep_the_eager_trigger_on() {
    let f = Fixture::new().await;
    let object = f.create("held", &vec![7; 34 * 1_048_576]);
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.open_stage(&path("held")))
        .unwrap();
    let lane = f
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let landed = budget::drive(&f, &lane, &mut Delay).await;
    assert!(
        matches!(landed.outcome, PublicationOutcome::Landed(_)),
        "{landed:?}"
    );
    let after = summary(&f);
    f.store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(object, 0, b"x"))
        .unwrap();
    let state = coalesce(&f, TokioSyncRuntime.now());
    assert_eq!(
        (
            after.commit_requested,
            matches!(state, CoalesceState::Ready)
        ),
        (false, false),
        "after={after:?}, state={state:?}"
    );
}
